/**
 * Share links: a check (URL, claim, recall, travel...) is run on the server, its result is stored as a snapshot,
 * and /r/<id> shows it as a page with link-preview tags. Results are never taken from the browser, so a shared
 * page always shows what Oculon actually returned.
 */
import { randomBytes } from 'node:crypto';
import type { Oculon } from '../index.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export const SHARE_KINDS = ['url', 'factcheck', 'travel', 'audit', 'recall', 'emailsec', 'papers', 'country', 'airport'] as const;
export type ShareKind = (typeof SHARE_KINDS)[number];

export interface ShareSummary {
  kind: ShareKind;
  label: string;
  title: string;
  verdict: string;
  tone: 'ok' | 'warn' | 'bad' | 'info';
  points: string[];
  links: { text: string; url: string }[];
}

export interface Share {
  id: string;
  kind: ShareKind;
  input: string;
  createdAt: string;
  summary: ShareSummary;
  sources: string[];
}

type Anyr = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const LABEL: Record<ShareKind, string> = { url: 'Link check', factcheck: 'Fact check', travel: 'Travel risk', audit: 'Dependency audit', recall: 'Recall check', emailsec: 'Email security', papers: 'Research brief', country: 'Country brief', airport: 'Airport status' };

const fmt = (n: number | null | undefined, unit: string) => {
  if (n == null) return 'n/a';
  if (unit === 'USD') return n >= 1e12 ? `$${(n / 1e12).toFixed(2)} trillion` : n >= 1e9 ? `$${(n / 1e9).toFixed(1)} billion` : `$${Math.round(n).toLocaleString('en-US')}`;
  if (unit === 'people') return n >= 1e6 ? `${(n / 1e6).toFixed(1)} million` : Math.round(n).toLocaleString('en-US');
  return `${n.toFixed(1)}%`;
};

/** A plain summary of any shareable result: a title, a verdict, a few points and the key links. */
export function summarize(kind: ShareKind, r: Anyr): ShareSummary {
  const x = r.result as Anyr;
  const base = { kind, label: LABEL[kind] };
  switch (kind) {
    case 'url':
      return { ...base, title: x.host, verdict: x.verdict, tone: x.verdict === 'malicious' ? 'bad' : x.verdict === 'suspicious' ? 'warn' : 'ok', points: [`Risk ${x.risk}/100`, ...x.reasons.slice(0, 5), ...(x.verdict === 'no known threats' ? ['No source flags it. That is not a guarantee the page is safe.'] : [])], links: x.scans?.latest ? [{ text: 'Latest urlscan.io scan', url: x.scans.latest }] : [] };
    case 'factcheck': {
      const all = [...x.factChecks, ...x.web] as Anyr[];
      const cited = all.filter((e) => !x.cited.length || x.cited.includes(e.n)).slice(0, 5);
      return { ...base, title: x.claim, verdict: x.verdict, tone: /false|misleading/.test(x.verdict) ? 'bad' : /true/.test(x.verdict) ? 'ok' : 'warn', points: [x.summary.replace(/\s*\[\d+\]/g, ''), ...(x.confidence ? [`Confidence ${x.confidence}%`] : [])].filter(Boolean), links: cited.map((e) => ({ text: `${e.publisher}${e.rating ? `: "${e.rating}"` : ''}`, url: e.url })) };
    }
    case 'travel':
      return { ...base, title: x.place.name.split(',').slice(0, 2).join(','), verdict: `${x.level} risk`, tone: x.level === 'low' ? 'ok' : x.level === 'moderate' ? 'warn' : 'bad', points: x.points.length ? x.points.slice(0, 6) : ['No warnings from the sources checked.'], links: [x.advisories.us && { text: 'US travel advisory', url: x.advisories.us.url }, x.advisories.uk && { text: 'UK travel advice', url: x.advisories.uk.url }].filter(Boolean) };
    case 'audit': {
      const s = x.summary;
      const flagged = (x.packages as Anyr[]).filter((p) => p.flags.length).slice(0, 6);
      return { ...base, title: `${s.checked} package${s.checked === 1 ? '' : 's'} checked`, verdict: s.vulnerable ? `${s.vulnerable} vulnerable` : 'no known vulnerabilities', tone: s.vulnerable ? 'bad' : s.deprecated || s.stale ? 'warn' : 'ok', points: flagged.map((p) => `${p.name}@${p.version}: ${p.flags.slice(0, 2).join('; ')}`), links: flagged.flatMap((p) => (p.advisories as Anyr[]).slice(0, 1).map((a) => ({ text: `${a.aliases[0] ?? a.id} (${p.name})`, url: a.url }))).slice(0, 5) };
    }
    case 'recall': {
      const v = x.vehicle;
      const title = v ? `${v.year} ${v.make} ${v.model}` : x.query;
      const park = (x.recalls as Anyr[]).some((c) => c.parkIt || c.parkOutside);
      return { ...base, title, verdict: x.recalls.length ? `${x.recalls.length} recall${x.recalls.length === 1 ? '' : 's'}` : 'no recalls found', tone: park ? 'bad' : x.recalls.length ? 'warn' : 'ok', points: [...(x.recalls as Anyr[]).slice(0, 5).map((c) => `${c.date ?? ''} ${c.title}: ${c.hazard}`.trim().slice(0, 220)), ...(x.note ? [x.note] : [])], links: (x.recalls as Anyr[]).slice(0, 5).map((c) => ({ text: `${c.source} ${c.id}`, url: c.url })) };
    }
    case 'emailsec':
      return { ...base, title: x.domain, verdict: x.verdict, tone: x.verdict === 'protected' ? 'ok' : x.verdict === 'partly protected' ? 'warn' : 'bad', points: [`Score ${x.score}/100`, `SPF: ${x.spf.all ?? (x.spf.record ? 'present' : 'missing')}`, `DMARC: ${x.dmarc.policy ? `p=${x.dmarc.policy}` : 'missing'}`, `DKIM: ${x.dkim.selectorsFound.length ? x.dkim.selectorsFound.join(', ') : 'no common selector found'}`, ...x.fixes.slice(0, 3)], links: [] };
    case 'papers':
      return { ...base, title: x.topic, verdict: x.trend ? `field ${x.trend}` : `${x.totalWorks ?? 0} works`, tone: 'info', points: [...(x.overview ? [x.overview.replace(/\s*\[\d+(?:,\s*\d+)*\]/g, '')] : []), ...(x.mostCited as Anyr[]).slice(0, 4).map((p) => `${p.title} (${p.year}, ${p.citations} citations)`)], links: (x.mostCited as Anyr[]).slice(0, 5).map((p) => ({ text: p.title.slice(0, 80), url: p.openAccessUrl ?? p.url })) };
    case 'country':
      return { ...base, title: x.name, verdict: x.advisories.us ? `US advisory level ${x.advisories.us.level}` : x.region ?? '', tone: (x.advisories.us?.level ?? 1) >= 3 ? 'bad' : (x.advisories.us?.level ?? 1) === 2 ? 'warn' : 'info', points: [`Head of state: ${x.leaders.headOfState ?? 'n/a'}${x.leaders.headOfGovernment && x.leaders.headOfGovernment !== x.leaders.headOfState ? `; government: ${x.leaders.headOfGovernment}` : ''}`, ...(x.indicators as Anyr[]).filter((i) => i.value != null).map((i) => `${i.name}: ${fmt(i.value, i.unit)} (${i.year})`), ...(x.currency.perUsd ? [`1 USD = ${x.currency.perUsd.toFixed(2)} ${x.currency.code}`] : []), ...(x.outages as string[]).slice(0, 1).map((o) => `Internet outage: ${o}`)], links: (x.headlines as Anyr[]).slice(0, 4).map((h) => ({ text: h.title, url: h.url })) };
    case 'airport':
      return { ...base, title: x.airport.name, verdict: x.verdict, tone: x.verdict === 'normal' ? 'ok' : x.verdict === 'disrupted' ? 'bad' : 'warn', points: x.points.slice(0, 6), links: [] };
  }
}

/** Runs the check for a shareable kind. */
export async function runShareable(o: Oculon, kind: ShareKind, q: string): Promise<ModuleResult<unknown>> {
  switch (kind) {
    case 'url': return o.urlCheck(q);
    case 'factcheck': return o.factCheck(q);
    case 'travel': return o.travel(q);
    case 'audit': return o.audit(q);
    case 'recall': return o.recall(q);
    case 'emailsec': return o.emailSecurity(q);
    case 'papers': return o.papers(q);
    case 'country': return o.country(q);
    case 'airport': return o.airport(q);
  }
}

const sourcesOf = (prov: Provenance[]) => [...new Set(prov.filter((p) => p.status === 'LIVE' || p.status === 'CACHED').map((p) => p.source))];

function table(o: Oculon) {
  o.ctx.store.db.exec('CREATE TABLE IF NOT EXISTS shares (id TEXT PRIMARY KEY, kind TEXT NOT NULL, input TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS shares_lookup ON shares (kind, input, created_at);');
  return o.ctx.store.db;
}

/** Runs the check and stores a snapshot; the same check within 6 hours reuses its link. */
export async function createShare(o: Oculon, kind: string, input: string): Promise<Share> {
  if (!(SHARE_KINDS as readonly string[]).includes(kind)) throw new Error(`cannot share "${kind}"`);
  const k = kind as ShareKind;
  const q = input.trim().slice(0, 2000);
  if (!q) throw new Error('missing input');
  const db = table(o);
  const recent = db.prepare('SELECT id FROM shares WHERE kind = ? AND input = ? AND created_at > ? ORDER BY created_at DESC LIMIT 1').get(k, q, Date.now() - 6 * 3600_000) as { id: string } | undefined;
  if (recent) return getShare(o, recent.id)!;
  const r = await runShareable(o, k, q);
  const share: Share = { id: randomBytes(6).toString('base64url'), kind: k, input: q, createdAt: new Date().toISOString(), summary: summarize(k, r as Anyr), sources: sourcesOf(r.provenance) };
  db.prepare('INSERT INTO shares (id, kind, input, payload, created_at) VALUES (?, ?, ?, ?, ?)').run(share.id, k, q, JSON.stringify(share), Date.now());
  return share;
}

export function getShare(o: Oculon, id: string): Share | null {
  if (!/^[A-Za-z0-9_-]{6,16}$/.test(id)) return null;
  const row = table(o).prepare('SELECT payload FROM shares WHERE id = ?').get(id) as { payload: string } | undefined;
  return row ? (JSON.parse(row.payload) as Share) : null;
}

const esc = (s: string) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const safeUrl = (u: string) => (/^https?:\/\//i.test(u) ? esc(u) : '#');

/** The public page for a share, with Open Graph and Twitter card tags. */
export function sharePage(s: Share, origin: string, appUrl: string): string {
  const x = s.summary;
  const title = `${x.label}: ${x.title} · ${x.verdict}`;
  const desc = (x.points[0] ?? '').slice(0, 200);
  const url = `${origin}/r/${s.id}`;
  const color = { ok: '#00f0ff', warn: '#ffd34d', bad: '#ff7a6b', info: '#e8e8e8' }[x.tone];
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Oculon</title><meta name="description" content="${esc(desc)}">
<meta property="og:type" content="article"><meta property="og:site_name" content="Oculon"><meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(desc)}"><meta property="og:url" content="${esc(url)}"><meta property="og:image" content="${esc(origin)}/assets/og.png"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${esc(title)}"><meta name="twitter:description" content="${esc(desc)}"><meta name="twitter:image" content="${esc(origin)}/assets/og.png">
<link rel="icon" href="/favicon.ico"><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#000;--card:#0a0a0a;--line:#1f1f1f;--text:#f2f2f2;--mut:#9aa5a7;--accent:#00f0ff}
@media (prefers-color-scheme:light){:root{--bg:#fff;--card:#fafafa;--line:#e4e4e4;--text:#0a0a0a;--mut:#555;--accent:#00838f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:'Space Grotesk',system-ui,sans-serif;line-height:1.55}
main{max-width:760px;margin:0 auto;padding:48px 16px 64px}
.brand{font-family:'Space Mono',monospace;letter-spacing:.2em;text-transform:uppercase;font-size:13px;color:var(--accent);text-decoration:none}
.kind{font-family:'Space Mono',monospace;font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);margin-top:36px}
h1{font-weight:500;font-size:clamp(28px,5vw,44px);line-height:1.1;letter-spacing:-.02em;margin:10px 0 18px;overflow-wrap:anywhere}
.verdict{display:inline-block;font-family:'Space Mono',monospace;font-size:13px;text-transform:uppercase;letter-spacing:.08em;padding:4px 12px;border:1px solid ${color};color:${color}}
ul{list-style:none;padding:0;margin:26px 0;border-top:1px solid var(--line)}li{padding:12px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
h2{font-size:14px;font-family:'Space Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);font-weight:400;margin:30px 0 8px}
a{color:var(--accent)}.links a{display:block;padding:6px 0;text-decoration:none;overflow-wrap:anywhere}
.meta{color:var(--mut);font-size:14px}.cta{display:inline-block;margin-top:34px;background:var(--accent);color:#04130d;padding:11px 18px;text-decoration:none;font-weight:600}
</style></head><body><main>
<a class="brand" href="${esc(origin)}/">◉ Oculon</a>
<div class="kind">${esc(x.label)}</div>
<h1>${esc(x.title)}</h1>
<span class="verdict">${esc(x.verdict)}</span>
<ul>${x.points.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>
${x.links.length ? `<h2>Sources</h2><div class="links">${x.links.map((l) => `<a href="${safeUrl(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.text)} ↗</a>`).join('')}</div>` : ''}
<p class="meta">Checked ${esc(s.createdAt.slice(0, 16).replace('T', ' '))} UTC from ${esc(s.sources.join(', ') || 'public sources')}. A snapshot: run it again for the latest.</p>
<a class="cta" href="${esc(appUrl)}">Run your own check →</a>
</main></body></html>`;
}
