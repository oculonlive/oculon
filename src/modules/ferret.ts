/**
 * Ferret: finds footprints of things that are not announced yet.
 * New hostnames in Certificate Transparency logs, pages that only recently appeared in the
 * Wayback Machine, hosts seen in urlscan.io scans, freshly created public GitHub repos, and Google Safe Browsing
 * verdicts on everything new.
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { entityId } from '../core/graph.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { certspotter, crtsh, type CertEntry } from '../sources/certs.js';
import { recentRepos } from '../sources/github.js';
import { captures, normalizePath } from '../sources/wayback.js';
import { safeBrowsing, urlscan } from '../sources/websec.js';

export type FindingKind = 'subdomain' | 'page' | 'repo';

export interface Finding {
  kind: FindingKind;
  value: string;
  firstSeen: string;
  source: string;
  url: string;
  score: number;
  reasons: string[];
  /** True only when a previous scan of this domain exists and did not contain this item. */
  newSinceLastScan: boolean;
}

export interface FerretResult {
  domain: string;
  /** URLs Google Safe Browsing flags among the domain and new findings. */
  flagged: { url: string; threat: string }[];
  windowDays: number;
  firstScan: boolean;
  findings: Finding[];
  counts: Record<FindingKind, number>;
}

export interface FerretOptions {
  days?: number;
  /** GitHub org/user to check. Defaults to the domain's first label (openai.com -> openai). */
  org?: string | false;
  limit?: number;
}

const HOT: [RegExp, number, string][] = [
  [/\b(beta|preview|alpha|early|waitlist|preorder|pre-order)\b/, 25, 'pre-release word'],
  [/\b(labs?|research|experimental|exp|next|future|sandbox|playground)\b/, 18, 'experimental area'],
  [/\b(launch|announce|reveal|event|keynote|invite)\b/, 18, 'launch word'],
  [/\b(device|hardware|glasses|watch|car|robot|phone|wearable|chip)\b/, 20, 'hardware word'],
  [/\b(agent|agents|assistant|copilot|ai|gpt|model|voice|vision|video)\b/, 12, 'AI product word'],
  [/\b(pay|wallet|card|checkout|store|shop|marketplace|ads|commerce)\b/, 12, 'commerce word'],
  [/\b(app|studio|platform|pro|plus|max|enterprise|business|team|edu)\b/, 8, 'product word'],
  [/\b(v\d+|\d+\.\d+|gen\d+)\b/, 10, 'version marker'],
];

const NOISE: RegExp[] = [
  /^(www|mail|smtp|imap|pop|mx\d*|webmail|autodiscover|autoconfig|cpanel|whm|ftp|ns\d*|mta-sts|_dmarc|lyncdiscover|sip|enterpriseenrollment|enterpriseregistration)\./,
  /\b[0-9a-f]{10,}\b/,
  /\b(static|cdn|assets|img|images|media|cache|edge|lb|origin|status|metrics|monitoring|grafana|prometheus|sentry|analytics|tracking|email|em\d*|click|links?|bounce|unsubscribe)\b/,
];

const PAGE_NOISE = /\/(tag|tags|category|author|page|feed|search|login|signin|signup|cart|legal|privacy|terms|cookie|cookies|sitemap|wp-|cdn-cgi)(\/|$)|\/\d{4}\/\d{2}\//;

function tokens(value: string): string {
  return value.toLowerCase().replace(/[._/\-]+/g, ' ');
}

export function scoreName(kind: FindingKind, value: string, firstSeenMs: number, nowMs: number, windowDays: number): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = kind === 'repo' ? 30 : kind === 'subdomain' ? 25 : 15;
  const t = ` ${tokens(value)} `;
  for (const [re, w, why] of HOT) {
    const m = re.exec(t);
    if (m) {
      score += w;
      reasons.push(`${why}: "${m[0].trim()}"`);
    }
  }
  const ageDays = (nowMs - firstSeenMs) / DAY_MS;
  const recency = clamp(1 - ageDays / windowDays, 0, 1);
  score += Math.round(recency * 20);
  if (recency > 0.8) reasons.push('first seen in the last few days');
  return { score: clamp(score, 0, 100), reasons };
}

export function isNoiseHost(host: string): boolean {
  return NOISE.some((re) => re.test(host));
}

/** First time each hostname under `domain` appeared on any certificate. */
export function firstSeenHosts(entries: CertEntry[], domain: string): Map<string, number> {
  const first = new Map<string, number>();
  const d = domain.toLowerCase();
  for (const e of entries) {
    const t = Date.parse(e.notBefore);
    if (!Number.isFinite(t)) continue;
    for (const raw of e.names) {
      const host = raw.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
      if (host === d || !host.endsWith(`.${d}`)) continue;
      const prev = first.get(host);
      if (prev === undefined || t < prev) first.set(host, t);
    }
  }
  return first;
}

function tsToMs(ts: string): number {
  const iso = `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T${ts.slice(8, 10) || '00'}:${ts.slice(10, 12) || '00'}:00Z`;
  return Date.parse(iso);
}

export async function ferret(ctx: Ctx, domainInput: string, opts: FerretOptions = {}): Promise<ModuleResult<FerretResult>> {
  const domain = domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  const days = opts.days ?? 30;
  const nowMs = ctx.now().getTime();
  const since = nowMs - days * DAY_MS;
  const provenance: Provenance[] = [];
  const domainId = entityId('domain', domain);
  const firstScan = !(ctx.graph.get(domainId)?.attrs.lastScan);
  const org = opts.org === false ? null : (opts.org ?? domain.split('.')[0]!);

  const [certsPrimary, recentCaps, olderCaps, repos, scans] = await Promise.all([
    crtsh(ctx, domain),
    captures(ctx, domain, days, 0),
    captures(ctx, domain, 400, days + 1),
    org ? recentRepos(ctx, org) : Promise.resolve(null),
    urlscan(ctx, domain, 100),
  ]);
  provenance.push(scans.prov);

  let certs = certsPrimary;
  provenance.push(certsPrimary.prov);
  if (!certsPrimary.data) {
    certs = await certspotter(ctx, domain);
    provenance.push(certs.prov);
  }
  provenance.push(recentCaps.prov, olderCaps.prov);
  if (repos) provenance.push(repos.prov);

  const raw: Omit<Finding, 'score' | 'reasons' | 'newSinceLastScan'>[] = [];

  // Subdomains first seen inside the window.
  if (certs.data) {
    for (const [host, t] of firstSeenHosts(certs.data, domain)) {
      if (t < since || isNoiseHost(host)) continue;
      raw.push({ kind: 'subdomain', value: host, firstSeen: new Date(t).toISOString(), source: certs.prov.source, url: `https://crt.sh/?q=${host}` });
    }
  }

  // Pages captured recently that never showed up in the previous ~year.
  if (recentCaps.data && olderCaps.data) {
    const older = new Set(olderCaps.data.map((c) => normalizePath(c.url)).filter(Boolean));
    const seen = new Set<string>();
    for (const c of recentCaps.data) {
      const p = normalizePath(c.url);
      if (!p || older.has(p) || seen.has(p) || p.endsWith(`${domain}/`) || PAGE_NOISE.test(p)) continue;
      seen.add(p);
      const t = tsToMs(c.timestamp);
      raw.push({ kind: 'page', value: p, firstSeen: new Date(t).toISOString(), source: 'wayback', url: `https://web.archive.org/web/${c.timestamp}/${c.url}` });
    }
  }

  // Hostnames that urlscan.io users scanned but that never appeared on a certificate we saw
  // (often wildcard-covered hosts, which CT logs cannot reveal).
  if (scans.data) {
    const certHosts = new Set(certs.data ? firstSeenHosts(certs.data, domain).keys() : []);
    const known = new Set(raw.filter((f) => f.kind === 'subdomain').map((f) => f.value));
    const firstScanAt = new Map<string, { t: number; url: string }>();
    for (const s of scans.data) {
      const host = s.host.replace(/^www\./, '');
      const t = Date.parse(s.time);
      if (!host.endsWith(`.${domain}`) || certHosts.has(host) || known.has(host) || isNoiseHost(host) || !Number.isFinite(t)) continue;
      const prev = firstScanAt.get(host);
      if (!prev || t < prev.t) firstScanAt.set(host, { t, url: s.screenshot });
    }
    for (const [host, { t, url }] of firstScanAt) {
      if (t < since) continue;
      raw.push({ kind: 'subdomain', value: host, firstSeen: new Date(t).toISOString(), source: 'urlscan', url });
    }
  }

  // Public repos created inside the window.
  if (repos?.data) {
    for (const r of repos.data) {
      const t = Date.parse(r.created_at);
      if (r.fork || t < since) continue;
      raw.push({
        kind: 'repo',
        value: `${r.full_name}${r.description ? ` — ${r.description}` : ''}`,
        firstSeen: r.created_at,
        source: 'github',
        url: r.html_url,
      });
    }
  }

  ctx.graph.upsert('domain', domain);
  const findings: Finding[] = raw.map((f) => {
    const kindForId = f.kind === 'subdomain' ? 'subdomain' : f.kind === 'repo' ? 'repo' : 'url';
    const name = f.kind === 'repo' ? f.value.split(' — ')[0]! : f.value;
    const id = entityId(kindForId, name);
    const existed = ctx.graph.has(id);
    ctx.graph.upsert(kindForId, name, { firstSeen: f.firstSeen, source: f.source, url: f.url });
    ctx.graph.link(domainId, id, f.kind === 'repo' ? 'owns_repo' : f.kind === 'subdomain' ? 'has_subdomain' : 'has_page', f.source);
    const { score, reasons } = scoreName(f.kind, f.value, Date.parse(f.firstSeen), nowMs, days);
    const newSinceLastScan = !firstScan && !existed;
    return {
      ...f,
      score: clamp(score + (newSinceLastScan ? 10 : 0), 0, 100),
      reasons: newSinceLastScan ? [...reasons, 'new since your last scan'] : reasons,
      newSinceLastScan,
    };
  });

  // Google Safe Browsing over the domain and every new host/page: a flagged new subdomain is a strong signal
  // (compromise, or a lookalike phishing page riding on the brand).
  const toCheck = [`https://${domain}/`, ...findings.filter((f) => f.kind !== 'repo').map((f) => (f.kind === 'subdomain' ? `https://${f.value}/` : `https://${f.value}`))];
  const sb = await safeBrowsing(ctx, toCheck);
  provenance.push(sb.prov);
  const flagged = sb.data ?? [];
  for (const f of findings) {
    const hit = flagged.find((x) => x.url.includes(f.value));
    if (hit) {
      f.score = clamp(f.score + 30, 0, 100);
      f.reasons.push(`flagged by Google Safe Browsing: ${hit.threat}`);
    }
  }

  findings.sort((a, b) => b.score - a.score || b.firstSeen.localeCompare(a.firstSeen));
  const limited = findings.slice(0, opts.limit ?? 100);
  ctx.graph.upsert('domain', domain, { lastScan: new Date(nowMs).toISOString() });

  const createdAt = new Date(nowMs).toISOString();
  const signals: Signal[] = limited
    .filter((f) => f.score >= 60)
    .slice(0, 10)
    .map((f) => ({
      id: signalId('ferret', domain, f.kind, f.value),
      module: 'ferret',
      title: `${domain}: new ${f.kind} ${f.value.split(' — ')[0]}`,
      score: f.score,
      entity: domainId,
      evidence: [{ source: f.source, text: `${f.kind} first seen ${f.firstSeen.slice(0, 10)}; ${f.reasons.join(', ') || 'recent'}`, url: f.url }],
      createdAt,
    }));
  signals.forEach((s) => ctx.graph.saveSignal(s));

  const counts = { subdomain: 0, page: 0, repo: 0 } as Record<FindingKind, number>;
  for (const f of findings) counts[f.kind]++;

  return {
    module: 'ferret',
    input: domain,
    generatedAt: createdAt,
    result: { domain, flagged, windowDays: days, firstScan, findings: limited, counts },
    signals,
    provenance,
  };
}
