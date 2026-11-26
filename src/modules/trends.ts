/**
 * Scam Trends: what people checked with Oculon this week, as counts and categories only.
 * Reads the stored checks (modules/checks.ts) of the last 7 days and the 7 before, and reports checks by kind, the
 * verdict split, the most common scam patterns and link warning signs, the most impersonated brands and the
 * top-level domains of flagged links. Nothing that was checked is ever returned: no inputs, labels, URLs, messages,
 * addresses or numbers. Free text from results is never echoed either; it is matched against a fixed list of
 * categories, and only known brand names and plain top-level domains are counted. Any bucket with fewer than
 * MIN_BUCKET checks is left out.
 */
import type { Ctx } from '../core/context.js';

export const MIN_BUCKET = 3;
/** Below this many checks in the week the page says there is too little to call a trend. */
export const ENOUGH = 20;

export interface TrendBucket { name: string; checks: number }

export interface ScamTrends {
  generatedAt: string;
  from: string;
  to: string;
  previousFrom: string;
  total: number;
  previousTotal: number;
  /** Change against the week before, in percent; null when either week has fewer than MIN_BUCKET checks. */
  changePct: number | null;
  enough: boolean;
  note: string | null;
  minBucket: number;
  byKind: { kind: string; label: string; checks: number; previous: number | null; changePct: number | null }[];
  /** Checks in kinds too small to show on their own. */
  otherKinds: number;
  verdicts: { tone: 'bad' | 'warn' | 'ok' | 'info'; label: string; checks: number; share: number }[];
  patterns: TrendBucket[];
  brands: TrendBucket[];
  tlds: TrendBucket[];
}

const KIND_LABEL: Record<string, string> = {
  scam: 'Scam message', url: 'Link', site: 'Website', qr: 'QR code', job: 'Job offer', headers: 'Email headers', eml: 'Email file',
  emailsec: 'Email security', iban: 'IBAN', phone: 'Phone number', ip: 'IP address', hash: 'File hash', lookalike: 'Lookalike domains',
  wallet: 'Wallet', token: 'Token', rhtoken: 'Robinhood Chain token', honeypot: 'Honeypot', address: 'Crypto address', approvals: 'Wallet approvals',
  contract: 'Contract risk', poisoning: 'Address poisoning', trace: 'Fund trace', signature: 'Signature request', tx: 'Transaction',
  creator: 'Token creator', invite: 'Invite link', apk: 'Android app', image: 'Image', doc: 'Document', where: 'Photo location',
  repo: 'Code repository', archive: 'Page archive', company: 'Company', sanctions: 'Sanctions', factcheck: 'Fact check', recall: 'Recall',
  travel: 'Travel', cve: 'Vulnerability', exposure: 'Domain exposure', domainreport: 'Domain report', walletreport: 'Wallet report', stocktoken: 'Stock token',
};

const TONE_LABEL = { bad: 'Dangerous', warn: 'Suspicious', ok: 'No known risk', info: 'No verdict' } as const;

/** Warning signs in check results, by the fixed wording the modules use. Unmatched text is ignored. */
const SIGNS: [RegExp, string][] = [
  [/Google Safe Browsing flags it/i, 'flagged by Google Safe Browsing'],
  [/listed as phishing or a wallet drainer/i, 'on a phishing or wallet-drainer blocklist'],
  [/URLhaus lists this URL/i, 'listed by URLhaus as malicious'],
  [/malware URLs? on this host/i, 'host serves known malware'],
  [/urlscan\.io scans of this host are tagged/i, 'tagged malicious by urlscan.io'],
  [/the domain was registered \d+ days? ago/i, 'domain registered in the last 30 days'],
  [/the domain is young/i, 'domain under 6 months old'],
  [/the host is a raw IP address/i, 'raw IP address instead of a name'],
  [/punycode/i, 'look-alike characters (punycode)'],
  [/top-level domain often used for abuse/i, 'top-level domain often used for abuse'],
  [/mentions "[^"]+" but is not on/i, 'brand name on a domain the brand does not own'],
  [/contains "@", which can hide/i, '"@" hiding the real destination'],
  [/unusually deep subdomain chain/i, 'deep subdomain chain'],
  [/many hyphens in the host name/i, 'many hyphens in the host name'],
  [/no HTTPS in the link/i, 'no HTTPS'],
  [/link shortener hides/i, 'link shortener hides the destination'],
  [/promises an airdrop, claim, giveaway or presale/i, 'promises an airdrop or giveaway'],
  [/the classic fake support or fake project pattern/i, 'fake support or fake project channel'],
  [/Telegram itself labels this account as scam or fake/i, 'labelled scam or fake by Telegram'],
  [/signed with the Android debug key/i, 'app signed with a debug key'],
  [/wakes up on every incoming SMS/i, 'app reads every incoming SMS'],
];

/** Brands the link check knows (urlcheck.ts) plus the chat platforms the invite check names. */
const BRANDS = new Set(['paypal', 'apple', 'icloud', 'microsoft', 'office365', 'outlook', 'google', 'gmail', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'metamask', 'binance', 'coinbase', 'kraken', 'ledger', 'trezor', 'wellsfargo', 'chase', 'bankofamerica', 'hsbc', 'dhl', 'fedex', 'usps', 'steam', 'discord', 'telegram', 'docusign', 'dropbox', 'adobe', 'linkedin', 'twitter', 'opensea', 'uniswap', 'phantom', 'trustwallet', 'robinhood']);
const BRAND_TEXT = [/mentions "([a-z0-9]+)" but is not on/i, /uses "([a-z0-9 ]+)" and "[^"]*" in its name/i, /uses the name "([a-z0-9 ]+)" with only/i];
const ABUSE_TLD = /^\.([a-z]{2,24}) is a top-level domain often used for abuse/i;
const PATTERN_NAME = /^[A-Za-z0-9 ,"'()/-]{3,90}$/;
/** Checks that are about one link, so a flagged verdict is a flagged link. */
const LINK_KINDS = new Set(['url', 'site']);
const FLAGGED_LINK =/^(malicious|suspicious|phishing|likely scam|dangerous)/i;

type Any = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Top-level domain of a host or URL, when it is a plain name (not an IP). */
export function tldOf(s: string): string | null {
  let host = s.trim().toLowerCase();
  try { if (/^[a-z][a-z0-9+.-]*:\/\//.test(host)) host = new URL(host).hostname; } catch { return null; }
  host = host.replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (!host.includes('.') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return null;
  const tld = host.split('.').at(-1)!;
  return /^(xn--[a-z0-9-]{2,30}|[a-z]{2,24})$/.test(tld) ? tld : null;
}

/** Every string under the listed keys, at any depth (reasons, heuristics, flags, warnings, findings). */
function reasonTexts(v: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 6 || !v || typeof v !== 'object') return out;
  if (Array.isArray(v)) { for (const x of v) reasonTexts(x, out, depth + 1); return out; }
  for (const [k, x] of Object.entries(v as Any)) {
    if (/^(reasons|heuristics|flags|warnings|findings)$/.test(k) && Array.isArray(x)) {
      for (const s of x) {
        if (typeof s === 'string') out.push(s);
        else if (Array.isArray(s) && typeof s[0] === 'string') out.push(s[0]);
        else if (s && typeof s === 'object' && typeof (s as Any).text === 'string') out.push((s as Any).text);
      }
    } else if (x && typeof x === 'object') reasonTexts(x, out, depth + 1);
  }
  return out;
}

/** The categories one stored check contributes: patterns, warning signs, brands, TLDs. Each counts once per check. */
export function categoriesOf(kind: string, result: unknown, tone: string): { patterns: Set<string>; brands: Set<string>; tlds: Set<string> } {
  const patterns = new Set<string>(), brands = new Set<string>(), tlds = new Set<string>();
  const o = (result ?? {}) as Any;
  const x = (o.result && typeof o.result === 'object' ? o.result : o) as Any;
  // Scam and job checks name their patterns from a fixed list in code; the matched text (evidence) is never read.
  if ((kind === 'scam' || kind === 'job') && Array.isArray(x.patterns)) {
    for (const p of x.patterns as Any[]) if (typeof p?.name === 'string' && PATTERN_NAME.test(p.name)) patterns.add(p.name.toLowerCase());
  }
  for (const t of reasonTexts(x)) {
    for (const [re, name] of SIGNS) if (re.test(t)) patterns.add(name);
    for (const re of BRAND_TEXT) { const b = re.exec(t)?.[1]?.toLowerCase().replace(/\s+/g, ''); if (b && BRANDS.has(b)) brands.add(b); }
    const abuse = ABUSE_TLD.exec(t)?.[1]?.toLowerCase();
    if (abuse) tlds.add(abuse);
  }
  // Top-level domains of the links a flagged check was about, and of flagged links inside a message.
  if ((tone === 'bad' || tone === 'warn') && LINK_KINDS.has(kind)) {
    for (const k of ['host', 'domain', 'finalUrl', 'url']) {
      if (typeof x[k] === 'string') { const t = tldOf(x[k]); if (t) { tlds.add(t); break; } }
    }
  }
  if (Array.isArray(x.links)) {
    for (const l of x.links as Any[]) if (typeof l?.url === 'string' && typeof l.verdict === 'string' && FLAGGED_LINK.test(l.verdict)) { const t = tldOf(l.url); if (t) tlds.add(t); }
  }
  return { patterns, brands, tlds };
}

const ctxOf = (x: Ctx | { ctx: Ctx }): Ctx => ('ctx' in x ? x.ctx : x);
const pct = (now: number, before: number) => (now >= MIN_BUCKET && before >= MIN_BUCKET ? Math.round(((now - before) / before) * 100) : null);
const top = (m: Map<string, number>, n = 8): TrendBucket[] => [...m].filter(([, c]) => c >= MIN_BUCKET).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n).map(([name, checks]) => ({ name, checks }));
const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);

/** Trends over the 7 days ending now, compared with the 7 days before. */
export function scamTrends(source: Ctx | { ctx: Ctx }, days = 7): ScamTrends {
  const ctx = ctxOf(source);
  const now = ctx.now().getTime();
  const span = Math.max(1, Math.min(30, Math.round(days))) * 86_400_000;
  const from = now - span, prevFrom = now - 2 * span;
  const db = ctx.store.db;
  const hasTable = Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'checks'").get());
  const rows = hasTable ? (db.prepare('SELECT kind, verdict, result, created_at FROM checks WHERE created_at >= ? AND created_at < ?').all(prevFrom, now) as unknown as { kind: string; verdict: string; result: string | null; created_at: number }[]) : [];
  const kinds = new Map<string, number>(), prevKinds = new Map<string, number>();
  const tones = new Map<string, number>();
  const patterns = new Map<string, number>(), brands = new Map<string, number>(), tlds = new Map<string, number>();
  let total = 0, previousTotal = 0;
  for (const r of rows) {
    if (r.created_at < from) { previousTotal++; bump(prevKinds, r.kind); continue; }
    total++;
    bump(kinds, r.kind);
    let tone = 'info';
    try { tone = String((JSON.parse(r.verdict) as { tone?: string }).tone ?? 'info'); } catch { /* keep info */ }
    if (!(tone in TONE_LABEL)) tone = 'info';
    bump(tones, tone);
    let result: unknown = null;
    try { result = r.result ? JSON.parse(r.result) : null; } catch { /* too large or damaged: counts only */ }
    const c = categoriesOf(r.kind, result, tone);
    for (const p of c.patterns) bump(patterns, p);
    for (const b of c.brands) bump(brands, b);
    for (const t of c.tlds) bump(tlds, t);
  }
  const byKind = [...kinds].filter(([, n]) => n >= MIN_BUCKET).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([kind, checks]) => {
    const prev = prevKinds.get(kind) ?? 0;
    return { kind, label: KIND_LABEL[kind] ?? kind, checks, previous: prev >= MIN_BUCKET ? prev : null, changePct: pct(checks, prev) };
  });
  const shown = byKind.reduce((s, k) => s + k.checks, 0);
  const verdicts = (['bad', 'warn', 'ok', 'info'] as const).map((tone) => ({ tone, label: TONE_LABEL[tone], checks: tones.get(tone) ?? 0, share: total ? Math.round(((tones.get(tone) ?? 0) / total) * 100) : 0 })).filter((v) => v.checks >= MIN_BUCKET);
  const enough = total >= ENOUGH;
  return {
    generatedAt: new Date(now).toISOString(),
    from: new Date(from).toISOString(),
    to: new Date(now).toISOString(),
    previousFrom: new Date(prevFrom).toISOString(),
    total,
    previousTotal,
    changePct: pct(total, previousTotal),
    enough,
    note: total === 0
      ? 'No checks were recorded in this window.'
      : !enough
        ? `Only ${total} check${total === 1 ? '' : 's'} in this window: too few to call a trend. Groups with fewer than ${MIN_BUCKET} checks are not shown.`
        : null,
    minBucket: MIN_BUCKET,
    byKind,
    otherKinds: total - shown,
    verdicts,
    patterns: top(patterns),
    brands: top(brands),
    tlds: top(tlds),
  };
}

/** A weekly "Scam of the week" X post, or null when the week has too little data to say anything honest. */
export function trendsPostText(t: ScamTrends, link = 'oculon.live/trends'): string | null {
  if (!t.enough || (!t.patterns.length && !t.brands.length)) return null;
  const lines = ['Scam of the week, from what people checked with Oculon', ''];
  if (t.patterns[0]) lines.push(`The most common warning sign: ${t.patterns[0].name} (${t.patterns[0].checks} checks).`, '');
  if (t.brands[0]) lines.push(`• Most impersonated brand: ${t.brands[0].name} (${t.brands[0].checks} checks)`);
  if (t.tlds[0]) lines.push(`• Top-level domain seen most on flagged links: .${t.tlds[0].name} (${t.tlds[0].checks})`);
  const bad = t.verdicts.find((v) => v.tone === 'bad');
  lines.push(`• ${t.total} checks this week${t.changePct !== null ? ` (${t.changePct >= 0 ? '+' : ''}${t.changePct}% on last week)` : ''}${bad ? `, ${bad.share}% rated dangerous` : ''}`);
  for (const p of t.patterns.slice(1, 3)) lines.push(`• Also common: ${p.name} (${p.checks})`);
  lines.push('', `Counts only, nothing anyone checked is shown: ${link}`);
  let out = lines.join('\n');
  while (out.length >= 600 && lines.length > 6) { lines.splice(lines.length - 3, 1); out = lines.join('\n'); }
  return out;
}
