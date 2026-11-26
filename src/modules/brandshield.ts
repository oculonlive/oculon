/**
 * Brand Shield: which domains are pretending to be this brand right now?
 *   1. Lookalike candidates and the certificates naming the brand, from the lookalike module (DNS via Google DNS,
 *      Certificate Transparency via crt.sh with CertSpotter as fallback).
 *   2. Certificate names that contain the brand but are not the brand's own domain are resolved in DNS.
 *   3. The most suspicious live ones go through the URL check (Safe Browsing, URLhaus, phishing lists, domain age).
 * Each domain gets a score with the reasons behind it. A high score is a lead to investigate, not proof of phishing.
 * crt.sh is often slow: when it does not answer in time the report says so and the certificate part is incomplete.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { candidates, lookalikes, type LookalikeReport } from './lookalike.js';
import { apexOf, urlCheck, urlHeuristics, type UrlVerdict } from './urlcheck.js';

export interface BrandHit {
  domain: string;
  score: number;
  level: 'high' | 'medium' | 'low';
  reasons: string[];
  origin: string[];
  resolves: boolean | null;
  ips: string[];
  mail: boolean;
  certFirstSeen: string | null;
  certIssuer: string | null;
  urlCheck: { verdict: UrlVerdict; risk: number; reasons: string[] } | null;
}

export interface BrandShieldReport {
  domain: string;
  brand: string;
  hits: BrandHit[];
  counts: { high: number; medium: number; low: number; resolving: number; candidatesChecked: number; certNames: number };
  certificates: { status: 'ok' | 'fallback' | 'failed' | 'timed out'; note: string };
  checkedWithUrlCheck: string[];
  note: string;
}

const DAY = 86_400_000;
const LURE = /(log-?in|sign-?in|secure|verify|verification|account|support|wallet|airdrop|claim|reward|bonus|giveaway|recover|unlock|update|auth|kyc|refund|billing|payment|connect|validate|restore|official)/;
const URLCHECK_TOP = 4;
const DNS_MAX = 30;

interface Doh { Status?: number; Answer?: { type: number; data: string }[] }
/** Same request and cache entry as the lookalike module's DNS lookups. */
async function resolveA(ctx: Ctx, name: string) {
  return ctx.http.get<Doh>(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=A`, { source: 'google-dns', ttlSec: 12 * 3600, retries: 1, keep: (x: Doh) => ({ Status: x.Status, Answer: (x.Answer ?? []).map((a) => ({ type: a.type, data: a.data })) }) });
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]!); } }));
  return out;
}

const level = (s: number): BrandHit['level'] => (s >= 70 ? 'high' : s >= 40 ? 'medium' : 'low');

/** Score one domain from what is known about it. Pure, so the ranking is testable. */
export function scoreHit(h: Omit<BrandHit, 'score' | 'level' | 'reasons'>, brand: string, nowMs: number, lookalikeKind?: string): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let s = 0;
  const flat = h.domain.replace(/[-.]/g, '');
  if (flat.includes(brand)) { s += 20; reasons.push(`contains the brand name "${brand}"`); }
  else if (lookalikeKind) { s += 20; reasons.push(`imitates the name (${lookalikeKind})`); }
  const lure = LURE.exec(h.domain.replace(brand, ' '))?.[1];
  if (lure) { s += 25; reasons.push(`adds the word "${lure}", common in phishing`); }
  try {
    for (const x of urlHeuristics(new URL(`https://${h.domain}/`))) {
      if (/top-level domain|punycode/.test(x)) { s += 15; reasons.push(x); }
      else if (/hyphens|deep subdomain/.test(x)) { s += 5; reasons.push(x); }
    }
  } catch { /* not a valid host */ }
  if (h.certFirstSeen) {
    const age = Math.floor((nowMs - Date.parse(h.certFirstSeen)) / DAY);
    if (age <= 7) { s += 25; reasons.push(`certificate issued ${age <= 0 ? 'today' : `${age} day${age === 1 ? '' : 's'} ago`}`); }
    else if (age <= 30) { s += 15; reasons.push(`certificate issued ${age} days ago`); }
    else { s += 5; reasons.push(`certificate issued ${age} days ago`); }
  }
  if (h.resolves) { s += 15; reasons.push(`resolves in DNS${h.ips.length ? ` (${h.ips.slice(0, 2).join(', ')})` : ''}`); }
  else if (h.resolves === false) reasons.push('does not resolve in DNS right now');
  if (h.mail) { s += 10; reasons.push('has mail servers, so it can send email'); }
  if (h.urlCheck) {
    if (h.urlCheck.verdict === 'malicious') { s += 40; reasons.push(`URL check: malicious (${h.urlCheck.reasons[0] ?? 'flagged'})`); }
    else if (h.urlCheck.verdict === 'suspicious') { s += 15; reasons.push(`URL check: suspicious (${h.urlCheck.reasons[0] ?? `risk ${h.urlCheck.risk}`})`); }
    else reasons.push('URL check: no known threats');
  }
  return { score: Math.min(100, s), reasons };
}

const TIMEOUT = Symbol('timeout');

export async function brandShield(ctx: Ctx, input: string, opts: { budgetMs?: number } = {}): Promise<ModuleResult<BrandShieldReport>> {
  const host = (input ?? '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[/?#].*$/, '').replace(/\.$/, '');
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host)) throw new Error(`not a domain: ${input}. Give the brand's own domain, for example example.com`);
  const domain = apexOf(host);
  candidates(domain); // throws on input that is not a domain
  const brand = domain.split('.')[0]!;
  const provenance: Provenance[] = [];
  const now = ctx.now().getTime();

  // The lookalike module waits up to a minute per crt.sh attempt. Past the budget the report goes out without it;
  // the work carries on and its answers land in the cache for the next run.
  const budget = opts.budgetMs ?? 100_000;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const la = await Promise.race([
    lookalikes(ctx, domain).catch((e: Error) => e),
    new Promise<typeof TIMEOUT>((r) => { timer = setTimeout(() => r(TIMEOUT), budget); }),
  ]);
  clearTimeout(timer);

  let report: LookalikeReport | null = null;
  let certificates: BrandShieldReport['certificates'];
  if (la === TIMEOUT) {
    certificates = { status: 'timed out', note: `the lookalike and certificate search did not finish within ${Math.round(budget / 1000)} s (crt.sh is often slow). It keeps running in the background; run Brand Shield again in a few minutes for the full picture.` };
    provenance.push({ source: 'crt.sh', url: 'https://crt.sh', status: 'ERROR', fetchedAt: ctx.now().toISOString(), note: 'did not answer within the time budget' });
  } else if (la instanceof Error) {
    throw la;
  } else {
    report = la.result;
    provenance.push(...la.provenance);
    const crt = la.provenance.find((p) => p.source === 'crt.sh');
    const cs = la.provenance.find((p) => p.source === 'certspotter');
    certificates = !crt || crt.status === 'LIVE' || crt.status === 'CACHED'
      ? { status: 'ok', note: `Certificate Transparency searched through crt.sh${crt?.status === 'CACHED' ? ' (cached answer)' : ''}` }
      : cs && (cs.status === 'LIVE' || cs.status === 'CACHED')
        ? { status: 'fallback', note: `crt.sh did not answer (${crt.note ?? crt.status}). CertSpotter answered instead, but its free search only covers the brand's own names, so certificates on other domains are missing.` }
        : { status: 'failed', note: `no Certificate Transparency source answered (crt.sh: ${crt.note ?? crt.status}); certificate results are missing` };
  }

  // Merge lookalikes that exist and certificate names, keyed by host.
  const items = new Map<string, Omit<BrandHit, 'score' | 'level' | 'reasons'> & { kind?: string }>();
  for (const l of report?.live ?? []) {
    items.set(l.domain, { domain: l.domain, origin: [`lookalike: ${l.kind}`], resolves: true, ips: l.ips, mail: l.mx, certFirstSeen: l.certSeen, certIssuer: null, urlCheck: null, kind: l.kind });
  }
  for (const c of report?.certs ?? []) {
    if (c.name === domain || c.name.endsWith(`.${domain}`)) continue;
    const prev = items.get(c.name);
    if (prev) { prev.origin.push('certificate'); prev.certFirstSeen ??= c.firstSeen; prev.certIssuer = c.issuer; continue; }
    items.set(c.name, { domain: c.name, origin: ['certificate'], resolves: null, ips: [], mail: false, certFirstSeen: c.firstSeen, certIssuer: c.issuer, urlCheck: null });
  }

  // DNS for certificate names not resolved yet, most suspicious first.
  const pending = [...items.values()].filter((x) => x.resolves === null)
    .map((x) => ({ x, pre: scoreHit(x, brand, now, x.kind).score }))
    .sort((a, b) => b.pre - a.pre).slice(0, DNS_MAX).map((p) => p.x);
  let dnsFailed = 0;
  await pool(pending, 8, async (x) => {
    const r = await resolveA(ctx, x.domain);
    if (!r.data) { dnsFailed++; return; }
    x.ips = (r.data.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
    x.resolves = x.ips.length > 0;
  });
  if (pending.length) provenance.push({ source: 'google-dns', url: 'https://dns.google/resolve', status: dnsFailed === pending.length ? 'ERROR' : 'LIVE', fetchedAt: ctx.now().toISOString(), note: `${pending.length} certificate names resolved${dnsFailed ? `, ${dnsFailed} lookups failed` : ''}` });

  // URL check on the top few that are live.
  const ranked = () => [...items.values()].map((x) => ({ x, ...scoreHit(x, brand, now, x.kind) })).sort((a, b) => b.score - a.score || a.x.domain.localeCompare(b.x.domain));
  const toCheck = ranked().filter((r) => r.x.resolves).slice(0, URLCHECK_TOP).map((r) => r.x);
  await Promise.all(toCheck.map(async (x) => {
    try {
      const u = await urlCheck(ctx, `https://${x.domain}/`);
      x.urlCheck = { verdict: u.result.verdict, risk: u.result.risk, reasons: u.result.reasons.slice(0, 4) };
      provenance.push(...u.provenance.map((p) => ({ ...p, note: `${x.domain}: ${p.note ?? p.status}` })));
    } catch (e) {
      provenance.push({ source: 'urlcheck', url: `https://${x.domain}/`, status: 'ERROR', fetchedAt: ctx.now().toISOString(), note: (e as Error).message.slice(0, 120) });
    }
  }));

  const hits: BrandHit[] = ranked().slice(0, 50).map(({ x, score, reasons }) => ({ domain: x.domain, score, level: level(score), reasons, origin: x.origin, resolves: x.resolves, ips: x.ips, mail: x.mail, certFirstSeen: x.certFirstSeen, certIssuer: x.certIssuer, urlCheck: x.urlCheck }));
  const counts = {
    high: hits.filter((h) => h.level === 'high').length, medium: hits.filter((h) => h.level === 'medium').length, low: hits.filter((h) => h.level === 'low').length,
    resolving: hits.filter((h) => h.resolves).length, candidatesChecked: report?.checked ?? 0, certNames: report?.certs.length ?? 0,
  };
  const nowIso = ctx.now().toISOString();
  const top = hits.filter((h) => h.level === 'high');
  const signals: Signal[] = top.length ? [{
    id: signalId('brandshield', domain, top.slice(0, 5).map((h) => h.domain).join(',')), module: 'brandshield', title: `${top.length} high-risk domain${top.length === 1 ? '' : 's'} imitating ${domain}`, score: 66, entity: domain,
    evidence: top.slice(0, 3).map((h) => ({ source: h.urlCheck?.verdict === 'malicious' ? 'urlcheck' : h.certFirstSeen ? 'crt.sh' : 'google-dns', text: `${h.domain}: ${h.reasons.slice(0, 3).join('; ')}`, url: `https://crt.sh/?q=${encodeURIComponent(h.domain)}` })), createdAt: nowIso,
  }] : [];
  return {
    module: 'brandshield', input: domain, generatedAt: nowIso,
    result: {
      domain, brand, hits, counts, certificates, checkedWithUrlCheck: toCheck.map((x) => x.domain),
      note: 'Scores rank leads, they do not prove phishing: some of these domains are parked, owned by the brand itself, or unrelated businesses with a similar name. A fresh certificate on a live domain with a login or claim word is the strongest sign. Certificates are from the last 90 days.',
    },
    signals, provenance,
  };
}
