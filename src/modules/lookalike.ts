/**
 * Lookalike domains: the typos, swapped letters, homoglyphs, extra words and other endings a phisher would
 * register to pass for a brand. Oculon generates the candidates offline, asks DNS which ones exist (Google DNS),
 * and checks Certificate Transparency for any certificate naming the brand (crt.sh, CertSpotter as fallback):
 * a fresh certificate on a lookalike usually means a phishing site is about to go live.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { certspotter, type CertEntry } from '../sources/certs.js';

export interface Lookalike { domain: string; kind: string; ips: string[]; mx: boolean; certSeen: string | null }
export interface CertHit { name: string; firstSeen: string; issuer: string }
export interface LookalikeReport {
  domain: string;
  checked: number;
  live: Lookalike[];
  certs: CertHit[];
  risk: 'high' | 'medium' | 'low';
  note: string;
}

const KEYS: Record<string, string> = { q: 'wa', w: 'qes', e: 'wrd', r: 'etf', t: 'ryg', y: 'tuh', u: 'yij', i: 'uok', o: 'ipl', p: 'ol', a: 'qsz', s: 'adw', d: 'sfe', f: 'dgr', g: 'fht', h: 'gjy', j: 'hku', k: 'jli', l: 'kp', z: 'ax', x: 'zc', c: 'xv', v: 'cb', b: 'vn', n: 'bm', m: 'n' };
const GLYPHS: [string, string][] = [['o', '0'], ['l', '1'], ['i', '1'], ['i', 'l'], ['l', 'i'], ['e', '3'], ['a', '4'], ['s', '5'], ['m', 'rn'], ['rn', 'm'], ['w', 'vv'], ['vv', 'w'], ['d', 'cl'], ['g', 'q'], ['u', 'v']];
const WORDS = ['login', 'secure', 'support', 'verify', 'account', 'app', 'help', 'official', 'wallet', 'claim', 'airdrop', 'pay', 'billing'];
const TLDS = ['com', 'net', 'org', 'io', 'co', 'app', 'live', 'xyz', 'top', 'site', 'online', 'info', 'shop', 'click', 'link', 'vip', 'pro'];

/** Candidate lookalikes for a domain, labelled by how they were made. Deterministic and capped. */
export function candidates(domain: string, max = 160): { domain: string; kind: string }[] {
  const d = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  const dot = d.indexOf('.');
  if (dot < 1) throw new Error(`not a domain: ${domain}`);
  const name = d.slice(0, dot), tld = d.slice(dot + 1);
  const out = new Map<string, string>();
  const put = (n: string, t: string, kind: string) => { const c = `${n}.${t}`; if (n && c !== d && /^[a-z0-9-]+$/.test(n) && !n.startsWith('-') && !n.endsWith('-') && !out.has(c)) out.set(c, kind); };
  for (const t of TLDS) if (t !== tld) put(name, t, 'other ending');
  for (let i = 0; i < name.length; i++) {
    put(name.slice(0, i) + name.slice(i + 1), tld, 'missing letter');
    put(name.slice(0, i) + name[i] + name.slice(i), tld, 'double letter');
    if (i < name.length - 1) put(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2), tld, 'swapped letters');
    for (const k of KEYS[name[i]!] ?? '') put(name.slice(0, i) + k + name.slice(i + 1), tld, 'keyboard typo');
    if (i > 0) put(`${name.slice(0, i)}-${name.slice(i)}`, tld, 'hyphen');
  }
  for (const [a, b] of GLYPHS) { let at = name.indexOf(a); while (at >= 0) { put(name.slice(0, at) + b + name.slice(at + a.length), tld, 'lookalike characters'); at = name.indexOf(a, at + 1); } }
  for (const w of WORDS) { put(`${name}-${w}`, tld, 'brand plus word'); put(`${w}-${name}`, tld, 'brand plus word'); put(`${name}${w}`, 'com', 'brand plus word'); }
  // Endings and words first: they are what phishing kits register most often.
  const order = ['brand plus word', 'other ending', 'lookalike characters', 'missing letter', 'swapped letters', 'double letter', 'hyphen', 'keyboard typo'];
  return [...out].map(([domain, kind]) => ({ domain, kind })).sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind)).slice(0, max);
}

interface Doh { Status?: number; Answer?: { type: number; data: string }[] }
async function resolve(ctx: Ctx, name: string, type: 'A' | 'MX') {
  return ctx.http.get<Doh>(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { source: 'google-dns', ttlSec: 12 * 3600, retries: 1, keep: (x: Doh) => ({ Status: x.Status, Answer: (x.Answer ?? []).map((a) => ({ type: a.type, data: a.data })) }) });
}

/** Certificates whose names contain the brand anywhere (crt.sh full-text match), unexpired only. */
async function crtBrand(ctx: Ctx, brand: string) {
  type Row = { name_value: string; not_before: string; issuer_name: string };
  const url = `https://crt.sh/?q=${encodeURIComponent(`%${brand}%`)}&output=json&exclude=expired`;
  const r = await ctx.http.get<Row[]>(url, { source: 'crt.sh', ttlSec: 6 * 3600, timeoutMs: 60_000, retries: 1, keep: (rows: Row[]) => (Array.isArray(rows) ? rows.slice(0, 3000).map((x) => ({ name_value: x.name_value, not_before: x.not_before, issuer_name: x.issuer_name })) : rows) });
  const data: CertEntry[] | null = Array.isArray(r.data)
    ? r.data.map((row) => ({ names: row.name_value.split(/\s+/).filter(Boolean), notBefore: row.not_before.endsWith('Z') ? row.not_before : `${row.not_before}Z`, issuer: /O=([^,]+)/.exec(row.issuer_name)?.[1]?.replace(/"/g, '') ?? row.issuer_name }))
    : null;
  return { data, prov: r.prov };
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]!); } }));
  return out;
}

export async function lookalikes(ctx: Ctx, input: string): Promise<ModuleResult<LookalikeReport>> {
  const domain = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  const cands = candidates(domain);
  const name = domain.split('.')[0]!;
  const provenance: Provenance[] = [];
  let failed = 0;
  const found = await pool(cands, 8, async (c) => {
    const a = await resolve(ctx, c.domain, 'A');
    if (!a.data) { failed++; return null; }
    const ips = (a.data.Answer ?? []).filter((x) => x.type === 1).map((x) => x.data);
    if (!ips.length) return null;
    const mx = await resolve(ctx, c.domain, 'MX');
    return { ...c, ips, mx: (mx.data?.Answer ?? []).some((x) => x.type === 15 && !/^0 \.$/.test(x.data)), certSeen: null } as Lookalike;
  });
  provenance.push({ source: 'google-dns', url: 'https://dns.google/resolve', status: failed === cands.length ? 'ERROR' : 'LIVE', fetchedAt: ctx.now().toISOString(), note: `${cands.length} candidates resolved${failed ? `, ${failed} lookups failed` : ''}` });

  // Certificates naming the brand anywhere, from the last 90 days, excluding the brand's own domain.
  let ct = await crtBrand(ctx, name.length >= 4 ? name : domain);
  if (!ct.data) { const alt = await certspotter(ctx, domain); provenance.push(ct.prov); ct = alt; }
  provenance.push(ct.prov);
  const since = ctx.now().getTime() - 90 * 86_400_000;
  const certMap = new Map<string, CertHit>();
  for (const e of (ct.data ?? []) as CertEntry[]) {
    if (new Date(e.notBefore).getTime() < since) continue;
    for (const n of e.names) {
      const host = n.replace(/^\*\./, '').toLowerCase();
      if (!host.includes(name) || host === domain || host.endsWith(`.${domain}`)) continue;
      const prev = certMap.get(host);
      if (!prev || e.notBefore < prev.firstSeen) certMap.set(host, { name: host, firstSeen: e.notBefore, issuer: e.issuer });
    }
  }
  const certs = [...certMap.values()].sort((a, b) => b.firstSeen.localeCompare(a.firstSeen)).slice(0, 40);
  const live = found.filter((x): x is Lookalike => !!x).map((l) => ({ ...l, certSeen: certMap.get(l.domain)?.firstSeen ?? null }));
  const fresh = certs.filter((c) => ctx.now().getTime() - new Date(c.firstSeen).getTime() < 14 * 86_400_000);
  const risk: LookalikeReport['risk'] = fresh.length || live.some((l) => l.mx && l.kind !== 'other ending') ? 'high' : live.length || certs.length ? 'medium' : 'low';
  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = fresh.length ? [{
    id: signalId('lookalike', domain, fresh.slice(0, 5).map((c) => c.name).join(',')), module: 'lookalike', title: `${fresh.length} new certificate${fresh.length === 1 ? '' : 's'} for lookalikes of ${domain}`, score: 62, entity: domain,
    evidence: fresh.slice(0, 3).map((c) => ({ source: 'crt.sh', text: `${c.name} · certificate from ${c.issuer}, ${c.firstSeen.slice(0, 10)}`, url: `https://crt.sh/?q=${encodeURIComponent(c.name)}` })), createdAt: nowIso,
  }] : [];
  return {
    module: 'lookalike', input: domain, generatedAt: nowIso,
    result: { domain, checked: cands.length, live, certs, risk, note: 'A lookalike that resolves is not proof of phishing: some are parked, owned by the brand, or unrelated. Fresh certificates and mail servers on a lookalike are the strongest signs.' },
    signals, provenance,
  };
}
