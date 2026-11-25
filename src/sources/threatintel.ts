/**
 * Threat intelligence sources for IP addresses and file hashes.
 *   Keyless: ip-api.com (location, proxy and hosting flags), GreyNoise Community (internet scanners),
 *     the Tor Project exit list, Spamhaus DROP (hijacked and criminal networks), PeeringDB (network type),
 *     Shodan InternetDB (open ports), CIRCL hashlookup (known files).
 *   Free keys: AbuseIPDB (ABUSEIPDB_API_KEY), AlienVault OTX (OTX_API_KEY), IPinfo Lite (IPINFO_TOKEN),
 *     VirusTotal (VIRUSTOTAL_API_KEY, non-commercial use), MalwareBazaar and ThreatFox (ABUSECH_AUTH_KEY).
 * A missing key only turns that one source off.
 */
import { isIP } from 'node:net';
import type { Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Provenance, Sourced } from '../core/types.js';

const nowIso = () => new Date().toISOString();

/** POST with a response cache keyed by URL and body (abuse.ch answers lookups only over POST). */
export async function postCached<T>(ctx: Ctx, url: string, body: string, contentType: string, headers: Record<string, string>, source: string, ttlSec: number): Promise<Sourced<T>> {
  const cacheKey = `post:${url}:${body}`;
  const cached = ctx.store.cacheGet(cacheKey);
  if (cached && Date.now() - cached.fetchedAt < ttlSec * 1000) {
    try {
      return { data: JSON.parse(cached.body) as T, prov: { source, url, status: 'CACHED', fetchedAt: new Date(cached.fetchedAt).toISOString() } };
    } catch {}
  }
  const r = await ctx.http.postBytes(url, new TextEncoder().encode(body), { source, headers: { 'content-type': contentType, ...headers }, timeoutMs: 25_000 });
  if (!r.data) return { data: null, prov: r.prov };
  try {
    const text = r.data.toString('utf8');
    const data = JSON.parse(text) as T;
    ctx.store.cachePut(cacheKey, text);
    return { data, prov: r.prov };
  } catch {
    return { data: null, prov: { ...r.prov, status: 'ERROR', note: 'invalid JSON' } };
  }
}

/* ---------- address helpers ---------- */

/** IPv4 or IPv6 as a BigInt plus its bit length, for CIDR matching. */
export function ipToBig(ip: string): { v: bigint; bits: number } | null {
  const fam = isIP(ip);
  if (fam === 4) {
    const p = ip.split('.').map(Number);
    return { v: BigInt(((p[0]! << 24) >>> 0) + (p[1]! << 16) + (p[2]! << 8) + p[3]!), bits: 32 };
  }
  if (fam === 6) {
    let s = ip.toLowerCase();
    const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (v4) {
      const b = ipToBig(v4[1]!);
      if (!b) return null;
      s = s.replace(v4[1]!, `${(b.v >> 16n).toString(16)}:${(b.v & 0xffffn).toString(16)}`);
    }
    const [head, tail] = s.split('::') as [string, string | undefined];
    const h = head ? head.split(':') : [];
    const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
    const groups = tail !== undefined ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
    if (groups.length !== 8) return null;
    let v = 0n;
    for (const g of groups) v = (v << 16n) + BigInt(parseInt(g || '0', 16));
    return { v, bits: 128 };
  }
  return null;
}

export function inCidr(ip: string, cidr: string): boolean {
  const [net, lenS] = cidr.split('/') as [string, string | undefined];
  const a = ipToBig(ip);
  const b = ipToBig(net);
  if (!a || !b || a.bits !== b.bits) return false;
  const len = lenS === undefined ? a.bits : Number(lenS);
  if (!Number.isInteger(len) || len < 0 || len > a.bits) return false;
  const shift = BigInt(a.bits - len);
  return a.v >> shift === b.v >> shift;
}

const PRIVATE_RANGES = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3', '::/127', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64', '2001:db8::/32', 'fc00::/7', 'fe80::/10', 'ff00::/8'];

/** Private, loopback, documentation, multicast and other addresses that are not on the public internet. */
export function isPublicIp(ip: string): boolean {
  if (!isIP(ip)) return false;
  return !PRIVATE_RANGES.some((r) => inCidr(ip, r));
}

/* ---------- keyless IP sources ---------- */

export interface IpApi { country: string | null; countryCode: string | null; region: string | null; city: string | null; lat: number | null; lon: number | null; isp: string | null; org: string | null; as: string | null; reverse: string | null; mobile: boolean; proxy: boolean; hosting: boolean }

export async function ipApi(ctx: Ctx, ip: string): Promise<Sourced<IpApi>> {
  // The free endpoint is HTTP only and allows 45 requests a minute, non-commercial use.
  const r = await ctx.http.get<Record<string, unknown>>(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,reverse,mobile,proxy,hosting`, { source: 'ip-api', ttlSec: 12 * 3600 });
  const d = r.data;
  if (!d || d.status !== 'success') return { data: null, prov: d ? { ...r.prov, status: 'ERROR', note: String(d.message ?? 'lookup failed') } : r.prov };
  const s = (k: string) => (typeof d[k] === 'string' && d[k] ? (d[k] as string) : null);
  const n = (k: string) => (typeof d[k] === 'number' ? (d[k] as number) : null);
  return { data: { country: s('country'), countryCode: s('countryCode'), region: s('regionName'), city: s('city'), lat: n('lat'), lon: n('lon'), isp: s('isp'), org: s('org'), as: s('as'), reverse: s('reverse'), mobile: d.mobile === true, proxy: d.proxy === true, hosting: d.hosting === true }, prov: r.prov };
}

export interface GreyNoise { observed: boolean; noise: boolean; riot: boolean; classification: string | null; name: string | null; lastSeen: string | null; link: string | null }

export async function greyNoise(ctx: Ctx, ip: string): Promise<Sourced<GreyNoise>> {
  const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`;
  const r = await ctx.http.get<Record<string, unknown>>(url, { source: 'greynoise', ttlSec: 12 * 3600, retries: 1 });
  // GreyNoise answers 404 for an address it has never seen scanning: that is a result, not an outage.
  if (!r.data && r.prov.note === 'HTTP 404') return { data: { observed: false, noise: false, riot: false, classification: null, name: null, lastSeen: null, link: null }, prov: { ...r.prov, status: 'LIVE', note: 'not observed scanning the internet' } };
  const d = r.data;
  if (!d) return { data: null, prov: r.prov };
  return { data: { observed: d.noise === true || d.riot === true, noise: d.noise === true, riot: d.riot === true, classification: typeof d.classification === 'string' ? d.classification : null, name: typeof d.name === 'string' && d.name !== 'unknown' ? d.name : null, lastSeen: typeof d.last_seen === 'string' ? d.last_seen : null, link: typeof d.link === 'string' ? d.link : null }, prov: r.prov };
}

export async function torExits(ctx: Ctx): Promise<Sourced<Set<string>>> {
  const r = await ctx.http.get<string>('https://check.torproject.org/torbulkexitlist', { source: 'tor-exits', as: 'text', ttlSec: 3600 });
  return { data: r.data ? new Set(r.data.split(/\s+/).filter(Boolean)) : null, prov: r.prov };
}

export interface DropLists { cidrs: { cidr: string; id: string }[]; asns: { asn: number; name: string }[] }

const ndjson = <T>(text: string | null): T[] => (text ?? '').split('\n').map((l) => { try { return JSON.parse(l) as T; } catch { return null; } }).filter((x): x is T => x !== null);

export async function spamhausDrop(ctx: Ctx): Promise<{ data: DropLists | null; prov: Provenance[] }> {
  const [v4, v6, asn] = await Promise.all(['drop_v4.json', 'drop_v6.json', 'asndrop.json'].map((f) => ctx.http.get<string>(`https://www.spamhaus.org/drop/${f}`, { source: 'spamhaus-drop', as: 'text', ttlSec: 12 * 3600 })));
  const prov = [v4!.prov, v6!.prov, asn!.prov];
  if (!v4!.data && !v6!.data && !asn!.data) return { data: null, prov };
  const cidrs = [...ndjson<{ cidr?: string; sblid?: string }>(v4!.data), ...ndjson<{ cidr?: string; sblid?: string }>(v6!.data)].filter((x) => x.cidr).map((x) => ({ cidr: x.cidr!, id: x.sblid ?? '' }));
  const asns = ndjson<{ asn?: number; asname?: string }>(asn!.data).filter((x) => typeof x.asn === 'number').map((x) => ({ asn: x.asn!, name: x.asname ?? '' }));
  return { data: { cidrs, asns }, prov };
}

export interface PeeringNet { name: string; type: string | null; website: string | null; policy: string | null }

export async function peeringDb(ctx: Ctx, asn: number): Promise<Sourced<PeeringNet>> {
  const r = await ctx.http.get<{ data?: { name?: string; info_type?: string; website?: string; policy_general?: string }[] }>(`https://www.peeringdb.com/api/net?asn=${asn}`, { source: 'peeringdb', ttlSec: 7 * 86_400, retries: 1, keep: (d: { data?: unknown[] }) => ({ data: (d.data ?? []).slice(0, 1) }) });
  const n = r.data?.data?.[0];
  return { data: n?.name ? { name: n.name, type: n.info_type || null, website: n.website || null, policy: n.policy_general || null } : null, prov: r.prov };
}

export interface InternetDb { ports: number[]; vulns: string[]; hostnames: string[]; tags: string[] }

export async function internetDb(ctx: Ctx, ip: string): Promise<Sourced<InternetDb>> {
  const r = await ctx.http.get<{ ports?: number[]; vulns?: string[]; hostnames?: string[]; tags?: string[] }>(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { source: 'shodan-internetdb', ttlSec: 12 * 3600, retries: 1 });
  // 404 here means "no open ports seen", which is a result.
  if (!r.data && r.prov.note === 'HTTP 404') return { data: { ports: [], vulns: [], hostnames: [], tags: [] }, prov: { ...r.prov, status: 'LIVE', note: 'no open ports seen' } };
  const d = r.data;
  return { data: d ? { ports: d.ports ?? [], vulns: d.vulns ?? [], hostnames: d.hostnames ?? [], tags: d.tags ?? [] } : null, prov: r.prov };
}

/* ---------- keyed IP sources ---------- */

export interface AbuseIpDb { score: number; reports: number; reporters: number; lastReported: string | null; usageType: string | null; isp: string | null; domain: string | null; countryCode: string | null; isTor: boolean; whitelisted: boolean }

export async function abuseIpDb(ctx: Ctx, ip: string): Promise<Sourced<AbuseIpDb>> {
  const k = key('ABUSEIPDB_API_KEY');
  if (!k) return noKey('abuseipdb', 'ABUSEIPDB_API_KEY');
  const r = await ctx.http.get<{ data?: Record<string, unknown> }>(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { source: 'abuseipdb', ttlSec: 6 * 3600, retries: 1, headers: { Key: k } });
  const d = r.data?.data;
  if (!d) return { data: null, prov: r.prov };
  const s = (x: unknown) => (typeof x === 'string' && x ? x : null);
  return { data: { score: Number(d.abuseConfidenceScore ?? 0), reports: Number(d.totalReports ?? 0), reporters: Number(d.numDistinctUsers ?? 0), lastReported: s(d.lastReportedAt), usageType: s(d.usageType), isp: s(d.isp), domain: s(d.domain), countryCode: s(d.countryCode), isTor: d.isTor === true, whitelisted: d.isWhitelisted === true }, prov: r.prov };
}

export interface OtxPulses { count: number; pulses: { name: string; created: string | null; tags: string[]; url: string }[]; whitelisted: boolean; family: string[] }

interface OtxGeneral { pulse_info?: { count?: number; pulses?: { id?: string; name?: string; created?: string; tags?: string[] }[]; related?: { alienvault?: { malware_families?: string[] }; other?: { malware_families?: string[] } } }; validation?: { source?: string; name?: string }[] }

/** AlienVault OTX community threat reports ("pulses") that mention an IP, domain or file hash. */
export async function otx(ctx: Ctx, type: 'IPv4' | 'IPv6' | 'file' | 'domain', value: string): Promise<Sourced<OtxPulses>> {
  const k = key('OTX_API_KEY');
  if (!k) return noKey('otx', 'OTX_API_KEY');
  const r = await ctx.http.get<OtxGeneral>(`https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(value)}/general`, {
    source: 'otx',
    ttlSec: 6 * 3600,
    timeoutMs: 25_000,
    retries: 1,
    headers: { 'X-OTX-API-KEY': k },
    keep: (d: OtxGeneral) => ({ pulse_info: { count: d.pulse_info?.count ?? 0, pulses: (d.pulse_info?.pulses ?? []).slice(0, 6).map((p) => ({ id: p.id, name: p.name, created: p.created, tags: (p.tags ?? []).slice(0, 6) })), related: d.pulse_info?.related }, validation: (d.validation ?? []).slice(0, 3) }),
  });
  if (!r.data) return { data: null, prov: r.prov };
  const pi = r.data.pulse_info ?? {};
  const fam = [...(pi.related?.alienvault?.malware_families ?? []), ...(pi.related?.other?.malware_families ?? [])];
  return {
    data: {
      count: pi.count ?? 0,
      pulses: (pi.pulses ?? []).filter((p) => p.name).map((p) => ({ name: p.name!, created: p.created ?? null, tags: p.tags ?? [], url: `https://otx.alienvault.com/pulse/${p.id ?? ''}` })),
      whitelisted: (r.data.validation ?? []).some((v) => /whitelist|alexa|majestic|akamai|false_positive/i.test(`${v.source ?? ''} ${v.name ?? ''}`)),
      family: [...new Set(fam.map((f) => String(f)))].slice(0, 6),
    },
    prov: r.prov,
  };
}

export interface IpInfoLite { asn: string | null; asName: string | null; asDomain: string | null; country: string | null; countryCode: string | null }

export async function ipInfo(ctx: Ctx, ip: string): Promise<Sourced<IpInfoLite>> {
  const k = key('IPINFO_TOKEN');
  if (!k) return noKey('ipinfo', 'IPINFO_TOKEN');
  const r = await ctx.http.get<Record<string, unknown>>(`https://api.ipinfo.io/lite/${encodeURIComponent(ip)}?token=${encodeURIComponent(k)}`, { source: 'ipinfo', ttlSec: 24 * 3600, retries: 1 });
  const d = r.data;
  const s = (x: unknown) => (typeof x === 'string' && x ? x : null);
  return { data: d ? { asn: s(d.asn), asName: s(d.as_name), asDomain: s(d.as_domain), country: s(d.country), countryCode: s(d.country_code) } : null, prov: r.prov };
}

export interface VtStats { malicious: number; suspicious: number; harmless: number; undetected: number; engines: number; reputation: number | null; label: string | null; name: string | null; type: string | null; size: number | null; firstSeen: string | null; owner: string | null; link: string }

interface VtObject { data?: { attributes?: { last_analysis_stats?: Record<string, number>; reputation?: number; as_owner?: string; meaningful_name?: string; type_description?: string; size?: number; first_submission_date?: number; popular_threat_classification?: { suggested_threat_label?: string } } } }

/** VirusTotal verdicts for an IP address or a file hash (free public API: 4 requests a minute, 500 a day, non-commercial). */
export async function virusTotal(ctx: Ctx, kind: 'ip' | 'file', value: string): Promise<Sourced<VtStats>> {
  const k = key('VIRUSTOTAL_API_KEY');
  if (!k) return noKey('virustotal', 'VIRUSTOTAL_API_KEY');
  const path = kind === 'ip' ? `ip_addresses/${encodeURIComponent(value)}` : `files/${encodeURIComponent(value)}`;
  const link = kind === 'ip' ? `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(value)}` : `https://www.virustotal.com/gui/file/${encodeURIComponent(value)}`;
  const r = await ctx.http.get<VtObject>(`https://www.virustotal.com/api/v3/${path}`, {
    source: 'virustotal',
    ttlSec: 12 * 3600,
    retries: 1,
    headers: { 'x-apikey': k },
    keep: (d: VtObject) => {
      const a = d.data?.attributes ?? {};
      return { data: { attributes: { last_analysis_stats: a.last_analysis_stats, reputation: a.reputation, as_owner: a.as_owner, meaningful_name: a.meaningful_name, type_description: a.type_description, size: a.size, first_submission_date: a.first_submission_date, popular_threat_classification: { suggested_threat_label: a.popular_threat_classification?.suggested_threat_label } } } };
    },
  });
  if (!r.data && r.prov.note === 'HTTP 404') return { data: null, prov: { ...r.prov, status: 'LIVE', note: 'not in VirusTotal' } };
  const a = r.data?.data?.attributes;
  if (!a) return { data: null, prov: r.prov };
  const st = a.last_analysis_stats ?? {};
  const engines = Object.values(st).reduce((x, y) => x + (Number(y) || 0), 0);
  return {
    data: { malicious: st.malicious ?? 0, suspicious: st.suspicious ?? 0, harmless: st.harmless ?? 0, undetected: st.undetected ?? 0, engines, reputation: typeof a.reputation === 'number' ? a.reputation : null, label: a.popular_threat_classification?.suggested_threat_label ?? null, name: a.meaningful_name ?? null, type: a.type_description ?? null, size: a.size ?? null, firstSeen: a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString() : null, owner: a.as_owner ?? null, link },
    prov: r.prov,
  };
}

/* ---------- file hash sources ---------- */

export interface CirclHit { known: boolean; fileName: string | null; size: number | null; sources: string[]; knownMalicious: string | null; trust: number | null }

/** CIRCL hashlookup: is this a known file (NIST NSRL and other software sets), or known malware? */
export async function circlHash(ctx: Ctx, algo: 'md5' | 'sha1' | 'sha256', hash: string): Promise<Sourced<CirclHit>> {
  const r = await ctx.http.get<Record<string, unknown>>(`https://hashlookup.circl.lu/lookup/${algo}/${encodeURIComponent(hash)}`, { source: 'circl-hashlookup', ttlSec: 7 * 86_400, retries: 1 });
  if (!r.data && r.prov.note === 'HTTP 404') return { data: { known: false, fileName: null, size: null, sources: [], knownMalicious: null, trust: null }, prov: { ...r.prov, status: 'LIVE', note: 'hash not in the known-file sets' } };
  const d = r.data;
  if (!d) return { data: null, prov: r.prov };
  const src = [d.source, d['db']].filter((x): x is string => typeof x === 'string');
  const trust = Number(d['hashlookup:trust']);
  return { data: { known: true, fileName: typeof d.FileName === 'string' ? d.FileName : null, size: d.FileSize != null ? Number(d.FileSize) || null : null, sources: [...new Set(src)], knownMalicious: typeof d.KnownMalicious === 'string' ? d.KnownMalicious : null, trust: Number.isFinite(trust) ? trust : null }, prov: r.prov };
}

export interface BazaarHit { sha256: string; fileName: string | null; fileType: string | null; signature: string | null; firstSeen: string | null; lastSeen: string | null; tags: string[]; delivery: string | null; link: string }

export async function malwareBazaar(ctx: Ctx, hash: string): Promise<Sourced<BazaarHit>> {
  const k = key('ABUSECH_AUTH_KEY');
  if (!k) return noKey('malwarebazaar', 'ABUSECH_AUTH_KEY');
  const r = await postCached<{ query_status?: string; data?: Record<string, unknown>[] }>(ctx, 'https://mb-api.abuse.ch/api/v1/', new URLSearchParams({ query: 'get_info', hash }).toString(), 'application/x-www-form-urlencoded', { 'Auth-Key': k }, 'malwarebazaar', 12 * 3600);
  if (!r.data) return { data: null, prov: r.prov };
  const x = r.data.query_status === 'ok' ? r.data.data?.[0] : undefined;
  if (!x) return { data: null, prov: { ...r.prov, note: r.data.query_status === 'hash_not_found' ? 'not a known malware sample' : r.data.query_status } };
  const s = (v: unknown) => (typeof v === 'string' && v ? v : null);
  const sha = s(x.sha256_hash) ?? hash;
  return { data: { sha256: sha, fileName: s(x.file_name), fileType: s(x.file_type), signature: s(x.signature), firstSeen: s(x.first_seen), lastSeen: s(x.last_seen), tags: Array.isArray(x.tags) ? (x.tags as string[]).slice(0, 8) : [], delivery: s(x.delivery_method), link: `https://bazaar.abuse.ch/sample/${encodeURIComponent(sha)}/` }, prov: r.prov };
}

export interface ThreatFoxHit { ioc: string; threat: string | null; malware: string | null; confidence: number | null; firstSeen: string | null; link: string }

/** ThreatFox indicators of compromise: an IP:port, domain or file hash used by a malware family. */
export async function threatFox(ctx: Ctx, kind: 'hash' | 'ioc', value: string): Promise<Sourced<ThreatFoxHit[]>> {
  const k = key('ABUSECH_AUTH_KEY');
  if (!k) return noKey('threatfox', 'ABUSECH_AUTH_KEY');
  const body = kind === 'hash' ? { query: 'search_hash', hash: value } : { query: 'search_ioc', search_term: value, exact_match: false };
  const r = await postCached<{ query_status?: string; data?: unknown }>(ctx, 'https://threatfox-api.abuse.ch/api/v1/', JSON.stringify(body), 'application/json', { 'Auth-Key': k }, 'threatfox', 6 * 3600);
  if (!r.data) return { data: null, prov: r.prov };
  if (r.data.query_status !== 'ok' || !Array.isArray(r.data.data)) return { data: [], prov: { ...r.prov, note: r.data.query_status === 'no_result' ? 'no matching indicators' : r.data.query_status } };
  return {
    data: (r.data.data as Record<string, unknown>[]).slice(0, 10).map((x) => ({ ioc: String(x.ioc ?? value), threat: typeof x.threat_type_desc === 'string' ? x.threat_type_desc : typeof x.threat_type === 'string' ? x.threat_type : null, malware: typeof x.malware_printable === 'string' ? x.malware_printable : null, confidence: x.confidence_level != null ? Number(x.confidence_level) : null, firstSeen: typeof x.first_seen === 'string' ? x.first_seen : null, link: `https://threatfox.abuse.ch/ioc/${encodeURIComponent(String(x.id ?? ''))}/` })),
    prov: r.prov,
  };
}

export const unavailable = (source: string, url: string, note: string): Provenance => ({ source, url, status: 'UNAVAILABLE', fetchedAt: nowIso(), note });
