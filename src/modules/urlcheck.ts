/**
 * URL check: is a link dangerous, and who is behind it?
 *   Google Safe Browsing: malware, phishing, unwanted software (SAFE_BROWSING_KEY).
 *   URLhaus (abuse.ch): known malware distribution URLs and hosts (ABUSECH_AUTH_KEY).
 *   urlscan.io: public scan history of the host, with community tags (URLSCAN_API_KEY optional).
 *   RDAP: domain registration date (age) and registrar, no key.
 *   Plain heuristics on the URL itself: IP hosts, punycode, brand names on other domains, risky TLDs, @ tricks.
 * The verdict says what the sources found; "no known threats" is not a promise that a page is safe.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';
import { safeBrowsing } from '../sources/websec.js';
import { ensurePhishLists, phishDomain } from '../sources/phishlists.js';

export type UrlVerdict = 'malicious' | 'suspicious' | 'no known threats';

export interface UrlCheck {
  url: string;
  host: string;
  domain: string;
  verdict: UrlVerdict;
  /** 0 (nothing found) to 100 (confirmed malicious). */
  risk: number;
  reasons: string[];
  safeBrowsing: { threats: string[] } | null;
  urlhaus: { url: { status: string; threat: string | null; tags: string[]; dateAdded: string | null; reference: string | null } | null; host: { urls: number; online: number; firstSeen: string | null } | null } | null;
  domainInfo: { registered: string | null; ageDays: number | null; expires: string | null; registrar: string | null } | null;
  scans: { count: number; firstSeen: string | null; lastSeen: string | null; titles: string[]; tags: string[]; ips: string[]; countries: string[]; servers: string[]; latest: string | null } | null;
  heuristics: string[];
}

const DAY = 86_400_000;
const TWO_LEVEL = /^(co|com|net|org|gov|ac|edu|or|ne|go|mil|nic)$/;
const RISKY_TLDS = new Set(['zip', 'mov', 'xyz', 'top', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'fit', 'loan', 'cam', 'quest', 'cfd', 'sbs', 'icu', 'buzz', 'monster']);
const BRANDS = ['paypal', 'apple', 'icloud', 'microsoft', 'office365', 'outlook', 'google', 'gmail', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'metamask', 'binance', 'coinbase', 'kraken', 'ledger', 'trezor', 'wellsfargo', 'chase', 'bankofamerica', 'hsbc', 'dhl', 'fedex', 'usps', 'steam', 'discord', 'telegram', 'docusign', 'dropbox', 'adobe', 'linkedin', 'twitter', 'opensea', 'uniswap'];

/** Normalizes input ("example.com/x", "https://...") to a URL. */
export function normalizeUrl(input: string): URL {
  const s = input.trim();
  if (!s) throw new Error('missing URL');
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `http://${s}`);
  } catch {
    throw new Error(`not a URL: ${input}`);
  }
}

/** Registrable domain by a simple rule: last two labels, or three under common second levels (co.uk, com.au). */
export function apexOf(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2 || /^\d+$/.test(parts.at(-1)!)) return parts.join('.');
  const n = parts.at(-1)!.length === 2 && TWO_LEVEL.test(parts.at(-2)!) ? 3 : 2;
  return parts.slice(-n).join('.');
}

/** Warning signs visible in the URL itself. */
export function urlHeuristics(u: URL): string[] {
  const out: string[] = [];
  const host = u.hostname.toLowerCase();
  const apex = apexOf(host);
  const tld = host.split('.').at(-1) ?? '';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) out.push('the host is a raw IP address');
  if (host.split('.').some((l) => l.startsWith('xn--'))) out.push('the host uses punycode (look-alike characters)');
  if (RISKY_TLDS.has(tld)) out.push(`.${tld} is a top-level domain often used for abuse`);
  const apexName = apex.split('.')[0] ?? '';
  const brand = BRANDS.find((b) => host.replace(/[-.]/g, '').includes(b) && apexName !== b);
  if (brand) out.push(`mentions "${brand}" but is not on ${brand}'s own domain`);
  if (u.username || u.href.includes('@')) out.push('contains "@", which can hide the real destination');
  if (host.split('.').length >= 5) out.push('unusually deep subdomain chain');
  if (u.href.length > 200) out.push('very long URL');
  if ((host.match(/-/g) ?? []).length >= 3) out.push('many hyphens in the host name');
  return out;
}

/** POST a form and cache the JSON answer (URLhaus takes form bodies). */
async function postForm<T>(ctx: Ctx, url: string, form: Record<string, string>, headers: Record<string, string>, source: string, ttlSec: number): Promise<Sourced<T>> {
  const body = new URLSearchParams(form).toString();
  const cacheKey = `post:${url}:${body}`;
  const cached = ctx.store.cacheGet(cacheKey);
  if (cached && Date.now() - cached.fetchedAt < ttlSec * 1000) return { data: JSON.parse(cached.body) as T, prov: { source, url, status: 'CACHED', fetchedAt: new Date(cached.fetchedAt).toISOString() } };
  const r = await ctx.http.postBytes(url, new TextEncoder().encode(body), { source, headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, timeoutMs: 30_000 });
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

const URLHAUS = 'https://urlhaus-api.abuse.ch/v1';

interface HausUrl { query_status: string; url_status?: string; threat?: string | null; tags?: string[] | null; date_added?: string | null; urlhaus_reference?: string | null }
interface HausHost { query_status: string; url_count?: string | number; firstseen?: string | null; urls?: { url_status?: string }[] }

async function urlhaus(ctx: Ctx, url: string, host: string): Promise<{ data: UrlCheck['urlhaus']; prov: Provenance[] }> {
  const k = key('ABUSECH_AUTH_KEY');
  if (!k) return { data: null, prov: [{ source: 'urlhaus', url: URLHAUS, status: 'UNAVAILABLE', fetchedAt: new Date().toISOString(), note: 'set ABUSECH_AUTH_KEY (free at auth.abuse.ch)' }] };
  const h = { 'Auth-Key': k };
  const [u, hs] = await Promise.all([
    postForm<HausUrl>(ctx, `${URLHAUS}/url/`, { url }, h, 'urlhaus', 3600),
    postForm<HausHost>(ctx, `${URLHAUS}/host/`, { host }, h, 'urlhaus', 3600),
  ]);
  const urlHit = u.data?.query_status === 'ok' ? { status: u.data.url_status ?? 'unknown', threat: u.data.threat ?? null, tags: u.data.tags ?? [], dateAdded: u.data.date_added ?? null, reference: u.data.urlhaus_reference ?? null } : null;
  const hostHit = hs.data?.query_status === 'ok' ? { urls: Number(hs.data.url_count ?? hs.data.urls?.length ?? 0), online: (hs.data.urls ?? []).filter((x) => x.url_status === 'online').length, firstSeen: hs.data.firstseen ?? null } : null;
  return { data: u.data || hs.data ? { url: urlHit, host: hostHit } : null, prov: [u.prov, hs.prov] };
}

interface RdapEvent { eventAction: string; eventDate: string }
interface RdapEntity { roles?: string[]; vcardArray?: [string, [string, unknown, string, unknown][]] }

async function rdap(ctx: Ctx, domain: string): Promise<Sourced<UrlCheck['domainInfo']>> {
  const r = await ctx.http.get<{ events?: RdapEvent[]; entities?: RdapEntity[] }>(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    source: 'rdap',
    ttlSec: 7 * 86_400,
    timeoutMs: 20_000,
    keep: (d: { events?: RdapEvent[]; entities?: RdapEntity[] }) => ({ events: d.events ?? [], entities: (d.entities ?? []).filter((e) => e.roles?.includes('registrar')).map((e) => ({ roles: e.roles, vcardArray: e.vcardArray })) }),
  });
  if (!r.data) return { data: null, prov: r.prov };
  const ev = (a: string) => r.data!.events?.find((e) => e.eventAction === a)?.eventDate ?? null;
  const registered = ev('registration');
  const card = r.data.entities?.[0]?.vcardArray?.[1] ?? [];
  const registrar = String(card.find((f) => f[0] === 'fn')?.[3] ?? '') || null;
  return { data: { registered, ageDays: registered ? Math.floor((ctx.now().getTime() - Date.parse(registered)) / DAY) : null, expires: ev('expiration'), registrar }, prov: r.prov };
}

interface ScanHit { task?: { time?: string; url?: string; tags?: string[] }; page?: { title?: string; ip?: string; country?: string; server?: string; url?: string }; _id?: string }

async function scanHistory(ctx: Ctx, host: string): Promise<Sourced<UrlCheck['scans']>> {
  const k = key('URLSCAN_API_KEY');
  const r = await ctx.http.get<ScanHit[]>(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`page.domain:"${host}"`)}&size=50`, {
    source: 'urlscan',
    ttlSec: 3 * 3600,
    ...(k ? { headers: { 'api-key': k } } : {}),
    keep: (d: { results?: ScanHit[] }) => (d.results ?? []).map((x) => ({ task: { time: x.task?.time, url: x.task?.url, tags: x.task?.tags }, page: { title: x.page?.title, ip: x.page?.ip, country: x.page?.country, server: x.page?.server, url: x.page?.url }, _id: x._id })),
  });
  if (!r.data) return { data: null, prov: r.prov };
  const hits = r.data;
  const times = hits.map((h) => h.task?.time ?? '').filter(Boolean).sort();
  const uniq = (xs: (string | undefined)[], n = 5) => [...new Set(xs.filter((x): x is string => Boolean(x)))].slice(0, n);
  return {
    data: {
      count: hits.length,
      firstSeen: times[0] ?? null,
      lastSeen: times.at(-1) ?? null,
      titles: uniq(hits.map((h) => h.page?.title?.trim()), 3),
      tags: uniq(hits.flatMap((h) => h.task?.tags ?? []), 8),
      ips: uniq(hits.map((h) => h.page?.ip)),
      countries: uniq(hits.map((h) => h.page?.country)),
      servers: uniq(hits.map((h) => h.page?.server)),
      latest: hits[0]?._id ? `https://urlscan.io/result/${hits[0]._id}/` : null,
    },
    prov: r.prov,
  };
}

const BAD_TAG = /phish|malware|scam|fraud|crypto.?drain|fake|credential|spam/i;

export async function urlCheck(ctx: Ctx, input: string): Promise<ModuleResult<UrlCheck>> {
  const u = normalizeUrl(input);
  const url = u.href;
  const host = u.hostname.toLowerCase();
  const domain = apexOf(host);
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const [sb, haus, who, scans] = await Promise.all([
    safeBrowsing(ctx, [url, `${u.protocol}//${host}/`]),
    urlhaus(ctx, url, host),
    isIp ? Promise.resolve<Sourced<UrlCheck['domainInfo']>>({ data: null, prov: { source: 'rdap', url: '', status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: 'IP address, no domain registration' } }) : rdap(ctx, domain),
    scanHistory(ctx, host),
  ]);
  const provenance: Provenance[] = [sb.prov, ...haus.prov, who.prov, scans.prov];
  // Open crypto phishing blocklists (ScamSniffer, MetaMask), stored locally and refreshed daily.
  let blocklisted: string[] = [];
  if (!isIp) {
    try { provenance.push(...(await ensurePhishLists(ctx)).slice(0, 1)); blocklisted = phishDomain(ctx, host).listed; } catch { /* lists are optional */ }
  }
  const heuristics = urlHeuristics(u);

  const reasons: string[] = [];
  let risk = 0;
  const threats = sb.data ? [...new Set(sb.data.map((m) => m.threat.toLowerCase().replace(/_/g, ' ')))] : [];
  if (threats.length) { risk = 100; reasons.push(`Google Safe Browsing flags it: ${threats.join(', ')}`); }
  if (blocklisted.length) { risk = 100; reasons.push(`listed as phishing or a wallet drainer by the ${blocklisted.join(' and the ')}`); }
  const hu = haus.data?.url;
  if (hu) {
    risk = Math.max(risk, hu.status === 'online' ? 100 : 80);
    reasons.push(`URLhaus lists this URL as ${hu.threat ?? 'malicious'} (${hu.status}${hu.tags.length ? `, ${hu.tags.join(', ')}` : ''})`);
  }
  const age = who.data?.ageDays;
  const hh = haus.data?.host;
  // Big, old platforms (GitHub, cloud storage) host files their users upload; malware among them says little
  // about the platform itself, so host-level hits count fully only for young or small hosts.
  const sharedHost = hh != null && hh.urls >= 50 && age != null && age > 5 * 365;
  let hostHit = false;
  if (hh && hh.urls > 0) {
    if (sharedHost) {
      risk += 5;
      reasons.push(`the host serves user uploads; URLhaus has ${hh.urls} malware URLs on it, but not this one`);
    } else {
      hostHit = hh.online > 0;
      risk = Math.max(risk, hh.online ? 85 : 55);
      reasons.push(`URLhaus has ${hh.urls} malware URL${hh.urls === 1 ? '' : 's'} on this host${hh.online ? `, ${hh.online} still online` : ''}`);
    }
  }
  // Tags starting with "@" name the submitter (a feed or user), not a finding.
  const badTags = (scans.data?.tags ?? []).filter((t) => !t.startsWith('@') && BAD_TAG.test(t));
  if (badTags.length) { risk = Math.max(risk, 70); reasons.push(`urlscan.io scans of this host are tagged: ${badTags.join(', ')}`); }
  if (age != null && age < 30) { risk = Math.max(risk, 45) + 10; reasons.push(`the domain was registered ${age} day${age === 1 ? '' : 's'} ago`); }
  else if (age != null && age < 180) { risk += 10; reasons.push(`the domain is young (${age} days)`); }
  for (const h of heuristics) risk += /not on .* own domain|punycode/.test(h) ? 35 : /top-level domain|raw IP|"@"/.test(h) ? 15 : 10;
  reasons.push(...heuristics);
  // Only when the link was given with http:// (a bare domain gets http:// added here).
  if (/^http:\/\//i.test(input.trim()) && !threats.length && !hu) reasons.push('no HTTPS in the link as given');
  risk = clamp(Math.round(risk), 0, 100);
  const verdict: UrlVerdict = threats.length || hu || hostHit || blocklisted.length ? 'malicious' : risk >= 40 ? 'suspicious' : 'no known threats';
  if (verdict === 'no known threats' && age != null && age > 365) reasons.push(`the domain is ${Math.floor(age / 365)} year${age >= 730 ? 's' : ''} old`);

  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = [];
  if (verdict === 'malicious') {
    const s: Signal = {
      id: signalId('urlcheck', url, nowIso.slice(0, 10)),
      module: 'urlcheck',
      title: `Malicious link: ${host}`,
      score: clamp(risk, 60, 95),
      entity: ctx.graph.upsert('domain', domain),
      evidence: reasons.slice(0, 4).map((text) => ({ source: threats.length ? 'safe-browsing' : 'urlhaus', text, ...(hu?.reference ? { url: hu.reference } : {}) })),
      createdAt: nowIso,
    };
    ctx.graph.saveSignal(s);
    signals.push(s);
  }
  return {
    module: 'urlcheck',
    input,
    generatedAt: nowIso,
    result: { url, host, domain, verdict, risk, reasons, safeBrowsing: sb.data ? { threats } : null, urlhaus: haus.data, domainInfo: who.data, scans: scans.data, heuristics },
    signals,
    provenance,
  };
}
