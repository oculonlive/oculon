/**
 * BGP routing: who can reach what on the internet, and who is announcing address space that is not theirs.
 *   RIPEstat (no key): country prefix visibility, AS visibility and neighbours, and for an IP address the
 *     announcing network, RPKI validity, abuse contact and location.
 *   Cloudflare Radar (token): detected BGP origin hijacks and route leaks, plus the countries most targeted
 *     by DDoS attacks. A high-confidence hijack is how traffic gets rerouted to steal crypto or spy on it.
 * A country-wide shutdown or a cut cable shows up as announced prefixes disappearing, which is independent
 * evidence next to traffic-based outage detection.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';

const RIPE = 'https://stat.ripe.net/data';
const CF = 'https://api.cloudflare.com/client/v4/radar';

export interface CountryRouting {
  country: string;
  /** Visible IPv4 prefixes per hour over the window. */
  series: { time: string; v4: number; v6: number; asns: number }[];
  latest: { v4: number; v6: number; asns: number } | null;
  baseline: { v4: number; v6: number; asns: number } | null;
  /** Latest versus baseline median, e.g. -0.35 = 35% fewer prefixes visible. */
  v4Change: number | null;
}

export interface AsnRouting {
  asn: string;
  name: string | null;
  visibilityV4: number | null;
  visibilityV6: number | null;
  prefixesV4: number;
  prefixesV6: number;
  neighbours: number;
}

export interface IpRouting {
  ip: string;
  prefix: string | null;
  announced: boolean;
  origins: { asn: string; name: string }[];
  /** RPKI validity of the announcement: valid, invalid (possible hijack or misconfiguration), unknown. */
  rpki: string | null;
  abuse: string[];
  country: string | null;
  city: string | null;
  registry: string | null;
}

export interface Hijack {
  id: number;
  hijacker: string;
  hijackerCountry: string | null;
  victims: string[];
  victimCountries: string[];
  prefixes: string[];
  confidence: number;
  peers: number;
  start: string;
  end: string;
  durationSec: number;
  ongoing: boolean;
  tags: string[];
  /** Hijacker and every victim belong to the same organisation (sister AS numbers): almost never a real hijack. */
  sameOrg: boolean;
  url: string;
}

export interface RouteLeak {
  id: number;
  leaker: string;
  countries: string[];
  path: string[];
  prefixes: number;
  origins: number;
  announcements: number;
  start: string;
  end: string;
  finished: boolean;
  url: string;
}

export interface BgpIncidents {
  hijacks: Hijack[];
  leaks: RouteLeak[];
  /** Share of DDoS attack traffic by target country, last 24h (Cloudflare's network). */
  attacks: { layer7: { country: string; name: string; share: number }[]; layer3: { country: string; name: string; share: number }[] } | null;
}

const median = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)]! : 0;
};

/** Repairs UTF-8 names that arrive double-encoded (mojibake) and drops soft hyphens and doubled spaces. */
export function cleanOrgName(name: string): string {
  let s = name ?? '';
  if (/[\u00C2\u00C3][\u0080-\u00BF]/.test(s)) {
    const fixed = Buffer.from(s, 'latin1').toString('utf8');
    if (!fixed.includes('\uFFFD')) s = fixed;
  }
  return s.replace(/\u00AD/g, '').replace(/\s{2,}/g, ' ').trim();
}

export async function countryRouting(ctx: Ctx, cc: string, hours = 48): Promise<{ data: CountryRouting | null; prov: Provenance }> {
  const start = new Date(ctx.now().getTime() - hours * 3_600_000).toISOString().slice(0, 13);
  const r = await ctx.http.get<{ data?: { stats?: { timeline?: { starttime: string }[]; v4_prefixes_ris: number; v6_prefixes_ris: number; asns_ris: number }[] } }>(
    `${RIPE}/country-routing-stats/data.json?resource=${encodeURIComponent(cc.toUpperCase())}&starttime=${start}:00&resolution=1h&sourceapp=oculon`,
    { source: 'ripestat', ttlSec: 1800, timeoutMs: 45_000 },
  );
  const stats = r.data?.data?.stats ?? [];
  if (!stats.length) return { data: null, prov: r.prov };
  const series = stats.map((s) => ({ time: s.timeline?.[0]?.starttime ?? '', v4: s.v4_prefixes_ris, v6: s.v6_prefixes_ris, asns: s.asns_ris }));
  const latest = series.at(-1)!;
  const base = series.slice(0, Math.max(1, series.length - 3));
  const baseline = { v4: median(base.map((x) => x.v4)), v6: median(base.map((x) => x.v6)), asns: median(base.map((x) => x.asns)) };
  return { data: { country: cc.toUpperCase(), series, latest, baseline, v4Change: baseline.v4 ? Math.round(((latest.v4 - baseline.v4) / baseline.v4) * 1000) / 1000 : null }, prov: r.prov };
}

export async function asnRouting(ctx: Ctx, asnInput: string): Promise<{ data: AsnRouting | null; prov: Provenance[] }> {
  const asn = asnInput.toUpperCase().replace(/^AS/, '');
  const [st, ov] = await Promise.all([
    ctx.http.get<{ data?: { visibility?: { v4?: { ris_peers_seeing: number; total_ris_peers: number }; v6?: { ris_peers_seeing: number; total_ris_peers: number } }; announced_space?: { v4?: { prefixes: number }; v6?: { prefixes: number } }; observed_neighbours?: number } }>(`${RIPE}/routing-status/data.json?resource=AS${asn}&sourceapp=oculon`, { source: 'ripestat', ttlSec: 900, timeoutMs: 60_000 }),
    ctx.http.get<{ data?: { holder?: string } }>(`${RIPE}/as-overview/data.json?resource=AS${asn}&sourceapp=oculon`, { source: 'ripestat', ttlSec: 7 * 86_400 }),
  ]);
  const d = st.data?.data;
  // routing-status can take minutes for the largest networks; still return who the AS is.
  if (!d) return { data: ov.data?.data?.holder ? { asn: `AS${asn}`, name: ov.data.data.holder, visibilityV4: null, visibilityV6: null, prefixesV4: 0, prefixesV6: 0, neighbours: 0 } : null, prov: [st.prov, ov.prov] };
  const pct = (v?: { ris_peers_seeing: number; total_ris_peers: number }) => (v && v.total_ris_peers ? Math.round((v.ris_peers_seeing / v.total_ris_peers) * 100) / 100 : null);
  return {
    data: { asn: `AS${asn}`, name: ov.data?.data?.holder ?? null, visibilityV4: pct(d.visibility?.v4), visibilityV6: pct(d.visibility?.v6), prefixesV4: d.announced_space?.v4?.prefixes ?? 0, prefixesV6: d.announced_space?.v6?.prefixes ?? 0, neighbours: d.observed_neighbours ?? 0 },
    prov: [st.prov, ov.prov],
  };
}

export const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(':'));

/** Who announces an IP address, whether RPKI says they may, who to report abuse to, and where it is. */
export async function ipRouting(ctx: Ctx, ip: string): Promise<{ data: IpRouting | null; prov: Provenance[] }> {
  const q = encodeURIComponent(ip);
  const [po, ab, geo] = await Promise.all([
    ctx.http.get<{ data?: { announced?: boolean; resource?: string; asns?: { asn: number; holder: string }[]; block?: { desc?: string } } }>(`${RIPE}/prefix-overview/data.json?resource=${q}&sourceapp=oculon`, { source: 'ripestat', ttlSec: 3600 }),
    ctx.http.get<{ data?: { abuse_contacts?: string[] } }>(`${RIPE}/abuse-contact-finder/data.json?resource=${q}&sourceapp=oculon`, { source: 'ripestat', ttlSec: 7 * 86_400 }),
    ctx.http.get<{ data?: { located_resources?: { locations?: { country?: string; city?: string }[] }[] } }>(`${RIPE}/maxmind-geo-lite/data.json?resource=${q}&sourceapp=oculon`, { source: 'ripestat', ttlSec: 7 * 86_400 }),
  ]);
  const prov = [po.prov, ab.prov, geo.prov];
  const p = po.data?.data;
  if (!p) return { data: null, prov };
  const origins = (p.asns ?? []).map((a) => ({ asn: `AS${a.asn}`, name: a.holder }));
  let rpki: string | null = null;
  if (origins[0] && p.resource) {
    const rv = await ctx.http.get<{ data?: { status?: string } }>(`${RIPE}/rpki-validation/data.json?resource=${origins[0].asn}&prefix=${encodeURIComponent(p.resource)}&sourceapp=oculon`, { source: 'ripestat', ttlSec: 3600 });
    prov.push(rv.prov);
    rpki = rv.data?.data?.status ?? null;
  }
  const loc = geo.data?.data?.located_resources?.[0]?.locations?.[0];
  return {
    data: {
      ip,
      prefix: p.resource ?? null,
      announced: Boolean(p.announced),
      origins,
      rpki,
      abuse: ab.data?.data?.abuse_contacts ?? [],
      country: loc?.country && loc.country !== '?' ? loc.country : null,
      city: loc?.city || null,
      registry: p.block?.desc ?? null,
    },
    prov,
  };
}

type HijackEvent = { id: number; hijacker_asn: number; hijacker_country?: string; victim_asns?: number[]; victim_countries?: string[]; prefixes?: string[]; confidence_score: number; peer_ip_count?: number; min_hijack_ts: string; max_hijack_ts: string; duration?: number; on_going_count?: number; is_stale?: boolean; tags?: { name: string; score: number }[] };
type LeakEvent = { id: number; leak_asn: number; countries?: string[]; leak_seg?: number[]; prefix_count?: number; origin_count?: number; leak_count?: number; min_ts: string; max_ts: string; finished?: boolean };
type AsnInfo = { asn: number; org_name: string; country_code?: string }[];

/** Cloudflare Radar BGP hijacks and route leaks, optionally for one AS or country, plus DDoS target countries. */
export async function bgpIncidents(ctx: Ctx, opts: { days?: number; asn?: string; country?: string; minConfidence?: number } = {}): Promise<{ data: BgpIncidents | null; prov: Provenance[] }> {
  const token = key('CLOUDFLARE_API_TOKEN');
  if (!token) return { data: null, prov: [{ source: 'cloudflare-radar', url: CF, status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: 'set CLOUDFLARE_API_TOKEN for BGP hijacks and route leaks' }] };
  const days = opts.days ?? 2;
  const range = days <= 1 ? '1d' : days <= 2 ? '2d' : days <= 7 ? '7d' : '14d';
  const auth = { authorization: `Bearer ${token}` };
  const asn = opts.asn?.toUpperCase().replace(/^AS/, '');
  const filter = `${asn ? `&involvedAsn=${asn}` : ''}${opts.country ? `&involvedCountry=${opts.country.toUpperCase()}` : ''}`;
  const global = !asn && !opts.country;
  const [hj, lk, l7, l3] = await Promise.all([
    ctx.http.get<{ result?: { events?: HijackEvent[]; asn_info?: AsnInfo } }>(`${CF}/bgp/hijacks/events?dateRange=${range}&minConfidence=${opts.minConfidence ?? (global ? 8 : 5)}&per_page=${global ? 60 : 30}&sortBy=CONFIDENCE&sortOrder=DESC${filter}&format=json`, { source: 'cloudflare-radar', ttlSec: 900, headers: auth }),
    ctx.http.get<{ result?: { events?: LeakEvent[]; asn_info?: AsnInfo } }>(`${CF}/bgp/leaks/events?dateRange=${range}&per_page=${global ? 60 : 30}&sortBy=PREFIXES&sortOrder=DESC${filter}&format=json`, { source: 'cloudflare-radar', ttlSec: 900, headers: auth }),
    global ? ctx.http.get<{ result?: { top_0?: { targetCountryAlpha2: string; targetCountryName: string; value: string }[] } }>(`${CF}/attacks/layer7/top/locations/target?dateRange=1d&limit=8&format=json`, { source: 'cloudflare-radar', ttlSec: 3600, headers: auth }) : null,
    global ? ctx.http.get<{ result?: { top_0?: { targetCountryAlpha2: string; targetCountryName: string; value: string }[] } }>(`${CF}/attacks/layer3/top/locations/target?dateRange=1d&limit=8&format=json`, { source: 'cloudflare-radar', ttlSec: 3600, headers: auth }) : null,
  ]);
  const prov = [hj.prov, lk.prov, ...(l7 ? [l7.prov] : []), ...(l3 ? [l3.prov] : [])];
  if (!hj.data && !lk.data) return { data: null, prov };
  const names = new Map<number, string>();
  for (const a of [...(hj.data?.result?.asn_info ?? []), ...(lk.data?.result?.asn_info ?? [])]) names.set(a.asn, cleanOrgName(a.org_name));
  const asName = (n: number) => `${names.get(n) ?? 'unknown network'} (AS${n})`;
  const ts = (s: string) => (/Z$|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`);
  const org = (n: number) => (names.get(n) ?? `#${n}`).toLowerCase();
  const hijacks: Hijack[] = (hj.data?.result?.events ?? []).map((e) => ({
    id: e.id,
    hijacker: asName(e.hijacker_asn),
    hijackerCountry: e.hijacker_country ?? null,
    victims: (e.victim_asns ?? []).map(asName),
    victimCountries: e.victim_countries ?? [],
    prefixes: e.prefixes ?? [],
    confidence: e.confidence_score,
    peers: e.peer_ip_count ?? 0,
    start: ts(e.min_hijack_ts),
    end: ts(e.max_hijack_ts),
    durationSec: e.duration ?? 0,
    ongoing: (e.on_going_count ?? 0) > 0 && !e.is_stale,
    tags: (e.tags ?? []).filter((t) => t.score > 0).map((t) => t.name),
    sameOrg: Boolean(e.victim_asns?.length) && e.victim_asns!.every((v) => org(v) === org(e.hijacker_asn)),
    url: `https://radar.cloudflare.com/routing/as${e.hijacker_asn}`,
  }));
  const leaks: RouteLeak[] = (lk.data?.result?.events ?? []).map((e) => ({
    id: e.id,
    leaker: asName(e.leak_asn),
    countries: e.countries ?? [],
    path: (e.leak_seg ?? []).map((n) => `AS${n}`),
    prefixes: e.prefix_count ?? 0,
    origins: e.origin_count ?? 0,
    announcements: e.leak_count ?? 0,
    start: ts(e.min_ts),
    end: ts(e.max_ts),
    finished: e.finished !== false,
    url: `https://radar.cloudflare.com/routing/as${e.leak_asn}`,
  }));
  const top = (r: typeof l7) => (r?.data?.result?.top_0 ?? []).map((x) => ({ country: x.targetCountryAlpha2, name: x.targetCountryName, share: Math.round(Number(x.value) * 10) / 1000 }));
  return { data: { hijacks, leaks, attacks: global ? { layer7: top(l7), layer3: top(l3) } : null }, prov };
}

/**
 * Only hijacks that are very likely real: Radar confidence 9+ and either seen by many peers, lasting an hour,
 * or covering many prefixes. Most single-peer events are misconfigurations seen by one vantage point.
 */
export function incidentSignals(inc: BgpIncidents, now: Date): Signal[] {
  const fresh = (iso: string) => now.getTime() - Date.parse(iso) < 48 * 3_600_000;
  const out: Signal[] = [];
  for (const h of inc.hijacks) {
    if (h.confidence < 9 || !fresh(h.end) || !(h.peers >= 10 || h.durationSec >= 3600 || h.prefixes.length >= 10)) continue;
    // Sister networks of one organisation moving prefixes between their own AS numbers are not hijacks.
    if (h.sameOrg) continue;
    out.push({
      id: signalId('bgp', 'hijack', String(h.id)),
      module: 'bgp',
      title: `Possible BGP hijack: ${h.hijacker} announced ${h.prefixes.length} prefix${h.prefixes.length === 1 ? '' : 'es'} of ${h.victims.slice(0, 2).join(', ') || 'another network'}${h.ongoing ? ', ongoing' : ''}`,
      score: Math.min(82, 62 + (h.ongoing ? 6 : 0) + (h.prefixes.length >= 10 ? 6 : 0) + (h.peers >= 50 ? 6 : 0)),
      evidence: [{ source: 'cloudflare-radar', text: `Radar confidence score ${h.confidence}, seen by ${h.peers} peers, ${h.prefixes.slice(0, 4).join(', ')}${h.prefixes.length > 4 ? '...' : ''}, since ${h.start.slice(0, 16).replace('T', ' ')} UTC${h.tags.length ? `, ${h.tags.slice(0, 3).join(', ')}` : ''}`, url: h.url }],
      createdAt: now.toISOString(),
    });
  }
  for (const l of inc.leaks) {
    if (l.prefixes < 100 || !fresh(l.end)) continue;
    out.push({
      id: signalId('bgp', 'leak', String(l.id)),
      module: 'bgp',
      title: `BGP route leak by ${l.leaker}: ${l.prefixes} prefixes from ${l.origins} networks${l.finished ? '' : ', ongoing'}`,
      score: Math.min(78, 58 + (l.finished ? 0 : 6) + (l.prefixes >= 1000 ? 10 : 0)),
      evidence: [{ source: 'cloudflare-radar', text: `path ${l.path.join(' > ')}, countries ${l.countries.join(', ')}, ${l.announcements} leaked announcements since ${l.start.slice(0, 16).replace('T', ' ')} UTC`, url: l.url }],
      createdAt: now.toISOString(),
    });
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 5);
}

export interface BgpResult {
  country: CountryRouting | null;
  asn: AsnRouting | null;
  ip?: IpRouting | null;
  incidents?: BgpIncidents | null;
}

/**
 * `bgp('PK')` country routing, `bgp('AS15169')` a network, `bgp('8.8.8.8')` an address,
 * `bgp('world')` (or empty) global hijacks, leaks and DDoS targets. Countries and networks include incidents involving them.
 */
export async function bgp(ctx: Ctx, resource: string, days = 2): Promise<ModuleResult<BgpResult>> {
  const now = ctx.now();
  const q = resource.trim();
  const done = (result: BgpResult, provenance: Provenance[], signals: Signal[] = []): ModuleResult<BgpResult> => {
    for (const s of signals) ctx.graph.saveSignal(s);
    return { module: 'bgp', input: q || 'world', generatedAt: now.toISOString(), result, signals, provenance };
  };
  if (!q || /^(world|global|all)$/i.test(q)) {
    const inc = await bgpIncidents(ctx, { days });
    return done({ country: null, asn: null, incidents: inc.data }, inc.prov, inc.data ? incidentSignals(inc.data, now) : []);
  }
  if (isIp(q)) {
    const ip = await ipRouting(ctx, q);
    return done({ country: null, asn: null, ip: ip.data }, ip.prov);
  }
  if (/^(AS)?\d+$/i.test(q)) {
    const [a, inc] = await Promise.all([asnRouting(ctx, q), bgpIncidents(ctx, { days: Math.max(days, 7), asn: q })]);
    return done({ country: null, asn: a.data, incidents: inc.data }, [...a.prov, ...inc.prov], inc.data ? incidentSignals(inc.data, now) : []);
  }
  if (!/^[A-Za-z]{2}$/.test(q)) throw new Error('give a two-letter country code (e.g. PK), an AS number (e.g. AS15169), an IP address, or "world"');
  const [c, inc] = await Promise.all([countryRouting(ctx, q), bgpIncidents(ctx, { days, country: q })]);
  return done({ country: c.data, asn: null, incidents: inc.data }, [c.prov, ...inc.prov], inc.data ? incidentSignals(inc.data, now) : []);
}
