import type { Ctx } from '../core/context.js';
import type { Provenance } from '../core/types.js';

export interface Airport {
  ident: string;
  iata: string | null;
  name: string;
  type: 'large_airport' | 'medium_airport';
  lat: number;
  lon: number;
  country: string;
  /** ISO 3166-2 region, e.g. US-AK. */
  region: string;
  city: string;
}

const URL_CSV = 'https://davidmegginson.github.io/ourairports-data/airports.csv';
const DERIVED_KEY = 'derived:ourairports:large-medium:v2';
const TTL_MS = 30 * 86_400_000;

/** Minimal RFC 4180 line parser (OurAirports quotes every text field). */
export function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (q) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out;
}

export function parseAirports(csv: string): Airport[] {
  const lines = csv.split(/\r?\n/);
  const head = parseCsvLine(lines[0] ?? '');
  const col = (n: string) => head.indexOf(n);
  const [iType, iIdent, iName, iLat, iLon, iCountry, iCity, iIata, iRegion] = ['type', 'ident', 'name', 'latitude_deg', 'longitude_deg', 'iso_country', 'municipality', 'iata_code', 'iso_region'].map(col) as number[];
  const out: Airport[] = [];
  for (const line of lines.slice(1)) {
    if (!line.includes('large_airport') && !line.includes('medium_airport')) continue;
    const f = parseCsvLine(line);
    const type = f[iType!];
    if (type !== 'large_airport' && type !== 'medium_airport') continue;
    const lat = Number(f[iLat!]);
    const lon = Number(f[iLon!]);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    out.push({ ident: f[iIdent!] ?? '', iata: f[iIata!] || null, name: f[iName!] ?? '', type, lat, lon, country: f[iCountry!] ?? '', region: f[iRegion!] ?? '', city: f[iCity!] ?? '' });
  }
  return out;
}

let memo: Airport[] | null = null;

/** Large and medium airports worldwide (OurAirports, public domain). Cached for 30 days. */
export async function airports(ctx: Ctx): Promise<{ data: Airport[] | null; prov: Provenance }> {
  if (memo) return { data: memo, prov: { source: 'ourairports', url: URL_CSV, status: 'CACHED', fetchedAt: new Date().toISOString() } };
  const derived = ctx.store.cacheGet(DERIVED_KEY);
  if (derived && Date.now() - derived.fetchedAt < TTL_MS) {
    memo = JSON.parse(derived.body) as Airport[];
    return { data: memo, prov: { source: 'ourairports', url: URL_CSV, status: 'CACHED', fetchedAt: new Date(derived.fetchedAt).toISOString() } };
  }
  // ttlSec 0: the raw 12 MB CSV is only needed to rebuild the derived list.
  const r = await ctx.http.get<string>(URL_CSV, { source: 'ourairports', as: 'text', ttlSec: 0, timeoutMs: 60_000 });
  if (!r.data) {
    if (derived) {
      memo = JSON.parse(derived.body) as Airport[];
      return { data: memo, prov: { ...r.prov, status: 'CACHED', note: 'stale airport list' } };
    }
    return { data: null, prov: r.prov };
  }
  memo = parseAirports(r.data);
  ctx.store.cachePut(DERIVED_KEY, JSON.stringify(memo));
  ctx.store.db.prepare('DELETE FROM cache WHERE key = ?').run(URL_CSV);
  return { data: memo, prov: r.prov };
}

export function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371;
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

export function nearestAirport(list: Airport[], lat: number, lon: number, filter?: (a: Airport) => boolean): { airport: Airport; km: number } | null {
  let best: { airport: Airport; km: number } | null = null;
  for (const a of list) {
    if (filter && !filter(a)) continue;
    // Cheap bounding pre-check before the trig.
    if (best && Math.abs(a.lat - lat) * 111 > best.km) continue;
    const km = haversineKm(lat, lon, a.lat, a.lon);
    if (!best || km < best.km) best = { airport: a, km };
  }
  return best;
}

export const airportLabel = (a: Airport) => `${a.name}${a.iata ? ` (${a.iata})` : ''}, ${a.city ? `${a.city}, ` : ''}${a.country}`;
