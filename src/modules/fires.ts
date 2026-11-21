/**
 * Fires: active fire and thermal hotspots near a place from NASA FIRMS (free MAP_KEY), seen by the VIIRS
 * instruments on NOAA-21, NOAA-20 and Suomi NPP and by MODIS on Terra and Aqua, within about three hours of the
 * pass. Products whose feed has stopped are skipped using FIRMS' data_availability list; MODIS detections that
 * duplicate a VIIRS detection of the same pass are dropped. Besides wildfires this catches industrial fires,
 * refinery flares and strikes on infrastructure.
 */
import type { Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { geocode, type Place } from '../sources/earth.js';

export interface Hotspot {
  lat: number;
  lon: number;
  time: string;
  satellite: string;
  confidence: 'low' | 'nominal' | 'high';
  /** Fire radiative power, MW. */
  frp: number;
  daynight: 'D' | 'N';
  /** FIRMS product the detection came from, e.g. VIIRS_NOAA21_NRT, MODIS_NRT. */
  product?: string;
}

/** FIRMS near-real-time products, best first: VIIRS (375 m) before MODIS (1 km). */
export const FIRMS_PRODUCTS: Record<string, string> = {
  VIIRS_NOAA21_NRT: 'NOAA-21',
  VIIRS_NOAA20_NRT: 'NOAA-20',
  VIIRS_SNPP_NRT: 'Suomi NPP',
  MODIS_NRT: 'MODIS',
  LANDSAT_NRT: 'Landsat',
};
const DEFAULT_PRODUCTS = ['VIIRS_NOAA21_NRT', 'VIIRS_NOAA20_NRT', 'VIIRS_SNPP_NRT', 'MODIS_NRT'];

export interface Fires {
  place: Place | null;
  days: number;
  hotspots: Hotspot[];
  high: number;
  totalFrp: number;
  /** Groups of hotspots within about 3 km, largest first. */
  clusters: { lat: number; lon: number; count: number; frp: number; last: string }[];
}

export function parseFirmsCsv(csv: string, satellite: string): Hotspot[] {
  const [head, ...rows] = csv.trim().split('\n');
  if (!head?.startsWith('latitude')) return [];
  const cols = head.split(',');
  const at = (name: string) => cols.indexOf(name);
  return rows
    .map((r) => r.split(','))
    .filter((c) => c.length >= cols.length)
    .map((c) => {
      const conf = (c[at('confidence')] ?? '').trim().toLowerCase();
      const t = (c[at('acq_time')] ?? '0000').padStart(4, '0');
      // MODIS reports confidence as 0-100 (FIRMS: <30 low, 30-79 nominal, >=80 high); VIIRS and Landsat as letters.
      const pct = /^\d+$/.test(conf) ? Number(conf) : null;
      const level: Hotspot['confidence'] = pct !== null ? (pct >= 80 ? 'high' : pct < 30 ? 'low' : 'nominal') : conf === 'h' || conf === 'high' ? 'high' : conf === 'l' || conf === 'low' ? 'low' : 'nominal';
      // MODIS rows name the platform (Terra / Aqua); keep it so passes can be told apart.
      const platform = satellite === 'MODIS' ? (c[at('satellite')] ?? '').trim() : '';
      return {
        lat: Number(c[at('latitude')]),
        lon: Number(c[at('longitude')]),
        time: `${c[at('acq_date')]}T${t.slice(0, 2)}:${t.slice(2)}:00Z`,
        satellite: platform ? `MODIS ${platform}` : satellite,
        confidence: level,
        frp: Number(c[at('frp')]) || 0,
        daynight: (c[at('daynight')] === 'N' ? 'N' : 'D') as Hotspot['daynight'],
      };
    })
    .filter((h) => Number.isFinite(h.lat) && Number.isFinite(h.lon));
}

/**
 * Merge detections from several FIRMS products: exact duplicates dropped, and a MODIS (1 km at nadir, up to ~2 km
 * off-nadir) detection dropped when a VIIRS (375 m) detection lies within `km` and `minutes` of it, since both saw
 * the same fire on the same pass.
 */
export function dedupeHotspots(hs: Hotspot[], km = 2, minutes = 30): Hotspot[] {
  const exact = new Set<string>();
  const unique: Hotspot[] = [];
  for (const h of hs) {
    const k = `${h.lat.toFixed(4)},${h.lon.toFixed(4)},${h.time}`;
    if (exact.has(k)) continue;
    exact.add(k);
    unique.push(h);
  }
  const viirs = unique.filter((h) => !h.satellite.startsWith('MODIS'));
  return unique.filter((h) => {
    if (!h.satellite.startsWith('MODIS')) return true;
    const t = Date.parse(h.time);
    return !viirs.some((v) => Math.abs(Date.parse(v.time) - t) <= minutes * 60_000 && Math.hypot((v.lat - h.lat) * 111, (v.lon - h.lon) * 111 * Math.cos((h.lat * Math.PI) / 180)) <= km);
  });
}

/** FIRMS products with near-real-time data up to `sinceDay` (YYYY-MM-DD), from the data_availability endpoint. */
export function parseAvailability(csv: string, sinceDay: string): string[] {
  const [head, ...rows] = csv.trim().split('\n');
  if (!head?.startsWith('data_id')) return [];
  return rows
    .map((r) => r.trim().split(','))
    .filter((c) => c[0]?.endsWith('_NRT') && (c[2] ?? '') >= sinceDay)
    .map((c) => c[0]!);
}

export function clusterHotspots(hs: Hotspot[], km = 3): Fires['clusters'] {
  const out: { lat: number; lon: number; count: number; frp: number; last: string }[] = [];
  for (const h of [...hs].sort((a, b) => b.frp - a.frp)) {
    const c = out.find((x) => Math.hypot((x.lat - h.lat) * 111, (x.lon - h.lon) * 111 * Math.cos((h.lat * Math.PI) / 180)) <= km);
    if (c) {
      c.count++;
      c.frp += h.frp;
      if (h.time > c.last) c.last = h.time;
    } else out.push({ lat: h.lat, lon: h.lon, count: 1, frp: h.frp, last: h.time });
  }
  return out.map((c) => ({ ...c, frp: Math.round(c.frp) })).sort((a, b) => b.frp - a.frp);
}

/**
 * `opts.products` overrides the FIRMS products queried (default: every VIIRS NRT product with current data plus
 * MODIS_NRT; add LANDSAT_NRT for 30 m detections over the US and Canada, which carry no FRP).
 */
export async function fires(ctx: Ctx, placeQuery: string, days = 2, opts: { products?: string[] } = {}): Promise<ModuleResult<Fires>> {
  const now = ctx.now();
  const provenance: Provenance[] = [];
  const d = Math.max(1, Math.min(5, Math.round(days)));
  const g = await geocode(ctx, placeQuery, 1);
  provenance.push(g.prov);
  const place = g.data?.[0] ?? null;
  const empty = (p: Provenance): ModuleResult<Fires> => ({ module: 'fires', input: placeQuery, generatedAt: now.toISOString(), result: { place, days: d, hotspots: [], high: 0, totalFrp: 0, clusters: [] }, signals: [], provenance: [...provenance, p] });
  const k = key('FIRMS_MAP_KEY');
  if (!k) return empty(noKey('firms', 'FIRMS_MAP_KEY').prov);
  if (!place) return empty({ source: 'nominatim', url: '', status: 'UNAVAILABLE', fetchedAt: now.toISOString(), note: `place not found: ${placeQuery}` });
  // At least ~1 degree around the place so a town's surroundings are included; at most ~6 degrees.
  let [s, n, w, e] = place.bbox;
  const pad = (lo: number, hi: number, c: number): [number, number] => (hi - lo < 1 ? [c - 0.5, c + 0.5] : hi - lo > 6 ? [c - 3, c + 3] : [lo, hi]);
  [s, n] = pad(s, n, place.lat);
  [w, e] = pad(w, e, place.lon);
  const area = [w, s, e, n].map((x) => x.toFixed(3)).join(',');
  // Skip products whose feed has stopped (e.g. a satellite in safe mode): ask FIRMS what is current, once a day.
  let products = opts.products?.length ? opts.products.filter((p) => p in FIRMS_PRODUCTS) : DEFAULT_PRODUCTS;
  if (!opts.products?.length) {
    const av = await ctx.http.get<string>(`https://firms.modaps.eosdis.nasa.gov/api/data_availability/csv/${k}/all`, { source: 'firms', as: 'text', ttlSec: 6 * 3600, timeoutMs: 30_000 });
    provenance.push(av.prov);
    const current = av.data ? parseAvailability(av.data, new Date(now.getTime() - (d + 1) * 86_400_000).toISOString().slice(0, 10)) : [];
    if (current.length) products = DEFAULT_PRODUCTS.filter((p) => current.includes(p));
  }
  const raw: Hotspot[] = [];
  const results = await Promise.all(
    products.map(async (src) => ({ src, r: await ctx.http.get<string>(`https://firms.modaps.eosdis.nasa.gov/api/area/csv/${k}/${src}/${area}/${d}`, { source: 'firms', as: 'text', ttlSec: 1800, timeoutMs: 60_000 }) })),
  );
  for (const { src, r } of results) {
    provenance.push(r.prov);
    if (r.data) raw.push(...parseFirmsCsv(r.data, FIRMS_PRODUCTS[src]!).map((h) => ({ ...h, product: src })));
  }
  const hotspots = dedupeHotspots(raw);
  hotspots.sort((a, b) => b.time.localeCompare(a.time));
  const high = hotspots.filter((h) => h.confidence === 'high').length;
  const totalFrp = Math.round(hotspots.reduce((t, h) => t + h.frp, 0));
  const clusters = clusterHotspots(hotspots);
  const signals: Signal[] = [];
  const big = clusters.filter((c) => c.count >= 10 || c.frp >= 500);
  if (big.length) {
    const top = big[0]!;
    signals.push({
      id: signalId('fires', place.name, now.toISOString().slice(0, 10)),
      module: 'fires',
      title: `Large fire activity near ${place.name.split(',')[0]}: ${big.length} cluster(s), largest ${top.count} detections, ${top.frp} MW`,
      score: Math.min(85, 55 + big.length * 3 + Math.min(15, Math.round(top.frp / 200))),
      evidence: big.slice(0, 3).map((c) => ({ source: 'nasa-firms', text: `${c.count} hotspots at ${c.lat.toFixed(3)}, ${c.lon.toFixed(3)} totaling ${c.frp} MW, last ${c.last.slice(0, 16).replace('T', ' ')} UTC`, url: `https://firms.modaps.eosdis.nasa.gov/map/#d:24hrs;@${c.lon.toFixed(3)},${c.lat.toFixed(3)},11z` })),
      createdAt: now.toISOString(),
    });
  }
  for (const sig of signals) ctx.graph.saveSignal(sig);
  return { module: 'fires', input: placeQuery, generatedAt: now.toISOString(), result: { place, days: d, hotspots, high, totalFrp, clusters }, signals, provenance };
}
