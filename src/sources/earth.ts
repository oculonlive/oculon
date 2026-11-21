/** Earth observation sources: NASA EONET natural events, NASA GIBS imagery, OpenStreetMap Nominatim geocoding. */
import { enc, type Ctx } from '../core/context.js';
import type { Provenance, Sourced } from '../core/types.js';

export interface EonetEvent {
  id: string;
  title: string;
  category: string;
  date: string;
  lat: number | null;
  lon: number | null;
  magnitude: number | null;
  unit: string | null;
  url: string;
}

interface EonetRaw {
  id: string;
  title: string;
  link?: string;
  sources?: { url: string }[];
  categories: { id: string }[];
  geometry: { date: string; type: string; coordinates: unknown; magnitudeValue?: number | null; magnitudeUnit?: string | null }[];
}

/** Open natural events (storms, wildfires, volcanoes, floods, ...) updated in the last `days` days. */
export async function eonetEvents(ctx: Ctx, days = 7): Promise<Sourced<EonetEvent[]>> {
  const r = await ctx.http.get<{ events?: EonetRaw[] }>(`https://eonet.gsfc.nasa.gov/api/v3/events?status=open&days=${days}`, { source: 'nasa-eonet', ttlSec: 1800, timeoutMs: 40_000 });
  const data =
    r.data?.events?.map((e) => {
      const g = e.geometry[e.geometry.length - 1];
      const point = g?.type === 'Point' && Array.isArray(g.coordinates) ? (g.coordinates as number[]) : null;
      return {
        id: e.id,
        title: e.title,
        category: e.categories[0]?.id ?? 'unknown',
        date: g?.date ?? '',
        lat: point?.[1] ?? null,
        lon: point?.[0] ?? null,
        magnitude: g?.magnitudeValue ?? null,
        unit: g?.magnitudeUnit ?? null,
        url: e.sources?.[0]?.url ?? e.link ?? `https://eonet.gsfc.nasa.gov/api/v3/events/${e.id}`,
      };
    }) ?? null;
  return { data, prov: r.prov };
}

export interface Place {
  name: string;
  lat: number;
  lon: number;
  /** [south, north, west, east] */
  bbox: [number, number, number, number];
  type: string;
  importance: number;
}

const MINOR = new Set(['road', 'street', 'house', 'building', 'amenity', 'shop', 'highway', 'residential', 'neighbourhood', 'postcode']);

/** True when every word of the query appears in the first part of the display name (the place itself). */
export function nameMatches(displayName: string, q: string): boolean {
  const head = (displayName.split(',')[0] ?? '').toLowerCase();
  return q
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean)
    .every((w) => head.includes(w));
}

/** Geocode with Nominatim (usage policy: max 1 request/second, identifying User-Agent; cached 30 days). */
export async function geocode(ctx: Ctx, q: string, limit = 5): Promise<Sourced<Place[]>> {
  const r = await ctx.http.get<{ display_name: string; lat: string; lon: string; boundingbox: string[]; addresstype?: string; type?: string; importance?: number }[]>(
    `https://nominatim.openstreetmap.org/search?q=${enc(q)}&format=json&limit=${limit}&accept-language=en`,
    { source: 'nominatim', ttlSec: 30 * 86_400 },
  );
  const data =
    r.data?.map((p) => ({
      name: p.display_name,
      lat: Number(p.lat),
      lon: Number(p.lon),
      bbox: p.boundingbox.map(Number) as Place['bbox'],
      type: p.addresstype ?? p.type ?? 'place',
      importance: p.importance ?? 0,
    }))
      // Keep Nominatim relevance order, but prefer results whose own name matches the query, and push
      // streets/buildings last. (Sorting by importance alone let an unrelated, more famous city win.)
      .map((p, i) => ({ p, i, match: nameMatches(p.name, q) }))
      .sort((a, b) => Number(b.match) - Number(a.match) || Number(MINOR.has(a.p.type)) - Number(MINOR.has(b.p.type)) || a.i - b.i)
      .map((x) => x.p) ?? null;
  return { data, prov: r.prov };
}

export const NIGHT_LIGHTS = 'VIIRS_NOAA20_GapFilled_BRDF_Corrected_DayNightBand_Radiance';
export const TRUE_COLOR = 'MODIS_Terra_CorrectedReflectance_TrueColor';

const mercator = (lat: number, lon: number): [number, number] => [(lon * 20037508.34) / 180, Math.log(Math.tan(((90 + lat) * Math.PI) / 360)) * 6378137];

/**
 * One GIBS WMS image for a date. Past-date imagery does not change, so PNGs are cached (base64) for 30 days.
 * Night lights are only published in Web Mercator; true color is requested in EPSG:4326 (lat,lon axis order).
 */
export async function gibsImage(ctx: Ctx, layer: string, bbox: Place['bbox'], date: string, size = 256): Promise<{ png: Buffer | null; prov: Provenance }> {
  const [s, n, w, e] = bbox;
  const merc = layer === NIGHT_LIGHTS;
  const box = merc ? [...mercator(s, w), ...mercator(n, e)].map((v) => Math.round(v)).join(',') : [s, w, n, e].join(',');
  const crs = merc ? 'EPSG:3857' : 'EPSG:4326';
  const url = `https://gibs.earthdata.nasa.gov/wms/${merc ? 'epsg3857' : 'epsg4326'}/best/wms.cgi?SERVICE=WMS&REQUEST=GetMap&VERSION=1.3.0&LAYERS=${layer}&CRS=${crs}&BBOX=${box}&WIDTH=${size}&HEIGHT=${size}&FORMAT=image/png&TIME=${date}`;
  const key = `bytes:${url}`;
  const cached = ctx.store.cacheGet(key);
  if (cached && Date.now() - cached.fetchedAt < 30 * 86_400_000) {
    return { png: Buffer.from(cached.body, 'base64'), prov: { source: 'nasa-gibs', url, status: 'CACHED', fetchedAt: new Date(cached.fetchedAt).toISOString() } };
  }
  const r = await ctx.http.getBytes(url, { source: 'nasa-gibs', timeoutMs: 60_000 });
  if (r.data && r.data.subarray(0, 4).toString('latin1') !== '\x89PNG') {
    return { png: null, prov: { ...r.prov, status: 'ERROR', note: r.data.toString('utf8').slice(0, 160).replace(/\s+/g, ' ') } };
  }
  if (r.data) ctx.store.cachePut(key, r.data.toString('base64'));
  return { png: r.data, prov: r.prov };
}
