import type { Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface Quake {
  id: string;
  mag: number;
  place: string;
  time: number;
  url: string;
  tsunami: boolean;
  alert: string | null;
  lat: number | null;
  lon: number | null;
}

interface Feature {
  id: string;
  properties: { mag: number; place: string; time: number; url: string; tsunami: number; alert: string | null };
  geometry?: { coordinates?: number[] };
}

const toQuake = (f: Feature): Quake => ({
  id: f.id,
  mag: f.properties.mag,
  place: f.properties.place,
  time: f.properties.time,
  url: f.properties.url,
  tsunami: f.properties.tsunami === 1,
  alert: f.properties.alert,
  lon: f.geometry?.coordinates?.[0] ?? null,
  lat: f.geometry?.coordinates?.[1] ?? null,
});

/** M4.5+ earthquakes in the past day. */
export async function recentQuakes(ctx: Ctx): Promise<Sourced<Quake[]>> {
  const r = await ctx.http.get<{ features?: Feature[] }>('https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_day.geojson', {
    source: 'usgs',
    ttlSec: 600,
  });
  return { data: r.data?.features?.map(toQuake) ?? null, prov: r.prov };
}

/** Earthquakes of at least `minMag` between two dates (YYYY-MM-DD), for looking back in time. */
export async function quakesBetween(ctx: Ctx, start: string, end: string, minMag = 6): Promise<Sourced<Quake[]>> {
  const r = await ctx.http.get<{ features?: Feature[] }>(
    `https://earthquake.usgs.gov/fdsnws/event/1/query?format=geojson&starttime=${start}&endtime=${end}&minmagnitude=${minMag}&orderby=magnitude`,
    { source: 'usgs', ttlSec: 30 * 86_400 },
  );
  return { data: r.data?.features?.map(toQuake) ?? null, prov: r.prov };
}
