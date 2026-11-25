/**
 * Satellites, from CelesTrak (keyless; CelesTrak asks clients not to fetch the same data more often than every
 * two hours, so results are cached for that long).
 *   No query: objects launched in the last 30 days, grouped by launch.
 *   A name ("hubble", "starlink-1007") or a NORAD catalog number: orbit, owner, launch date and status.
 * Orbit heights come from the published mean motion and eccentricity (Kepler's third law), not a live position.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Sourced } from '../core/types.js';

export interface Orbit { periodMin: number; apogeeKm: number; perigeeKm: number; inclination: number; regime: 'LEO' | 'MEO' | 'GEO' | 'HEO' | 'other' }

export interface SatObject {
  name: string;
  norad: number;
  intlId: string;
  epoch: string | null;
  orbit: Orbit | null;
  owner: string | null;
  type: string | null;
  launchDate: string | null;
  launchSite: string | null;
  status: string | null;
  decayed: string | null;
  url: string;
}

export interface SatResult {
  query: string | null;
  mode: 'recent' | 'search';
  objects: SatObject[];
  launches: { id: string; objects: number; names: string[] }[];
  total: number;
  note: string;
}

interface Gp { OBJECT_NAME?: string; OBJECT_ID?: string; EPOCH?: string; MEAN_MOTION?: number; ECCENTRICITY?: number; INCLINATION?: number; NORAD_CAT_ID?: number }
interface Satcat { NORAD_CAT_ID?: number; OBJECT_TYPE?: string; OPS_STATUS_CODE?: string; OWNER?: string; LAUNCH_DATE?: string; LAUNCH_SITE?: string; DECAY_DATE?: string }

const EARTH_R = 6378.137;
const MU = 398600.4418;

/** Period, apogee and perigee from mean motion (revolutions per day) and eccentricity. */
export function orbitFrom(meanMotion: number, ecc: number, inclination: number): Orbit | null {
  if (!(meanMotion > 0) || !(ecc >= 0 && ecc < 1)) return null;
  const n = (meanMotion * 2 * Math.PI) / 86_400;
  const a = Math.cbrt(MU / (n * n));
  const apogee = a * (1 + ecc) - EARTH_R;
  const perigee = a * (1 - ecc) - EARTH_R;
  const periodMin = 1440 / meanMotion;
  const regime: Orbit['regime'] = ecc > 0.25 ? 'HEO' : apogee < 2000 ? 'LEO' : Math.abs(periodMin - 1436) < 30 && ecc < 0.05 ? 'GEO' : apogee < 35_000 ? 'MEO' : 'other';
  return { periodMin: Math.round(periodMin * 10) / 10, apogeeKm: Math.round(apogee), perigeeKm: Math.round(perigee), inclination: Math.round(inclination * 100) / 100, regime };
}

const STATUS: Record<string, string> = { '+': 'operational', '-': 'not operational', P: 'partially operational', B: 'backup', S: 'spare', X: 'extended mission', D: 'decayed', '?': 'unknown' };
const TYPES: Record<string, string> = { PAY: 'payload', 'R/B': 'rocket body', DEB: 'debris', UNK: 'unknown' };

async function celestrak<T>(ctx: Ctx, url: string): Promise<Sourced<T[]>> {
  // An empty search answers with plain text ("No GP data found"), so read text and parse here.
  const r = await ctx.http.get<string>(url, { source: 'celestrak', as: 'text', ttlSec: 2 * 3600, timeoutMs: 30_000, retries: 1 });
  // CelesTrak answers 404 for a search with no match.
  if (r.data == null && r.prov.note === 'HTTP 404') return { data: [], prov: { ...r.prov, status: 'LIVE', note: 'no match' } };
  if (r.data == null) return { data: null, prov: r.prov };
  try {
    const d = JSON.parse(r.data) as unknown;
    return { data: Array.isArray(d) ? (d as T[]) : [], prov: r.prov };
  } catch {
    return { data: [], prov: { ...r.prov, note: r.data.trim().slice(0, 80) || 'no data' } };
  }
}

function toObject(g: Gp, s?: Satcat): SatObject {
  const norad = Number(g.NORAD_CAT_ID ?? s?.NORAD_CAT_ID ?? 0);
  return {
    name: g.OBJECT_NAME ?? `NORAD ${norad}`,
    norad,
    intlId: g.OBJECT_ID ?? '',
    epoch: g.EPOCH ? `${g.EPOCH.slice(0, 19)}Z` : null,
    orbit: g.MEAN_MOTION != null ? orbitFrom(Number(g.MEAN_MOTION), Number(g.ECCENTRICITY ?? 0), Number(g.INCLINATION ?? 0)) : null,
    owner: s?.OWNER || null,
    type: s?.OBJECT_TYPE ? TYPES[s.OBJECT_TYPE] ?? s.OBJECT_TYPE : null,
    launchDate: s?.LAUNCH_DATE || null,
    launchSite: s?.LAUNCH_SITE || null,
    status: s?.OPS_STATUS_CODE ? STATUS[s.OPS_STATUS_CODE] ?? s.OPS_STATUS_CODE : null,
    decayed: s?.DECAY_DATE || null,
    url: `https://celestrak.org/satcat/table-satcat.php?CATNR=${norad}`,
  };
}

export async function satellites(ctx: Ctx, input = ''): Promise<ModuleResult<SatResult>> {
  const q = input.trim();
  const provenance: Provenance[] = [];
  const base = 'https://celestrak.org';
  if (!q) {
    const g = await celestrak<Gp>(ctx, `${base}/NORAD/elements/gp.php?GROUP=last-30-days&FORMAT=json`);
    provenance.push(g.prov);
    if (!g.data) throw new Error(`CelesTrak is not answering right now (${g.prov.note ?? g.prov.status})`);
    const byLaunch = new Map<string, Gp[]>();
    for (const x of g.data) {
      const id = (x.OBJECT_ID ?? '').replace(/[A-Z]+$/, '');
      if (!id) continue;
      byLaunch.set(id, [...(byLaunch.get(id) ?? []), x]);
    }
    const launches = [...byLaunch].map(([id, xs]) => {
      const names = [...new Set(xs.map((x) => (x.OBJECT_NAME ?? '').replace(/[-\s]?\d+[A-Z]?$/, '').trim() || x.OBJECT_NAME || '').filter(Boolean))].slice(0, 4);
      return { id, objects: xs.length, names };
    }).sort((a, b) => b.id.localeCompare(a.id));
    return {
      module: 'satellites',
      input: '',
      generatedAt: ctx.now().toISOString(),
      result: { query: null, mode: 'recent', objects: [], launches: launches.slice(0, 30), total: g.data.length, note: 'Objects CelesTrak catalogued from launches in the last 30 days, newest launch first (international designator YYYY-NNN).' },
      signals: [],
      provenance,
    };
  }
  const isNum = /^\d{1,9}$/.test(q);
  if (!isNum && q.length < 3) throw new Error('give at least 3 characters of a satellite name, or a NORAD number');
  const g = await celestrak<Gp>(ctx, `${base}/NORAD/elements/gp.php?${isNum ? `CATNR=${q}` : `NAME=${encodeURIComponent(q)}`}&FORMAT=json`);
  provenance.push(g.prov);
  if (!g.data) throw new Error(`CelesTrak is not answering right now (${g.prov.note ?? g.prov.status})`);
  // Exact names first ("HUBBLE" before "HUBBLE 6"), then by catalog number.
  const lower = q.toLowerCase();
  const sorted = [...g.data].sort((a, b) => Number((b.OBJECT_NAME ?? '').toLowerCase() === lower || (b.OBJECT_NAME ?? '').toLowerCase().startsWith(`${lower} (`)) - Number((a.OBJECT_NAME ?? '').toLowerCase() === lower || (a.OBJECT_NAME ?? '').toLowerCase().startsWith(`${lower} (`)) || Number(a.NORAD_CAT_ID ?? 0) - Number(b.NORAD_CAT_ID ?? 0));
  const top = sorted.slice(0, 10);
  let cat: Satcat[] = [];
  if (top.length) {
    const s = await celestrak<Satcat>(ctx, `${base}/satcat/records.php?CATNR=${top.slice(0, 5).map((x) => x.NORAD_CAT_ID).join(',')}&FORMAT=json`);
    provenance.push(s.prov);
    cat = s.data ?? [];
  } else if (isNum) {
    // Decayed objects have no current orbit but are still in the catalog.
    const s = await celestrak<Satcat & { OBJECT_NAME?: string; OBJECT_ID?: string }>(ctx, `${base}/satcat/records.php?CATNR=${q}&FORMAT=json`);
    provenance.push(s.prov);
    if (s.data?.[0]) top.push({ OBJECT_NAME: s.data[0].OBJECT_NAME, OBJECT_ID: s.data[0].OBJECT_ID, NORAD_CAT_ID: Number(q) });
    cat = s.data ?? [];
  }
  const objects = top.map((x) => toObject(x, cat.find((c) => Number(c.NORAD_CAT_ID) === Number(x.NORAD_CAT_ID))));
  return {
    module: 'satellites',
    input: q,
    generatedAt: ctx.now().toISOString(),
    result: { query: q, mode: 'search', objects, launches: [], total: g.data.length, note: objects.length ? 'Orbit heights are computed from the latest published orbital elements.' : 'No object with that name or number is in orbit. Decayed objects are only found by NORAD number.' },
    signals: [],
    provenance,
  };
}
