/** Space weather (NOAA SWPC, keyless; NASA DONKI and NeoWs, NASA_API_KEY or DEMO_KEY) and air quality (OpenAQ). */
import type { Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Provenance, Sourced } from '../core/types.js';

export interface KpReading {
  time: string;
  kp: number;
}

export async function kpIndex(ctx: Ctx): Promise<Sourced<KpReading[]>> {
  const r = await ctx.http.get<unknown>('https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json', { source: 'noaa-swpc', ttlSec: 900 });
  // The product has been published both as row arrays (header first) and as objects; accept either.
  const rows = Array.isArray(r.data) ? r.data : [];
  const data = rows
    .map((x) => (Array.isArray(x) ? { time: String(x[0]), kp: Number(x[1]) } : { time: String((x as { time_tag: string }).time_tag), kp: Number((x as { Kp: number }).Kp) }))
    .filter((x) => Number.isFinite(x.kp));
  return { data: r.data ? data : null, prov: r.prov };
}

export interface Flare {
  maxClass: string;
  maxTime: string;
  beginTime: string;
}

export async function xrayFlares(ctx: Ctx): Promise<Sourced<Flare[]>> {
  const r = await ctx.http.get<{ max_class?: string; max_time?: string; begin_time?: string }[]>('https://services.swpc.noaa.gov/json/goes/primary/xray-flares-7-day.json', {
    source: 'noaa-swpc',
    ttlSec: 900,
  });
  return { data: r.data?.filter((f) => f.max_class).map((f) => ({ maxClass: f.max_class!, maxTime: f.max_time ?? '', beginTime: f.begin_time ?? '' })) ?? null, prov: r.prov };
}

/** Flare class to a sortable magnitude: A1=1e-8 ... X1=1e-4 (W/m^2). */
export function flareFlux(cls: string): number {
  const m = /^([ABCMX])(\d+(?:\.\d+)?)/.exec(cls.trim().toUpperCase());
  if (!m) return 0;
  const base = { A: 1e-8, B: 1e-7, C: 1e-6, M: 1e-5, X: 1e-4 }[m[1] as 'A' | 'B' | 'C' | 'M' | 'X'];
  return base * Number(m[2]);
}

// ---------------------------------------------------------------------------------------------------------------
// NOAA SWPC official products: alerts/warnings/watches, solar wind now, NOAA scales and the 3-day forecast.

export interface SwpcAlert {
  productId: string;
  /** SWPC message code, e.g. ALTK05 (alert, K-index 5), WARK04 (warning), WATA50 (watch), ALTXMF (X-ray M5). */
  code: string;
  kind: 'ALERT' | 'WARNING' | 'WATCH' | 'SUMMARY' | 'CANCEL' | 'OTHER';
  issued: string;
  title: string;
  /** NOAA scale named in the message, e.g. G1, R2, S1. */
  scale: string | null;
  message: string;
}

/** Parse one SWPC alerts.json message body into a typed record. */
export function parseSwpcAlert(x: { product_id?: string; issue_datetime?: string; message?: string }): SwpcAlert {
  const msg = (x.message ?? '').replace(/\r/g, '');
  const code = /Space Weather Message Code:\s*(\S+)/.exec(msg)?.[1] ?? x.product_id ?? '';
  const head = /^(EXTENDED WARNING|WARNING|ALERT|CONTINUED ALERT|WATCH|SUMMARY|CANCEL[A-Z ]*?)\s*:\s*(.+)$/m.exec(msg);
  const label = head?.[1] ?? '';
  const kind: SwpcAlert['kind'] = /WARNING/.test(label) ? 'WARNING' : /ALERT/.test(label) ? 'ALERT' : /WATCH/.test(label) ? 'WATCH' : /SUMMARY/.test(label) ? 'SUMMARY' : /CANCEL/.test(label) ? 'CANCEL' : 'OTHER';
  const scale = /NOAA Scale:\s*([GRS][1-5])/i.exec(msg)?.[1]?.toUpperCase() ?? null;
  const issuedRaw = (x.issue_datetime ?? '').trim();
  const issued = issuedRaw ? `${issuedRaw.replace(' ', 'T').replace(/\.\d+$/, '')}Z` : '';
  return { productId: x.product_id ?? '', code, kind, issued, title: head ? `${label}: ${head[2]!.trim()}` : msg.split('\n').find((l) => l.trim() && !/^(Space Weather Message Code|Serial Number|Issue Time)/.test(l))?.trim() ?? code, scale, message: msg.trim() };
}

/** SWPC alerts, warnings, watches and summaries issued in the last ~30 days, newest first. */
export async function swpcAlerts(ctx: Ctx): Promise<Sourced<SwpcAlert[]>> {
  const r = await ctx.http.get<{ product_id?: string; issue_datetime?: string; message?: string }[]>('https://services.swpc.noaa.gov/products/alerts.json', { source: 'noaa-swpc', ttlSec: 600 });
  return { data: Array.isArray(r.data) ? r.data.map(parseSwpcAlert).sort((a, b) => b.issued.localeCompare(a.issued)) : null, prov: r.prov };
}

export interface SolarWind {
  time: string | null;
  speedKmS: number | null;
  /** Total interplanetary magnetic field, nT. */
  bt: number | null;
  /** North-south component (GSM), nT. Strongly negative Bz drives geomagnetic storms. */
  bz: number | null;
}

/** Latest solar wind speed and magnetic field at L1 (SWPC summary products). */
export async function solarWind(ctx: Ctx): Promise<{ data: SolarWind | null; prov: Provenance[] }> {
  const [sp, mag] = await Promise.all([
    ctx.http.get<{ proton_speed?: number; time_tag?: string }[]>('https://services.swpc.noaa.gov/products/summary/solar-wind-speed.json', { source: 'noaa-swpc', ttlSec: 300 }),
    ctx.http.get<{ bt?: number; bz_gsm?: number; time_tag?: string }[]>('https://services.swpc.noaa.gov/products/summary/solar-wind-mag-field.json', { source: 'noaa-swpc', ttlSec: 300 }),
  ]);
  const s = Array.isArray(sp.data) ? sp.data[0] : undefined;
  const m = Array.isArray(mag.data) ? mag.data[0] : undefined;
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' && v.trim() && Number.isFinite(Number(v)) ? Number(v) : null);
  const data = s || m ? { time: s?.time_tag ?? m?.time_tag ?? null, speedKmS: num(s?.proton_speed), bt: num(m?.bt), bz: num(m?.bz_gsm) } : null;
  return { data, prov: [sp.prov, mag.prov] };
}

export interface NoaaScales {
  /** Current R (radio blackout), S (radiation storm), G (geomagnetic storm) levels, 0-5. */
  now: { r: number; s: number; g: number };
  /** Next days: probability (%) of R1-R2 / R3+ blackouts and S1+ storms, plus the forecast G level. */
  days: { date: string; rMinorProb: number | null; rMajorProb: number | null; sProb: number | null; g: number }[];
}

export async function noaaScales(ctx: Ctx): Promise<Sourced<NoaaScales>> {
  type Day = { DateStamp?: string; R?: { Scale?: string | null; MinorProb?: string | null; MajorProb?: string | null }; S?: { Scale?: string | null; Prob?: string | null }; G?: { Scale?: string | null } };
  const r = await ctx.http.get<Record<string, Day>>('https://services.swpc.noaa.gov/products/noaa-scales.json', { source: 'noaa-swpc', ttlSec: 900 });
  if (!r.data || typeof r.data !== 'object') return { data: null, prov: r.prov };
  const n = (v: string | null | undefined) => (v === null || v === undefined || v === '' ? null : Number(v));
  const cur = r.data['0'];
  const days = ['1', '2', '3'].map((k) => r.data![k]).filter((d): d is Day => Boolean(d));
  return {
    data: {
      now: { r: n(cur?.R?.Scale) ?? 0, s: n(cur?.S?.Scale) ?? 0, g: n(cur?.G?.Scale) ?? 0 },
      days: days.map((d) => ({ date: d.DateStamp ?? '', rMinorProb: n(d.R?.MinorProb), rMajorProb: n(d.R?.MajorProb), sProb: n(d.S?.Prob), g: n(d.G?.Scale) ?? 0 })),
    },
    prov: r.prov,
  };
}

export interface Forecast3Day {
  issued: string | null;
  observedKpMax24h: number | null;
  expectedKpMax: number | null;
  /** Highest forecast Kp per day, e.g. { 'Nov 19': 5 }. */
  kpByDay: Record<string, number>;
  rationale: string | null;
}

/** Parse SWPC's plain-text 3-day forecast. */
export function parseForecast3Day(txt: string): Forecast3Day {
  const issued = /:Issued:\s*(.+)/.exec(txt)?.[1]?.trim() ?? null;
  const observed = /greatest observed 3 hr Kp over the past 24 hours was\s+([\d.]+)/i.exec(txt.replace(/\s+/g, ' '));
  const expected = /greatest expected 3 hr Kp for .+? is\s+([\d.]+)/i.exec(txt.replace(/\s+/g, ' '));
  const kpByDay: Record<string, number> = {};
  const block = /NOAA Kp index breakdown[^\n]*\n\s*\n?([^\n]+)\n((?:\s*\d\d-\d\dUT[^\n]*\n?)+)/.exec(txt);
  if (block) {
    const days = block[1]!.trim().split(/\s{2,}/);
    for (const row of block[2]!.trim().split('\n')) {
      const vals = row.replace(/\(G\d\)/g, '').trim().split(/\s+/).slice(1).map(Number);
      vals.forEach((v, i) => {
        const d = days[i];
        if (d && Number.isFinite(v)) kpByDay[d] = Math.max(kpByDay[d] ?? 0, v);
      });
    }
  }
  const rationale = /A\. NOAA Geomagnetic[\s\S]*?Rationale:\s*([\s\S]+?)\n\s*\n/.exec(txt)?.[1]?.replace(/\s+/g, ' ').trim() ?? null;
  return { issued, observedKpMax24h: observed ? Number(observed[1]) : null, expectedKpMax: expected ? Number(expected[1]) : null, kpByDay, rationale };
}

export async function forecast3Day(ctx: Ctx): Promise<Sourced<Forecast3Day>> {
  const r = await ctx.http.get<string>('https://services.swpc.noaa.gov/text/3-day-forecast.txt', { source: 'noaa-swpc', as: 'text', ttlSec: 1800 });
  return { data: r.data && r.data.includes('3-Day Forecast') ? parseForecast3Day(r.data) : null, prov: r.prov };
}

// ---------------------------------------------------------------------------------------------------------------
// NASA DONKI (space weather database) and NeoWs (near-Earth objects). NASA_API_KEY, falling back to DEMO_KEY
// (30 requests/hour, 50/day per IP).

const nasaKey = () => key('NASA_API_KEY') ?? 'DEMO_KEY';
const day = (d: Date) => d.toISOString().slice(0, 10);

export interface DonkiCme {
  id: string;
  start: string;
  speedKmS: number | null;
  halfAngle: number | null;
  type: string | null;
  /** WSA-ENLIL model predicts the shock reaching Earth (shock arrival time), or a glancing blow. */
  earthArrival: string | null;
  earthGlancing: boolean;
  /** Model Kp range for the arrival (kp_90 .. kp_180), when the run gives one. */
  kpPredicted: number | null;
  note: string;
  url: string;
}

interface DonkiCmeRaw {
  activityID?: string;
  startTime?: string;
  note?: string;
  link?: string;
  cmeAnalyses?: { isMostAccurate?: boolean; speed?: number; halfAngle?: number; type?: string; enlilList?: { estimatedShockArrivalTime?: string | null; isEarthGB?: boolean; isEarthMinorImpact?: boolean; kp_90?: number | null; kp_135?: number | null; kp_180?: number | null }[] | null }[] | null;
}

export function parseDonkiCme(c: DonkiCmeRaw): DonkiCme {
  const analyses = c.cmeAnalyses ?? [];
  const best = analyses.find((a) => a.isMostAccurate) ?? analyses[0];
  const runs = analyses.flatMap((a) => a.enlilList ?? []);
  const hit = runs.filter((e) => e.estimatedShockArrivalTime).sort((a, b) => (a.estimatedShockArrivalTime ?? '').localeCompare(b.estimatedShockArrivalTime ?? ''));
  const kps = runs.flatMap((e) => [e.kp_90, e.kp_135, e.kp_180]).filter((k): k is number => typeof k === 'number');
  return {
    id: c.activityID ?? '',
    start: c.startTime ?? '',
    speedKmS: best?.speed ?? null,
    halfAngle: best?.halfAngle ?? null,
    type: best?.type ?? null,
    earthArrival: hit[0]?.estimatedShockArrivalTime ?? null,
    earthGlancing: runs.some((e) => e.isEarthGB || e.isEarthMinorImpact),
    kpPredicted: kps.length ? Math.max(...kps) : null,
    note: (c.note ?? '').slice(0, 300),
    url: c.link ?? 'https://kauai.ccmc.gsfc.nasa.gov/DONKI/',
  };
}

/** Coronal mass ejections in the last `days`, with WSA-ENLIL Earth-arrival predictions. */
export async function donkiCmes(ctx: Ctx, days = 7): Promise<Sourced<DonkiCme[]>> {
  const end = ctx.now();
  const start = new Date(end.getTime() - days * 86_400_000);
  const r = await ctx.http.get<DonkiCmeRaw[]>(`https://api.nasa.gov/DONKI/CME?startDate=${day(start)}&endDate=${day(end)}&api_key=${nasaKey()}`, { source: 'nasa-donki', ttlSec: 3 * 3600, timeoutMs: 45_000 });
  return { data: Array.isArray(r.data) ? r.data.map(parseDonkiCme) : null, prov: r.prov };
}

export interface DonkiStorm {
  id: string;
  start: string;
  kpMax: number;
  url: string;
}

/** Geomagnetic storms (Kp >= 5) logged by DONKI in the last `days`. */
export async function donkiStorms(ctx: Ctx, days = 30): Promise<Sourced<DonkiStorm[]>> {
  const end = ctx.now();
  const start = new Date(end.getTime() - days * 86_400_000);
  const r = await ctx.http.get<{ gstID?: string; startTime?: string; link?: string; allKpIndex?: { kpIndex?: number }[] }[]>(`https://api.nasa.gov/DONKI/GST?startDate=${day(start)}&endDate=${day(end)}&api_key=${nasaKey()}`, {
    source: 'nasa-donki',
    ttlSec: 3 * 3600,
    timeoutMs: 45_000,
  });
  return {
    data: Array.isArray(r.data) ? r.data.map((g) => ({ id: g.gstID ?? '', start: g.startTime ?? '', kpMax: Math.max(0, ...(g.allKpIndex ?? []).map((k) => k.kpIndex ?? 0)), url: g.link ?? '' })) : null,
    prov: r.prov,
  };
}

export interface DonkiNotification {
  type: string;
  id: string;
  issued: string;
  title: string;
  summary: string;
  url: string;
}

/** NASA M2M space weather notifications (CME, flare, SEP, IPS, radiation belt...) in the last `days`. */
export async function donkiNotifications(ctx: Ctx, days = 7): Promise<Sourced<DonkiNotification[]>> {
  const end = ctx.now();
  const start = new Date(end.getTime() - days * 86_400_000);
  const r = await ctx.http.get<{ messageType?: string; messageID?: string; messageURL?: string; messageIssueTime?: string; messageBody?: string }[]>(
    `https://api.nasa.gov/DONKI/notifications?startDate=${day(start)}&endDate=${day(end)}&type=all&api_key=${nasaKey()}`,
    { source: 'nasa-donki', ttlSec: 3 * 3600, timeoutMs: 45_000 },
  );
  return {
    data: Array.isArray(r.data)
      ? r.data
          .map((n) => {
            const body = (n.messageBody ?? '').replace(/\r/g, '');
            return {
              type: n.messageType ?? '',
              id: n.messageID ?? '',
              issued: n.messageIssueTime ?? '',
              title: /## Message Type:\s*(.+)/.exec(body)?.[1]?.trim() ?? n.messageType ?? '',
              summary: (/## Summary:\s*([\s\S]+?)(?:\n## |$)/.exec(body)?.[1] ?? '').replace(/\s+/g, ' ').trim().slice(0, 400),
              url: n.messageURL ?? '',
            };
          })
          .sort((a, b) => b.issued.localeCompare(a.issued))
      : null,
    prov: r.prov,
  };
}

export interface CloseApproach {
  id: string;
  name: string;
  time: string;
  missLunar: number;
  missKm: number;
  velocityKmS: number;
  diameterM: { min: number; max: number };
  hazardous: boolean;
  url: string;
}

/** Near-Earth object close approaches from today over the next `days` (max 7), closest first. */
export async function closeApproaches(ctx: Ctx, days = 3): Promise<Sourced<CloseApproach[]>> {
  const start = ctx.now();
  const end = new Date(start.getTime() + Math.max(0, Math.min(7, days) - 1) * 86_400_000);
  type Neo = {
    id?: string;
    name?: string;
    nasa_jpl_url?: string;
    is_potentially_hazardous_asteroid?: boolean;
    estimated_diameter?: { meters?: { estimated_diameter_min?: number; estimated_diameter_max?: number } };
    close_approach_data?: { close_approach_date_full?: string; close_approach_date?: string; miss_distance?: { lunar?: string; kilometers?: string }; relative_velocity?: { kilometers_per_second?: string }; orbiting_body?: string }[];
  };
  const r = await ctx.http.get<{ near_earth_objects?: Record<string, Neo[]> }>(`https://api.nasa.gov/neo/rest/v1/feed?start_date=${day(start)}&end_date=${day(end)}&api_key=${nasaKey()}`, { source: 'nasa-neows', ttlSec: 6 * 3600, timeoutMs: 45_000 });
  if (!r.data?.near_earth_objects) return { data: null, prov: r.prov };
  const out: CloseApproach[] = [];
  for (const neo of Object.values(r.data.near_earth_objects).flat()) {
    const ca = neo.close_approach_data?.find((c) => (c.orbiting_body ?? 'Earth') === 'Earth');
    if (!ca) continue;
    out.push({
      id: neo.id ?? '',
      name: (neo.name ?? '').replace(/[()]/g, '').trim(),
      time: ca.close_approach_date_full ?? ca.close_approach_date ?? '',
      missLunar: Number(ca.miss_distance?.lunar ?? NaN),
      missKm: Math.round(Number(ca.miss_distance?.kilometers ?? NaN)),
      velocityKmS: Math.round(Number(ca.relative_velocity?.kilometers_per_second ?? NaN) * 10) / 10,
      diameterM: { min: Math.round(neo.estimated_diameter?.meters?.estimated_diameter_min ?? 0), max: Math.round(neo.estimated_diameter?.meters?.estimated_diameter_max ?? 0) },
      hazardous: neo.is_potentially_hazardous_asteroid === true,
      url: neo.nasa_jpl_url ?? `https://ssd.jpl.nasa.gov/tools/sbdb_lookup.html#/?sstr=${neo.id ?? ''}`,
    });
  }
  return { data: out.filter((x) => Number.isFinite(x.missLunar)).sort((a, b) => a.missLunar - b.missLunar), prov: r.prov };
}

export interface AirStation {
  name: string;
  distanceKm: number;
  parameter: string;
  value: number;
  unit: string;
  time: string;
}

/** Latest fine-particle (PM2.5) readings near a point, only stations that reported in the last 3 days. */
export async function airQuality(ctx: Ctx, lat: number, lon: number): Promise<Sourced<AirStation[]>> {
  const k = key('OPENAQ_API_KEY');
  if (!k) return noKey('openaq', 'OPENAQ_API_KEY');
  const headers = { 'x-api-key': k };
  const locs = await ctx.http.get<{ results?: { id: number; name: string; distance?: number; datetimeLast?: { utc?: string }; sensors?: { id: number; parameter?: { name?: string; units?: string } }[] }[] }>(
    `https://api.openaq.org/v3/locations?coordinates=${lat.toFixed(4)},${lon.toFixed(4)}&radius=25000&limit=50&parameters_id=2`,
    { source: 'openaq', ttlSec: 3600, headers },
  );
  if (!locs.data?.results) return { data: null, prov: locs.prov };
  const cutoff = ctx.now().getTime() - 3 * 86_400_000;
  // A station can be "active" through other sensors while its PM2.5 sensor died years ago,
  // so freshness is checked on each reading, not on the station.
  const candidates = locs.data.results.filter((l) => l.datetimeLast?.utc && Date.parse(l.datetimeLast.utc) > cutoff).slice(0, 8);
  const readings = await Promise.all(
    candidates.map(async (l) => {
      const sensor = l.sensors?.find((s) => s.parameter?.name === 'pm25');
      if (!sensor) return null;
      const latest = await ctx.http.get<{ results?: { value: number; sensorsId?: number; datetime?: { utc?: string } }[] }>(`https://api.openaq.org/v3/locations/${l.id}/latest`, { source: 'openaq', ttlSec: 1800, headers });
      // /latest returns every sensor at the station; take the PM2.5 one only. An exact 0 is a sensor fault.
      const v = latest.data?.results?.find((x) => x.sensorsId === sensor.id && x.value !== undefined && x.value > 0);
      const t = v?.datetime?.utc;
      if (!v || !t || Date.parse(t) < cutoff) return null;
      return { name: l.name, distanceKm: Math.round((l.distance ?? 0) / 100) / 10, parameter: 'pm25', value: v.value, unit: sensor.parameter?.units ?? 'µg/m³', time: t };
    }),
  );
  return { data: readings.filter((x): x is AirStation => x !== null), prov: locs.prov };
}

/** US EPA PM2.5 category (2024 breakpoints). */
export function pm25Category(v: number): string {
  if (v <= 9) return 'good';
  if (v <= 35.4) return 'moderate';
  if (v <= 55.4) return 'unhealthy for sensitive groups';
  if (v <= 125.4) return 'unhealthy';
  if (v <= 225.4) return 'very unhealthy';
  return 'hazardous';
}
