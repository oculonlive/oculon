/**
 * Condor extensions: space weather (NOAA SWPC) and air quality near a place (OpenAQ).
 * Kept separate from condor.ts so each stays readable; exported through the same CLI and SDK surface.
 */
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { geocode, type Place } from '../sources/earth.js';
import {
  airQuality,
  closeApproaches,
  donkiCmes,
  donkiNotifications,
  donkiStorms,
  flareFlux,
  forecast3Day,
  kpIndex,
  noaaScales,
  pm25Category,
  solarWind,
  swpcAlerts,
  xrayFlares,
  type AirStation,
  type CloseApproach,
  type DonkiCme,
  type DonkiNotification,
  type DonkiStorm,
  type Flare,
  type Forecast3Day,
  type KpReading,
  type NoaaScales,
  type SolarWind,
  type SwpcAlert,
} from '../sources/space.js';

export interface SpaceWeather {
  kpNow: number | null;
  kpMax24h: number | null;
  stormLevel: string;
  strongestFlare: Flare | null;
  flares7d: number;
  kp: KpReading[];
  /** SWPC alerts, warnings and watches issued within the window (summaries and cancellations left out). */
  alerts?: SwpcAlert[];
  solarWind?: SolarWind | null;
  scales?: NoaaScales | null;
  forecast?: Forecast3Day | null;
  /** NASA DONKI CMEs in the window; `earthArrival` set when the ENLIL model has the shock reaching Earth. */
  cmes?: DonkiCme[];
  storms?: DonkiStorm[];
  notifications?: DonkiNotification[];
  /** Near-Earth objects passing in the next 3 days, closest first (top 10). */
  neo?: CloseApproach[];
}

/** NOAA G-scale from Kp. */
export function gScale(kp: number): string {
  if (kp >= 9) return 'G5 extreme storm';
  if (kp >= 8) return 'G4 severe storm';
  if (kp >= 7) return 'G3 strong storm';
  if (kp >= 6) return 'G2 moderate storm';
  if (kp >= 5) return 'G1 minor storm';
  return 'quiet';
}

const SCALE_LABEL: Record<string, string> = { G: 'geomagnetic storm', R: 'radio blackout', S: 'solar radiation storm' };

/**
 * Space weather now: Kp and GOES flares (as before) plus SWPC alerts/warnings/watches, solar wind at L1, NOAA scales,
 * the 3-day forecast, NASA DONKI CMEs (with Earth-arrival predictions), storms and notifications, and near-Earth
 * object close approaches. `days` is the look-back window for alerts and DONKI (default 7, max 30).
 * `opts.nasa: false` skips the NASA calls (DONKI, NeoWs).
 */
export async function spaceWeather(ctx: Ctx, days = 7, opts: { nasa?: boolean } = {}): Promise<ModuleResult<SpaceWeather>> {
  const win = Math.max(1, Math.min(30, Math.round(days) || 7));
  const nasa = opts.nasa !== false;
  const none = <T,>() => Promise.resolve<{ data: T | null; prov: Provenance | null }>({ data: null, prov: null });
  const [kp, fl, al, sw, sc, fc, cm, gs, nt, neo] = await Promise.all([
    kpIndex(ctx),
    xrayFlares(ctx),
    swpcAlerts(ctx),
    solarWind(ctx),
    noaaScales(ctx),
    forecast3Day(ctx),
    nasa ? donkiCmes(ctx, win) : none<DonkiCme[]>(),
    nasa ? donkiStorms(ctx, win) : none<DonkiStorm[]>(),
    nasa ? donkiNotifications(ctx, win) : none<DonkiNotification[]>(),
    nasa ? closeApproaches(ctx, 3) : none<CloseApproach[]>(),
  ]);
  const nowIso = ctx.now().toISOString();
  const nowMs = ctx.now().getTime();
  const recent = (kp.data ?? []).filter((r) => Date.parse(`${r.time.replace(' ', 'T')}Z`.replace('ZZ', 'Z')) > ctx.now().getTime() - 86_400_000);
  const kpNow = kp.data?.length ? kp.data[kp.data.length - 1]!.kp : null;
  const kpMax24h = recent.length ? Math.max(...recent.map((r) => r.kp)) : kpNow;
  const strongest = (fl.data ?? []).reduce<Flare | null>((best, f) => (!best || flareFlux(f.maxClass) > flareFlux(best.maxClass) ? f : best), null);

  const signals: Signal[] = [];
  if (kpMax24h !== null && kpMax24h >= 5) {
    signals.push({
      id: signalId('condor', 'kp', nowIso.slice(0, 13)),
      module: 'condor',
      title: `Geomagnetic ${gScale(kpMax24h)} (Kp ${kpMax24h.toFixed(1)})`,
      score: clamp(Math.round(40 + (kpMax24h - 5) * 12), 0, 95),
      evidence: [{ source: 'noaa-swpc', text: `max Kp ${kpMax24h.toFixed(2)} in 24h; can disturb GPS, HF radio and power grids, aurora at lower latitudes`, url: 'https://www.swpc.noaa.gov/products/planetary-k-index' }],
      createdAt: nowIso,
    });
  }
  if (strongest && flareFlux(strongest.maxClass) >= 1e-5) {
    signals.push({
      id: signalId('condor', 'flare', strongest.maxTime),
      module: 'condor',
      title: `Solar flare ${strongest.maxClass} peaked ${strongest.maxTime.slice(0, 16)}Z`,
      score: flareFlux(strongest.maxClass) >= 1e-4 ? 80 : 55,
      evidence: [{ source: 'noaa-swpc', text: `GOES X-ray flare ${strongest.maxClass}; X-class flares can cause radio blackouts on the sunlit side of Earth`, url: 'https://www.swpc.noaa.gov/products/goes-x-ray-flux' }],
      createdAt: nowIso,
    });
  }

  // SWPC official products issued in the last 24 h that name a NOAA scale of level 2 or more (level 1 is routine).
  const alerts = (al.data ?? []).filter((a) => a.kind !== 'SUMMARY' && a.kind !== 'CANCEL' && a.kind !== 'OTHER' && Date.parse(a.issued) > nowMs - win * 86_400_000);
  const strongAlerts = alerts.filter((a) => a.scale && Number(a.scale.slice(1)) >= 2 && Date.parse(a.issued) > nowMs - 86_400_000);
  const bestByScale = new Map<string, SwpcAlert>();
  for (const a of strongAlerts) {
    const k = `${a.kind}:${a.scale![0]}`;
    const cur = bestByScale.get(k);
    if (!cur || Number(a.scale!.slice(1)) > Number(cur.scale!.slice(1))) bestByScale.set(k, a);
  }
  for (const a of bestByScale.values()) {
    const level = Number(a.scale!.slice(1));
    signals.push({
      id: signalId('condor', 'swpc', a.code, a.issued.slice(0, 13)),
      module: 'condor',
      title: `NOAA SWPC ${a.kind.toLowerCase()}: ${a.scale} ${SCALE_LABEL[a.scale![0]!] ?? ''} (${a.title.replace(/^[A-Z ]+:\s*/, '')})`.replace(/\s+/g, ' '),
      score: clamp(35 + level * 10 + (a.kind === 'ALERT' ? 5 : 0), 0, 90),
      evidence: [{ source: 'noaa-swpc', text: `${a.code} issued ${a.issued.slice(0, 16)}Z: ${a.title}`, url: 'https://www.swpc.noaa.gov/products/alerts-watches-and-warnings' }],
      createdAt: nowIso,
    });
  }

  // G3+ forecast for the next three days.
  const fcd = fc.data;
  if (fcd?.expectedKpMax !== null && fcd?.expectedKpMax !== undefined && fcd.expectedKpMax >= 7) {
    signals.push({
      id: signalId('condor', 'forecast', fcd.issued ?? nowIso.slice(0, 10)),
      module: 'condor',
      title: `NOAA forecasts ${gScale(fcd.expectedKpMax)} in the next 3 days (Kp ${fcd.expectedKpMax.toFixed(2)})`,
      score: clamp(Math.round(50 + (fcd.expectedKpMax - 7) * 10), 0, 85),
      evidence: [{ source: 'noaa-swpc', text: fcd.rationale ?? `expected max Kp ${fcd.expectedKpMax}`, url: 'https://services.swpc.noaa.gov/text/3-day-forecast.txt' }],
      createdAt: nowIso,
    });
  }

  // Earth-directed CMEs: the ENLIL model has the shock arriving within the next 5 days (or the last 12 h).
  const earthCmes = (cm.data ?? []).filter((c) => c.earthArrival && Date.parse(c.earthArrival) > nowMs - 12 * 3600_000 && Date.parse(c.earthArrival) < nowMs + 5 * 86_400_000);
  for (const c of earthCmes) {
    const kpP = c.kpPredicted;
    signals.push({
      id: signalId('condor', 'cme', c.id),
      module: 'condor',
      title: `Earth-directed CME ${c.id}: shock arrival ${c.earthArrival!.slice(0, 16).replace('T', ' ')} UTC${kpP !== null ? `, model Kp up to ${kpP}` : ''}`,
      score: clamp(45 + (kpP !== null && kpP >= 7 ? 25 : kpP !== null && kpP >= 5 ? 10 : 0) + ((c.speedKmS ?? 0) >= 1000 ? 5 : 0), 0, 85),
      evidence: [{ source: 'nasa-donki', text: `CME start ${c.start}, ${c.speedKmS ?? '?'} km/s, half-angle ${c.halfAngle ?? '?'} deg${c.earthGlancing ? ', glancing blow possible' : ''}`, url: c.url }],
      createdAt: nowIso,
    });
  }

  // Potentially hazardous asteroids inside one lunar distance, or anything sizeable inside 0.1 LD.
  const neoList = neo.data ?? [];
  for (const o of neoList.filter((x) => (x.hazardous && x.missLunar <= 1) || (x.missLunar <= 0.1 && x.diameterM.max >= 20))) {
    signals.push({
      id: signalId('condor', 'neo', o.id, o.time.slice(0, 11)),
      module: 'condor',
      title: `Asteroid ${o.name} passes ${o.missLunar.toFixed(2)} lunar distances from Earth on ${o.time}`,
      score: o.hazardous ? 60 : 45,
      evidence: [{ source: 'nasa-neows', text: `${o.missKm.toLocaleString('en-US')} km at ${o.velocityKmS} km/s, est. ${o.diameterM.min}-${o.diameterM.max} m${o.hazardous ? ', flagged potentially hazardous' : ''}`, url: o.url }],
      createdAt: nowIso,
    });
  }

  signals.forEach((s) => ctx.graph.saveSignal(s));
  const provenance: Provenance[] = [kp.prov, fl.prov, al.prov, ...sw.prov, sc.prov, fc.prov];
  for (const p of [cm.prov, gs.prov, nt.prov, neo.prov]) if (p) provenance.push(p);
  return {
    module: 'condor',
    input: 'space',
    generatedAt: nowIso,
    result: {
      kpNow,
      kpMax24h,
      stormLevel: kpMax24h === null ? 'unknown' : gScale(kpMax24h),
      strongestFlare: strongest,
      flares7d: fl.data?.length ?? 0,
      kp: (kp.data ?? []).slice(-24),
      alerts: alerts.slice(0, 20).map((a) => ({ ...a, message: a.message.slice(0, 600) })),
      solarWind: sw.data,
      scales: sc.data,
      forecast: fcd,
      cmes: cm.data ?? [],
      storms: gs.data ?? [],
      notifications: (nt.data ?? []).slice(0, 15),
      neo: neoList.slice(0, 10),
    },
    signals,
    provenance,
  };
}

export interface AirResult {
  place: Place;
  stations: (AirStation & { category: string })[];
  median: number | null;
  category: string | null;
}

export async function air(ctx: Ctx, placeQuery: string): Promise<ModuleResult<AirResult>> {
  const provenance: Provenance[] = [];
  const g = await geocode(ctx, placeQuery);
  provenance.push(g.prov);
  const place = g.data?.[0];
  if (!place) throw new Error(`place not found: ${placeQuery}`);
  const aq = await airQuality(ctx, place.lat, place.lon);
  provenance.push(aq.prov);
  const stations = (aq.data ?? []).map((s) => ({ ...s, category: pm25Category(s.value) }));
  const vals = stations.map((s) => s.value).sort((a, b) => a - b);
  const median = vals.length ? vals[Math.floor(vals.length / 2)]! : null;
  const category = median === null ? null : pm25Category(median);
  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = [];
  if (median !== null && median > 55.4) {
    signals.push({
      id: signalId('condor', 'air', place.name, nowIso.slice(0, 13)),
      module: 'condor',
      title: `Air quality ${category} in ${place.name.split(',')[0]} (PM2.5 ${median.toFixed(0)} µg/m³)`,
      score: clamp(Math.round(45 + (median - 55) / 5), 0, 90),
      evidence: stations.slice(0, 4).map((s) => ({ source: 'openaq', text: `${s.name}: ${s.value} ${s.unit} at ${s.time.slice(0, 16)}Z` })),
      createdAt: nowIso,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }
  return { module: 'condor', input: placeQuery, generatedAt: nowIso, result: { place, stations, median, category }, signals, provenance };
}
