/**
 * Condor: eyes in orbit, all free and keyless.
 *   events():   open natural events from NASA EONET (storms, wildfires, volcanoes, floods...).
 *   lights():   night-time light of a place from NASA VIIRS (moonlight-corrected, gap-filled), recent vs baseline.
 *               A sharp drop can mean blackout, conflict or evacuation; a rise can mean new activity.
 *   snapshot(): true-color satellite image of a place for a date, saved as PNG.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DAY_MS, oculonHome, type Ctx } from '../core/context.js';
import { brightness, decodePng, type Brightness } from '../core/png.js';
import { clamp, median } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { sentinelImage, type SentinelKind } from '../sources/sentinel.js';
import { eonetEvents, geocode, gibsImage, NIGHT_LIGHTS, TRUE_COLOR, type EonetEvent, type Place } from '../sources/earth.js';

const isoDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/** Severity rule per category, documented so a score can always be explained. */
export function eventSeverity(e: EonetEvent): { score: number; why: string } | null {
  const m = e.magnitude;
  switch (e.category) {
    case 'severeStorms':
      if (m !== null && m >= 96) return { score: 85, why: `${m} kt winds (major hurricane strength)` };
      if (m !== null && m >= 64) return { score: 70, why: `${m} kt winds (hurricane strength)` };
      return null;
    case 'volcanoes':
      return { score: 65, why: 'active volcano' };
    case 'wildfires':
      if (m !== null && e.unit?.toLowerCase().includes('acre') && m >= 10_000) return { score: clamp(Math.round(50 + 8 * Math.log10(m / 10_000 + 1) * 10), 0, 85), why: `${Math.round(m).toLocaleString('en-US')} acres` };
      return null;
    case 'floods':
      return { score: 60, why: 'flood' };
    case 'earthquakes':
      return { score: 60, why: 'earthquake' };
    default:
      return null;
  }
}

export async function events(ctx: Ctx, days = 7): Promise<ModuleResult<{ events: (EonetEvent & { severity: number | null; why: string | null })[] }>> {
  const r = await eonetEvents(ctx, days);
  const nowIso = ctx.now().toISOString();
  const list = (r.data ?? []).map((e) => {
    const s = eventSeverity(e);
    return { ...e, severity: s?.score ?? null, why: s?.why ?? null };
  });
  list.sort((a, b) => (b.severity ?? 0) - (a.severity ?? 0) || b.date.localeCompare(a.date));
  const signals: Signal[] = list
    .filter((e) => e.severity !== null)
    .map((e) => {
      const id = ctx.graph.upsert('event', e.title, { category: e.category, lat: e.lat, lon: e.lon, eonet: e.id });
      return {
        id: signalId('condor', e.id, e.date),
        module: 'condor',
        title: `${e.title}: ${e.why}`,
        score: e.severity!,
        entity: id,
        evidence: [{ source: 'nasa-eonet', text: `${e.category} updated ${e.date.slice(0, 16)}Z${e.lat !== null ? ` at ${e.lat.toFixed(2)}, ${e.lon!.toFixed(2)}` : ''}`, url: e.url }],
        createdAt: nowIso,
      };
    });
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { module: 'condor', input: 'events', generatedAt: nowIso, result: { events: list }, signals, provenance: [r.prov] };
}

/** Keep the analysis window city-sized: big admin areas are cropped around their center, tiny ones widened. */
export function analysisBox(p: Place, maxDeg = 1.2, minDeg = 0.15): Place['bbox'] {
  let [s, n, w, e] = p.bbox;
  const fit = (lo: number, hi: number, c: number): [number, number] => {
    const span = hi - lo;
    if (span > maxDeg) return [c - maxDeg / 2, c + maxDeg / 2];
    if (span < minDeg) return [c - minDeg / 2, c + minDeg / 2];
    return [lo, hi];
  };
  [s, n] = fit(s, n, p.lat);
  [w, e] = fit(w, e, p.lon);
  return [s, n, w, e];
}

export interface DayLight extends Brightness {
  date: string;
}

export interface LightsResult {
  place: Place;
  alternatives: string[];
  bbox: Place['bbox'];
  recent: DayLight[];
  baseline: DayLight[];
  recentMedian: number | null;
  baselineMedian: number | null;
  /** recent / baseline. */
  ratio: number | null;
  verdict: 'DROP' | 'RISE' | 'STABLE' | 'INSUFFICIENT_DATA';
  latestDate: string | null;
}

/** Days with less than this share of pixels covered are treated as missing. */
const MIN_COVERAGE = 0.6;

export async function lights(ctx: Ctx, placeQuery: string, opts: { recentDays?: number; baselineDays?: number } = {}): Promise<ModuleResult<LightsResult>> {
  const provenance: Provenance[] = [];
  const nowMs = ctx.now().getTime();
  const nowIso = new Date(nowMs).toISOString();
  const recentDays = opts.recentDays ?? 5;
  const baselineDays = opts.baselineDays ?? 30;

  const g = await geocode(ctx, placeQuery);
  provenance.push(g.prov);
  const place = g.data?.[0];
  if (!place) throw new Error(`place not found: ${placeQuery} (${g.prov.status} ${g.prov.note ?? ''})`);
  const bbox = analysisBox(place);

  const measure = async (date: string): Promise<DayLight | null> => {
    const img = await gibsImage(ctx, NIGHT_LIGHTS, bbox, date);
    provenance.push(img.prov);
    if (!img.png) return null;
    try {
      const b = brightness(decodePng(img.png));
      return b.coverage >= MIN_COVERAGE ? { date, ...b } : null;
    } catch {
      return null;
    }
  };

  // The gap-filled product lags a few days; walk back from yesterday to the newest day with data.
  let latest: DayLight | null = null;
  let latestMs = nowMs - DAY_MS;
  for (let back = 1; back <= 10 && !latest; back++) {
    latestMs = nowMs - back * DAY_MS;
    latest = await measure(isoDay(latestMs));
  }

  const recent: DayLight[] = latest ? [latest] : [];
  const baseline: DayLight[] = [];
  if (latest) {
    const recentDates = Array.from({ length: recentDays - 1 }, (_, i) => isoDay(latestMs - (i + 1) * DAY_MS));
    // Baseline: every other day of the window that ends a week before the recent window.
    const baseEnd = latestMs - (recentDays + 7) * DAY_MS;
    const baseDates = Array.from({ length: Math.ceil(baselineDays / 2) }, (_, i) => isoDay(baseEnd - i * 2 * DAY_MS));
    const [r, b] = await Promise.all([Promise.all(recentDates.map(measure)), Promise.all(baseDates.map(measure))]);
    recent.push(...r.filter((x): x is DayLight => x !== null));
    baseline.push(...b.filter((x): x is DayLight => x !== null));
  }

  const recentMedian = recent.length >= 2 ? median(recent.map((d) => d.mean)) : null;
  const baselineMedian = baseline.length >= 5 ? median(baseline.map((d) => d.mean)) : null;
  const ratio = recentMedian !== null && baselineMedian ? recentMedian / baselineMedian : null;
  const verdict: LightsResult['verdict'] = ratio === null ? 'INSUFFICIENT_DATA' : ratio <= 0.75 ? 'DROP' : ratio >= 1.33 ? 'RISE' : 'STABLE';

  const id = ctx.graph.upsert('event', `lights:${place.name}`, { lat: place.lat, lon: place.lon });
  if (recentMedian !== null) ctx.graph.observe(id, 'condor', 'night_light', recentMedian, 'nasa-gibs', { ratio });

  const signals: Signal[] = [];
  if (verdict === 'DROP' || verdict === 'RISE') {
    signals.push({
      id: signalId('condor', 'lights', place.name, isoDay(latestMs)),
      module: 'condor',
      title: `Night lights ${verdict === 'DROP' ? 'down' : 'up'} ${Math.abs(Math.round((ratio! - 1) * 100))}% over ${place.name.split(',')[0]}`,
      score: clamp(Math.round(45 + 60 * Math.abs(Math.log2(ratio!))), 0, 90),
      entity: id,
      evidence: [
        { source: 'nasa-gibs', text: `VIIRS night radiance median ${recentMedian!.toFixed(1)} over ${recent.length} recent nights vs ${baselineMedian!.toFixed(1)} over ${baseline.length} baseline nights`, value: ratio! },
      ],
      createdAt: nowIso,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }

  return {
    module: 'condor',
    input: placeQuery,
    generatedAt: nowIso,
    result: {
      place,
      alternatives: (g.data ?? []).slice(1).map((p) => p.name),
      bbox,
      recent,
      baseline,
      recentMedian,
      baselineMedian,
      ratio,
      verdict,
      latestDate: latest?.date ?? null,
    },
    signals,
    provenance,
  };
}

/** Save a true-color image of a place. Defaults to yesterday (MODIS imagery appears within about a day). */
export async function snapshot(ctx: Ctx, placeQuery: string, date?: string, dir = join(oculonHome(), 'condor')): Promise<ModuleResult<{ place: Place; date: string; file: string | null; url: string }>> {
  const g = await geocode(ctx, placeQuery);
  const place = g.data?.[0];
  if (!place) throw new Error(`place not found: ${placeQuery}`);
  const day = date ?? isoDay(ctx.now().getTime() - DAY_MS);
  const img = await gibsImage(ctx, TRUE_COLOR, analysisBox(place), day, 768);
  let file: string | null = null;
  if (img.png) {
    mkdirSync(dir, { recursive: true });
    file = join(dir, `${placeQuery.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${day}.png`);
    writeFileSync(file, img.png);
  }
  return { module: 'condor', input: placeQuery, generatedAt: ctx.now().toISOString(), result: { place, date: day, file, url: img.prov.url }, signals: [], provenance: [g.prov, img.prov] };
}

export interface SentinelShot {
  place: Place;
  kind: SentinelKind;
  /** Window searched; the least cloudy (optical) or newest (radar) pass inside it is used. */
  from: string;
  to: string;
  file: string | null;
}

/**
 * High-resolution satellite view (Copernicus Sentinel-2 at 10 m, or Sentinel-1 radar through clouds).
 * With `compareTo`, a second image of the same box ending on that date is saved for a before/after view.
 */
export async function sentinel(
  ctx: Ctx,
  placeQuery: string,
  opts: { date?: string; days?: number; kind?: SentinelKind; compareTo?: string; dir?: string } = {},
): Promise<ModuleResult<{ shots: SentinelShot[] }>> {
  const g = await geocode(ctx, placeQuery);
  const place = g.data?.[0];
  if (!place) throw new Error(`place not found: ${placeQuery}`);
  const kind = opts.kind ?? 'optical';
  const days = opts.days ?? (kind === 'radar' ? 12 : 20);
  // About 10-50 km across: sharp at 10 m per pixel without huge requests.
  const box = analysisBox(place, 0.45, 0.08);
  const dir = opts.dir ?? join(oculonHome(), 'condor');
  const provenance: Provenance[] = [g.prov];
  const shots: SentinelShot[] = [];
  const ends = [opts.date ? new Date(`${opts.date}T23:59:59Z`) : ctx.now(), ...(opts.compareTo ? [new Date(`${opts.compareTo}T23:59:59Z`)] : [])];
  for (const end of ends) {
    const from = new Date(end.getTime() - days * DAY_MS);
    const img = await sentinelImage(ctx, box, from, end, kind);
    provenance.push(img.prov);
    let file: string | null = null;
    if (img.png) {
      mkdirSync(dir, { recursive: true });
      file = join(dir, `${placeQuery.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${kind === 'radar' ? 's1' : 's2'}-${end.toISOString().slice(0, 10)}.png`);
      writeFileSync(file, img.png);
    }
    shots.push({ place, kind, from: from.toISOString().slice(0, 10), to: end.toISOString().slice(0, 10), file });
  }
  return { module: 'condor', input: placeQuery, generatedAt: ctx.now().toISOString(), result: { shots }, signals: [], provenance };
}
