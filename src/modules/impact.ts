/**
 * Disaster impact: for strong earthquakes and severe storms, who lives in the affected radius (Wikidata
 * settlements with population) and, when enough nights have passed, whether night lights dropped
 * (VIIRS, via Condor). Population figures are an approximate exposure estimate, not a casualty estimate.
 */
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { eonetEvents } from '../sources/earth.js';
import { recentQuakes } from '../sources/usgs.js';
import { settlementsNear, type Settlement } from '../sources/wikidata.js';
import { eventSeverity, lights } from './condor.js';

export interface Impact {
  event: string;
  kind: 'earthquake' | 'storm' | 'place';
  lat: number;
  lon: number;
  radiusKm: number;
  when: string;
  settlements: Settlement[];
  /** Sum of listed settlement populations; places can overlap, so treat it as an order of magnitude. */
  exposedPopulation: number;
  lights: { verdict: string; ratio: number | null; note: string } | null;
  url: string;
}

/** Shaking radius that matters for people, roughly: M6 -> 50 km, M7 -> 120 km, M8 -> ~290 km. */
export const quakeRadiusKm = (mag: number) => Math.round(clamp(50 * 2.4 ** (mag - 6), 20, 400));

async function assess(ctx: Ctx, e: Omit<Impact, 'settlements' | 'exposedPopulation' | 'lights'>, provenance: Provenance[], withLights: boolean): Promise<Impact> {
  const s = await settlementsNear(ctx, e.lat, e.lon, e.radiusKm, 25);
  provenance.push(s.prov);
  const settlements = s.data ?? [];
  let lightsRes: Impact['lights'] = null;
  // Night lights only say something once the gap-filled product covers nights after the event (it lags days).
  const ageDays = (ctx.now().getTime() - Date.parse(e.when)) / 86_400_000;
  if (withLights && settlements.length && ageDays >= 3) {
    const top = settlements[0]!;
    try {
      const l = await lights(ctx, top.name);
      provenance.push(...l.provenance.slice(0, 2));
      lightsRes = { verdict: l.result.verdict, ratio: l.result.ratio, note: `night lights over ${top.name}, recent nights vs the month before` };
    } catch {}
  } else if (withLights) lightsRes = { verdict: 'PENDING', ratio: null, note: 'too recent: night-light data covers this event after about 3 days' };
  return { ...e, settlements, exposedPopulation: settlements.reduce((a, x) => a + x.population, 0), lights: lightsRes };
}

/** Impact of current strong quakes (M6+) and severe storms, or of a place you name. */
export async function impact(ctx: Ctx, opts: { place?: { name: string; lat: number; lon: number }; radiusKm?: number; lights?: boolean } = {}): Promise<ModuleResult<{ impacts: Impact[] }>> {
  const provenance: Provenance[] = [];
  const nowIso = ctx.now().toISOString();
  const withLights = opts.lights !== false;
  const impacts: Impact[] = [];
  if (opts.place) {
    impacts.push(await assess(ctx, { event: opts.place.name, kind: 'place', lat: opts.place.lat, lon: opts.place.lon, radiusKm: opts.radiusKm ?? 50, when: nowIso, url: '' }, provenance, withLights));
  } else {
    const [q, ev] = await Promise.all([recentQuakes(ctx), eonetEvents(ctx, 3)]);
    provenance.push(q.prov, ev.prov);
    for (const e of (q.data ?? []).filter((x) => x.mag >= 6 && x.lat !== null)) {
      impacts.push(await assess(ctx, { event: `M${e.mag.toFixed(1)} earthquake ${e.place}`, kind: 'earthquake', lat: e.lat!, lon: e.lon!, radiusKm: quakeRadiusKm(e.mag), when: new Date(e.time).toISOString(), url: e.url }, provenance, withLights));
    }
    for (const e of (ev.data ?? []).filter((x) => x.category === 'severeStorms' && x.lat !== null && (eventSeverity(x)?.score ?? 0) >= 70)) {
      impacts.push(await assess(ctx, { event: e.title, kind: 'storm', lat: e.lat!, lon: e.lon!, radiusKm: 150, when: e.date, url: e.url }, provenance, withLights));
    }
  }
  const signals: Signal[] = impacts
    .filter((i) => i.kind !== 'place' && i.exposedPopulation >= 100_000)
    .map((i) => ({
      id: signalId('impact', i.event, i.when.slice(0, 10)),
      module: 'impact',
      title: `${i.event}: about ${i.exposedPopulation >= 1e6 ? `${(i.exposedPopulation / 1e6).toFixed(1)}M` : `${Math.round(i.exposedPopulation / 1000)}k`} people live within ${i.radiusKm} km`,
      score: clamp(Math.round(45 + 8 * Math.log10(i.exposedPopulation / 1e5 + 1) * 3 + (i.lights?.verdict === 'DROP' ? 15 : 0)), 0, 95),
      evidence: [
        ...i.settlements.slice(0, 4).map((s) => ({ source: 'wikidata', text: `${s.name}: ${s.population.toLocaleString('en-US')} people, ${s.distanceKm} km away`, url: `https://www.wikidata.org/wiki/${s.qid}` })),
        ...(i.lights ? [{ source: 'nasa-gibs', text: `${i.lights.note}: ${i.lights.verdict}${i.lights.ratio ? ` (${Math.round((i.lights.ratio - 1) * 100)}%)` : ''}` }] : []),
      ],
      createdAt: nowIso,
    }));
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { module: 'impact', input: opts.place?.name ?? 'current events', generatedAt: nowIso, result: { impacts }, signals, provenance };
}
