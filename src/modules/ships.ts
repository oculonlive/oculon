/**
 * Falcon at sea: live vessels around a place (traffic, anchored queue, vessel types) and single-ship tracking,
 * from aisstream.io. Anchored counts are stored so port congestion can be compared with the port's own history.
 */
import type { Ctx } from '../core/context.js';
import { clamp, median } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { collect, isStationary, shipType, type Box, type Vessel } from '../sources/ais.js';
import { normName, sdn } from '../sources/ofac.js';
import { geocode, type Place } from '../sources/earth.js';
import { analysisBox } from './condor.js';

export interface ShipsResult {
  place: Place;
  box: Box;
  seconds: number;
  vessels: (Vessel & { type: string; stationary: boolean })[];
  total: number;
  moving: number;
  stationary: number;
  byType: Record<string, number>;
  baselineStationary: number | null;
}

export async function shipsNear(ctx: Ctx, placeQuery: string, seconds = 30, wsImpl?: typeof WebSocket): Promise<ModuleResult<ShipsResult>> {
  const provenance: Provenance[] = [];
  const g = await geocode(ctx, placeQuery);
  provenance.push(g.prov);
  const place = g.data?.[0];
  if (!place) throw new Error(`place not found: ${placeQuery}`);
  const [s, n, w, e] = analysisBox(place, 0.8, 0.3);
  const box: Box = [
    [s, w],
    [n, e],
  ];
  const c = await collect([box], Math.min(120, Math.max(10, seconds)), [], wsImpl);
  provenance.push(c.prov);
  const vessels = c.vessels.map((v) => ({ ...v, type: shipType(v.typeCode), stationary: isStationary(v) }));
  const stationary = vessels.filter((v) => v.stationary).length;
  const byType: Record<string, number> = {};
  for (const v of vessels) byType[v.type] = (byType[v.type] ?? 0) + 1;

  const nowMs = ctx.now().getTime();
  const nowIso = new Date(nowMs).toISOString();
  const id = ctx.graph.upsert('event', `port:${place.name}`, { lat: place.lat, lon: place.lon });
  // Only runs that actually received data count toward the baseline.
  const hist = ctx.graph
    .history(id, 'stationary_vessels', 100)
    .filter((h) => nowMs - h.observedAt > 30 * 60_000)
    .map((h) => h.value ?? 0);
  const baseline = hist.length >= 3 ? median(hist) : null;
  if (c.messages > 0) ctx.graph.observe(id, 'falcon', 'stationary_vessels', stationary, 'aisstream', { total: vessels.length, seconds: c.seconds });

  const signals: Signal[] = [];
  if (baseline !== null && stationary >= Math.max(5, baseline * 1.5)) {
    signals.push({
      id: signalId('falcon', 'port', place.name, nowIso.slice(0, 13)),
      module: 'falcon',
      title: `Vessels waiting near ${place.name.split(',')[0]}: ${stationary} stationary (usual ~${Math.round(baseline)})`,
      score: clamp(Math.round(50 + 15 * Math.log2(stationary / Math.max(1, baseline))), 0, 85),
      entity: id,
      evidence: [{ source: 'aisstream', text: `${stationary} anchored/moored or stopped of ${vessels.length} vessels seen in ${c.seconds}s, vs median ${baseline} over ${hist.length} earlier samples` }],
      createdAt: nowIso,
    });
  }
  // OFAC screening of every vessel seen: by IMO number, else by exact vessel name.
  const list = await sdn(ctx);
  provenance.push(list.prov);
  const sanctioned = list.data
    ? vessels.flatMap((v) => {
        const e = (v.imo && list.data!.byImo.get(v.imo)) || (v.name && list.data!.byName.get(normName(v.name)));
        return e && (e.type.toLowerCase() === 'vessel' || v.imo) ? [{ v, e }] : [];
      })
    : [];
  for (const { v, e } of sanctioned) {
    signals.push({
      id: signalId('sanctions', 'vessel', String(v.mmsi), nowIso.slice(0, 10)),
      module: 'sanctions',
      title: `OFAC-listed vessel ${v.name ?? v.mmsi} seen near ${place.name.split(',')[0]}`,
      score: 85,
      entity: id,
      evidence: [{ source: 'ofac', text: `${e.name} [${e.program}] matched by ${v.imo && list.data!.byImo.get(v.imo) ? `IMO ${v.imo}` : 'name'}; ${v.sog ?? '?'} kn at ${v.lat.toFixed(3)}, ${v.lon.toFixed(3)}`, url: `https://sanctionssearch.ofac.treas.gov/Details.aspx?id=${e.uid}` }],
      createdAt: nowIso,
    });
  }
  const military = vessels.filter((v) => v.type === 'military');
  if (military.length >= 2) {
    signals.push({
      id: signalId('falcon', 'navy', place.name, nowIso.slice(0, 13)),
      module: 'falcon',
      title: `${military.length} military vessels broadcasting near ${place.name.split(',')[0]}`,
      score: clamp(45 + military.length * 6, 0, 80),
      entity: id,
      evidence: military.slice(0, 5).map((v) => ({ source: 'aisstream', text: `${v.name ?? 'unnamed'} (MMSI ${v.mmsi}) ${v.sog ?? '?'} kn`, url: `https://www.marinetraffic.com/en/ais/details/ships/mmsi:${v.mmsi}` })),
      createdAt: nowIso,
    });
  }
  signals.forEach((x) => ctx.graph.saveSignal(x));

  return {
    module: 'falcon',
    input: placeQuery,
    generatedAt: nowIso,
    result: { place, box, seconds: c.seconds, vessels: vessels.sort((a, b) => (a.name ?? '~').localeCompare(b.name ?? '~')), total: vessels.length, moving: vessels.length - stationary, stationary, byType, baselineStationary: baseline },
    signals,
    provenance,
  };
}

export interface ShipTrack {
  mmsi: number;
  found: boolean;
  vessel: (Vessel & { type: string }) | null;
  seconds: number;
}

/** Follow one ship anywhere for up to `seconds` (ships report every few seconds to a few minutes). */
export async function shipTrack(ctx: Ctx, mmsiInput: string, seconds = 60, wsImpl?: typeof WebSocket): Promise<ModuleResult<ShipTrack>> {
  const mmsi = Number(mmsiInput.trim());
  if (!Number.isInteger(mmsi) || String(mmsi).length !== 9) throw new Error('MMSI must be a 9-digit number');
  const c = await collect(
    [
      [
        [-90, -180],
        [90, 180],
      ],
    ],
    Math.min(180, Math.max(10, seconds)),
    [mmsi],
    wsImpl,
  );
  const v = c.vessels.find((x) => x.mmsi === mmsi) ?? null;
  if (v) ctx.graph.observe(ctx.graph.upsert('event', `vessel:${mmsi}`, { name: v.name }), 'falcon', 'vessel_seen', v.sog, 'aisstream', { lat: v.lat, lon: v.lon });
  return {
    module: 'falcon',
    input: String(mmsi),
    generatedAt: ctx.now().toISOString(),
    result: { mmsi, found: Boolean(v), vessel: v ? { ...v, type: shipType(v.typeCode) } : null, seconds: c.seconds },
    signals: [],
    provenance: [{ ...c.prov, ...(v ? {} : { note: `no report from MMSI ${mmsi} in ${c.seconds}s (out of coverage, in port with AIS off, or reporting rarely)` }) }],
  };
}
