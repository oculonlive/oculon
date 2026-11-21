/**
 * Falcon: aircraft intelligence from open ADS-B data.
 *   track(): one aircraft by registration or ICAO hex — owner, live position, nearest airport, movement since last check.
 *   mil():   worldwide military traffic grouped by region, with notable roles (tanker, AWACS, ISR, bomber...)
 *            and surges against the region's own history.
 */
import type { Ctx } from '../core/context.js';
import { entityId } from '../core/graph.js';
import { clamp, median } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import {
  aircraftInfo,
  byHex,
  byRegistration,
  hexForRegistration,
  isHex,
  military,
  openskyState,
  type AircraftInfo,
  type AircraftState,
} from '../sources/aircraft.js';
import { airportLabel, airports, nearestAirport, type Airport } from '../sources/airports.js';

export type FlightStatus = 'AIRBORNE' | 'ON_GROUND' | 'NOT_SEEN';

export interface Place {
  airport: string;
  ident: string;
  km: number;
  relation: 'at' | 'near' | 'over';
}

export interface TrackResult {
  query: string;
  hex: string | null;
  info: AircraftInfo | null;
  state: AircraftState | null;
  status: FlightStatus;
  place: Place | null;
  previous: { status: FlightStatus; place: Place | null; at: string } | null;
  change: string | null;
}

/** Ground traffic counts as "at" an airport within 8 km; low traffic "near" within 40 km; otherwise "over" within 150 km. */
export function locate(list: Airport[], s: AircraftState): Place | null {
  if (s.lat === null || s.lon === null) return null;
  const low = s.onGround || (s.altFt !== null && s.altFt < 5000);
  const n = nearestAirport(list, s.lat, s.lon);
  if (!n) return null;
  if (s.onGround && n.km <= 8) return { airport: airportLabel(n.airport), ident: n.airport.ident, km: Math.round(n.km), relation: 'at' };
  if (low && n.km <= 40) return { airport: airportLabel(n.airport), ident: n.airport.ident, km: Math.round(n.km), relation: 'near' };
  if (n.km <= 150) return { airport: airportLabel(n.airport), ident: n.airport.ident, km: Math.round(n.km), relation: 'over' };
  return null;
}

export function describeChange(prev: TrackResult['previous'], status: FlightStatus, place: Place | null): string | null {
  if (!prev) return null;
  const prevIdent = prev.place?.relation !== 'over' ? prev.place?.ident : undefined;
  const nowIdent = place?.relation !== 'over' ? place?.ident : undefined;
  if (status !== 'AIRBORNE' && prev.status !== 'AIRBORNE' && prevIdent && nowIdent && prevIdent !== nowIdent) {
    return `moved from ${prev.place!.airport} to ${place!.airport}`;
  }
  if (status === 'AIRBORNE' && prev.status !== 'AIRBORNE') return `took off${prev.place ? ` (last seen ${prev.place.relation} ${prev.place.airport})` : ''}`;
  if (status !== 'AIRBORNE' && prev.status === 'AIRBORNE' && place && place.relation !== 'over') return `landed ${place.relation} ${place.airport}`;
  return null;
}

export async function track(ctx: Ctx, queryInput: string): Promise<ModuleResult<TrackResult>> {
  const query = queryInput.trim();
  const provenance: Provenance[] = [];
  const nowIso = ctx.now().toISOString();

  let hex: string | null = isHex(query) ? query.toLowerCase() : null;
  let state: AircraftState | null = null;

  if (!hex) {
    const h = await hexForRegistration(ctx, query);
    provenance.push(h.prov);
    hex = h.data;
    if (!hex) {
      const byReg = await byRegistration(ctx, query);
      provenance.push(byReg.prov);
      state = byReg.data?.[0] ?? null;
      hex = state?.hex ?? null;
    }
  }

  const [info, live, list] = await Promise.all([
    hex ? aircraftInfo(ctx, hex) : Promise.resolve(null),
    hex && !state ? byHex(ctx, hex) : Promise.resolve(null),
    airports(ctx),
  ]);
  if (info) provenance.push(info.prov);
  if (live) provenance.push(live.prov);
  provenance.push(list.prov);
  state ??= live?.data?.[0] ?? null;

  if (hex && !state) {
    const os = await openskyState(ctx, hex);
    provenance.push(os.prov);
    state = os.data;
  }

  const status: FlightStatus = !state || state.lat === null ? 'NOT_SEEN' : state.onGround ? 'ON_GROUND' : 'AIRBORNE';
  const place = state && list.data ? locate(list.data, state) : null;

  let previous: TrackResult['previous'] = null;
  let change: string | null = null;
  const signals: Signal[] = [];

  const infoData = info?.data ?? null;
  if (hex) {
    const name = infoData?.registration ?? state?.registration ?? hex;
    const id = ctx.graph.upsert('aircraft', hex, {
      registration: name,
      ...(infoData?.type ? { type: infoData.type } : {}),
      ...(infoData?.owner ? { owner: infoData.owner } : {}),
    });
    if (infoData?.owner) ctx.graph.link(id, ctx.graph.upsert('company', infoData.owner), 'registered_to', 'hexdb');

    const last = ctx.store.db
      .prepare("SELECT payload, observed_at FROM observations WHERE entity_id = ? AND kind = 'position' ORDER BY observed_at DESC LIMIT 1")
      .get(id) as { payload: string; observed_at: number } | undefined;
    if (last) {
      const p = JSON.parse(last.payload) as { status: FlightStatus; place: Place | null };
      previous = { status: p.status, place: p.place, at: new Date(last.observed_at).toISOString() };
    }
    change = describeChange(previous, status, place);
    ctx.graph.observe(id, 'falcon', 'position', state?.altFt ?? null, state?.source ?? 'none', { status, place, lat: state?.lat, lon: state?.lon });

    if (change) {
      signals.push({
        id: signalId('falcon', hex, change, nowIso.slice(0, 13)),
        module: 'falcon',
        title: `${name}${infoData?.owner ? ` (${infoData.owner})` : ''} ${change}`,
        score: change.startsWith('moved') ? 70 : change.startsWith('landed') ? 60 : 50,
        entity: id,
        evidence: [
          { source: state?.source ?? 'adsb', text: `${status}${place ? `, ${place.relation} ${place.airport} (${place.km} km)` : ''}` },
          ...(previous ? [{ source: 'oculon-history', text: `previously ${previous.status}${previous.place ? ` ${previous.place.relation} ${previous.place.airport}` : ''} at ${previous.at}` }] : []),
        ],
        createdAt: nowIso,
      });
      signals.forEach((s) => ctx.graph.saveSignal(s));
    }
  }

  return {
    module: 'falcon',
    input: query,
    generatedAt: nowIso,
    result: { query, hex, info: info?.data ?? null, state, status, place, previous, change },
    signals,
    provenance,
  };
}

/** ICAO type designators with a role worth calling out. Airlifters are tracked but not treated as notable. */
export const ROLES: Record<string, string> = {
  K35R: 'tanker',
  K35E: 'tanker',
  KC46: 'tanker',
  A330: 'tanker/transport',
  E3TF: 'AWACS',
  E3CF: 'AWACS',
  E737: 'AWACS',
  E6: 'TACAMO',
  R135: 'ISR',
  E8: 'ISR',
  U2: 'ISR',
  Q4: 'ISR drone',
  Q9: 'drone',
  P8: 'maritime patrol',
  P3: 'maritime patrol',
  B52: 'bomber',
  B1: 'bomber',
  B2: 'bomber',
  C17: 'airlifter',
  C5M: 'airlifter',
  C30J: 'airlifter',
  A400: 'airlifter',
};

/** Countries large enough that one bucket would hide where activity is. */
const SPLIT_BY_REGION = new Set(['US', 'CA', 'AU', 'RU', 'CN', 'BR', 'IN']);

export interface MilRegion {
  key: string;
  label: string;
  count: number;
  notable: { role: string; type: string; registration: string | null; callsign: string | null; hex: string }[];
  baselineMedian: number | null;
  ratio: number | null;
}

export interface MilResult {
  total: number;
  withPosition: number;
  regions: MilRegion[];
  firstRuns: boolean;
}

export async function mil(ctx: Ctx): Promise<ModuleResult<MilResult>> {
  const provenance: Provenance[] = [];
  const nowIso = ctx.now().toISOString();
  const nowMs = ctx.now().getTime();
  const [ac, list] = await Promise.all([military(ctx), airports(ctx)]);
  provenance.push(ac.prov, list.prov);

  const large = list.data?.filter((a) => a.type === 'large_airport') ?? [];
  const groups = new Map<string, { label: Map<string, number>; items: AircraftState[] }>();
  const positioned = (ac.data ?? []).filter((a) => a.lat !== null && a.lon !== null);

  for (const a of positioned) {
    const n = large.length ? nearestAirport(large, a.lat!, a.lon!) : null;
    const key = n && n.km <= 500 ? (SPLIT_BY_REGION.has(n.airport.country) && n.airport.region ? n.airport.region : n.airport.country) : 'OCEAN';
    const label = n && n.km <= 500 ? `${n.airport.city || n.airport.name}, ${n.airport.country}` : n ? `open water, ~${Math.round(n.km)} km from ${n.airport.city || n.airport.name}` : 'unknown';
    const g = groups.get(key) ?? { label: new Map<string, number>(), items: [] as AircraftState[] };
    g.items.push(a);
    g.label.set(label, (g.label.get(label) ?? 0) + 1);
    groups.set(key, g);
  }

  let firstRuns = false;
  const regions: MilRegion[] = [...groups].map(([key, g]) => {
    const id = ctx.graph.upsert('event', `mil-region:${key}`);
    // Ignore observations from the last 20 minutes so a quick re-run does not become its own baseline.
    const hist = ctx.graph
      .history(id, 'mil_count', 200)
      .filter((h) => nowMs - h.observedAt > 20 * 60_000)
      .map((h) => h.value ?? 0);
    if (hist.length < 3) firstRuns = true;
    ctx.graph.observe(id, 'falcon', 'mil_count', g.items.length, 'adsb.lol');
    const base = hist.length >= 3 ? median(hist) : null;
    const notable = g.items
      .filter((a) => a.type && ROLES[a.type] && ROLES[a.type] !== 'airlifter')
      .map((a) => ({ role: ROLES[a.type!]!, type: a.type!, registration: a.registration, callsign: a.callsign, hex: a.hex }));
    const label = [...g.label].sort((x, y) => y[1] - x[1])[0]?.[0] ?? key;
    return { key, label, count: g.items.length, notable, baselineMedian: base, ratio: base ? g.items.length / Math.max(1, base) : null };
  });
  regions.sort((a, b) => b.notable.length - a.notable.length || b.count - a.count);

  const signals: Signal[] = [];
  for (const r of regions) {
    if (r.baselineMedian !== null && r.count >= Math.max(5, 2 * r.baselineMedian)) {
      signals.push({
        id: signalId('falcon', 'mil-surge', r.key, nowIso.slice(0, 13)),
        module: 'falcon',
        title: `Military air traffic surge near ${r.label}: ${r.count} aircraft (usual ~${Math.round(r.baselineMedian)})`,
        score: clamp(Math.round(55 + 10 * Math.log2(r.ratio!)), 0, 90),
        entity: entityId('event', `mil-region:${r.key}`),
        evidence: [{ source: 'adsb.lol', text: `${r.count} military-flagged aircraft vs median ${r.baselineMedian} over previous scans`, value: r.count }],
        createdAt: nowIso,
      });
    }
    if (r.notable.length >= 2) {
      const byRole = new Map<string, number>();
      r.notable.forEach((n) => byRole.set(n.role, (byRole.get(n.role) ?? 0) + 1));
      signals.push({
        id: signalId('falcon', 'mil-notable', r.key, nowIso.slice(0, 13)),
        module: 'falcon',
        title: `${[...byRole].map(([role, n]) => `${n}x ${role}`).join(', ')} active near ${r.label}`,
        score: clamp(40 + r.notable.length * 8 + (byRole.size - 1) * 5, 0, 85),
        entity: entityId('event', `mil-region:${r.key}`),
        evidence: r.notable.map((n) => ({ source: 'adsb.lol', text: `${n.type} (${n.role}) ${n.registration ?? ''} ${n.callsign ?? ''}`.replace(/\s+/g, ' ').trim(), url: `https://globe.adsb.lol/?icao=${n.hex}` })),
        createdAt: nowIso,
      });
    }
  }
  signals.sort((a, b) => b.score - a.score);
  signals.forEach((s) => ctx.graph.saveSignal(s));

  return {
    module: 'falcon',
    input: 'mil',
    generatedAt: nowIso,
    result: { total: ac.data?.length ?? 0, withPosition: positioned.length, regions, firstRuns },
    signals,
    provenance,
  };
}
