/**
 * Dark ships (Global Fishing Watch, free non-commercial token):
 *   darkShips(place): vessels that switched off AIS on purpose ("intentional disabling" as GFW's model judges it)
 *     inside the area of a place in the last N days: where they went dark, where they reappeared, for how long.
 *     Also in the same area and window: encounters (two vessels side by side at sea, the classic ship-to-ship
 *     transfer used for transshipment and sanctions evasion), loitering, and the port visits of every vessel that
 *     went dark or took part in an encounter. Vessels are checked against OFAC by IMO.
 *   vesselIdentity(query): name, MMSI or IMO to registry identity (flag, type, owners, earlier names), an OFAC
 *     check on the IMO and the vessel's event history for the past year (AIS gaps, encounters, loitering, port visits).
 * Coverage: GFW's gap and encounter models cover vessels it tracks closely, mostly fishing and carrier vessels;
 * tankers and cargo ships appear less often. Drifting fishing gear (buoys) is left out.
 */
import { key, noKey } from '../core/keys.js';
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';
import { geocode, type Place } from '../sources/earth.js';
import { sdn } from '../sources/ofac.js';
import { postJson } from '../sources/press.js';
import { screen } from './sanctions.js';

const GFW = 'https://gateway.api.globalfishingwatch.org/v3';
export const GFW_DATASETS = {
  gaps: 'public-global-gaps-events:latest',
  encounters: 'public-global-encounters-events:latest',
  loitering: 'public-global-loitering-events:latest',
  portVisits: 'public-global-port-visits-events:latest',
  identity: 'public-global-vessel-identity:latest',
} as const;

export interface DarkGap {
  vessel: string;
  mmsi: string | null;
  flag: string | null;
  type: string | null;
  off: string;
  on: string;
  hours: number;
  km: number;
  offPosition: { lat: number; lon: number } | null;
  onPosition: { lat: number; lon: number } | null;
  url: string;
  /** GFW vessel id. */
  vesselId?: string | null;
  /** OFAC SDN entry name when the vessel's IMO is listed. */
  sanctioned?: string | null;
}

export interface EventVessel {
  id: string | null;
  name: string;
  mmsi: string | null;
  flag: string | null;
  type: string | null;
  imo?: string | null;
  sanctioned?: string | null;
}

export interface Encounter {
  start: string;
  end: string;
  hours: number;
  lat: number | null;
  lon: number | null;
  /** GFW encounter type, e.g. carrier-fishing, fishing-fishing, tanker-fishing. */
  kind: string | null;
  /** GFW flags encounters involving vessels without public authorization as a potential risk. */
  potentialRisk: boolean;
  medianKm: number | null;
  a: EventVessel;
  b: EventVessel;
  /** One of the two vessels also switched off AIS in the area in the same window. */
  gapLinked: boolean;
  url: string;
}

export interface Loitering {
  vessel: EventVessel;
  start: string;
  end: string;
  hours: number;
  lat: number | null;
  lon: number | null;
  distanceFromShoreKm: number | null;
  /** The vessel also went dark or took part in an encounter in the area. */
  linked: boolean;
  url: string;
}

export interface PortVisit {
  vessel: EventVessel;
  port: string | null;
  portFlag: string | null;
  start: string;
  end: string;
  hours: number;
  lat: number | null;
  lon: number | null;
}

export interface DarkShips {
  place: Place | null;
  days: number;
  total: number;
  gaps: DarkGap[];
  encounters?: Encounter[];
  loitering?: Loitering[];
  /** Port visits by vessels that went dark or took part in an encounter in the area. */
  portVisits?: PortVisit[];
  /** Totals reported by GFW for the whole area and window, all event types (lists above are capped at 100 and
   * cover every vessel type; GFW counts an encounter once from each vessel's side, so it can be double). */
  totals?: { gaps: number; encounters: number; loitering: number; portVisits: number };
}

interface RawVessel {
  id?: string;
  name?: string | null;
  ssvid?: string;
  flag?: string | null;
  type?: string | null;
}

interface RawEvent {
  id?: string;
  type?: string;
  start: string;
  end: string;
  position?: { lat: number; lon: number };
  distances?: { startDistanceFromShoreKm?: number };
  vessel?: RawVessel;
  gap?: { intentionalDisabling?: boolean; distanceKm?: string | number; durationHours?: number; offPosition?: { lat: number; lon: number }; onPosition?: { lat: number; lon: number } };
  encounter?: { vessel?: RawVessel; type?: string; potentialRisk?: boolean; medianDistanceKilometers?: number };
  loitering?: { totalTimeHours?: number; averageDistanceFromShoreKm?: number };
  port_visit?: { durationHrs?: number; intermediateAnchorage?: Anchorage; startAnchorage?: Anchorage; endAnchorage?: Anchorage };
}

type Anchorage = { name?: string | null; flag?: string | null; topDestination?: string | null };
type GapEvent = RawEvent;
type EventsPage = { total?: number; entries?: RawEvent[] };

/** Pad small places (ports, towns) to at least ~2 degrees so the box covers nearby waters. */
export function seaBox(p: Place, minDeg = 2): [number, number, number, number] {
  let [s, n, w, e] = p.bbox;
  if (n - s < minDeg) (s = p.lat - minDeg / 2), (n = p.lat + minDeg / 2);
  if (e - w < minDeg) (w = p.lon - minDeg / 2), (e = p.lon + minDeg / 2);
  return [s, n, w, e];
}

const hoursBetween = (a: string, b: string) => Math.max(0, Math.round((Date.parse(b) - Date.parse(a)) / 3_600_000));
const vesselUrl = (id?: string | null) => (id ? `https://globalfishingwatch.org/map/vessel/${id}` : 'https://globalfishingwatch.org/map');
const toVessel = (v?: RawVessel): EventVessel => ({ id: v?.id ?? null, name: v?.name || `MMSI ${v?.ssvid ?? '?'}`, mmsi: v?.ssvid ?? null, flag: v?.flag ?? null, type: v?.type ?? null });

/** POST /v3/events for one dataset. */
async function gfwEvents(ctx: Ctx, token: string, body: Record<string, unknown>, limit = 100): Promise<Sourced<EventsPage>> {
  return postJson<EventsPage>(ctx, `${GFW}/events?limit=${limit}&offset=0`, body, { authorization: `Bearer ${token}` }, 'gfw', 6 * 3600);
}

export function parseEncounters(entries: RawEvent[]): Encounter[] {
  const seen = new Set<string>();
  const out: Encounter[] = [];
  for (const x of entries) {
    if (!x.encounter) continue;
    const a = toVessel(x.vessel);
    const b = toVessel(x.encounter.vessel);
    // GFW lists each encounter twice, once from each vessel's side.
    const k = [[a.id ?? a.mmsi, b.id ?? b.mmsi].sort().join('|'), x.start.slice(0, 13)].join('@');
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({
      start: x.start,
      end: x.end,
      hours: hoursBetween(x.start, x.end),
      lat: x.position?.lat ?? null,
      lon: x.position?.lon ?? null,
      kind: x.encounter.type ?? null,
      potentialRisk: x.encounter.potentialRisk === true,
      medianKm: x.encounter.medianDistanceKilometers ?? null,
      a,
      b,
      gapLinked: false,
      url: vesselUrl(a.id),
    });
  }
  return out.sort((p, q) => q.end.localeCompare(p.end));
}

export function parseLoitering(entries: RawEvent[]): Loitering[] {
  return entries
    .filter((x) => x.loitering && x.vessel?.type !== 'gear')
    .map((x) => ({
      vessel: toVessel(x.vessel),
      start: x.start,
      end: x.end,
      hours: Math.round(x.loitering?.totalTimeHours ?? hoursBetween(x.start, x.end)),
      lat: x.position?.lat ?? null,
      lon: x.position?.lon ?? null,
      distanceFromShoreKm: x.loitering?.averageDistanceFromShoreKm !== undefined ? Math.round(x.loitering.averageDistanceFromShoreKm) : (x.distances?.startDistanceFromShoreKm ?? null),
      linked: false,
      url: vesselUrl(x.vessel?.id),
    }))
    .sort((p, q) => q.end.localeCompare(p.end));
}

export function parsePortVisits(entries: RawEvent[]): PortVisit[] {
  return entries
    .filter((x) => x.port_visit)
    .map((x) => {
      const ancs = [x.port_visit?.intermediateAnchorage, x.port_visit?.startAnchorage, x.port_visit?.endAnchorage].filter((a): a is Anchorage => Boolean(a));
      const named = ancs.find((a) => a.name) ?? ancs.find((a) => a.topDestination);
      return {
        vessel: toVessel(x.vessel),
        port: named?.name ?? named?.topDestination ?? null,
        portFlag: named?.flag ?? ancs[0]?.flag ?? null,
        start: x.start,
        end: x.end,
        hours: Math.round(x.port_visit?.durationHrs ?? hoursBetween(x.start, x.end)),
        lat: x.position?.lat ?? null,
        lon: x.position?.lon ?? null,
      };
    })
    .sort((p, q) => q.end.localeCompare(p.end));
}

/** GFW vessel id -> IMO via the identity dataset, for up to 50 ids in one request. */
async function imosForIds(ctx: Ctx, token: string, ids: string[]): Promise<Sourced<Map<string, string>>> {
  const qs = ids
    .slice(0, 50)
    .map((id, i) => `ids[${i}]=${encodeURIComponent(id)}`)
    .join('&');
  const r = await ctx.http.get<{ entries?: { selfReportedInfo?: { id?: string; imo?: string | null }[]; registryInfo?: { imo?: string | null }[] }[] }>(`${GFW}/vessels?datasets[0]=${GFW_DATASETS.identity}&${qs}`, {
    source: 'gfw',
    ttlSec: 7 * 86_400,
    headers: { authorization: `Bearer ${token}` },
  });
  if (!r.data) return { data: null, prov: r.prov };
  const map = new Map<string, string>();
  for (const e of r.data.entries ?? []) {
    const imo = e.registryInfo?.find((x) => x.imo)?.imo ?? e.selfReportedInfo?.find((x) => x.imo)?.imo;
    if (!imo || !/^\d{7}$/.test(imo)) continue;
    for (const s of e.selfReportedInfo ?? []) if (s.id) map.set(s.id, imo);
  }
  return { data: map, prov: r.prov };
}

export async function darkShips(ctx: Ctx, placeQuery: string, days = 30, opts: { extra?: boolean } = {}): Promise<ModuleResult<DarkShips>> {
  const now = ctx.now();
  const provenance: Provenance[] = [];
  const t = key('GFW_API_TOKEN');
  const g = await geocode(ctx, placeQuery, 1);
  provenance.push(g.prov);
  const place = g.data?.[0] ?? null;
  const empty = (p: Provenance): ModuleResult<DarkShips> => ({ module: 'darkships', input: placeQuery, generatedAt: now.toISOString(), result: { place, days, total: 0, gaps: [] }, signals: [], provenance: [...provenance, p] });
  if (!t) return empty(noKey('gfw', 'GFW_API_TOKEN').prov);
  if (!place) return empty({ source: 'nominatim', url: '', status: 'UNAVAILABLE', fetchedAt: now.toISOString(), note: `place not found: ${placeQuery}` });
  const [s, n, w, e] = seaBox(place);
  const startDate = new Date(now.getTime() - days * 86_400_000).toISOString().slice(0, 10);
  const endDate = now.toISOString().slice(0, 10);
  const geometry = { type: 'Polygon', coordinates: [[[w, s], [e, s], [e, n], [w, n], [w, s]]] };
  const extra = opts.extra !== false;
  const [r, enc, loi] = await Promise.all([
    gfwEvents(ctx, t, { datasets: [GFW_DATASETS.gaps], startDate, endDate, geometry }),
    extra ? gfwEvents(ctx, t, { datasets: [GFW_DATASETS.encounters], startDate, endDate, geometry }) : null,
    extra ? gfwEvents(ctx, t, { datasets: [GFW_DATASETS.loitering], startDate, endDate, geometry }) : null,
  ]);
  provenance.push(r.prov);
  if (enc) provenance.push(enc.prov);
  if (loi) provenance.push(loi.prov);
  const gaps: DarkGap[] = ((r.data?.entries ?? []) as GapEvent[])
    .filter((x) => x.gap?.intentionalDisabling && x.vessel?.type !== 'gear')
    .map((x) => ({
      vessel: x.vessel?.name || `MMSI ${x.vessel?.ssvid ?? '?'}`,
      mmsi: x.vessel?.ssvid ?? null,
      flag: x.vessel?.flag ?? null,
      type: x.vessel?.type ?? null,
      off: x.start,
      on: x.end,
      hours: Math.round(x.gap?.durationHours ?? 0),
      km: Math.round(Number(x.gap?.distanceKm ?? 0)),
      offPosition: x.gap?.offPosition ?? null,
      onPosition: x.gap?.onPosition ?? null,
      url: vesselUrl(x.vessel?.id),
      vesselId: x.vessel?.id ?? null,
    }))
    .sort((a, b) => b.on.localeCompare(a.on));

  const encounters = parseEncounters(enc?.data?.entries ?? []);
  const loitering = parseLoitering(loi?.data?.entries ?? []);
  const gapIds = new Set(gaps.flatMap((x) => [x.vesselId, x.mmsi]).filter((x): x is string => Boolean(x)));
  for (const en of encounters) en.gapLinked = [en.a.id, en.a.mmsi, en.b.id, en.b.mmsi].some((x) => x && gapIds.has(x));
  const interest = [...new Set([...gaps.map((x) => x.vesselId), ...encounters.flatMap((x) => [x.a.id, x.b.id])].filter((x): x is string => Boolean(x)))].slice(0, 50);
  for (const l of loitering) l.linked = Boolean(l.vessel.id && interest.includes(l.vessel.id));

  // OFAC by IMO for every vessel of interest, and where those vessels went into port.
  let portVisits: PortVisit[] = [];
  let portTotal = 0;
  const sanctionedById = new Map<string, { imo: string; name: string }>();
  if (extra && interest.length) {
    const [imos, pv] = await Promise.all([imosForIds(ctx, t, interest), gfwEvents(ctx, t, { datasets: [GFW_DATASETS.portVisits], startDate, endDate, vessels: interest, confidences: ['3', '4'] })]);
    provenance.push(imos.prov, pv.prov);
    portVisits = parsePortVisits(pv.data?.entries ?? []);
    portTotal = pv.data?.total ?? portVisits.length;
    if (imos.data?.size) {
      const list = await sdn(ctx);
      provenance.push(list.prov);
      for (const [id, imo] of imos.data) {
        const hit = list.data?.byImo.get(imo);
        if (hit) sanctionedById.set(id, { imo, name: hit.name });
      }
      const tag = (v: EventVessel) => {
        if (!v.id) return;
        v.imo = imos.data!.get(v.id) ?? null;
        v.sanctioned = sanctionedById.get(v.id)?.name ?? null;
      };
      for (const en of encounters) tag(en.a), tag(en.b);
      for (const l of loitering) tag(l.vessel);
      for (const p of portVisits) tag(p.vessel);
      for (const gp of gaps) gp.sanctioned = gp.vesselId ? (sanctionedById.get(gp.vesselId)?.name ?? null) : null;
    }
  }

  const signals: Signal[] = [];
  const iso = now.toISOString();
  const recent = gaps.filter((x) => now.getTime() - Date.parse(x.on) < 3 * 86_400_000);
  if (recent.length >= 3) {
    signals.push({
      id: signalId('darkships', place.name, iso.slice(0, 10)),
      module: 'darkships',
      title: `${recent.length} vessels near ${place.name.split(',')[0]} reappeared after switching off AIS in the last 3 days`,
      score: Math.min(80, 50 + recent.length * 3),
      evidence: recent.slice(0, 4).map((x) => ({ source: 'gfw', text: `${x.vessel}${x.flag ? ` (${x.flag})` : ''} dark for ${x.hours} h, moved ${x.km} km`, url: x.url })),
      createdAt: iso,
    });
  }
  const label = (v: EventVessel) => `${v.name}${v.flag ? ` (${v.flag})` : ''}${v.type ? ` ${v.type}` : ''}`;
  for (const en of encounters.filter((x) => x.gapLinked || x.a.sanctioned || x.b.sanctioned).slice(0, 5)) {
    const listed = [en.a, en.b].filter((v) => v.sanctioned);
    signals.push({
      id: signalId('darkships', 'encounter', en.a.id ?? en.a.name, en.b.id ?? en.b.name, en.start.slice(0, 13)),
      module: 'darkships',
      title: `Possible ship-to-ship transfer near ${place.name.split(',')[0]}: ${en.a.name} met ${en.b.name}${listed.length ? ' (OFAC-listed vessel)' : ' (vessel also went dark)'}`,
      score: Math.min(95, (listed.length ? 85 : 68) + (listed.length && en.gapLinked ? 5 : 0) + (en.potentialRisk ? 3 : 0)),
      evidence: [
        { source: 'gfw', text: `${label(en.a)} and ${label(en.b)} together ${en.hours} h from ${en.start.slice(0, 16).replace('T', ' ')} UTC${en.lat !== null ? ` at ${en.lat.toFixed(3)}, ${en.lon!.toFixed(3)}` : ''}${en.kind ? `, ${en.kind}` : ''}`, url: en.url },
        ...listed.map((v) => ({ source: 'ofac', text: `${v.name} IMO ${v.imo} matches OFAC SDN entry "${v.sanctioned}"`, url: 'https://sanctionssearch.ofac.treas.gov/' })),
        ...(en.gapLinked ? [{ source: 'gfw', text: 'one of the vessels switched off AIS in this area in the same window' }] : []),
      ],
      createdAt: iso,
    });
  }
  const sanctionedGaps = gaps.filter((x) => x.sanctioned);
  if (sanctionedGaps.length) {
    signals.push({
      id: signalId('darkships', 'sanctioned-gap', place.name, iso.slice(0, 10)),
      module: 'darkships',
      title: `OFAC-listed vessel switched off AIS near ${place.name.split(',')[0]}: ${sanctionedGaps[0]!.vessel}`,
      score: 82,
      evidence: sanctionedGaps.slice(0, 3).map((x) => ({ source: 'gfw', text: `${x.vessel} dark ${x.hours} h from ${x.off.slice(0, 16).replace('T', ' ')} UTC; OFAC SDN "${x.sanctioned}"`, url: x.url })),
      createdAt: iso,
    });
  }
  const sanctionedPorts = portVisits.filter((p) => p.vessel.sanctioned);
  if (sanctionedPorts.length) {
    signals.push({
      id: signalId('darkships', 'sanctioned-port', place.name, iso.slice(0, 10)),
      module: 'darkships',
      title: `OFAC-listed vessel ${sanctionedPorts[0]!.vessel.name} called at ${sanctionedPorts[0]!.port ?? 'a port'}${sanctionedPorts[0]!.portFlag ? ` (${sanctionedPorts[0]!.portFlag})` : ''}`,
      score: 75,
      evidence: sanctionedPorts.slice(0, 3).map((p) => ({ source: 'gfw', text: `${p.vessel.name} IMO ${p.vessel.imo} at ${p.port ?? '?'} ${p.start.slice(0, 10)} to ${p.end.slice(0, 10)}`, url: vesselUrl(p.vessel.id) })),
      createdAt: iso,
    });
  }
  for (const sig of signals) ctx.graph.saveSignal(sig);
  const result: DarkShips = { place, days, total: gaps.length, gaps };
  if (extra) {
    result.encounters = encounters;
    result.loitering = loitering.slice(0, 50);
    result.portVisits = portVisits.slice(0, 50);
    result.totals = { gaps: r.data?.total ?? gaps.length, encounters: enc?.data?.total ?? encounters.length, loitering: loi?.data?.total ?? loitering.length, portVisits: portTotal };
  }
  return { module: 'darkships', input: placeQuery, generatedAt: iso, result, signals, provenance };
}

export interface VesselEvent {
  kind: 'gap' | 'encounter' | 'loitering' | 'port_visit';
  start: string;
  end: string;
  hours: number;
  lat: number | null;
  lon: number | null;
  /** Port name for a visit, the other vessel for an encounter. */
  detail: string | null;
}

export interface VesselHistory {
  days: number;
  gaps: number;
  encounters: number;
  loitering: number;
  portVisits: number;
  /** Most recent events across all four kinds, newest first. */
  recent: VesselEvent[];
  /** Ports visited in the window, most visits first. */
  ports: { port: string; flag: string | null; visits: number }[];
}

export interface VesselIdentity {
  name: string | null;
  mmsi: string | null;
  imo: string | null;
  callsign: string | null;
  flag: string | null;
  types: string[];
  owners: { name: string; flag: string | null; from: string | null; to: string | null }[];
  earlierNames: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  sanctions: string | null;
  url: string | null;
  /** GFW vessel ids under this identity (one per AIS identity it used). */
  ids?: string[];
  history?: VesselHistory | null;
}

/** One vessel's events over the last `days` (AIS gaps, encounters, loitering, port visits), all its GFW ids together. */
export async function vesselHistory(ctx: Ctx, ids: string[], days = 365): Promise<{ data: VesselHistory | null; prov: Provenance[] }> {
  const t = key('GFW_API_TOKEN');
  if (!t) return { data: null, prov: [noKey('gfw', 'GFW_API_TOKEN').prov] };
  if (!ids.length) return { data: null, prov: [] };
  const now = ctx.now();
  const base = { startDate: new Date(now.getTime() - days * 86_400_000).toISOString().slice(0, 10), endDate: now.toISOString().slice(0, 10), vessels: ids.slice(0, 20) };
  const [gp, en, lo, pv] = await Promise.all([
    gfwEvents(ctx, t, { ...base, datasets: [GFW_DATASETS.gaps] }, 50),
    gfwEvents(ctx, t, { ...base, datasets: [GFW_DATASETS.encounters] }, 50),
    gfwEvents(ctx, t, { ...base, datasets: [GFW_DATASETS.loitering] }, 50),
    gfwEvents(ctx, t, { ...base, datasets: [GFW_DATASETS.portVisits], confidences: ['3', '4'] }, 100),
  ]);
  const prov = [gp.prov, en.prov, lo.prov, pv.prov];
  if (!gp.data && !en.data && !lo.data && !pv.data) return { data: null, prov };
  const pos = (x: RawEvent) => ({ lat: x.position?.lat ?? x.gap?.offPosition?.lat ?? null, lon: x.position?.lon ?? x.gap?.offPosition?.lon ?? null });
  const gapEvents = (gp.data?.entries ?? []).filter((x) => x.gap?.intentionalDisabling !== false);
  const encs = parseEncounters(en.data?.entries ?? []);
  const loits = parseLoitering(lo.data?.entries ?? []);
  const visits = parsePortVisits(pv.data?.entries ?? []);
  const recent: VesselEvent[] = [
    ...gapEvents.map((x) => ({ kind: 'gap' as const, start: x.start, end: x.end, hours: Math.round(x.gap?.durationHours ?? hoursBetween(x.start, x.end)), ...pos(x), detail: x.gap?.distanceKm !== undefined ? `moved ${Math.round(Number(x.gap.distanceKm))} km while dark` : null })),
    ...encs.map((x) => {
      const other = ids.includes(x.a.id ?? '') ? x.b : x.a;
      return { kind: 'encounter' as const, start: x.start, end: x.end, hours: x.hours, lat: x.lat, lon: x.lon, detail: `${other.name}${other.flag ? ` (${other.flag})` : ''}${other.type ? ` ${other.type}` : ''}` };
    }),
    ...loits.map((x) => ({ kind: 'loitering' as const, start: x.start, end: x.end, hours: x.hours, lat: x.lat, lon: x.lon, detail: x.distanceFromShoreKm !== null ? `${x.distanceFromShoreKm} km from shore` : null })),
    ...visits.map((x) => ({ kind: 'port_visit' as const, start: x.start, end: x.end, hours: x.hours, lat: x.lat, lon: x.lon, detail: x.port ? `${x.port}${x.portFlag ? ` (${x.portFlag})` : ''}` : null })),
  ].sort((a, b) => b.end.localeCompare(a.end));
  const portCount = new Map<string, { port: string; flag: string | null; visits: number }>();
  for (const v of visits) {
    if (!v.port) continue;
    const k = `${v.port}|${v.portFlag}`;
    const c = portCount.get(k) ?? { port: v.port, flag: v.portFlag, visits: 0 };
    c.visits++;
    portCount.set(k, c);
  }
  return {
    data: {
      days,
      gaps: gp.data?.total ?? gapEvents.length,
      encounters: en.data?.total ?? encs.length,
      loitering: lo.data?.total ?? loits.length,
      portVisits: pv.data?.total ?? visits.length,
      recent: recent.slice(0, 25),
      ports: [...portCount.values()].sort((a, b) => b.visits - a.visits).slice(0, 10),
    },
    prov,
  };
}

export async function vesselIdentity(ctx: Ctx, query: string, opts: { history?: boolean; historyDays?: number } = {}): Promise<ModuleResult<VesselIdentity[]>> {
  const now = ctx.now().toISOString();
  const t = key('GFW_API_TOKEN');
  if (!t) return { module: 'darkships', input: query, generatedAt: now, result: [], signals: [], provenance: [noKey('gfw', 'GFW_API_TOKEN').prov] };
  const r = await ctx.http.get<{
    entries?: {
      selfReportedInfo?: { id?: string; ssvid?: string; shipname?: string; flag?: string; callsign?: string; imo?: string; transmissionDateFrom?: string; transmissionDateTo?: string }[];
      registryInfo?: { shipname?: string; flag?: string; imo?: string; ssvid?: string; callsign?: string }[];
      registryOwners?: { name?: string; flag?: string; dateFrom?: string; dateTo?: string }[];
      combinedSourcesInfo?: { shiptypes?: { name: string }[] }[];
    }[];
  }>(`${GFW}/vessels/search?query=${encodeURIComponent(query)}&datasets[0]=${GFW_DATASETS.identity}&includes[0]=OWNERSHIP&limit=5`, { source: 'gfw', ttlSec: 24 * 3600, headers: { authorization: `Bearer ${t}` } });
  const provenance: Provenance[] = [r.prov];
  const out: VesselIdentity[] = [];
  for (const e of r.data?.entries ?? []) {
    const self = [...(e.selfReportedInfo ?? [])].sort((a, b) => (b.transmissionDateTo ?? '').localeCompare(a.transmissionDateTo ?? ''));
    const latest = self[0];
    const reg = e.registryInfo?.[0];
    const imo = reg?.imo ?? self.find((x) => x.imo)?.imo ?? null;
    out.push({
      name: reg?.shipname ?? latest?.shipname ?? null,
      mmsi: latest?.ssvid ?? reg?.ssvid ?? null,
      imo,
      callsign: reg?.callsign ?? latest?.callsign ?? null,
      flag: reg?.flag ?? latest?.flag ?? null,
      types: [...new Set((e.combinedSourcesInfo ?? []).flatMap((c) => c.shiptypes?.map((x) => x.name) ?? []))],
      owners: (e.registryOwners ?? []).map((o) => ({ name: o.name ?? '?', flag: o.flag ?? null, from: o.dateFrom ?? null, to: o.dateTo ?? null })),
      earlierNames: [...new Set(self.map((x) => x.shipname).filter((x): x is string => Boolean(x)))].slice(1, 8),
      firstSeen: self.at(-1)?.transmissionDateFrom ?? null,
      lastSeen: latest?.transmissionDateTo ?? null,
      sanctions: null,
      url: latest?.id ? `https://globalfishingwatch.org/map/vessel/${latest.id}` : null,
      ids: [...new Set(self.map((x) => x.id).filter((x): x is string => Boolean(x)))],
    });
  }
  // Sanctions check on IMO numbers (OFAC SDN, already cached locally).
  for (const v of out.slice(0, 3)) {
    if (!v.imo) continue;
    const s = await screen(ctx, `IMO ${v.imo}`);
    v.sanctions = s.result.verdict;
  }
  // Event history for the top matches (4 requests each).
  if (opts.history !== false) {
    for (const v of out.slice(0, 2)) {
      const h = await vesselHistory(ctx, v.ids ?? [], opts.historyDays ?? 365);
      v.history = h.data;
      provenance.push(...h.prov);
    }
  }
  const signals: Signal[] = [];
  for (const v of out) {
    const h = v.history;
    if (v.sanctions !== 'SANCTIONED' || !h || h.gaps + h.encounters + h.loitering + h.portVisits === 0) continue;
    const lastPort = h.recent.find((x) => x.kind === 'port_visit');
    signals.push({
      id: signalId('darkships', 'sanctioned-active', v.imo ?? v.name ?? '', now.slice(0, 10)),
      module: 'darkships',
      title: `OFAC-listed vessel ${v.name ?? v.imo} active in the last ${h.days} days: ${h.encounters} encounters, ${h.gaps} AIS gaps, ${h.portVisits} port visits`,
      score: Math.min(90, 72 + (h.encounters ? 8 : 0) + (h.gaps ? 5 : 0)),
      entity: v.imo ? `IMO ${v.imo}` : undefined,
      evidence: [
        { source: 'ofac', text: `IMO ${v.imo} is on the OFAC SDN list` },
        ...h.recent.slice(0, 3).map((x) => ({ source: 'gfw', text: `${x.kind.replace('_', ' ')} ${x.start.slice(0, 10)} to ${x.end.slice(0, 10)}${x.detail ? `: ${x.detail}` : ''}`, url: v.url ?? undefined })),
        ...(lastPort ? [{ source: 'gfw', text: `last port call: ${lastPort.detail ?? '?'} ${lastPort.end.slice(0, 10)}` }] : []),
      ],
      createdAt: now,
    });
  }
  for (const sig of signals) ctx.graph.saveSignal(sig);
  return { module: 'darkships', input: query, generatedAt: now, result: out, signals, provenance };
}
