/**
 * Geofences: named boxes on the map. Each check looks inside every fence for military aircraft, military
 * vessels, earthquakes and natural events, and reports only what is NEW since the previous check.
 * The first check of a fence records a baseline.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { Provenance, Signal } from '../core/types.js';
import { collect, shipType } from '../sources/ais.js';
import { aroundPoint } from '../sources/aircraft.js';
import { eonetEvents, geocode } from '../sources/earth.js';
import { recentQuakes } from '../sources/usgs.js';
import { ROLES } from './falcon.js';

export const FENCE_KINDS = ['air', 'sea', 'quake', 'events'] as const;
export type FenceKind = (typeof FENCE_KINDS)[number];

export interface Fence {
  id: number;
  name: string;
  south: number;
  west: number;
  north: number;
  east: number;
  kinds: FenceKind[];
  createdAt: string;
  lastRun: string | null;
  lastState: FenceState | null;
}

export interface FenceState {
  milAircraft: Record<string, string>;
  milVessels: Record<string, string>;
  quakes: Record<string, string>;
  events: Record<string, string>;
}

interface Row {
  id: number;
  name: string;
  south: number;
  west: number;
  north: number;
  east: number;
  kinds: string;
  created_at: number;
  last_run: number | null;
  last_state: string | null;
}

const toFence = (r: Row): Fence => ({
  id: r.id,
  name: r.name,
  south: r.south,
  west: r.west,
  north: r.north,
  east: r.east,
  kinds: JSON.parse(r.kinds) as FenceKind[],
  createdAt: new Date(r.created_at).toISOString(),
  lastRun: r.last_run ? new Date(r.last_run).toISOString() : null,
  lastState: r.last_state ? (JSON.parse(r.last_state) as FenceState) : null,
});

export function validBox(s: number, w: number, n: number, e: number): boolean {
  return [s, w, n, e].every(Number.isFinite) && s >= -90 && n <= 90 && s < n && w >= -180 && e <= 180 && w < e && n - s <= 30 && e - w <= 30;
}

export function addFence(ctx: Ctx, name: string, box: [number, number, number, number], kinds: string[] = [...FENCE_KINDS]): Fence {
  const [s, w, n, e] = box;
  if (!validBox(s, w, n, e)) throw new Error('invalid box: need south<north, west<east, at most 30 degrees per side');
  const k = kinds.filter((x): x is FenceKind => (FENCE_KINDS as readonly string[]).includes(x));
  if (!k.length) throw new Error(`kinds must include one of: ${FENCE_KINDS.join(', ')}`);
  const clean = name.trim().slice(0, 60) || 'fence';
  const id = Number(ctx.store.db.prepare('INSERT INTO fences (name, south, west, north, east, kinds, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(clean, s, w, n, e, JSON.stringify(k), ctx.now().getTime()).lastInsertRowid);
  return listFences(ctx).find((f) => f.id === id)!;
}

/** Box of `radiusKm` around a geocoded place. */
export async function boxAround(ctx: Ctx, place: string, radiusKm = 100): Promise<[number, number, number, number]> {
  const g = await geocode(ctx, place);
  const p = g.data?.[0];
  if (!p) throw new Error(`place not found: ${place}`);
  const dLat = radiusKm / 111;
  const dLon = radiusKm / (111 * Math.max(0.2, Math.cos((p.lat * Math.PI) / 180)));
  return [p.lat - dLat, p.lon - dLon, p.lat + dLat, p.lon + dLon].map((v) => Math.round(v * 1000) / 1000) as [number, number, number, number];
}

export function listFences(ctx: Ctx): Fence[] {
  return (ctx.store.db.prepare('SELECT * FROM fences ORDER BY id').all() as unknown as Row[]).map(toFence);
}

export function removeFence(ctx: Ctx, id: number): boolean {
  return ctx.store.db.prepare('DELETE FROM fences WHERE id = ?').run(id).changes > 0;
}

const inside = (f: Fence, lat: number | null | undefined, lon: number | null | undefined) => lat != null && lon != null && lat >= f.south && lat <= f.north && lon >= f.west && lon <= f.east;

export interface FenceCheck {
  fence: Fence;
  baseline: boolean;
  changes: string[];
  counts: { milAircraft: number; milVessels: number; quakes: number; events: number };
}

/** Check every fence once. Quakes and natural events are fetched once and shared across fences. */
export async function checkFences(ctx: Ctx, opts: { aisSeconds?: number } = {}): Promise<{ checks: FenceCheck[]; signals: Signal[]; provenance: Provenance[] }> {
  const fences = listFences(ctx);
  const provenance: Provenance[] = [];
  if (!fences.length) return { checks: [], signals: [], provenance };
  const needQuake = fences.some((f) => f.kinds.includes('quake'));
  const needEvents = fences.some((f) => f.kinds.includes('events'));
  const [quakes, events] = await Promise.all([needQuake ? recentQuakes(ctx) : Promise.resolve(null), needEvents ? eonetEvents(ctx, 7) : Promise.resolve(null)]);
  if (quakes) provenance.push(quakes.prov);
  if (events) provenance.push(events.prov);

  const checks: FenceCheck[] = [];
  const signals: Signal[] = [];
  const nowIso = ctx.now().toISOString();
  for (const f of fences) {
    const prev = f.lastState;
    const state: FenceState = { milAircraft: {}, milVessels: {}, quakes: {}, events: {} };
    if (f.kinds.includes('air')) {
      const lat = (f.south + f.north) / 2;
      const lon = (f.west + f.east) / 2;
      const halfDiagKm = Math.hypot((f.north - f.south) * 111, (f.east - f.west) * 111 * Math.cos((lat * Math.PI) / 180)) / 2;
      const r = await aroundPoint(ctx, lat, lon, halfDiagKm / 1.852);
      provenance.push(r.prov);
      for (const a of r.data ?? []) if (a.military && inside(f, a.lat, a.lon)) state.milAircraft[a.hex] = `${a.type ?? '?'}${a.type && ROLES[a.type] ? ` (${ROLES[a.type]})` : ''} ${a.callsign ?? a.registration ?? a.hex}`.trim();
    }
    if (f.kinds.includes('sea')) {
      const c = await collect(
        [
          [
            [f.south, f.west],
            [f.north, f.east],
          ],
        ],
        opts.aisSeconds ?? 20,
      );
      provenance.push(c.prov);
      for (const v of c.vessels) if (shipType(v.typeCode) === 'military') state.milVessels[String(v.mmsi)] = v.name ?? String(v.mmsi);
    }
    if (f.kinds.includes('quake')) for (const q of (quakes?.data ?? []).filter((x) => inside(f, x.lat, x.lon))) state.quakes[q.id] = `M${q.mag.toFixed(1)} ${q.place}`;
    if (f.kinds.includes('events')) for (const e of (events?.data ?? []).filter((x) => inside(f, x.lat, x.lon))) state.events[e.id] = e.title;

    const changes: string[] = [];
    if (prev) {
      const fresh = (now: Record<string, string>, before: Record<string, string>) => Object.entries(now).filter(([k]) => !(k in before)).map(([, v]) => v);
      for (const v of fresh(state.milAircraft, prev.milAircraft)) changes.push(`military aircraft entered: ${v}`);
      for (const v of fresh(state.milVessels, prev.milVessels)) changes.push(`military vessel appeared: ${v}`);
      for (const v of fresh(state.quakes, prev.quakes)) changes.push(`earthquake: ${v}`);
      for (const v of fresh(state.events, prev.events)) changes.push(`natural event: ${v}`);
    }
    // Aircraft come and go; keep a 6-hour memory so a plane circling in and out is not reported every check.
    const keep = prev && f.lastRun && Date.now() - Date.parse(f.lastRun) < 6 * 3_600_000 ? { ...prev.milAircraft, ...state.milAircraft } : state.milAircraft;
    const stored: FenceState = { ...state, milAircraft: keep, milVessels: { ...(prev?.milVessels ?? {}), ...state.milVessels } };
    ctx.store.db.prepare('UPDATE fences SET last_run = ?, last_state = ? WHERE id = ?').run(ctx.now().getTime(), JSON.stringify(stored), f.id);
    checks.push({ fence: f, baseline: !prev, changes, counts: { milAircraft: Object.keys(state.milAircraft).length, milVessels: Object.keys(state.milVessels).length, quakes: Object.keys(state.quakes).length, events: Object.keys(state.events).length } });
    if (changes.length) {
      signals.push({
        id: signalId('fence', String(f.id), changes.join('|')),
        module: 'fence',
        title: `Fence ${f.name}: ${changes[0]}${changes.length > 1 ? ` (+${changes.length - 1} more)` : ''}`,
        score: Math.min(90, (changes.some((c) => /military/.test(c)) ? 65 : 55) + (changes.length - 1) * 5),
        evidence: changes.map((c) => ({ source: `fence:${f.name}`, text: c })),
        createdAt: nowIso,
      });
    }
  }
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { checks, signals, provenance };
}
