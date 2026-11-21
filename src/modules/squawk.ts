/**
 * Squawk: aircraft currently transmitting a transponder emergency code, worldwide, from adsb.lol (keyless).
 *   7500 unlawful interference (hijack), 7700 general emergency, 7600 radio failure.
 * Each aircraft gets its registration and type (adsb.lol database, then hexdb.io when missing) and the nearest
 * airport. Aircraft on the ground and stationary or long-stale positions are left out: those are mostly
 * maintenance tests and transponders left on the wrong code at the gate.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { aircraftInfo, bySquawk, EMERGENCY_CODES, type AircraftState, type EmergencyCode } from '../sources/aircraft.js';
import { airportLabel, airports, nearestAirport } from '../sources/airports.js';

export interface SquawkAircraft {
  code: EmergencyCode;
  meaning: string;
  hex: string;
  callsign: string | null;
  registration: string | null;
  type: string | null;
  owner: string | null;
  lat: number | null;
  lon: number | null;
  altFt: number | null;
  speedKt: number | null;
  track: number | null;
  /** adsb.lol `emergency` field (general, nordo, unlawful, minfuel...) when the transponder sets it. */
  emergency: string | null;
  seenSec: number | null;
  nearestAirport: { name: string; ident: string; km: number } | null;
  url: string;
}

export interface Squawks {
  total: number;
  byCode: Record<EmergencyCode, number>;
  aircraft: SquawkAircraft[];
  /** Left out as ground tests, stationary or stale. */
  ignored: number;
}

const ORDER: EmergencyCode[] = ['7500', '7700', '7600'];
const BASE_SCORE: Record<EmergencyCode, number> = { '7500': 90, '7700': 70, '7600': 55 };

/** True for squawks that are almost certainly not a real airborne emergency. */
export function isGroundOrTest(a: AircraftState, maxSeenSec = 120): boolean {
  if (a.lat === null || a.lon === null) return true;
  if ((a.seenSec ?? 0) > maxSeenSec) return true;
  const slow = (a.speedKt ?? 0) < 40;
  if (a.onGround && slow) return true;
  if ((a.altFt === null || a.altFt <= 0) && slow) return true;
  return false;
}

export async function squawks(ctx: Ctx, opts: { codes?: EmergencyCode[]; lookup?: boolean } = {}): Promise<ModuleResult<Squawks>> {
  const now = ctx.now().toISOString();
  const codes = (opts.codes?.length ? opts.codes : ORDER).filter((c) => c in EMERGENCY_CODES);
  const provenance: Provenance[] = [];
  const lists = await Promise.all(codes.map(async (code) => ({ code, r: await bySquawk(ctx, code) })));
  const kept: { code: EmergencyCode; a: AircraftState }[] = [];
  let ignored = 0;
  const seen = new Set<string>();
  for (const { code, r } of lists) {
    provenance.push(r.prov);
    for (const a of r.data ?? []) {
      // The squawk endpoint matches on the current code; double-check in case of a stale cache entry.
      if (a.squawk && a.squawk !== code) continue;
      if (seen.has(a.hex)) continue;
      seen.add(a.hex);
      if (isGroundOrTest(a)) ignored++;
      else kept.push({ code, a });
    }
  }

  const ap = kept.length ? await airports(ctx) : null;
  if (ap) provenance.push(ap.prov);
  const out: SquawkAircraft[] = [];
  for (const { code, a } of kept) {
    let registration = a.registration;
    let type = a.type;
    let owner: string | null = null;
    if (opts.lookup !== false && (!registration || !type) && out.length < 15) {
      const info = await aircraftInfo(ctx, a.hex);
      if (info.data) {
        registration ??= info.data.registration;
        type ??= info.data.typeCode ?? info.data.type;
        owner = info.data.owner;
      }
    }
    const near = ap?.data && a.lat !== null && a.lon !== null ? nearestAirport(ap.data, a.lat, a.lon) : null;
    out.push({
      code,
      meaning: EMERGENCY_CODES[code],
      hex: a.hex,
      callsign: a.callsign,
      registration,
      type,
      owner,
      lat: a.lat,
      lon: a.lon,
      altFt: a.altFt,
      speedKt: a.speedKt,
      track: a.track,
      emergency: a.emergency && a.emergency !== 'none' ? a.emergency : null,
      seenSec: a.seenSec,
      nearestAirport: near ? { name: airportLabel(near.airport), ident: near.airport.ident, km: Math.round(near.km) } : null,
      url: `https://globe.adsb.lol/?icao=${a.hex}`,
    });
  }
  out.sort((x, y) => ORDER.indexOf(x.code) - ORDER.indexOf(y.code));

  const signals: Signal[] = out.map((x) => {
    const who = [x.callsign, x.registration, x.type].filter(Boolean).join(' / ') || `hex ${x.hex}`;
    const where = x.nearestAirport ? `${x.nearestAirport.km} km from ${x.nearestAirport.name}` : `${x.lat!.toFixed(2)}, ${x.lon!.toFixed(2)}`;
    // A matching emergency flag from the transponder makes the code more credible than a fat-fingered squawk.
    const confirmed = x.emergency !== null;
    return {
      id: signalId('squawk', x.hex, x.code, now.slice(0, 13)),
      module: 'squawk',
      title: `Squawk ${x.code} (${x.meaning}): ${who} ${where}`,
      score: Math.min(98, BASE_SCORE[x.code] + (confirmed ? 5 : 0)),
      entity: x.registration ?? x.hex,
      evidence: [
        {
          source: 'adsb.lol',
          text: `${who} squawking ${x.code} at ${x.altFt ?? '?'} ft, ${x.speedKt === null ? '?' : Math.round(x.speedKt)} kt, position ${x.lat!.toFixed(3)}, ${x.lon!.toFixed(3)}${confirmed ? `, emergency flag "${x.emergency}"` : ''}${x.seenSec !== null ? `, seen ${Math.round(x.seenSec)} s ago` : ''}`,
          url: x.url,
        },
      ],
      createdAt: now,
    };
  });
  for (const s of signals) ctx.graph.saveSignal(s);
  const byCode = { '7500': 0, '7600': 0, '7700': 0 } as Record<EmergencyCode, number>;
  for (const x of out) byCode[x.code]++;
  return { module: 'squawk', input: codes.join(','), generatedAt: now, result: { total: out.length, byCode, aircraft: out, ignored }, signals, provenance };
}
