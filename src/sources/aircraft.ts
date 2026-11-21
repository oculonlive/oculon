import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

/** Live state of one aircraft, normalized across ADS-B providers. Altitudes in feet, speed in knots. */
export interface AircraftState {
  hex: string;
  registration: string | null;
  type: string | null;
  callsign: string | null;
  lat: number | null;
  lon: number | null;
  altFt: number | null;
  onGround: boolean;
  speedKt: number | null;
  track: number | null;
  squawk: string | null;
  /** Seconds since the last message. */
  seenSec: number | null;
  source: 'adsb.lol' | 'opensky';
  /** adsb.lol `emergency` field as the transponder reports it: none, general, lifeguard, minfuel, nordo, unlawful, downed. */
  emergency?: string | null;
  /** adsb.lol database flags: 1 military, 2 interesting, 4 PIA (privacy ICAO address), 8 LADD (FAA limited display). */
  dbFlags?: number;
}

export interface AircraftInfo {
  hex: string;
  registration: string | null;
  manufacturer: string | null;
  type: string | null;
  typeCode: string | null;
  owner: string | null;
}

interface AdsbLolAc {
  hex: string;
  r?: string;
  t?: string;
  flight?: string;
  lat?: number;
  lon?: number;
  alt_baro?: number | 'ground';
  gs?: number;
  track?: number;
  squawk?: string;
  seen?: number;
  seen_pos?: number;
  desc?: string;
  ownOp?: string;
  emergency?: string;
  dbFlags?: number;
}

export function fromAdsbLol(a: AdsbLolAc): AircraftState {
  return {
    hex: a.hex.toLowerCase().replace(/^~/, ''),
    registration: a.r?.trim() || null,
    type: a.t?.trim() || null,
    callsign: a.flight?.trim() || null,
    lat: a.lat ?? null,
    lon: a.lon ?? null,
    altFt: typeof a.alt_baro === 'number' ? a.alt_baro : a.alt_baro === 'ground' ? 0 : null,
    onGround: a.alt_baro === 'ground',
    speedKt: a.gs ?? null,
    track: a.track ?? null,
    squawk: a.squawk ?? null,
    seenSec: a.seen_pos ?? a.seen ?? null,
    source: 'adsb.lol',
    ...(a.emergency !== undefined ? { emergency: a.emergency } : {}),
    ...(a.dbFlags !== undefined ? { dbFlags: a.dbFlags } : {}),
  };
}

const ADSB = 'https://api.adsb.lol/v2';

async function adsbList(ctx: Ctx, path: string, ttlSec = 30): Promise<Sourced<AircraftState[]>> {
  const r = await ctx.http.get<{ ac?: AdsbLolAc[] }>(`${ADSB}${path}`, { source: 'adsb.lol', ttlSec, timeoutMs: 30_000 });
  return { data: r.data ? (r.data.ac ?? []).map(fromAdsbLol) : null, prov: r.prov };
}

export const byHex = (ctx: Ctx, hex: string) => adsbList(ctx, `/hex/${enc(hex.toLowerCase())}`);
export const byRegistration = (ctx: Ctx, reg: string) => adsbList(ctx, `/reg/${enc(reg.toUpperCase())}`);
/** Aircraft flagged as military in the adsb.lol database, worldwide. */
export const military = (ctx: Ctx) => adsbList(ctx, '/mil', 120);
/** Aircraft broadcasting a callsign (flight number such as "UAE44"). */
export const byCallsign = (ctx: Ctx, callsign: string) => adsbList(ctx, `/callsign/${enc(callsign.trim().toUpperCase())}`);

export type EmergencyCode = '7500' | '7600' | '7700';
/** Transponder emergency codes: 7500 unlawful interference (hijack), 7600 radio failure, 7700 general emergency. */
export const EMERGENCY_CODES: Record<EmergencyCode, string> = { '7500': 'hijack / unlawful interference', '7600': 'radio failure', '7700': 'general emergency' };
/** Aircraft currently squawking a given code, worldwide. */
export const bySquawk = (ctx: Ctx, code: string) => adsbList(ctx, `/sqk/${enc(code)}`, 30);
/** Aircraft on the FAA LADD list (owner asked to limit public display), worldwide. Large response (~1-2k aircraft). */
export const ladd = (ctx: Ctx) => adsbList(ctx, '/ladd', 300);
/** Aircraft using an FAA PIA (privacy ICAO address), i.e. a temporary hex not tied to the real registration. */
export const privacy = (ctx: Ctx) => adsbList(ctx, '/pia', 300);

/** Aircraft within `nm` nautical miles of a point (max 250), with the military flag from adsb.lol's database. */
export async function aroundPoint(ctx: Ctx, lat: number, lon: number, nm: number): Promise<Sourced<(AircraftState & { military: boolean })[]>> {
  const r = await ctx.http.get<{ ac?: (AdsbLolAc & { dbFlags?: number })[] }>(`${ADSB}/point/${lat.toFixed(4)}/${lon.toFixed(4)}/${Math.min(250, Math.max(1, Math.round(nm)))}`, {
    source: 'adsb.lol',
    ttlSec: 60,
    timeoutMs: 30_000,
  });
  return { data: r.data ? (r.data.ac ?? []).map((a) => ({ ...fromAdsbLol(a), military: ((a.dbFlags ?? 0) & 1) === 1 })) : null, prov: r.prov };
}

/** Fallback live state from OpenSky (anonymous access). Its altitude is in meters; converted here. */
export async function openskyState(ctx: Ctx, hex: string): Promise<Sourced<AircraftState | null>> {
  const r = await ctx.http.get<{ states?: unknown[][] | null }>(`https://opensky-network.org/api/states/all?icao24=${enc(hex.toLowerCase())}`, {
    source: 'opensky',
    ttlSec: 30,
  });
  const s = r.data?.states?.[0];
  if (!r.data) return { data: null, prov: r.prov };
  if (!s) return { data: null, prov: { ...r.prov, note: 'aircraft not currently seen' } };
  const n = (v: unknown) => (typeof v === 'number' ? v : null);
  const altM = n(s[7]);
  return {
    data: {
      hex: String(s[0]),
      registration: null,
      type: null,
      callsign: typeof s[1] === 'string' ? s[1].trim() || null : null,
      lon: n(s[5]),
      lat: n(s[6]),
      altFt: altM === null ? null : Math.round(altM * 3.28084),
      onGround: s[8] === true,
      speedKt: n(s[9]) === null ? null : Math.round(n(s[9])! * 1.94384),
      track: n(s[10]),
      squawk: typeof s[14] === 'string' ? s[14] : null,
      seenSec: n(s[4]) === null ? null : Math.max(0, Math.round(Date.now() / 1000 - n(s[4])!)),
      source: 'opensky',
    },
    prov: r.prov,
  };
}

/** Registration -> ICAO 24-bit address (hex) via hexdb.io. */
export async function hexForRegistration(ctx: Ctx, reg: string): Promise<Sourced<string>> {
  const r = await ctx.http.get<string>(`https://hexdb.io/reg-hex?reg=${enc(reg.toUpperCase())}`, { source: 'hexdb', as: 'text', ttlSec: 30 * 86_400 });
  const hex = r.data?.trim();
  return { data: hex && /^[0-9a-f]{6}$/i.test(hex) ? hex.toLowerCase() : null, prov: r.prov };
}

export async function aircraftInfo(ctx: Ctx, hex: string): Promise<Sourced<AircraftInfo>> {
  const r = await ctx.http.get<Record<string, string>>(`https://hexdb.io/api/v1/aircraft/${enc(hex.toUpperCase())}`, {
    source: 'hexdb',
    ttlSec: 30 * 86_400,
  });
  const d = r.data;
  if (!d || !d.ModeS) return { data: null, prov: r.prov };
  return {
    data: {
      hex: d.ModeS.toLowerCase(),
      registration: d.Registration || null,
      manufacturer: d.Manufacturer || null,
      type: d.Type || null,
      typeCode: d.ICAOTypeCode || null,
      owner: d.RegisteredOwners || null,
    },
    prov: r.prov,
  };
}

export const isHex = (s: string) => /^[0-9a-f]{6}$/i.test(s.trim());
