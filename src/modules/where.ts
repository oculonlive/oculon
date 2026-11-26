/**
 * Where and when was this photo taken? Reads the GPS position and capture time from the photo's EXIF data,
 * names the place (OpenStreetMap Nominatim), and recalls the weather and daylight there at that hour (Open-Meteo
 * historical weather, sun position computed here), so a claim like "taken yesterday in the storm" can be
 * checked against the file. EXIF can be edited and most apps strip it; the report says what the file claims,
 * and where the claims disagree with each other.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export interface WhereReport {
  name: string;
  verdict: 'location found' | 'time found, no location' | 'no location data' | 'conflicting data';
  risk: number;
  gps: { lat: number; lon: number; altitudeM: number | null; map: string } | null;
  place: string | null;
  country: string | null;
  taken: { local: string | null; utcOffset: string | null; gpsUtc: string | null; modified: string | null } | null;
  camera: string | null;
  software: string | null;
  weather: { hour: string; tempC: number | null; precipMm: number | null; cloudPct: number | null; condition: string | null; daylight: boolean | null; sunElevation: number | null } | null;
  reasons: string[];
  notes: string[];
  advice: string[];
}

type Exif = { gps: { lat: number; lon: number; alt: number | null; date: string | null; time: string | null } | null; dto: string | null; offset: string | null; modified: string | null; make: string | null; model: string | null; software: string | null };

/** EXIF from a JPEG APP1 segment or a PNG eXIf chunk: GPS, capture time, camera. */
export function readExif(b: Buffer): Exif {
  let tiff: Buffer | null = null;
  if (b[0] === 0xff && b[1] === 0xd8) {
    let i = 2;
    while (i + 4 < b.length && b[i] === 0xff) {
      const m = b[i + 1]!;
      if (m === 0xda || m === 0xd9) break;
      const len = b.readUInt16BE(i + 2);
      if (m === 0xe1 && b.toString('latin1', i + 4, i + 10) === 'Exif\0\0') { tiff = b.subarray(i + 10, i + 2 + len); break; }
      i += 2 + len;
    }
  } else if (b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    let i = 8;
    while (i + 12 <= b.length) {
      const len = b.readUInt32BE(i), t = b.toString('latin1', i + 4, i + 8);
      if (t === 'eXIf') { tiff = b.subarray(i + 8, i + 8 + len); break; }
      if (t === 'IEND') break;
      i += 12 + len;
    }
  }
  const out: Exif = { gps: null, dto: null, offset: null, modified: null, make: null, model: null, software: null };
  if (!tiff || tiff.length < 8) return out;
  const le = tiff.toString('latin1', 0, 2) === 'II';
  const u16 = (o: number) => (le ? tiff!.readUInt16LE(o) : tiff!.readUInt16BE(o));
  const u32 = (o: number) => (le ? tiff!.readUInt32LE(o) : tiff!.readUInt32BE(o));
  const ifd = (off: number): Map<number, { type: number; count: number; at: number }> => {
    const m = new Map<number, { type: number; count: number; at: number }>();
    if (off + 2 > tiff!.length) return m;
    const n = u16(off);
    for (let k = 0; k < n && off + 2 + k * 12 + 12 <= tiff!.length; k++) {
      const e = off + 2 + k * 12;
      const type = u16(e + 2), count = u32(e + 4);
      const size = ({ 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 } as Record<number, number>)[type] ?? 1;
      m.set(u16(e), { type, count, at: size * count > 4 ? u32(e + 8) : e + 8 });
    }
    return m;
  };
  const str = (e?: { count: number; at: number }) => (e && e.at + e.count <= tiff!.length ? tiff!.toString('latin1', e.at, e.at + e.count).replace(/\0+$/, '').trim() || null : null);
  const rats = (e?: { count: number; at: number }) => (e && e.at + e.count * 8 <= tiff!.length ? Array.from({ length: e.count }, (_, k) => { const d = u32(e.at + k * 8 + 4); return d ? u32(e.at + k * 8) / d : 0; }) : null);
  try {
    const i0 = ifd(u32(4));
    out.make = str(i0.get(0x010f)); out.model = str(i0.get(0x0110)); out.software = str(i0.get(0x0131)); out.modified = str(i0.get(0x0132));
    const ex = i0.get(0x8769);
    if (ex) { const e = ifd(u32(ex.at)); out.dto = str(e.get(0x9003)) ?? str(e.get(0x9004)); out.offset = str(e.get(0x9011)); }
    const g = i0.get(0x8825);
    if (g) {
      const gi = ifd(u32(g.at));
      const lat = rats(gi.get(2)), lon = rats(gi.get(4));
      if (lat?.length === 3 && lon?.length === 3) {
        const dms = (r: number[]) => r[0]! + r[1]! / 60 + r[2]! / 3600;
        const la = dms(lat) * (/S/i.test(str(gi.get(1)) ?? '') ? -1 : 1), lo = dms(lon) * (/W/i.test(str(gi.get(3)) ?? '') ? -1 : 1);
        const alt = rats(gi.get(6))?.[0] ?? null;
        const t = rats(gi.get(7));
        out.gps = { lat: la, lon: lo, alt: alt === null ? null : alt * (tiff![gi.get(5)?.at ?? 0] === 1 ? -1 : 1), date: str(gi.get(29)), time: t?.length === 3 ? `${String(Math.floor(t[0]!)).padStart(2, '0')}:${String(Math.floor(t[1]!)).padStart(2, '0')}:${String(Math.floor(t[2]!)).padStart(2, '0')}` : null };
      }
    }
  } catch { /* a damaged EXIF block gives what was read so far */ }
  return out;
}

/** Sun elevation in degrees (NOAA approximation). */
export function sunElevation(lat: number, lon: number, utc: Date): number {
  const d = utc.getTime() / 86_400_000 - 10_957.5; // days since J2000
  const g = ((357.529 + 0.98560028 * d) % 360) * (Math.PI / 180);
  const q = (280.459 + 0.98564736 * d) % 360;
  const L = (q + 1.915 * Math.sin(g) + 0.02 * Math.sin(2 * g)) * (Math.PI / 180);
  const e = (23.439 - 0.00000036 * d) * (Math.PI / 180);
  const dec = Math.asin(Math.sin(e) * Math.sin(L));
  const ra = Math.atan2(Math.cos(e) * Math.sin(L), Math.cos(L));
  const gmst = (18.697374558 + 24.06570982441908 * d) % 24;
  const ha = ((gmst * 15 + lon) * (Math.PI / 180)) - ra;
  const la = lat * (Math.PI / 180);
  return Math.round(Math.asin(Math.sin(la) * Math.sin(dec) + Math.cos(la) * Math.cos(dec) * Math.cos(ha)) * (180 / Math.PI) * 10) / 10;
}

const WMO: Record<number, string> = { 0: 'clear sky', 1: 'mainly clear', 2: 'partly cloudy', 3: 'overcast', 45: 'fog', 48: 'fog', 51: 'light drizzle', 53: 'drizzle', 55: 'heavy drizzle', 61: 'light rain', 63: 'rain', 65: 'heavy rain', 71: 'light snow', 73: 'snow', 75: 'heavy snow', 80: 'rain showers', 81: 'rain showers', 82: 'violent rain showers', 95: 'thunderstorm', 96: 'thunderstorm with hail', 99: 'thunderstorm with hail' };

export async function whereCheck(ctx: Ctx, file: Buffer, name = 'photo.jpg'): Promise<ModuleResult<WhereReport>> {
  if (!file.length) throw new Error('the file is empty');
  if (!(file[0] === 0xff && file[1] === 0xd8) && file.readUInt32BE(0) !== 0x89504e47) throw new Error('not a JPEG or PNG photo (HEIC from iPhones: export or share it as JPEG first)');
  const x = readExif(file);
  const provenance: Provenance[] = [{ source: 'oculon-exif', url: 'local', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: 'EXIF read from the file here' }];
  const reasons: string[] = [], notes: string[] = [];
  const camera = [x.make, x.model].filter(Boolean).join(' ') || null;
  const toIso = (s: string | null) => (s && /^\d{4}:\d{2}:\d{2} \d{2}:\d{2}/.test(s) ? s.replace(/^(\d{4}):(\d{2}):(\d{2}) /, '$1-$2-$3T') : null);
  const local = toIso(x.dto);
  const gpsUtc = x.gps?.date && x.gps.time ? `${x.gps.date.replace(/:/g, '-')}T${x.gps.time}Z` : null;
  let conflict = false;
  if (x.gps && Math.abs(x.gps.lat) < 0.0001 && Math.abs(x.gps.lon) < 0.0001) { x.gps = null; notes.push('The GPS position is 0,0 (no fix): ignored.'); }
  let gps: WhereReport['gps'] = null, place: string | null = null, country: string | null = null, weather: WhereReport['weather'] = null;
  if (x.gps) {
    gps = { lat: Math.round(x.gps.lat * 1e6) / 1e6, lon: Math.round(x.gps.lon * 1e6) / 1e6, altitudeM: x.gps.alt === null ? null : Math.round(x.gps.alt), map: `https://www.openstreetmap.org/?mlat=${x.gps.lat.toFixed(6)}&mlon=${x.gps.lon.toFixed(6)}#map=16/${x.gps.lat.toFixed(5)}/${x.gps.lon.toFixed(5)}` };
    const r = await ctx.http.get<{ display_name?: string; address?: { country?: string } }>(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&zoom=16&lat=${gps.lat}&lon=${gps.lon}`, { source: 'nominatim', ttlSec: 30 * 86_400 });
    provenance.push(r.prov);
    place = r.data?.display_name ?? null; country = r.data?.address?.country ?? null;
  }
  // Weather and daylight at that hour, when both a place and a time are known.
  if (gps && (local || gpsUtc)) {
    const day = (local ?? gpsUtc)!.slice(0, 10);
    const age = (ctx.now().getTime() - Date.parse(day)) / 86_400_000;
    const url = age > 6
      ? `https://archive-api.open-meteo.com/v1/archive?latitude=${gps.lat}&longitude=${gps.lon}&start_date=${day}&end_date=${day}&hourly=temperature_2m,precipitation,cloud_cover,weather_code,is_day&timezone=auto`
      : `https://api.open-meteo.com/v1/forecast?latitude=${gps.lat}&longitude=${gps.lon}&start_date=${day}&end_date=${day}&hourly=temperature_2m,precipitation,cloud_cover,weather_code,is_day&timezone=auto`;
    const w = age >= 0 && Date.parse(day) > Date.parse('1940-01-01') ? await ctx.http.get<{ utc_offset_seconds?: number; hourly?: { time: string[]; temperature_2m: (number | null)[]; precipitation: (number | null)[]; cloud_cover: (number | null)[]; weather_code: (number | null)[]; is_day: (number | null)[] } }>(url, { source: 'open-meteo', ttlSec: 30 * 86_400 }) : null;
    if (w) provenance.push(w.prov);
    const off = w?.data?.utc_offset_seconds ?? null;
    // The capture hour in local time: EXIF local time, or the GPS UTC time moved to the place's offset.
    const localHour = local ? local.slice(0, 13) : gpsUtc && off !== null ? new Date(Date.parse(gpsUtc) + off * 1000).toISOString().slice(0, 13) : null;
    const h = w?.data?.hourly;
    const k = h && localHour ? h.time.findIndex((t) => t.startsWith(localHour)) : -1;
    // Same moment as the weather hour: the local capture time when there is one.
    const utc = local && off !== null ? new Date(Date.parse(`${local}Z`) - off * 1000) : gpsUtc ? new Date(gpsUtc) : null;
    const elev = utc && !Number.isNaN(utc.getTime()) ? sunElevation(gps.lat, gps.lon, utc) : null;
    if (h && k >= 0) weather = { hour: `${h.time[k]} local`, tempC: h.temperature_2m[k] ?? null, precipMm: h.precipitation[k] ?? null, cloudPct: h.cloud_cover[k] ?? null, condition: h.weather_code[k] !== null && h.weather_code[k] !== undefined ? WMO[h.weather_code[k]!] ?? `code ${h.weather_code[k]}` : null, daylight: h.is_day[k] === null || h.is_day[k] === undefined ? null : h.is_day[k] === 1, sunElevation: elev };
    else if (elev !== null) weather = { hour: localHour ?? '', tempC: null, precipMm: null, cloudPct: null, condition: null, daylight: elev > -0.8, sunElevation: elev };
    if (weather) reasons.push(`at ${weather.hour}: ${[weather.condition, weather.tempC !== null ? `${weather.tempC} °C` : null, weather.precipMm ? `${weather.precipMm} mm of rain that hour` : null, weather.daylight === null ? null : weather.daylight ? 'daylight' : 'dark (the sun was down)'].filter(Boolean).join(', ')}`);
    // Local EXIF time and GPS UTC time should agree up to the place's offset.
    if (local && gpsUtc && off !== null) {
      const diff = Math.abs(Date.parse(`${local}Z`) - off * 1000 - Date.parse(gpsUtc)) / 60_000;
      if (diff > 90) { conflict = true; reasons.push(`the capture time (${local.replace('T', ' ')} local) and the GPS time (${gpsUtc.replace('T', ' ').replace('Z', ' UTC')}) are ${Math.round(diff / 60)} hours apart: one of them was changed, or the camera clock was wrong`); }
    }
  }
  if (x.modified && local && Math.abs(Date.parse(toIso(x.modified) ?? local) - Date.parse(local)) > 86_400_000) notes.push(`Saved again on ${toIso(x.modified)!.replace('T', ' ')}, after it was taken.`);
  if (x.software) notes.push(`Last saved by ${x.software}.`);
  if (!gps) notes.push(local ? 'The photo has a capture time but no position. Phones leave the position out when location is off for the camera.' : 'No position and no capture time: the data was removed (most apps and social networks strip it) or never written.');
  notes.push('EXIF can be edited with free tools; treat it as a claim made by the file, not as proof.');
  const verdict: WhereReport['verdict'] = conflict ? 'conflicting data' : gps ? 'location found' : local ? 'time found, no location' : 'no location data';
  if (place) reasons.unshift(`taken at ${place}`);
  const advice = gps ? ['Compare the place and the weather with what the photo shows and what the sender claims.', 'Before you share this photo, remove its location: it reveals where it was taken.'] : ['Ask for the original file (not a forwarded copy) if you need the time and place.'];
  return { module: 'where', input: name.slice(0, 120), generatedAt: ctx.now().toISOString(), signals: [], provenance, result: { name: name.slice(0, 120), verdict, risk: conflict ? 40 : 0, gps, place, country, taken: local || gpsUtc || x.modified ? { local, utcOffset: x.offset, gpsUtc, modified: toIso(x.modified) } : null, camera, software: x.software, weather, reasons, notes, advice } };
}
