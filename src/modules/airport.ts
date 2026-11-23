/**
 * Airport status: is this airport running normally right now?
 *   aviationweather.gov (NOAA, no key, worldwide): the latest METAR (flight category, wind, visibility, ceiling)
 *     and the TAF forecast.
 *   FAA NAS status (no key, US airports): ground stops, ground delay programs, arrival and departure delays,
 *     closures.
 *   adsb.lol: aircraft squawking an emergency code within 150 km.
 * The airport is found by IATA or ICAO code, or by name, in OurAirports.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';
import { airportLabel, airports, haversineKm, type Airport } from '../sources/airports.js';
import { squawks } from './squawk.js';

export type AirportVerdict = 'normal' | 'weather watch' | 'delays' | 'disrupted';

export interface AirportStatus {
  airport: { ident: string; iata: string | null; name: string; city: string; country: string; lat: number; lon: number };
  verdict: AirportVerdict;
  points: string[];
  metar: { raw: string; time: string; category: string | null; windKt: number | null; gustKt: number | null; visibility: string | null; ceilingFt: number | null; tempC: number | null; weather: string | null } | null;
  taf: { raw: string; issued: string } | null;
  faa: { delays: { type: string; reason: string; detail: string }[]; checked: boolean };
  emergencies: { callsign: string | null; code: string; meaning: string; km: number }[];
}

/** Finds an airport by IATA ("JFK"), ICAO ("KJFK") or words of its name or city. */
export function findAirport(list: Airport[], q: string): Airport | null {
  const s = q.trim().toUpperCase();
  if (/^[A-Z]{3}$/.test(s)) return list.find((a) => a.iata === s) ?? null;
  if (/^[A-Z0-9]{4}$/.test(s)) { const a = list.find((x) => x.ident === s); if (a) return a; }
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  const hits = list.filter((a) => words.every((w) => `${a.name} ${a.city}`.toLowerCase().includes(w)));
  return hits.sort((a, b) => Number(b.type === 'large_airport') - Number(a.type === 'large_airport'))[0] ?? null;
}

interface Metar { rawOb?: string; reportTime?: string; fltCat?: string; wspd?: number | string; wgst?: number; visib?: string | number; temp?: number; wxString?: string; clouds?: { cover: string; base: number | null }[] }

async function metar(ctx: Ctx, icao: string): Promise<Sourced<AirportStatus['metar']>> {
  const r = await ctx.http.get<Metar[]>(`https://aviationweather.gov/api/data/metar?ids=${icao}&format=json`, { source: 'aviationweather', ttlSec: 600 });
  const m = r.data?.[0];
  if (!m?.rawOb) return { data: null, prov: r.prov };
  const ceiling = (m.clouds ?? []).filter((c) => /BKN|OVC|OVX/.test(c.cover) && c.base != null).map((c) => c.base!).sort((a, b) => a - b)[0] ?? null;
  return { data: { raw: m.rawOb, time: m.reportTime ?? '', category: m.fltCat ?? null, windKt: typeof m.wspd === 'number' ? m.wspd : null, gustKt: m.wgst ?? null, visibility: m.visib != null ? `${m.visib} SM` : null, ceilingFt: ceiling, tempC: m.temp ?? null, weather: m.wxString ?? null }, prov: r.prov };
}

async function taf(ctx: Ctx, icao: string): Promise<Sourced<AirportStatus['taf']>> {
  const r = await ctx.http.get<{ rawTAF?: string; issueTime?: string }[]>(`https://aviationweather.gov/api/data/taf?ids=${icao}&format=json`, { source: 'aviationweather', ttlSec: 1800 });
  const t = r.data?.[0];
  return { data: t?.rawTAF ? { raw: t.rawTAF, issued: t.issueTime ?? '' } : null, prov: r.prov };
}

const text = (xml: string, tag: string) => new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(xml)?.[1]?.trim() ?? '';

/** FAA NAS status XML → delays and closures for one airport (IATA code without the K). */
export function parseFaaStatus(xml: string, iata: string): AirportStatus['faa']['delays'] {
  const out: AirportStatus['faa']['delays'] = [];
  for (const block of xml.split('<Delay_type>').slice(1)) {
    const type = text(block, 'Name');
    const items = block.split(/<(?:Ground_Stop|Program|Delay|Airport)>/).slice(1);
    for (const it of items) {
      const arpt = text(it, 'ARPT');
      if (arpt !== iata) continue;
      const reason = text(it, 'Reason').replace(/^!\S+\s+\S+\s+/, '');
      const detail = [text(it, 'Avg') && `average ${text(it, 'Avg')}`, text(it, 'Max') && `max ${text(it, 'Max')}`, text(it, 'End_Time') && `until ${text(it, 'End_Time')}`, text(it, 'Min') && text(it, 'Trend') && `${text(it, 'Min')}-${text(it, 'Max')} ${text(it, 'Trend')}`, text(it, 'Reopen') && `reopens ${text(it, 'Reopen')}`].filter(Boolean).join(', ');
      out.push({ type, reason: reason.slice(0, 200), detail });
    }
  }
  return out;
}

const MEANING: Record<string, string> = { '7500': 'hijack', '7600': 'radio failure', '7700': 'general emergency' };

export async function airportStatus(ctx: Ctx, query: string): Promise<ModuleResult<AirportStatus>> {
  const provenance: Provenance[] = [];
  const list = await airports(ctx);
  provenance.push(list.prov);
  const a = findAirport(list.data ?? [], query);
  if (!a) throw new Error(`airport not found: ${query} (try an IATA code like JFK or an ICAO code like EGLL)`);
  const isUs = a.country === 'US';
  const [m, t, faaXml, sq] = await Promise.all([
    metar(ctx, a.ident),
    taf(ctx, a.ident),
    isUs ? ctx.http.get<string>('https://nasstatus.faa.gov/api/airport-status-information', { source: 'faa-nas', as: 'text', ttlSec: 300 }) : Promise.resolve(null),
    squawks(ctx, { lookup: false }).catch(() => null),
  ]);
  provenance.push(m.prov, t.prov);
  if (faaXml) provenance.push(faaXml.prov);
  if (sq) provenance.push(...sq.provenance);

  // FAA ground-stop and closure lists also carry routine NOTAM closures for general aviation; keep real disruptions.
  const delays = faaXml?.data && a.iata ? parseFaaStatus(faaXml.data, a.iata).filter((d) => !/NON SKED TRANSIENT GA|PPR/.test(d.reason)) : [];
  const emergencies = (sq?.result.aircraft ?? [])
    .filter((x) => x.lat != null && x.lon != null)
    .map((x) => ({ callsign: x.callsign ?? null, code: x.code, meaning: x.meaning || MEANING[x.code] || 'emergency', km: Math.round(haversineKm(a.lat, a.lon, x.lat!, x.lon!)) }))
    .filter((x) => x.km <= 150);

  const points: string[] = [];
  let verdict: AirportVerdict = 'normal';
  for (const d of delays) points.push(`FAA ${d.type.toLowerCase()}: ${d.reason}${d.detail ? ` (${d.detail})` : ''}`);
  if (delays.some((d) => /ground stop|closure/i.test(d.type))) verdict = 'disrupted';
  else if (delays.length) verdict = 'delays';
  const w = m.data;
  if (w) {
    const bad = w.category === 'LIFR' || w.category === 'IFR' || (w.gustKt ?? 0) >= 35 || /TS|FZ|\+SN|\+RA|GR/.test(w.weather ?? '');
    if (bad && verdict === 'normal') verdict = 'weather watch';
    points.push(`Weather ${w.category ?? 'n/a'}${w.weather ? `, ${w.weather}` : ''}: wind ${w.windKt ?? '?'} kt${w.gustKt ? ` gusting ${w.gustKt}` : ''}, visibility ${w.visibility ?? '?'}${w.ceilingFt != null ? `, ceiling ${w.ceilingFt} ft` : ''}${w.tempC != null ? `, ${w.tempC}°C` : ''}`);
  } else points.push('No current METAR from this airport');
  for (const e of emergencies) points.push(`Aircraft ${e.callsign ?? 'unknown'} squawking ${e.code} (${e.meaning}) ${e.km} km away`);
  if (isUs && !delays.length) points.push('No FAA delays or ground stops reported');

  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = [];
  if (verdict === 'disrupted') {
    const s: Signal = { id: signalId('airport', a.ident, nowIso.slice(0, 13)), module: 'airport', title: `${a.iata ?? a.ident} disrupted: ${points[0]}`.slice(0, 160), score: 65, evidence: points.slice(0, 3).map((x) => ({ source: 'faa-nas', text: x })), createdAt: nowIso };
    ctx.graph.saveSignal(s);
    signals.push(s);
  }
  return {
    module: 'airport',
    input: query,
    generatedAt: nowIso,
    result: { airport: { ident: a.ident, iata: a.iata, name: airportLabel(a), city: a.city, country: a.country, lat: a.lat, lon: a.lon }, verdict, points, metar: w, taf: t.data, faa: { delays, checked: Boolean(faaXml?.data) }, emergencies },
    signals,
    provenance,
  };
}
