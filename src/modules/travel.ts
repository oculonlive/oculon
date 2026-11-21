/**
 * Travel and place risk brief: what a visitor should know about a place for the coming week.
 *   Official advice: US State Department travel advisories (levels 1-4) and UK FCDO foreign travel advice.
 *   Weather: Open-Meteo 7-day forecast (storms, heavy rain, strong gusts, heat, cold, UV), no key.
 *   Air quality: OpenAQ PM2.5 near the place (OPENAQ_API_KEY).
 *   Health: WHO Disease Outbreak News for the country, last 90 days.
 *   Hazards: GDACS orange/red alerts in the country, strong earthquakes within 300 km in the last week,
 *     active fires within the place (NASA FIRMS, when FIRMS_MAP_KEY is set), and confirmed internet outages.
 * The brief reports what these sources say; it does not call a place safe.
 */
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';
import { haversineKm } from '../sources/airports.js';
import { recentQuakes } from '../sources/usgs.js';
import { blackout } from './blackout.js';
import { fires } from './fires.js';
import { hazards } from './hazards.js';
import { air } from './sky.js';

const DAY = 86_400_000;

export type RiskLevel = 'low' | 'moderate' | 'high' | 'severe';

export interface TravelBrief {
  place: { name: string; lat: number; lon: number; country: string | null; countryCode: string | null };
  level: RiskLevel;
  headline: string;
  points: string[];
  advisories: { us: { level: number; text: string; updated: string | null; url: string } | null; uk: { alerts: string[]; latestChange: string | null; updated: string | null; url: string } | null };
  weather: { days: { date: string; summary: string; tMax: number; tMin: number; rainMm: number; gustKmh: number; uv: number | null }[]; warnings: string[] } | null;
  air: { pm25: number | null; category: string | null; stations: number } | null;
  outbreaks: { title: string; date: string; url: string }[];
  hazards: { type: string; name: string; level: string; url: string }[];
  quakes: { mag: number; place: string; time: string; km: number; url: string }[];
  fires: { hotspots: number; clusters: number } | null;
  internet: { outages: string[] } | null;
}

interface NomPlace { display_name: string; lat: string; lon: string; address?: { country?: string; country_code?: string } }

async function locate(ctx: Ctx, q: string): Promise<Sourced<TravelBrief['place']>> {
  const r = await ctx.http.get<NomPlace[]>(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}&format=json&limit=1&addressdetails=1&accept-language=en`, { source: 'nominatim', ttlSec: 30 * 86_400 });
  const p = r.data?.[0];
  return { data: p ? { name: p.display_name, lat: Number(p.lat), lon: Number(p.lon), country: p.address?.country ?? null, countryCode: p.address?.country_code?.toUpperCase() ?? null } : null, prov: r.prov };
}

const norm = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();
// Names that differ between OpenStreetMap and the advisory publishers.
const ALIASES: Record<string, string[]> = {
  'united states': ['usa', 'united states of america'],
  'united kingdom': ['uk', 'great britain'],
  myanmar: ['burma', 'burma myanmar'],
  'czechia': ['czech republic'],
  'turkey': ['turkiye'],
  'ivory coast': ['cote d ivoire'],
  'democratic republic of the congo': ['democratic republic of the congo', 'drc', 'congo democratic republic'],
  'south korea': ['south korea', 'korea south', 'republic of korea'],
  'north korea': ['north korea', 'korea north'],
  'the bahamas': ['bahamas'],
  'the gambia': ['gambia'],
  'east timor': ['timor leste'],
  'eswatini': ['swaziland'],
};
const namesFor = (country: string) => { const n = norm(country); return [n, ...(ALIASES[n] ?? []).map(norm), ...Object.entries(ALIASES).filter(([, v]) => v.map(norm).includes(n)).map(([k]) => norm(k))]; };

interface UsAdvisory { Title: string; Link: string; Updated?: string; Published?: string }

async function usAdvisory(ctx: Ctx, country: string): Promise<{ data: TravelBrief['advisories']['us']; prov: Provenance }> {
  const r = await ctx.http.get<UsAdvisory[]>('https://cadataapi.state.gov/api/TravelAdvisories', { source: 'us-state-dept', ttlSec: 6 * 3600, timeoutMs: 30_000, keep: (d: UsAdvisory[]) => (Array.isArray(d) ? d.map((x) => ({ Title: x.Title, Link: x.Link, Updated: x.Updated })) : []) });
  const names = namesFor(country);
  const hit = (r.data ?? []).find((a) => { const head = norm(a.Title.split(' - ')[0] ?? ''); return names.includes(head) || names.some((n) => head.split(' ').length > 1 && head.includes(n)); });
  if (!hit) return { data: null, prov: r.prov };
  const m = /Level (\d):\s*(.+)$/i.exec(hit.Title);
  return { data: { level: Number(m?.[1] ?? 0), text: (m?.[2] ?? hit.Title).trim(), updated: hit.Updated ?? null, url: hit.Link }, prov: r.prov };
}

interface FcdoChild { title?: string; base_path?: string; details?: { country?: { name?: string; slug?: string; synonyms?: string[] } } }

async function ukAdvice(ctx: Ctx, country: string): Promise<{ data: TravelBrief['advisories']['uk']; prov: Provenance[] }> {
  const idx = await ctx.http.get<{ name: string; slug: string; synonyms: string[] }[]>('https://www.gov.uk/api/content/foreign-travel-advice', {
    source: 'uk-fcdo',
    ttlSec: 24 * 3600,
    keep: (d: { links?: { children?: FcdoChild[] } }) => (d.links?.children ?? []).map((c) => ({ name: c.details?.country?.name ?? c.title ?? '', slug: c.details?.country?.slug ?? (c.base_path ?? '').split('/').pop() ?? '', synonyms: c.details?.country?.synonyms ?? [] })),
  });
  const names = namesFor(country);
  const c = (idx.data ?? []).find((x) => names.includes(norm(x.name))) ?? (idx.data ?? []).find((x) => x.synonyms.some((s) => names.includes(norm(s))));
  if (!c) return { data: null, prov: [idx.prov] };
  const page = await ctx.http.get<{ alerts: string[]; change: string | null; updated: string | null }>(`https://www.gov.uk/api/content/foreign-travel-advice/${c.slug}`, {
    source: 'uk-fcdo',
    ttlSec: 6 * 3600,
    keep: (d: { public_updated_at?: string; details?: { alert_status?: string[]; change_description?: string } }) => ({ alerts: d.details?.alert_status ?? [], change: d.details?.change_description ?? null, updated: d.public_updated_at ?? null }),
  });
  if (!page.data) return { data: null, prov: [idx.prov, page.prov] };
  const ALERT: Record<string, string> = {
    avoid_all_travel_to_whole_country: 'advises against all travel to the whole country',
    avoid_all_but_essential_travel_to_whole_country: 'advises against all but essential travel to the whole country',
    avoid_all_travel_to_parts: 'advises against all travel to parts of the country',
    avoid_all_but_essential_travel_to_parts: 'advises against all but essential travel to parts of the country',
  };
  return { data: { alerts: page.data.alerts.map((a) => ALERT[a] ?? a.replace(/_/g, ' ')), latestChange: page.data.change, updated: page.data.updated, url: `https://www.gov.uk/foreign-travel-advice/${c.slug}` }, prov: [idx.prov, page.prov] };
}

const WMO: Record<number, string> = { 0: 'clear', 1: 'mainly clear', 2: 'partly cloudy', 3: 'overcast', 45: 'fog', 48: 'freezing fog', 51: 'light drizzle', 53: 'drizzle', 55: 'heavy drizzle', 56: 'freezing drizzle', 57: 'freezing drizzle', 61: 'light rain', 63: 'rain', 65: 'heavy rain', 66: 'freezing rain', 67: 'freezing rain', 71: 'light snow', 73: 'snow', 75: 'heavy snow', 77: 'snow grains', 80: 'showers', 81: 'heavy showers', 82: 'violent showers', 85: 'snow showers', 86: 'heavy snow showers', 95: 'thunderstorms', 96: 'thunderstorms with hail', 99: 'severe thunderstorms with hail' };

async function forecast(ctx: Ctx, lat: number, lon: number): Promise<Sourced<NonNullable<TravelBrief['weather']>>> {
  const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat.toFixed(3)}&longitude=${lon.toFixed(3)}&daily=weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,wind_gusts_10m_max,uv_index_max&timezone=auto&forecast_days=7`;
  const r = await ctx.http.get<{ daily?: { time: string[]; weather_code: number[]; temperature_2m_max: number[]; temperature_2m_min: number[]; precipitation_sum: number[]; wind_gusts_10m_max: number[]; uv_index_max?: (number | null)[] } }>(url, { source: 'open-meteo', ttlSec: 3 * 3600 });
  const d = r.data?.daily;
  if (!d) return { data: null, prov: r.prov };
  const days = d.time.map((date, i) => ({ date, summary: WMO[d.weather_code[i]!] ?? `code ${d.weather_code[i]}`, tMax: d.temperature_2m_max[i]!, tMin: d.temperature_2m_min[i]!, rainMm: d.precipitation_sum[i]!, gustKmh: d.wind_gusts_10m_max[i]!, uv: d.uv_index_max?.[i] ?? null }));
  const warnings: string[] = [];
  const when = (xs: typeof days) => xs.map((x) => x.date.slice(5)).join(', ');
  const storms = days.filter((x) => [95, 96, 99].includes(d.weather_code[days.indexOf(x)]!));
  if (storms.length) warnings.push(`thunderstorms on ${when(storms)}`);
  const rain = days.filter((x) => x.rainMm >= 50);
  if (rain.length) warnings.push(`heavy rain (${Math.max(...rain.map((x) => x.rainMm)).toFixed(0)} mm in a day) on ${when(rain)}`);
  const wind = days.filter((x) => x.gustKmh >= 75);
  if (wind.length) warnings.push(`strong gusts up to ${Math.max(...wind.map((x) => x.gustKmh)).toFixed(0)} km/h on ${when(wind)}`);
  const heat = days.filter((x) => x.tMax >= 38);
  if (heat.length) warnings.push(`extreme heat up to ${Math.max(...heat.map((x) => x.tMax)).toFixed(0)}°C on ${when(heat)}`);
  const cold = days.filter((x) => x.tMin <= -15);
  if (cold.length) warnings.push(`severe cold down to ${Math.min(...cold.map((x) => x.tMin)).toFixed(0)}°C on ${when(cold)}`);
  const snow = days.filter((x) => /heavy snow/.test(x.summary));
  if (snow.length) warnings.push(`heavy snow on ${when(snow)}`);
  const uv = days.filter((x) => (x.uv ?? 0) >= 11);
  if (uv.length) warnings.push(`extreme UV (index ${Math.max(...uv.map((x) => x.uv ?? 0)).toFixed(0)})`);
  return { data: { days, warnings }, prov: r.prov };
}

interface DonRaw { Title?: string; OverrideTitle?: string; UseOverrideTitle?: boolean; PublicationDateAndTime?: string; ItemDefaultUrl?: string }

async function outbreaks(ctx: Ctx, country: string): Promise<{ data: TravelBrief['outbreaks']; prov: Provenance }> {
  const r = await ctx.http.get<DonRaw[]>("https://www.who.int/api/news/diseaseoutbreaknews?$top=60&$orderby=PublicationDateAndTime%20desc&$select=Title,OverrideTitle,UseOverrideTitle,PublicationDateAndTime,ItemDefaultUrl", { source: 'who-don', ttlSec: 6 * 3600, timeoutMs: 30_000, keep: (d: { value?: DonRaw[] }) => d.value ?? [] });
  const since = ctx.now().getTime() - 90 * DAY;
  const names = namesFor(country);
  const data = (r.data ?? [])
    .map((x) => ({ title: (x.UseOverrideTitle && x.OverrideTitle) || x.Title || '', date: x.PublicationDateAndTime ?? '', url: `https://www.who.int/emergencies/disease-outbreak-news/item${x.ItemDefaultUrl ?? ''}` }))
    .filter((x) => Date.parse(x.date) >= since && names.some((n) => norm(x.title).includes(n)))
    .filter((x, i, a) => a.findIndex((y) => norm(y.title) === norm(x.title)) === i);
  return { data, prov: r.prov };
}

const LEVEL_ORDER: RiskLevel[] = ['low', 'moderate', 'high', 'severe'];

/** Brief for a place: official advice, weather, air, outbreaks, hazards, quakes, fires and internet outages. */
export async function travel(ctx: Ctx, placeQuery: string, opts: { fires?: boolean } = {}): Promise<ModuleResult<TravelBrief>> {
  const provenance: Provenance[] = [];
  const loc = await locate(ctx, placeQuery);
  provenance.push(loc.prov);
  const place = loc.data;
  if (!place) throw new Error(`place not found: ${placeQuery}`);
  const country = place.country ?? '';
  const settle = async <T>(p: Promise<T>): Promise<T | null> => { try { return await p; } catch { return null; } };

  const [us, uk, wx, aq, don, hz, qk, fr, bo] = await Promise.all([
    country ? usAdvisory(ctx, country) : null,
    country ? ukAdvice(ctx, country) : null,
    forecast(ctx, place.lat, place.lon),
    settle(air(ctx, placeQuery)),
    country ? outbreaks(ctx, country) : null,
    settle(hazards(ctx, 7)),
    recentQuakes(ctx),
    opts.fires === false ? null : settle(fires(ctx, placeQuery, 2)),
    settle(blackout(ctx, 2)),
  ]);
  if (us) provenance.push(us.prov);
  if (uk) provenance.push(...uk.prov);
  provenance.push(wx.prov);
  if (aq) provenance.push(...aq.provenance.slice(1));
  if (don) provenance.push(don.prov);
  if (hz) provenance.push(...hz.provenance);
  provenance.push(qk.prov);
  if (fr) provenance.push(...fr.provenance);
  if (bo) provenance.push(...bo.provenance);

  const names = country ? namesFor(country) : [];
  const now = ctx.now().getTime();
  const hazardsHere = (hz?.result ?? []).filter((h) => h.level !== 'Green' && h.current && names.some((n) => norm(h.countries).includes(n))).map((h) => ({ type: h.type, name: h.name, level: h.level, url: h.url }));
  const quakes = (qk.data ?? [])
    .filter((q) => q.lat != null && q.lon != null && q.mag >= 4.5 && now - q.time <= 7 * DAY)
    .map((q) => ({ mag: q.mag, place: q.place, time: new Date(q.time).toISOString(), km: Math.round(haversineKm(place.lat, place.lon, q.lat!, q.lon!)), url: q.url }))
    .filter((q) => q.km <= 300)
    .sort((a, b) => b.mag - a.mag);
  const outages = (bo?.result.outages ?? []).filter((o) => o.verified && ((place.countryCode && o.countryCode === place.countryCode) || (o.country && names.includes(norm(o.country))))).map((o) => `${o.cause ?? o.type ?? 'outage'} since ${o.start.slice(0, 10)}${o.end ? `, ended ${o.end.slice(0, 10)}` : ', ongoing'}`);

  // Level: the strictest of the official advice, raised by what is happening on the ground this week.
  let lvl = 0;
  const points: string[] = [];
  if (us?.data) { lvl = Math.max(lvl, us.data.level - 1); points.push(`US State Department: Level ${us.data.level}, ${us.data.text}`); }
  if (uk?.data?.alerts.length) { lvl = Math.max(lvl, uk.data.alerts.some((a) => /whole country/.test(a)) ? 3 : 1); points.push(`UK FCDO ${uk.data.alerts.join('; ')}`); }
  else if (uk?.data) points.push('UK FCDO has no travel restrictions in place');
  if (wx.data?.warnings.length) { lvl = Math.max(lvl, 1); points.push(`Weather: ${wx.data.warnings.join('; ')}`); }
  const pm = aq?.result.median ?? null;
  if (pm != null && pm > 55.4) { lvl = Math.max(lvl, 1); points.push(`Air quality ${aq!.result.category} (PM2.5 ${pm.toFixed(0)} µg/m³)`); }
  if (don?.data.length) { lvl = Math.max(lvl, 1); points.push(`WHO outbreak news: ${don.data.slice(0, 2).map((d) => d.title).join('; ')}`); }
  if (hazardsHere.length) { lvl = Math.max(lvl, hazardsHere.some((h) => h.level === 'Red') ? 3 : 2); points.push(`Disaster alerts: ${hazardsHere.map((h) => `${h.level.toLowerCase()} ${h.type} ${h.name}`).join('; ')}`); }
  // Moderate quakes far away are routine in seismic countries; only strong or close ones raise the level.
  const felt = quakes.find((q) => q.mag >= 6.5 || (q.mag >= 5.5 && q.km <= 150));
  if (felt) { lvl = Math.max(lvl, felt.mag >= 6.5 ? 2 : 1); points.push(`Earthquake M${felt.mag.toFixed(1)} ${felt.km} km away on ${felt.time.slice(0, 10)}`); }
  else if (quakes.length) points.push(`${quakes.length} moderate earthquake${quakes.length === 1 ? '' : 's'} within 300 km this week (strongest M${quakes[0]!.mag.toFixed(1)})`);
  // Refineries, steel works and flares show up as steady thermal hotspots that satellites cannot tell apart from
  // wildfires, so hotspots are reported but do not raise the level; large wildfires arrive as GDACS alerts above.
  const hot = fr?.result.hotspots.length ?? 0;
  const bigFires = (fr?.result.clusters ?? []).filter((c) => c.count >= 5 && haversineKm(place.lat, place.lon, c.lat, c.lon) <= 50).length;
  if (bigFires >= 3) points.push(`${bigFires} clusters of satellite heat detections within 50 km (fires or industrial heat)`);
  if (outages.length) { lvl = Math.max(lvl, 1); points.push(`Internet outage: ${outages[0]}`); }
  const level = LEVEL_ORDER[clamp(lvl, 0, 3)]!;
  const short = place.name.split(',')[0]!;
  const headline = points.length ? `${short}: ${level} risk. ${points[0]}` : `${short}: no warnings from the sources checked`;

  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = [];
  if (level === 'severe' || hazardsHere.some((h) => h.level === 'Red')) {
    const s: Signal = { id: signalId('travel', short, nowIso.slice(0, 10)), module: 'travel', title: `Travel risk ${level} for ${short}`, score: level === 'severe' ? 75 : 60, evidence: points.slice(0, 4).map((text) => ({ source: 'travel', text })), createdAt: nowIso };
    ctx.graph.saveSignal(s);
    signals.push(s);
  }
  return {
    module: 'travel',
    input: placeQuery,
    generatedAt: nowIso,
    result: {
      place,
      level,
      headline,
      points,
      advisories: { us: us?.data ?? null, uk: uk?.data ?? null },
      weather: wx.data,
      air: aq ? { pm25: pm, category: aq.result.category, stations: aq.result.stations.length } : null,
      outbreaks: don?.data ?? [],
      hazards: hazardsHere,
      quakes: quakes.slice(0, 5),
      fires: fr ? { hotspots: hot, clusters: fr.result.clusters.length } : null,
      internet: bo ? { outages } : null,
    },
    signals,
    provenance,
  };
}
