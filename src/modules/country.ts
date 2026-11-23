/**
 * Country brief: the state of a country in one page.
 *   World Bank (no key): GDP, growth, GDP per person, inflation, unemployment, population (latest year reported).
 *   IMF World Economic Outlook (no key): growth and inflation for this year and next.
 *   Wikidata (no key): head of state, head of government, capital, currency.
 *   open.er-api.com (no key): today's exchange rate against the US dollar.
 *   Plus US and UK travel advice, confirmed internet outages, orange and red disaster alerts and the latest
 *   Guardian headlines about the country.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Sourced } from '../core/types.js';
import { guardian } from '../sources/press.js';
import { blackout } from './blackout.js';
import { hazards } from './hazards.js';
import { namesFor, ukAdvice, usAdvisory } from './travel.js';

export interface CountryBrief {
  name: string;
  iso2: string;
  iso3: string;
  region: string | null;
  incomeLevel: string | null;
  capital: string | null;
  leaders: { headOfState: string | null; headOfGovernment: string | null };
  currency: { code: string | null; perUsd: number | null; asOf: string | null };
  indicators: { name: string; value: number | null; year: string | null; unit: string }[];
  outlook: { growth: Record<string, number>; inflation: Record<string, number> };
  advisories: { us: { level: number; text: string; url: string } | null; uk: { alerts: string[]; url: string } | null };
  outages: string[];
  hazards: { type: string; name: string; level: string; url: string }[];
  headlines: { title: string; url: string; date: string; source: string }[];
}

interface WbCountry { id: string; iso2Code: string; name: string; capitalCity: string; region?: { value?: string }; incomeLevel?: { value?: string } }

// World Bank formal names → the everyday names advisories and news use.
const COMMON: Record<string, string> = {
  KOR: 'South Korea', PRK: 'North Korea', EGY: 'Egypt', IRN: 'Iran', RUS: 'Russia', VNM: 'Vietnam', TUR: 'Turkey', VEN: 'Venezuela', YEM: 'Yemen', SYR: 'Syria', LAO: 'Laos',
  COD: 'Democratic Republic of the Congo', COG: 'Republic of the Congo', GMB: 'The Gambia', BHS: 'The Bahamas', HKG: 'Hong Kong', MAC: 'Macao', SVK: 'Slovakia', KGZ: 'Kyrgyzstan',
  FSM: 'Micronesia', CZE: 'Czech Republic', CIV: "Cote d'Ivoire", BRN: 'Brunei', CPV: 'Cape Verde', PSE: 'Palestine', LCA: 'St Lucia', VCT: 'St Vincent', KNA: 'St Kitts and Nevis', MKD: 'North Macedonia', SWZ: 'Eswatini', TLS: 'East Timor',
};
export const commonName = (c: { id: string; name: string }): string => COMMON[c.id] ?? c.name.split(',')[0]!.trim();

const norm = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();

async function wbCountries(ctx: Ctx): Promise<Sourced<WbCountry[]>> {
  return ctx.http.get<WbCountry[]>('https://api.worldbank.org/v2/country?format=json&per_page=400', {
    source: 'world-bank',
    ttlSec: 30 * 86_400,
    keep: (d: [unknown, WbCountry[]]) => (Array.isArray(d) && Array.isArray(d[1]) ? d[1].filter((c) => c.region?.value && c.region.value !== 'Aggregates').map((c) => ({ id: c.id, iso2Code: c.iso2Code, name: c.name, capitalCity: c.capitalCity, region: { value: c.region?.value }, incomeLevel: { value: c.incomeLevel?.value } })) : []),
  });
}

/** Finds a country by name, alias, or ISO code in the World Bank list. */
export function findCountry(list: WbCountry[], q: string): WbCountry | null {
  const n = norm(q);
  const names = namesFor(q);
  return (
    list.find((c) => c.iso2Code.toLowerCase() === n || c.id.toLowerCase() === n) ??
    list.find((c) => names.includes(norm(c.name))) ??
    // World Bank long forms: "Egypt, Arab Rep.", "Korea, Rep.", "Iran, Islamic Rep."
    list.find((c) => norm(commonName(c)) === n) ??
    (n === 'south korea' ? list.find((c) => c.id === 'KOR') : n === 'north korea' ? list.find((c) => c.id === 'PRK') : n === 'russia' ? list.find((c) => c.id === 'RUS') : n === 'vietnam' ? list.find((c) => c.id === 'VNM') : undefined) ??
    list.find((c) => norm(c.name).startsWith(n)) ??
    null
  );
}

const INDICATORS: [string, string, string][] = [
  ['NY.GDP.MKTP.CD', 'GDP', 'USD'],
  ['NY.GDP.MKTP.KD.ZG', 'GDP growth', '%'],
  ['NY.GDP.PCAP.CD', 'GDP per person', 'USD'],
  ['FP.CPI.TOTL.ZG', 'Inflation', '%'],
  ['SL.UEM.TOTL.ZS', 'Unemployment', '%'],
  ['SP.POP.TOTL', 'Population', 'people'],
];

async function indicator(ctx: Ctx, iso3: string, id: string): Promise<Sourced<{ value: number | null; year: string | null }>> {
  return ctx.http.get<{ value: number | null; year: string | null }>(`https://api.worldbank.org/v2/country/${iso3}/indicator/${id}?format=json&mrnev=1`, {
    source: 'world-bank',
    ttlSec: 7 * 86_400,
    keep: (d: [unknown, { value: number | null; date: string }[] | null]) => { const row = Array.isArray(d) ? d[1]?.[0] : undefined; return { value: row?.value ?? null, year: row?.date ?? null }; },
  });
}

async function imf(ctx: Ctx, code: string, iso3: string): Promise<Sourced<Record<string, number>>> {
  return ctx.http.get<Record<string, number>>(`https://www.imf.org/external/datamapper/api/v1/${code}/${iso3}`, {
    source: 'imf',
    ttlSec: 7 * 86_400,
    timeoutMs: 30_000,
    keep: (d: { values?: Record<string, Record<string, Record<string, number>>> }) => d.values?.[code]?.[iso3] ?? {},
  });
}

async function wikidata(ctx: Ctx, iso2: string): Promise<Sourced<{ hos: string | null; hog: string | null; capital: string | null; currency: string | null }>> {
  const q = `SELECT ?hosLabel ?hogLabel ?capLabel ?cur WHERE { ?c wdt:P297 "${iso2}". OPTIONAL{?c p:P35 ?s1. ?s1 ps:P35 ?hos. FILTER NOT EXISTS{?s1 pq:P582 ?e1}} OPTIONAL{?c p:P6 ?s2. ?s2 ps:P6 ?hog. FILTER NOT EXISTS{?s2 pq:P582 ?e2}} OPTIONAL{?c wdt:P36 ?cap} OPTIONAL{?c wdt:P38 ?cu. ?cu wdt:P498 ?cur} SERVICE wikibase:label { bd:serviceParam wikibase:language "en". } } LIMIT 5`;
  const r = await ctx.http.get<{ hos: string | null; hog: string | null; capital: string | null; currency: string | null }>(`https://query.wikidata.org/sparql?format=json&query=${encodeURIComponent(q)}`, {
    source: 'wikidata',
    ttlSec: 3 * 86_400,
    timeoutMs: 30_000,
    keep: (d: { results?: { bindings?: Record<string, { value: string }>[] } }) => {
      const b = d.results?.bindings ?? [];
      const pick = (k: string) => b.map((x) => x[k]?.value).find((v) => v && !/^Q\d+$/.test(v)) ?? null;
      return { hos: pick('hosLabel'), hog: pick('hogLabel'), capital: pick('capLabel'), currency: pick('cur') };
    },
  });
  return r;
}

async function usdRate(ctx: Ctx, code: string): Promise<Sourced<{ rate: number | null; asOf: string | null }>> {
  const r = await ctx.http.get<{ rates: Record<string, number>; asOf: string | null }>('https://open.er-api.com/v6/latest/USD', {
    source: 'exchange-rates',
    ttlSec: 6 * 3600,
    keep: (d: { rates?: Record<string, number>; time_last_update_utc?: string }) => ({ rates: d.rates ?? {}, asOf: d.time_last_update_utc ?? null }),
  });
  return { data: r.data ? { rate: r.data.rates[code] ?? null, asOf: r.data.asOf } : null, prov: r.prov };
}

export async function countryBrief(ctx: Ctx, input: string): Promise<ModuleResult<CountryBrief>> {
  const provenance: Provenance[] = [];
  const list = await wbCountries(ctx);
  provenance.push(list.prov);
  const c = findCountry(list.data ?? [], input);
  if (!c) throw new Error(`country not found: ${input}`);
  const settle = async <T>(p: Promise<T>): Promise<T | null> => { try { return await p; } catch { return null; } };
  const [ind, gro, inf, wd, us, uk, bo, hz, news] = await Promise.all([
    Promise.all(INDICATORS.map(([id]) => indicator(ctx, c.id, id))),
    imf(ctx, 'NGDP_RPCH', c.id),
    imf(ctx, 'PCPIPCH', c.id),
    wikidata(ctx, c.iso2Code),
    usAdvisory(ctx, commonName(c)),
    ukAdvice(ctx, commonName(c)),
    settle(blackout(ctx, 2)),
    settle(hazards(ctx, 7)),
    guardian(ctx, commonName(c), 3, 6),
  ]);
  provenance.push(...ind.map((x) => x.prov).slice(0, 1), gro.prov, wd.prov, us.prov, ...uk.prov, news.prov);
  if (bo) provenance.push(...bo.provenance);
  if (hz) provenance.push(...hz.provenance);
  const cur = wd.data?.currency ?? null;
  const fx = cur && cur !== 'USD' ? await usdRate(ctx, cur) : null;
  if (fx) provenance.push(fx.prov);

  const y = ctx.now().getUTCFullYear();
  const pickYears = (r: Record<string, number> | null) => Object.fromEntries(Object.entries(r ?? {}).filter(([k]) => Number(k) >= y - 1 && Number(k) <= y + 1));
  const names = namesFor(commonName(c));
  return {
    module: 'country',
    input,
    generatedAt: ctx.now().toISOString(),
    result: {
      name: commonName(c),
      iso2: c.iso2Code,
      iso3: c.id,
      region: c.region?.value ?? null,
      incomeLevel: c.incomeLevel?.value ?? null,
      capital: wd.data?.capital ?? c.capitalCity ?? null,
      leaders: { headOfState: wd.data?.hos ?? null, headOfGovernment: wd.data?.hog ?? null },
      currency: { code: cur, perUsd: cur === 'USD' ? 1 : fx?.data?.rate ?? null, asOf: fx?.data?.asOf ?? null },
      indicators: INDICATORS.map(([, name, unit], i) => ({ name, unit, value: ind[i]?.data?.value ?? null, year: ind[i]?.data?.year ?? null })),
      outlook: { growth: pickYears(gro.data), inflation: pickYears(inf.data) },
      advisories: { us: us.data ? { level: us.data.level, text: us.data.text, url: us.data.url } : null, uk: uk.data ? { alerts: uk.data.alerts, url: uk.data.url } : null },
      outages: (bo?.result.outages ?? []).filter((o) => o.verified && (o.countryCode === c.iso2Code || (o.country && names.includes(norm(o.country))))).map((o) => `${o.cause ?? o.type ?? 'outage'} since ${o.start.slice(0, 10)}${o.end ? `, ended ${o.end.slice(0, 10)}` : ', ongoing'}`),
      hazards: (hz?.result ?? []).filter((h) => h.level !== 'Green' && h.current && names.some((n) => norm(h.countries).includes(n))).map((h) => ({ type: h.type, name: h.name, level: h.level, url: h.url })),
      headlines: (news.data ?? []).slice(0, 6),
    },
    signals: [],
    provenance,
  };
}
