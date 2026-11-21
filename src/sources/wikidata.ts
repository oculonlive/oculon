/** Populated places near a point, from Wikidata (keyless SPARQL). */
import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface Settlement {
  name: string;
  population: number;
  distanceKm: number;
  qid: string;
}

/** Cities and towns within `radiusKm`, largest first; duplicate places keep their largest population figure. */
export async function settlementsNear(ctx: Ctx, lat: number, lon: number, radiusKm: number, limit = 40): Promise<Sourced<Settlement[]>> {
  const q = `SELECT ?place ?placeLabel ?pop ?dist WHERE {
  SERVICE wikibase:around { ?place wdt:P625 ?loc . bd:serviceParam wikibase:center "Point(${lon.toFixed(4)} ${lat.toFixed(4)})"^^geo:wktLiteral . bd:serviceParam wikibase:radius "${Math.round(radiusKm)}" . bd:serviceParam wikibase:distance ?dist . }
  ?place wdt:P1082 ?pop . ?place wdt:P31 ?type .
  VALUES ?type { wd:Q515 wd:Q1549591 wd:Q3957 wd:Q532 wd:Q1093829 wd:Q200250 wd:Q1637706 wd:Q5119 }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
} ORDER BY DESC(?pop) LIMIT ${limit * 2}`;
  const r = await ctx.http.get<{ results?: { bindings: { place: { value: string }; placeLabel: { value: string }; pop: { value: string }; dist: { value: string } }[] } }>(
    `https://query.wikidata.org/sparql?query=${enc(q)}`,
    { source: 'wikidata', ttlSec: 7 * 86_400, timeoutMs: 60_000, headers: { accept: 'application/sparql-results+json' } },
  );
  if (!r.data?.results) return { data: null, prov: r.prov };
  const best = new Map<string, Settlement>();
  for (const b of r.data.results.bindings) {
    const qid = b.place.value.split('/').pop()!;
    const s = { name: b.placeLabel.value, population: Number(b.pop.value), distanceKm: Math.round(Number(b.dist.value)), qid };
    if (!Number.isFinite(s.population)) continue;
    const prev = best.get(qid);
    if (!prev || s.population > prev.population) best.set(qid, s);
  }
  // Same-name entries (a city and its municipality) would double count; keep one per name.
  const byName = new Map<string, Settlement>();
  for (const s of best.values()) if (!byName.has(s.name) || byName.get(s.name)!.population < s.population) byName.set(s.name, s);
  return { data: [...byName.values()].sort((a, b) => b.population - a.population).slice(0, limit), prov: r.prov };
}
