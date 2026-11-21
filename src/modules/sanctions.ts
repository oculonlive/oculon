/**
 * Sanctions screening against the OFAC SDN list: wallets (listed address, or direct transactions with a listed
 * address), vessels (IMO number), and names (companies, people, vessels). Exact matches only: a name match
 * on the normalized full name or a listed alias, never a fuzzy guess.
 * Names are also matched worldwide through OpenSanctions (free non-commercial key): sanctions lists of many
 * countries, politically exposed persons, wanted lists and debarments, each match with its score.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { normName, sdn, type SdnEntry } from '../sources/ofac.js';
import { etherscanTxs, isEvmAddress } from '../sources/onchain.js';
import { key } from '../core/keys.js';
import { postJson } from '../sources/press.js';

export interface WorldMatch {
  name: string;
  schema: string;
  score: number;
  topics: string[];
  countries: string[];
  datasets: number;
  url: string;
  /** Owners, holdings, directors, family and associates of the best match (OpenSanctions entity graph). */
  related?: Related[];
}

export interface Related {
  relation: string;
  name: string;
  schema: string;
  /** e.g. ownership percentage or role. */
  detail: string | null;
  sanctioned: boolean;
  url: string;
}

const RELATION: Record<string, string> = {
  ownershipOwner: 'owns',
  ownershipAsset: 'owned by',
  directorshipOrganization: 'director',
  directorshipDirector: 'director of',
  predecessors: 'predecessor',
  successors: 'successor',
  familyPerson: 'family',
  familyRelative: 'family',
  associates: 'associate',
  associations: 'associate',
  employers: 'employer',
  employees: 'employee',
  membershipMember: 'member of',
  membershipOrganization: 'member',
  unknownLinkSubject: 'linked to',
  unknownLinkObject: 'linked to',
};

type OsEntity = { id: string; caption: string; schema: string; properties?: Record<string, unknown[]> };

/** The other side of each relationship of one OpenSanctions entity. */
export async function relatedEntities(ctx: Ctx, id: string, limit = 25): Promise<{ data: Related[] | null; prov: Provenance }> {
  const k = key('OPENSANCTIONS_API_KEY');
  if (!k) return { data: null, prov: { source: 'opensanctions', url: 'https://api.opensanctions.org', status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: 'set OPENSANCTIONS_API_KEY' } };
  const r = await ctx.http.get<OsEntity>(`https://api.opensanctions.org/entities/${encodeURIComponent(id)}?nested=true`, {
    source: 'opensanctions',
    ttlSec: 7 * 86_400,
    headers: { authorization: `ApiKey ${k}` },
    // Nested entities can be huge (securities, addresses); keep only relationship links.
    keep: (e: OsEntity) => ({ id: e.id, caption: e.caption, schema: e.schema, properties: Object.fromEntries(Object.entries(e.properties ?? {}).filter(([p]) => p in RELATION).map(([p, v]) => [p, v.slice(0, 60)])) }),
  });
  if (!r.data) return { data: null, prov: r.prov };
  const out: Related[] = [];
  const seen = new Set<string>();
  for (const [prop, links] of Object.entries(r.data.properties ?? {})) {
    const relation = RELATION[prop];
    if (!relation) continue;
    for (const link of links as OsEntity[]) {
      const lp = link.properties ?? {};
      // "Owned or Controlled By" just restates the relation, so it is left out.
      const role = (lp.role?.[0] ?? lp.relationship?.[0] ?? null) as string | null;
      const detail = [lp.percentage?.[0] ? `${lp.percentage[0]}%` : null, role && !/^owned or controlled/i.test(role) ? role : null, lp.endDate?.[0] ? `until ${lp.endDate[0]}` : null].filter(Boolean).join(', ') || null;
      for (const v of Object.values(lp)) {
        for (const other of v as unknown[]) {
          if (!other || typeof other !== 'object') continue;
          const o = other as OsEntity;
          if (!o.id || o.id === r.data.id || seen.has(o.id)) continue;
          seen.add(o.id);
          const topics = (o.properties?.topics ?? []) as string[];
          out.push({ relation, name: o.caption, schema: o.schema, detail: detail as string | null, sanctioned: topics.includes('sanction'), url: `https://www.opensanctions.org/entities/${o.id}/` });
        }
      }
    }
  }
  // Sanctioned relations first: they are the ones that matter for exposure.
  out.sort((a, b) => Number(b.sanctioned) - Number(a.sanctioned));
  return { data: out.slice(0, limit), prov: r.prov };
}

/** OpenSanctions match (people, companies, vessels). Only matches scoring 0.7 or more are kept. */
export async function worldMatch(ctx: Ctx, name: string): Promise<{ data: WorldMatch[] | null; prov: Provenance }> {
  const k = key('OPENSANCTIONS_API_KEY');
  if (!k) return { data: null, prov: { source: 'opensanctions', url: 'https://api.opensanctions.org', status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: 'set OPENSANCTIONS_API_KEY for worldwide lists' } };
  const r = await postJson<{ responses?: Record<string, { results?: { id: string; caption: string; schema: string; score?: number; datasets?: string[]; properties?: { topics?: string[]; country?: string[] } }[] }> }>(
    ctx,
    'https://api.opensanctions.org/match/default',
    { queries: { q: { schema: 'LegalEntity', properties: { name: [name] } } } },
    { authorization: `ApiKey ${k}` },
    'opensanctions',
    24 * 3600,
  );
  const results = (r.data?.responses?.q?.results ?? []).filter((x) => (x.score ?? 0) >= 0.7).slice(0, 5);
  const data: WorldMatch[] = results.map((x) => ({ name: x.caption, schema: x.schema, score: Math.round((x.score ?? 0) * 100) / 100, topics: x.properties?.topics ?? [], countries: x.properties?.country ?? [], datasets: x.datasets?.length ?? 0, url: `https://www.opensanctions.org/entities/${x.id}/` }));
  // One extra call for a confident best match: its owners, holdings and directors.
  if (results[0] && (results[0].score ?? 0) >= 0.8) {
    const rel = await relatedEntities(ctx, results[0].id);
    if (rel.data?.length) data[0]!.related = rel.data;
  }
  return { data: r.data ? data : null, prov: r.prov };
}

export interface Hit {
  kind: 'address' | 'counterparty' | 'imo' | 'name';
  matched: string;
  entry: { name: string; type: string; program: string; uid: string };
  detail?: string;
}

export interface ScreenResult {
  query: string;
  listDate: string | null;
  listSize: number;
  hits: Hit[];
  verdict: 'SANCTIONED' | 'EXPOSED' | 'LISTED_ELSEWHERE' | 'PEP' | 'CLEAR' | 'UNKNOWN';
  /** Worldwide matches for name queries (OpenSanctions); empty when not configured or not a name. */
  worldwide: WorldMatch[];
}

const brief = (e: SdnEntry) => ({ name: e.name, type: e.type, program: e.program, uid: e.uid });

export async function screen(ctx: Ctx, queryInput: string): Promise<ModuleResult<ScreenResult>> {
  const query = queryInput.trim();
  const provenance: Provenance[] = [];
  const idx = await sdn(ctx);
  provenance.push(idx.prov);
  const nowIso = ctx.now().toISOString();
  if (!idx.data) return { module: 'sanctions', input: query, generatedAt: nowIso, result: { query, listDate: null, listSize: 0, hits: [], verdict: 'UNKNOWN', worldwide: [] }, signals: [], provenance };
  const S = idx.data;
  const hits: Hit[] = [];

  const imo = /^(?:IMO\s*)?(\d{7})$/i.exec(query)?.[1];
  if (imo) {
    const e = S.byImo.get(imo);
    if (e) hits.push({ kind: 'imo', matched: `IMO ${imo}`, entry: brief(e) });
  } else if (isEvmAddress(query) || /^(T[1-9A-HJ-NP-Za-km-z]{33}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,})$/.test(query)) {
    const e = S.byAddress.get(query.toLowerCase());
    if (e) hits.push({ kind: 'address', matched: query, entry: brief(e) });
    // One hop: did this wallet transact directly with a listed address? (Ethereum, latest 100 transactions)
    if (isEvmAddress(query)) {
      const txs = await etherscanTxs(ctx, query, 1, 'desc', 100);
      provenance.push(txs.prov);
      const seen = new Set<string>();
      for (const t of txs.data ?? []) {
        const other = t.from.toLowerCase() === query.toLowerCase() ? t.to : t.from;
        const o = other?.toLowerCase();
        if (!o || seen.has(o)) continue;
        seen.add(o);
        const c = S.byAddress.get(o);
        if (c) hits.push({ kind: 'counterparty', matched: other, entry: brief(c), detail: `${t.from.toLowerCase() === query.toLowerCase() ? 'sent to' : 'received from'} a listed address on ${t.time.slice(0, 10)} (tx ${t.hash.slice(0, 12)}…)` });
      }
    }
  } else {
    const e = S.byName.get(normName(query));
    if (e) hits.push({ kind: 'name', matched: query, entry: brief(e) });
  }
  let worldwide: WorldMatch[] = [];
  if (!imo && !isEvmAddress(query) && query.length >= 3) {
    const w = await worldMatch(ctx, query);
    provenance.push(w.prov);
    worldwide = w.data ?? [];
  }
  const strong = worldwide.filter((w) => w.score >= 0.9);

  const verdict: ScreenResult['verdict'] = hits.some((h) => h.kind !== 'counterparty')
    ? 'SANCTIONED'
    : hits.length
      ? 'EXPOSED'
      : strong.some((w) => w.topics.includes('sanction'))
        ? 'LISTED_ELSEWHERE'
        : strong.some((w) => w.topics.some((t) => t.startsWith('role.pep') || t === 'role.pol'))
          ? 'PEP'
          : 'CLEAR';
  const signals: Signal[] = [];
  if (verdict === 'LISTED_ELSEWHERE') {
    signals.push({
      id: signalId('sanctions', query.toLowerCase()),
      module: 'sanctions',
      title: `${query}: on non-US sanctions lists (${strong[0]!.name}, ${strong[0]!.datasets} datasets)`,
      score: 80,
      evidence: strong.slice(0, 3).map((w) => ({ source: 'opensanctions', text: `${w.name} (${w.schema}, match ${w.score}): ${w.topics.join(', ')}`, url: w.url })),
      createdAt: nowIso,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  } else if (verdict !== 'CLEAR' && verdict !== 'PEP') {
    signals.push({
      id: signalId('sanctions', query.toLowerCase()),
      module: 'sanctions',
      title: `${query.length > 24 ? `${query.slice(0, 12)}…` : query}: ${verdict === 'SANCTIONED' ? `on the OFAC SDN list (${hits[0]!.entry.program || hits[0]!.entry.name})` : `transacted with ${hits.length} OFAC-listed address(es)`}`,
      score: verdict === 'SANCTIONED' ? 90 : 75,
      evidence: hits.map((h) => ({ source: 'ofac', text: `${h.kind}: ${h.entry.name} [${h.entry.program}]${h.detail ? ` — ${h.detail}` : ''}`, url: `https://sanctionssearch.ofac.treas.gov/Details.aspx?id=${h.entry.uid}` })),
      createdAt: nowIso,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }
  return { module: 'sanctions', input: query, generatedAt: nowIso, result: { query, listDate: S.fetchedAt, listSize: S.entries.length, hits, verdict, worldwide }, signals, provenance };
}

/** Screen many values at once (used on watchlist wallets, ships seen in fences, dossier names). */
export async function screenMany(ctx: Ctx, values: string[]): Promise<ScreenResult[]> {
  const out: ScreenResult[] = [];
  for (const v of [...new Set(values.filter(Boolean))].slice(0, 50)) out.push((await screen(ctx, v)).result);
  return out;
}
