/**
 * US Treasury OFAC Specially Designated Nationals list (public domain). Downloaded as CSV, parsed once a day,
 * and indexed by digital-currency address, vessel IMO number and normalized name.
 */
import type { Ctx } from '../core/context.js';
import type { Provenance } from '../core/types.js';

export interface SdnEntry {
  uid: string;
  name: string;
  type: string;
  program: string;
  remarks: string;
}

export interface SdnIndex {
  entries: SdnEntry[];
  byAddress: Map<string, SdnEntry>;
  byImo: Map<string, SdnEntry>;
  byName: Map<string, SdnEntry>;
  fetchedAt: string;
}

const URL_SDN = 'https://www.treasury.gov/ofac/downloads/sdn.csv';
const DERIVED = 'derived:ofac-sdn:v1';
let memo: SdnIndex | null = null;

/** CSV line parser for the SDN file (quoted fields, "-0-" means empty). */
export function parseSdnCsv(csv: string): SdnEntry[] {
  const out: SdnEntry[] = [];
  for (const line of csv.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const f: string[] = [];
    let cur = '';
    let q = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i]!;
      if (q) {
        if (c === '"' && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else if (c === '"') q = false;
        else cur += c;
      } else if (c === '"') q = true;
      else if (c === ',') {
        f.push(cur);
        cur = '';
      } else cur += c;
    }
    f.push(cur);
    const v = (i: number) => (f[i] ?? '').trim().replace(/^-0-$/, '');
    if (!v(0) || !v(1)) continue;
    out.push({ uid: v(0), name: v(1), type: v(2) || 'entity', program: v(3), remarks: v(11) });
  }
  return out;
}

export const normName = (s: string) =>
  s
    .toUpperCase()
    .normalize('NFKD')
    .replace(/[^A-Z0-9 ]/g, ' ')
    .replace(/\b(LTD|LLC|INC|CO|CORP|CORPORATION|COMPANY|LIMITED|SA|JSC|OOO|PJSC|GMBH|FZE|FZCO)\b/g, '')
    .replace(/\s+/g, ' ')
    .trim();

export function buildIndex(entries: SdnEntry[], fetchedAt: string): SdnIndex {
  const byAddress = new Map<string, SdnEntry>();
  const byImo = new Map<string, SdnEntry>();
  const byName = new Map<string, SdnEntry>();
  for (const e of entries) {
    for (const m of e.remarks.matchAll(/Digital Currency Address - [A-Z0-9]+ ([A-Za-z0-9]+)/g)) byAddress.set(m[1]!.toLowerCase(), e);
    for (const m of e.remarks.matchAll(/IMO (\d{7})/g)) byImo.set(m[1]!, e);
    byName.set(normName(e.name), e);
    for (const m of e.remarks.matchAll(/a\.k\.a\. '([^']+)'/g)) byName.set(normName(m[1]!), e);
  }
  return { entries, byAddress, byImo, byName, fetchedAt };
}

/** The SDN index, refreshed at most once a day. */
export async function sdn(ctx: Ctx): Promise<{ data: SdnIndex | null; prov: Provenance }> {
  if (memo && Date.now() - Date.parse(memo.fetchedAt) < 86_400_000) return { data: memo, prov: { source: 'ofac', url: URL_SDN, status: 'CACHED', fetchedAt: memo.fetchedAt } };
  const cached = ctx.store.cacheGet(DERIVED);
  if (cached && Date.now() - cached.fetchedAt < 86_400_000) {
    memo = buildIndex(JSON.parse(cached.body) as SdnEntry[], new Date(cached.fetchedAt).toISOString());
    return { data: memo, prov: { source: 'ofac', url: URL_SDN, status: 'CACHED', fetchedAt: memo.fetchedAt } };
  }
  const r = await ctx.http.get<string>(URL_SDN, { source: 'ofac', as: 'text', ttlSec: 0, timeoutMs: 90_000 });
  ctx.store.db.prepare('DELETE FROM cache WHERE key = ?').run(URL_SDN);
  if (!r.data) {
    if (cached) {
      memo = buildIndex(JSON.parse(cached.body) as SdnEntry[], new Date(cached.fetchedAt).toISOString());
      return { data: memo, prov: { ...r.prov, status: 'CACHED', note: 'stale sanctions list' } };
    }
    return { data: null, prov: r.prov };
  }
  const entries = parseSdnCsv(r.data);
  ctx.store.cachePut(DERIVED, JSON.stringify(entries));
  memo = buildIndex(entries, new Date().toISOString());
  return { data: memo, prov: r.prov };
}
