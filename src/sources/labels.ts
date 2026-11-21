/**
 * Open address labels: the eth-labels dataset (MIT, github.com/dawsbot/eth-labels), about 100k addresses
 * across EVM chains tagged by exchange, protocol, bridge, scam and so on. Downloaded once and indexed into the
 * local database; refreshed when older than 14 days. Lookups are offline and free.
 */
import type { Ctx } from '../core/context.js';
import type { Provenance } from '../core/types.js';

const URL_CSV = 'https://raw.githubusercontent.com/dawsbot/eth-labels/HEAD/data/csv/accounts.csv';
const REFRESH_MS = 14 * 86_400_000;

export interface AddressLabel {
  chainId: number;
  label: string;
  nameTag: string;
}

/** Minimal CSV line parser for quoted fields. */
export function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (q) {
      if (ch === '"' && line[i + 1] === '"') (cur += '"'), i++;
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') out.push(cur), (cur = '');
    else cur += ch;
  }
  out.push(cur);
  return out;
}

function ensureTable(ctx: Ctx) {
  ctx.store.db.exec(`CREATE TABLE IF NOT EXISTS address_labels (
    address TEXT NOT NULL, chain_id INTEGER NOT NULL, label TEXT NOT NULL, name_tag TEXT NOT NULL,
    PRIMARY KEY (address, chain_id, label)
  )`);
}

/** Load rows from CSV text into the table. Returns the number stored. */
export function loadLabels(ctx: Ctx, csv: string): number {
  ensureTable(ctx);
  const db = ctx.store.db;
  const ins = db.prepare('INSERT OR REPLACE INTO address_labels (address, chain_id, label, name_tag) VALUES (?, ?, ?, ?)');
  let n = 0;
  db.exec('BEGIN');
  try {
    db.exec('DELETE FROM address_labels');
    for (const line of csv.split('\n').slice(1)) {
      if (!line.trim()) continue;
      const [address, chainId, label, nameTag] = parseCsvLine(line.trim());
      if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) continue;
      ins.run(address.toLowerCase(), Number(chainId) || 1, label ?? '', nameTag ?? '');
      n++;
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
  ctx.store.cachePut('derived:eth-labels:loaded', String(n), ctx.now().getTime());
  return n;
}

/** Make sure the dataset is present and fresh; downloads about 12 MB at most every 14 days. */
export async function ensureLabels(ctx: Ctx): Promise<Provenance> {
  ensureTable(ctx);
  const loaded = ctx.store.cacheGet('derived:eth-labels:loaded');
  const nowIso = ctx.now().toISOString();
  if (loaded && ctx.now().getTime() - loaded.fetchedAt < REFRESH_MS) return { source: 'eth-labels', url: URL_CSV, status: 'CACHED', fetchedAt: new Date(loaded.fetchedAt).toISOString(), note: `${loaded.body} labeled addresses` };
  const r = await ctx.http.get<string>(URL_CSV, { source: 'eth-labels', as: 'text', ttlSec: 0, timeoutMs: 120_000 });
  if (!r.data) return loaded ? { ...r.prov, status: 'CACHED', note: 'refresh failed; using the stored copy' } : r.prov;
  const n = loadLabels(ctx, r.data);
  // The raw CSV is in the table now; no need to keep it in the HTTP cache too.
  ctx.store.db.prepare('DELETE FROM cache WHERE key = ?').run(URL_CSV);
  return { ...r.prov, note: `${n} labeled addresses`, fetchedAt: nowIso };
}

export function labelsFor(ctx: Ctx, address: string): AddressLabel[] {
  ensureTable(ctx);
  return (ctx.store.db.prepare('SELECT chain_id, label, name_tag FROM address_labels WHERE address = ? ORDER BY chain_id').all(address.toLowerCase()) as { chain_id: number; label: string; name_tag: string }[]).map((r) => ({ chainId: r.chain_id, label: r.label, nameTag: r.name_tag }));
}

/** Short human tag, e.g. "Binance 14 (binance)". */
export function describeLabels(ls: AddressLabel[]): string | null {
  if (!ls.length) return null;
  const tag = ls.find((l) => l.nameTag)?.nameTag;
  const kinds = [...new Set(ls.map((l) => l.label))].slice(0, 3).join(', ');
  return tag ? `${tag} (${kinds})` : kinds;
}
