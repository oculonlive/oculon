/**
 * Open phishing blocklists, kept in the local database and refreshed once a day (no keys):
 *   ScamSniffer scam-database: about 358k crypto phishing and wallet drainer domains (published with a 7-day
 *     delay), plus its older list of scam addresses (no longer updated since 2024).
 *   MetaMask eth-phishing-detect: the blocklist MetaMask uses to warn wallet users, and its allowlist of real
 *     sites, which keeps well known domains from being flagged by lookalike rules.
 * Lookups are offline: a domain matches when it or any parent domain is listed.
 */
import type { Ctx } from '../core/context.js';
import type { Provenance } from '../core/types.js';

const SOURCES = {
  scamsnifferDomains: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json',
  scamsnifferAddresses: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json',
  metamask: 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json',
};
const REFRESH_MS = 24 * 3600_000;
const LOADED = 'derived:phishlists:loaded';

function ensureTables(ctx: Ctx) {
  ctx.store.db.exec(`CREATE TABLE IF NOT EXISTS phish_domains (domain TEXT NOT NULL, source TEXT NOT NULL, PRIMARY KEY (domain, source));
    CREATE TABLE IF NOT EXISTS phish_addresses (address TEXT NOT NULL PRIMARY KEY, source TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS phish_allow (domain TEXT NOT NULL PRIMARY KEY)`);
}

/** Replace one list's rows in a single transaction. */
export function loadPhishList(ctx: Ctx, table: 'phish_domains' | 'phish_addresses' | 'phish_allow', source: string, values: string[]): number {
  ensureTables(ctx);
  const db = ctx.store.db;
  const col = table === 'phish_addresses' ? 'address' : 'domain';
  db.exec('BEGIN');
  try {
    if (table === 'phish_allow') db.exec('DELETE FROM phish_allow');
    else db.prepare(`DELETE FROM ${table} WHERE source = ?`).run(source);
    const ins = table === 'phish_allow' ? db.prepare('INSERT OR IGNORE INTO phish_allow (domain) VALUES (?)') : db.prepare(`INSERT OR IGNORE INTO ${table} (${col}, source) VALUES (?, ?)`);
    let n = 0;
    for (const v of values) {
      const x = String(v).trim().toLowerCase();
      if (!x || x.length > 253) continue;
      if (table === 'phish_allow') ins.run(x); else ins.run(x, source);
      n++;
    }
    db.exec('COMMIT');
    return n;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

/** Make sure the lists are present and at most a day old. */
export async function ensurePhishLists(ctx: Ctx): Promise<Provenance[]> {
  ensureTables(ctx);
  const loaded = ctx.store.cacheGet(LOADED);
  if (loaded && ctx.now().getTime() - loaded.fetchedAt < REFRESH_MS) return [{ source: 'phishing-lists', url: SOURCES.scamsnifferDomains, status: 'CACHED', fetchedAt: new Date(loaded.fetchedAt).toISOString(), note: loaded.body }];
  const out: Provenance[] = [];
  const counts: string[] = [];
  const get = async <T>(url: string, source: string): Promise<T | null> => {
    const r = await ctx.http.get<T>(url, { source, ttlSec: 0, timeoutMs: 120_000, retries: 1 });
    out.push(r.prov);
    ctx.store.db.prepare('DELETE FROM cache WHERE key = ?').run(url);
    return r.data;
  };
  const sd = await get<string[]>(SOURCES.scamsnifferDomains, 'scamsniffer');
  if (Array.isArray(sd)) counts.push(`${loadPhishList(ctx, 'phish_domains', 'scamsniffer', sd)} ScamSniffer domains`);
  const sa = await get<string[]>(SOURCES.scamsnifferAddresses, 'scamsniffer');
  if (Array.isArray(sa)) counts.push(`${loadPhishList(ctx, 'phish_addresses', 'scamsniffer', sa.filter((a) => /^0x[0-9a-f]{40}$/i.test(a)))} ScamSniffer addresses`);
  const mm = await get<{ blacklist?: string[]; whitelist?: string[] }>(SOURCES.metamask, 'metamask-phishing');
  if (mm?.blacklist) counts.push(`${loadPhishList(ctx, 'phish_domains', 'metamask', mm.blacklist)} MetaMask blocked domains`);
  if (mm?.whitelist) loadPhishList(ctx, 'phish_allow', 'metamask', mm.whitelist);
  if (counts.length) ctx.store.cachePut(LOADED, counts.join(', '), ctx.now().getTime());
  return out;
}

/** The domain itself and each parent domain: a.b.example.com -> [a.b.example.com, b.example.com, example.com]. */
const parents = (host: string) => { const p = host.toLowerCase().replace(/\.$/, '').split('.'); return p.slice(0, -1).map((_, i) => p.slice(i).join('.')); };

/** Which blocklists list this host (or a parent domain), unless the allowlist names it. */
export function phishDomain(ctx: Ctx, host: string): { listed: string[]; allowed: boolean } {
  ensureTables(ctx);
  const ps = parents(host);
  if (!ps.length) return { listed: [], allowed: false };
  const q = ps.map(() => '?').join(',');
  const allowed = Boolean(ctx.store.db.prepare(`SELECT 1 FROM phish_allow WHERE domain IN (${q}) LIMIT 1`).get(...ps));
  const rows = ctx.store.db.prepare(`SELECT DISTINCT source FROM phish_domains WHERE domain IN (${q})`).all(...ps) as { source: string }[];
  return { listed: allowed ? [] : rows.map((r) => (r.source === 'metamask' ? 'MetaMask phishing list' : 'ScamSniffer blocklist')), allowed };
}

export function phishAddress(ctx: Ctx, address: string): string | null {
  ensureTables(ctx);
  const r = ctx.store.db.prepare('SELECT source FROM phish_addresses WHERE address = ?').get(address.toLowerCase()) as { source: string } | undefined;
  return r ? 'ScamSniffer scam address list' : null;
}
