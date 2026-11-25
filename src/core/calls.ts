/**
 * What happened on the wire, for three features that share one hook in Http:
 *   - replay log: every source call made while a check runs (AsyncLocalStorage ties calls to that check);
 *   - /status: per-source success, failures and latency over the last day, from every live fetch;
 *   - auto fallback: a host that keeps failing is skipped for a few minutes (cached data or a mirror answers instead).
 * No dependencies: node:async_hooks and the install's own SQLite database.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import type { Store } from './store.js';
import type { Status } from './types.js';

export interface CallEntry {
  source: string;
  /** Host only; full URLs can carry query text the user typed. */
  host: string;
  status: Status;
  /** Wall time of the request, 0 for cache hits. */
  ms: number;
  at: string;
  note?: string;
  /** Answered by a mirror after the primary host failed or was skipped. */
  via?: string;
}

const log = new AsyncLocalStorage<CallEntry[]>();

/** Run `fn` and collect every source call it makes, including calls made by modules it calls. */
export async function withCallLog<T>(fn: () => Promise<T>): Promise<{ value: T; calls: CallEntry[] }> {
  const calls: CallEntry[] = [];
  const value = await log.run(calls, fn);
  return { value, calls };
}

export function logCall(e: CallEntry): void {
  const calls = log.getStore();
  if (calls && calls.length < 2000) calls.push(e);
}

/* ---------- source stats for /status ---------- */

const ensured = new WeakSet<Store>();
function ensure(store: Store): void {
  if (ensured.has(store)) return;
  store.db.exec(`CREATE TABLE IF NOT EXISTS source_calls (source TEXT NOT NULL, host TEXT NOT NULL, at INTEGER NOT NULL, ok INTEGER NOT NULL, ms INTEGER NOT NULL, note TEXT);
    CREATE INDEX IF NOT EXISTS source_calls_at ON source_calls (at);`);
  ensured.add(store);
}

let inserts = 0;
/** One live fetch (not cache hits). Rows older than two days are pruned now and then. */
export function recordSourceCall(store: Store, source: string, host: string, ok: boolean, ms: number, note?: string): void {
  try {
    ensure(store);
    const now = Date.now();
    store.db.prepare('INSERT INTO source_calls (source, host, at, ok, ms, note) VALUES (?, ?, ?, ?, ?, ?)').run(source, host, now, ok ? 1 : 0, Math.round(ms), note ? note.slice(0, 200) : null);
    if (++inserts % 500 === 0) store.db.prepare('DELETE FROM source_calls WHERE at < ?').run(now - 2 * 86_400_000);
  } catch {
    // Stats are best effort: a read-only or closed database must never break a check.
  }
}

export type SourceState = 'up' | 'slow' | 'down' | 'degraded';

export interface SourceStatus {
  source: string;
  hosts: string[];
  state: SourceState;
  calls: number;
  failed: number;
  /** Share of calls that worked, 0-100. */
  okPct: number;
  medianMs: number | null;
  lastOk: string | null;
  lastError: { at: string; note: string } | null;
  /** Skipped right now because it kept failing; a mirror or cached data answers instead. */
  skippedUntil: string | null;
}

const median = (xs: number[]) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)]!;
};

/** Every source that made a live call in the last `hours`, worst first. */
export function sourceStatus(store: Store, hours = 24, now = Date.now()): SourceStatus[] {
  ensure(store);
  const rows = store.db.prepare('SELECT source, host, at, ok, ms, note FROM source_calls WHERE at >= ? ORDER BY at ASC').all(now - hours * 3_600_000) as { source: string; host: string; at: number; ok: number; ms: number; note: string | null }[];
  const by = new Map<string, typeof rows>();
  for (const r of rows) (by.get(r.source) ?? by.set(r.source, []).get(r.source)!).push(r);
  const out: SourceStatus[] = [];
  for (const [source, rs] of by) {
    const failed = rs.filter((r) => !r.ok);
    const okRows = rs.filter((r) => r.ok);
    const recent = rs.slice(-5);
    const med = median(okRows.map((r) => r.ms));
    const lastErr = failed[failed.length - 1];
    const lastOk = okRows[okRows.length - 1];
    const hosts = [...new Set(rs.map((r) => r.host))];
    const skipped = hosts.map((h) => breakerOpenUntil(h, now)).filter((x): x is number => x !== null);
    const recentFail = recent.filter((r) => !r.ok).length;
    const state: SourceState = skipped.length || (recent.length >= 2 && recentFail === recent.length) ? 'down' : recentFail ? 'degraded' : med !== null && med > 5000 ? 'slow' : 'up';
    out.push({
      source,
      hosts,
      state,
      calls: rs.length,
      failed: failed.length,
      okPct: Math.round((okRows.length / rs.length) * 100),
      medianMs: med,
      lastOk: lastOk ? new Date(lastOk.at).toISOString() : null,
      lastError: lastErr ? { at: new Date(lastErr.at).toISOString(), note: lastErr.note ?? 'failed' } : null,
      skippedUntil: skipped.length ? new Date(Math.max(...skipped)).toISOString() : null,
    });
  }
  const rank: Record<SourceState, number> = { down: 0, degraded: 1, slow: 2, up: 3 };
  return out.sort((a, b) => rank[a.state] - rank[b.state] || b.calls - a.calls);
}

/* ---------- breaker: skip a host that keeps failing ---------- */

/** Failures in a row before a host is skipped, and for how long. */
export const BREAKER = { failures: 3, skipMs: 5 * 60_000 };
const breakers = new Map<string, { fails: number; openUntil: number }>();

export function breakerOpenUntil(host: string, now = Date.now()): number | null {
  const b = breakers.get(host);
  return b && b.openUntil > now ? b.openUntil : null;
}

export function breakerResult(host: string, ok: boolean, now = Date.now()): void {
  if (ok) {
    breakers.delete(host);
    return;
  }
  const b = breakers.get(host) ?? { fails: 0, openUntil: 0 };
  b.fails++;
  if (b.fails >= BREAKER.failures) {
    b.openUntil = now + BREAKER.skipMs;
    b.fails = 0;
  }
  breakers.set(host, b);
}

export function resetBreakers(): void {
  breakers.clear();
}

/* ---------- mirrors: the same API on another host ---------- */

export interface Mirror {
  host: string;
  /** Same request on the mirror, or null when this URL has no equivalent there. */
  rewrite: (u: URL) => { url: string; headers?: Record<string, string> } | null;
}

/**
 * Hosts with a drop-in equivalent: same query, same JSON shape. Used when the primary fails after its retries
 * or is being skipped. Sources with a different shape keep their own fallbacks in their modules.
 */
export const MIRRORS: Record<string, Mirror> = {
  // Google and Cloudflare DNS-over-HTTPS share the JSON format (RFC 8484 JSON flavour).
  'dns.google': { host: 'cloudflare-dns.com', rewrite: (u) => (u.pathname === '/resolve' ? { url: `https://cloudflare-dns.com/dns-query${u.search}`, headers: { accept: 'application/dns-json' } } : null) },
  'cloudflare-dns.com': { host: 'dns.google', rewrite: (u) => (u.pathname === '/dns-query' ? { url: `https://dns.google/resolve${u.search}` } : null) },
  // mempool.space and Blockstream both run the Esplora API.
  'mempool.space': { host: 'blockstream.info', rewrite: (u) => (u.pathname.startsWith('/api/') ? { url: `https://blockstream.info${u.pathname}${u.search}` } : null) },
  'blockstream.info': { host: 'mempool.space', rewrite: (u) => (u.pathname.startsWith('/api/') ? { url: `https://mempool.space${u.pathname}${u.search}` } : null) },
};
