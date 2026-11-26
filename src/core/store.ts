import { DatabaseSync } from 'node:sqlite';
import { copyFileSync, existsSync, mkdirSync, statSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { oculonHome } from './paths.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS cache (
  key TEXT PRIMARY KEY,
  body TEXT NOT NULL,
  fetched_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  attrs TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS edges (
  src TEXT NOT NULL,
  dst TEXT NOT NULL,
  rel TEXT NOT NULL,
  source TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (src, dst, rel)
);
CREATE INDEX IF NOT EXISTS edges_dst ON edges (dst);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL,
  module TEXT NOT NULL,
  kind TEXT NOT NULL,
  value REAL,
  payload TEXT NOT NULL DEFAULT '{}',
  source TEXT NOT NULL,
  observed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS obs_entity ON observations (entity_id, kind, observed_at);
CREATE TABLE IF NOT EXISTS signals (
  id TEXT PRIMARY KEY,
  module TEXT NOT NULL,
  entity_id TEXT,
  title TEXT NOT NULL,
  score REAL NOT NULL,
  evidence TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signals_time ON signals (created_at);
CREATE TABLE IF NOT EXISTS predictions (
  id TEXT PRIMARY KEY,
  market_id TEXT NOT NULL,
  slug TEXT NOT NULL,
  question TEXT NOT NULL,
  outcome TEXT NOT NULL,
  p_model REAL NOT NULL,
  p_market REAL NOT NULL,
  method TEXT NOT NULL,
  rationale TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  leaf TEXT NOT NULL,
  batch_id TEXT,
  merkle_path TEXT,
  resolved_at INTEGER,
  result INTEGER,
  brier_model REAL,
  brier_market REAL
);
CREATE INDEX IF NOT EXISTS predictions_open ON predictions (resolved_at);
CREATE TABLE IF NOT EXISTS quota (
  source TEXT NOT NULL,
  day TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (source, day)
);
CREATE TABLE IF NOT EXISTS watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  label TEXT,
  created_at INTEGER NOT NULL,
  last_run INTEGER,
  last_state TEXT,
  UNIQUE (kind, target)
);
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  runs INTEGER NOT NULL DEFAULT 0,
  watch INTEGER NOT NULL DEFAULT 0,
  report TEXT,
  markdown TEXT
);
CREATE TABLE IF NOT EXISTS scoops (
  signal_id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  oculon_at INTEGER NOT NULL,
  media_at INTEGER,
  media_source TEXT,
  media_url TEXT,
  lead_hours REAL,
  checked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  south REAL NOT NULL,
  west REAL NOT NULL,
  north REAL NOT NULL,
  east REAL NOT NULL,
  kinds TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_run INTEGER,
  last_state TEXT
);
CREATE TABLE IF NOT EXISTS narratives (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS narrative_items (
  url TEXT PRIMARY KEY,
  narrative_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  source TEXT NOT NULL,
  day TEXT NOT NULL,
  added_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS narrative_items_n ON narrative_items (narrative_id, day);
CREATE TABLE IF NOT EXISTS health (
  company TEXT NOT NULL,
  day TEXT NOT NULL,
  score REAL NOT NULL,
  parts TEXT NOT NULL,
  PRIMARY KEY (company, day)
);
CREATE TABLE IF NOT EXISTS scheduler_runs (
  name TEXT NOT NULL,
  day TEXT NOT NULL,
  ran_at INTEGER NOT NULL,
  PRIMARY KEY (name, day)
);
CREATE TABLE IF NOT EXISTS briefs (
  day TEXT PRIMARY KEY,
  markdown TEXT NOT NULL,
  model TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proof_batches (
  id TEXT PRIMARY KEY,
  root TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  receipts TEXT NOT NULL DEFAULT '[]',
  bitcoin_height INTEGER,
  bitcoin_time INTEGER,
  verified_at INTEGER
);
`;

/**
 * Rebuilds a database whose volume is full: a compacted copy is written to the temp directory (outside the volume),
 * raw API responses are dropped from it (they are only a cache), it is checked, and then it replaces the file, its
 * log and its index on the volume. Returns the reopened database; on any failure before the swap, the original.
 */
export function rescueFullDb(db: DatabaseSync, path: string, tmp = tmpdir()): DatabaseSync {
  const copy = join(tmp, `oculon-rescue-${process.pid}.db`);
  try {
    if (existsSync(copy)) unlinkSync(copy);
    db.exec(`VACUUM INTO '${copy.replace(/'/g, "''")}'`);
    const c = new DatabaseSync(copy);
    c.exec("DELETE FROM cache WHERE key NOT LIKE 'derived:%'");
    c.exec('VACUUM');
    const ok = (c.prepare('PRAGMA quick_check').get() as Record<string, string>)['quick_check'] === 'ok';
    c.close();
    if (!ok) return db;
  } catch { try { if (existsSync(copy)) unlinkSync(copy); } catch { /* ignore */ } return db; }
  db.close();
  for (const f of [`${path}-wal`, `${path}-shm`, path]) { try { if (existsSync(f)) unlinkSync(f); } catch { /* ignore */ } }
  copyFileSync(copy, path);
  try { unlinkSync(copy); } catch { /* ignore */ }
  return new DatabaseSync(path);
}

export class Store {
  db: DatabaseSync;

  constructor(path: string = process.env.OCULON_DB || join(oculonHome(), 'oculon.db')) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    // WAL plus a busy timeout: the web console runs the CLI in a second process against the same file.
    if (path !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 8000;');
    // A full volume leaves the write-ahead log unable to fold back, and then nothing can be written at all.
    if (path !== ':memory:') {
      try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch (e) {
        if (/full/i.test((e as Error).message)) { this.db = rescueFullDb(this.db, path); this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 8000;'); }
      }
    }
    this.db.exec(SCHEMA);
  }

  cacheGet(key: string): { body: string; fetchedAt: number } | undefined {
    const row = this.db.prepare('SELECT body, fetched_at FROM cache WHERE key = ?').get(key) as
      | { body: string; fetched_at: number }
      | undefined;
    return row ? { body: row.body, fetchedAt: row.fetched_at } : undefined;
  }

  cachePut(key: string, body: string, fetchedAt = Date.now()): void {
    this.db
      .prepare('INSERT INTO cache (key, body, fetched_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET body = excluded.body, fetched_at = excluded.fetched_at')
      .run(key, body, fetchedAt);
  }

  /**
   * Deletes everything the on-chain modules left behind (Robinhood Chain pools and deployers, wallet and
   * token checks, DeFi): their signals, scoops, observations, entities, edges and watch targets.
   */
  purgeOnchain(): Record<string, number> {
    const ent = "(%s LIKE 'wallet:%' OR %s LIKE 'token:%' OR %s LIKE 'event:token:%' OR %s LIKE 'event:deployer:%')";
    const on = (col: string) => ent.replaceAll('%s', col);
    const mods = "('heron', 'magpie', 'defi')";
    const run = (sql: string) => Number(this.db.prepare(sql).run().changes);
    return {
      scoops: run(`DELETE FROM scoops WHERE signal_id LIKE 'heron-%' OR signal_id LIKE 'magpie-%' OR signal_id LIKE 'defi-%'`),
      signals: run(`DELETE FROM signals WHERE module IN ${mods} OR (entity_id IS NOT NULL AND ${on('entity_id')})`),
      observations: run(`DELETE FROM observations WHERE module IN ${mods} OR ${on('entity_id')}`),
      edges: run(`DELETE FROM edges WHERE ${on('src')} OR ${on('dst')}`),
      entities: run(`DELETE FROM entities WHERE ${on('id')}`),
      watchlist: run(`DELETE FROM watchlist WHERE kind IN ('wallet', 'token') OR target LIKE '%@robinhood'`),
    };
  }

  /** Drop raw API responses older than `days` (derived entries such as calibration stay), optionally compacting the file. */
  pruneCache(days = 14, vacuum = false, now = Date.now()): { removed: number } {
    const removed = Number(this.db.prepare("DELETE FROM cache WHERE fetched_at < ? AND key NOT LIKE 'derived:%'").run(now - days * 86_400_000).changes);
    if (vacuum) this.db.exec('VACUUM');
    return { removed };
  }

  /** Size of the database file, its write-ahead log and the largest tables, in bytes. */
  storageReport(): { file: number; free: number; wal: number; tables: { name: string; bytes: number }[] } {
    const one = (sql: string) => Number(Object.values(this.db.prepare(sql).get() as Record<string, number>)[0] ?? 0);
    const pageSize = one('PRAGMA page_size');
    const file = one('PRAGMA page_count') * pageSize, free = one('PRAGMA freelist_count') * pageSize;
    let wal = 0;
    try { const f = (this.db.prepare("SELECT file FROM pragma_database_list WHERE name = 'main'").get() as { file: string } | undefined)?.file; if (f) wal = statSync(`${f}-wal`).size; } catch { /* no WAL file */ }
    let tables: { name: string; bytes: number }[] = [];
    try { tables = (this.db.prepare('SELECT name, sum(pgsize) AS bytes FROM dbstat GROUP BY name ORDER BY bytes DESC LIMIT 8').all() as { name: string; bytes: number }[]).map((r) => ({ name: r.name, bytes: Number(r.bytes) })); } catch { /* dbstat not compiled in */ }
    return { file, free, wal, tables };
  }

  /**
   * Keeps the file small on a volume with a hard limit: folds the write-ahead log back into the file, drops raw
   * API responses older than `cacheDays` and old observations, then compacts when `vacuum` is set.
   */
  relieve(cacheDays = 3, obsDays = 60, vacuum = false, now = Date.now()): { cache: number; observations: number } {
    try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* busy: next time */ }
    const cache = Number(this.db.prepare("DELETE FROM cache WHERE fetched_at < ? AND key NOT LIKE 'derived:%'").run(now - cacheDays * 86_400_000).changes)
      // Large responses (imagery, full lists) are the bulk of the file; a day old is old enough for them.
      + Number(this.db.prepare("DELETE FROM cache WHERE fetched_at < ? AND length(body) > 100000 AND key NOT LIKE 'derived:%'").run(now - 86_400_000).changes);
    const observations = Number(this.db.prepare('DELETE FROM observations WHERE observed_at < ?').run(now - obsDays * 86_400_000).changes);
    try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* busy */ }
    if (vacuum) {
      try { this.db.exec('VACUUM'); } catch { /* not enough room to rebuild: freed pages are still reused */ }
      try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* busy */ }
    }
    return { cache, observations };
  }

  close(): void {
    this.db.close();
  }
}
