import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
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

export class Store {
  readonly db: DatabaseSync;

  constructor(path: string = process.env.OCULON_DB || join(oculonHome(), 'oculon.db')) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    // WAL plus a busy timeout: the web console runs the CLI in a second process against the same file.
    if (path !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 8000;');
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

  close(): void {
    this.db.close();
  }
}
