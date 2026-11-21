import type { Store } from './store.js';
import type { Signal } from './types.js';

export type EntityKind =
  | 'domain'
  | 'subdomain'
  | 'url'
  | 'org'
  | 'repo'
  | 'topic'
  | 'article'
  | 'story'
  | 'market'
  | 'event'
  | 'aircraft'
  | 'company';

export interface Entity {
  id: string;
  kind: EntityKind;
  name: string;
  attrs: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
}

export interface Neighbor {
  id: string;
  kind: EntityKind;
  name: string;
  rel: string;
  direction: 'out' | 'in';
  source: string;
}

export function entityId(kind: EntityKind, name: string): string {
  return `${kind}:${name.trim().toLowerCase()}`;
}

interface EntityRow {
  id: string;
  kind: EntityKind;
  name: string;
  attrs: string;
  created_at: number;
  updated_at: number;
}

const toEntity = (r: EntityRow): Entity => ({
  id: r.id,
  kind: r.kind,
  name: r.name,
  attrs: JSON.parse(r.attrs) as Record<string, unknown>,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

/** Entity graph: everything Oculon sees (domains, repos, articles, markets...) becomes a node with typed edges. */
export class Graph {
  constructor(private readonly store: Store) {}

  get(id: string): Entity | undefined {
    const row = this.store.db.prepare('SELECT * FROM entities WHERE id = ?').get(id) as EntityRow | undefined;
    return row ? toEntity(row) : undefined;
  }

  has(id: string): boolean {
    return this.store.db.prepare('SELECT 1 FROM entities WHERE id = ?').get(id) !== undefined;
  }

  /** Insert or merge attributes. Returns the entity id. */
  upsert(kind: EntityKind, name: string, attrs: Record<string, unknown> = {}, now = Date.now()): string {
    const id = entityId(kind, name);
    const existing = this.get(id);
    const merged = JSON.stringify({ ...(existing?.attrs ?? {}), ...attrs });
    this.store.db
      .prepare(
        `INSERT INTO entities (id, kind, name, attrs, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET attrs = excluded.attrs, updated_at = excluded.updated_at`,
      )
      .run(id, kind, name.trim(), merged, now, now);
    return id;
  }

  link(src: string, dst: string, rel: string, source: string, weight = 1, now = Date.now()): void {
    this.store.db
      .prepare(
        `INSERT INTO edges (src, dst, rel, source, weight, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(src, dst, rel) DO UPDATE SET weight = excluded.weight, updated_at = excluded.updated_at`,
      )
      .run(src, dst, rel, source, weight, now, now);
  }

  neighbors(id: string): Neighbor[] {
    const rows = this.store.db
      .prepare(
        `SELECT e.dst AS id, n.kind, n.name, e.rel, 'out' AS direction, e.source FROM edges e JOIN entities n ON n.id = e.dst WHERE e.src = ?
         UNION ALL
         SELECT e.src AS id, n.kind, n.name, e.rel, 'in' AS direction, e.source FROM edges e JOIN entities n ON n.id = e.src WHERE e.dst = ?`,
      )
      .all(id, id) as unknown as Neighbor[];
    return rows;
  }

  observe(
    entity: string,
    module: string,
    kind: string,
    value: number | null,
    source: string,
    payload: Record<string, unknown> = {},
    now = Date.now(),
  ): void {
    this.store.db
      .prepare('INSERT INTO observations (entity_id, module, kind, value, payload, source, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(entity, module, kind, value, JSON.stringify(payload), source, now);
  }

  history(entity: string, kind: string, limit = 100): { value: number | null; observedAt: number }[] {
    const rows = this.store.db
      .prepare('SELECT value, observed_at FROM observations WHERE entity_id = ? AND kind = ? ORDER BY observed_at DESC LIMIT ?')
      .all(entity, kind, limit) as { value: number | null; observed_at: number }[];
    return rows.map((r) => ({ value: r.value, observedAt: r.observed_at }));
  }

  saveSignal(s: Signal): void {
    this.store.db
      .prepare(
        `INSERT INTO signals (id, module, entity_id, title, score, evidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET score = excluded.score, evidence = excluded.evidence, title = excluded.title`,
      )
      .run(s.id, s.module, s.entity ?? null, s.title, s.score, JSON.stringify(s.evidence), Date.parse(s.createdAt));
  }

  recentSignals(limit = 50): Signal[] {
    const rows = this.store.db
      .prepare('SELECT * FROM signals ORDER BY created_at DESC, score DESC LIMIT ?')
      .all(limit) as { id: string; module: string; entity_id: string | null; title: string; score: number; evidence: string; created_at: number }[];
    return rows.map((r) => ({
      id: r.id,
      module: r.module,
      title: r.title,
      score: r.score,
      ...(r.entity_id ? { entity: r.entity_id } : {}),
      evidence: JSON.parse(r.evidence),
      createdAt: new Date(r.created_at).toISOString(),
    }));
  }
}
