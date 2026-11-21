/**
 * Entity resolution and connection paths over the graph.
 *   resolveEntities: links nodes that are the same real thing under different kinds ("org:nvidia",
 *     "company:nvidia", "domain:nvidia.com", "topic:nvidia") with same_as edges. Rules are conservative:
 *     identical normalized names, or a domain whose main label equals a company or org name.
 *   connect: shortest path between two things ("how is X connected to Y"), treating edges as undirected.
 */
import type { Ctx } from '../core/context.js';
import type { EntityKind } from '../core/graph.js';

const SUFFIX = /\b(incorporated|inc|corp|corporation|co|company|llc|ltd|limited|plc|gmbh|ag|sa|holdings?|group|technologies|technology)\b\.?/g;

export function normEntityName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[.,]/g, ' ')
    .replace(SUFFIX, ' ')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();
}

/** "www.nvidia.com" -> "nvidia", "openai.co.uk" -> "openai". */
export function domainLabel(domain: string): string {
  const parts = domain.toLowerCase().replace(/^www\./, '').split('.');
  if (parts.length >= 3 && /^(co|com|org|net|ac|gov)$/.test(parts[parts.length - 2]!)) return parts[parts.length - 3]!;
  return parts.length >= 2 ? parts[parts.length - 2]! : parts[0]!;
}

const NAMED: EntityKind[] = ['company', 'org', 'topic', 'domain'];

export interface ResolveResult {
  checked: number;
  linked: { a: string; b: string; why: string }[];
}

export function resolveEntities(ctx: Ctx): ResolveResult {
  const rows = ctx.store.db.prepare(`SELECT id, kind, name FROM entities WHERE kind IN (${NAMED.map(() => '?').join(',')})`).all(...NAMED) as { id: string; kind: EntityKind; name: string }[];
  const byName = new Map<string, { id: string; kind: EntityKind }[]>();
  for (const r of rows) {
    const key = r.kind === 'domain' ? `domain:${domainLabel(r.name)}` : normEntityName(r.name);
    if (!key || key.length < 2) continue;
    const list = byName.get(key) ?? [];
    list.push(r);
    byName.set(key, list);
  }
  const linked: ResolveResult['linked'] = [];
  const has = ctx.store.db.prepare("SELECT 1 FROM edges WHERE rel = 'same_as' AND ((src = ? AND dst = ?) OR (src = ? AND dst = ?))");
  const add = (a: string, b: string, why: string) => {
    if (a === b || has.get(a, b, b, a)) return;
    ctx.graph.link(a, b, 'same_as', 'resolver', 1, ctx.now().getTime());
    linked.push({ a, b, why });
  };
  for (const [key, list] of byName) {
    if (key.startsWith('domain:')) continue;
    // Same name, different kinds. A topic only joins when an org or company has the name, so loose topics stay apart.
    const anchor = list.find((x) => x.kind === 'company') ?? list.find((x) => x.kind === 'org');
    if (anchor) for (const x of list) if (x.id !== anchor.id) add(anchor.id, x.id, `same name "${key}"`);
    // Domain whose main label is the name: nvidia.com belongs to Nvidia. Requires 4+ characters to avoid "arm.com"-style guesses on short words.
    const doms = byName.get(`domain:${key.replace(/\s+/g, '')}`) ?? [];
    if (anchor && key.replace(/\s+/g, '').length >= 4) for (const d of doms) add(anchor.id, d.id, `domain ${d.id.slice(7)} matches "${key}"`);
  }
  return { checked: rows.length, linked };
}

export interface PathStep {
  id: string;
  name: string;
  kind: string;
  /** Edge used to reach this node from the previous one. */
  via?: { rel: string; direction: 'out' | 'in'; source: string };
}

export interface ConnectResult {
  from: string | null;
  to: string | null;
  path: PathStep[] | null;
  explored: number;
  note?: string;
}

/** Find an entity by exact id, else by name (companies and orgs first). */
export function findEntity(ctx: Ctx, q: string): { id: string; name: string; kind: string } | undefined {
  const db = ctx.store.db;
  const exact = db.prepare('SELECT id, name, kind FROM entities WHERE id = ?').get(q.toLowerCase().trim()) as { id: string; name: string; kind: string } | undefined;
  if (exact) return exact;
  const rank = "CASE kind WHEN 'company' THEN 0 WHEN 'org' THEN 1 WHEN 'domain' THEN 2 WHEN 'topic' THEN 3 ELSE 4 END";
  const byName = db.prepare(`SELECT id, name, kind FROM entities WHERE lower(name) = ? ORDER BY ${rank} LIMIT 1`).get(q.toLowerCase().trim()) as { id: string; name: string; kind: string } | undefined;
  if (byName) return byName;
  return db.prepare(`SELECT id, name, kind FROM entities WHERE lower(name) LIKE ? ORDER BY ${rank}, length(name) LIMIT 1`).get(`%${q.toLowerCase().trim()}%`) as { id: string; name: string; kind: string } | undefined;
}

export function connect(ctx: Ctx, a: string, b: string, maxDepth = 6): ConnectResult {
  resolveEntities(ctx);
  const src = findEntity(ctx, a);
  const dst = findEntity(ctx, b);
  if (!src || !dst) return { from: src?.id ?? null, to: dst?.id ?? null, path: null, explored: 0, note: `not in the graph yet: ${[!src ? a : null, !dst ? b : null].filter(Boolean).join(', ')}. Run a dossier or investigation on it first.` };
  if (src.id === dst.id) return { from: src.id, to: dst.id, path: [{ id: src.id, name: src.name, kind: src.kind }], explored: 1 };
  const prev = new Map<string, { from: string; rel: string; direction: 'out' | 'in'; source: string }>();
  const seen = new Set([src.id]);
  let frontier = [src.id];
  for (let depth = 0; depth < maxDepth && frontier.length; depth++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const n of ctx.graph.neighbors(id)) {
        if (seen.has(n.id)) continue;
        seen.add(n.id);
        prev.set(n.id, { from: id, rel: n.rel, direction: n.direction, source: n.source });
        if (n.id === dst.id) {
          const path: PathStep[] = [];
          for (let cur: string | undefined = dst.id; cur; cur = prev.get(cur)?.from) {
            const e = ctx.graph.get(cur);
            const p = prev.get(cur);
            path.unshift({ id: cur, name: e?.name ?? cur, kind: e?.kind ?? '?', ...(p ? { via: { rel: p.rel, direction: p.direction, source: p.source } } : {}) });
            if (cur === src.id) break;
          }
          return { from: src.id, to: dst.id, path, explored: seen.size };
        }
        next.push(n.id);
      }
    }
    // Hubs (thousands of neighbors) would make this explode; the graph is local and small, so a cap is enough.
    frontier = next.slice(0, 5000);
  }
  return { from: src.id, to: dst.id, path: null, explored: seen.size, note: `no path within ${maxDepth} hops` };
}

/** Plain-English rendering: "Nvidia -[owns_repo]-> NVIDIA/cuda ...". */
export function describePath(path: PathStep[]): string {
  return path
    .map((s, i) => {
      if (i === 0 || !s.via) return `${s.name} (${s.kind})`;
      const arrow = s.via.direction === 'out' ? `-[${s.via.rel}]->` : `<-[${s.via.rel}]-`;
      return `${arrow} ${s.name} (${s.kind})`;
    })
    .join(' ');
}
