/**
 * Read-only views over the local store for the web app: search, entity profiles, Robinhood Chain
 * deployers, source health, accuracy and a signal timeline. Everything here reads data Oculon already
 * collected; nothing calls an external API.
 */
import type { Oculon } from '../index.js';
import { loadCalibration } from '../modules/calibrate.js';

type Row = Record<string, unknown>;
const parse = (s: unknown): Record<string, unknown> => {
  try {
    return JSON.parse(String(s ?? '{}')) as Record<string, unknown>;
  } catch {
    return {};
  }
};

/** Entities whose name or id contains the query, strongest-linked first. */
export function searchEntities(o: Oculon, q: string, limit = 12) {
  const db = o.ctx.store.db;
  const like = `%${q.replace(/[%_]/g, '')}%`;
  const rows = db
    .prepare(
      `SELECT e.id, e.kind, e.name, e.updated_at,
         (SELECT count(*) FROM edges x WHERE x.src = e.id OR x.dst = e.id) AS links
       FROM entities e WHERE e.name LIKE ? OR e.id LIKE ?
       ORDER BY (e.name = ?) DESC, links DESC, e.updated_at DESC LIMIT ?`,
    )
    .all(like, like, q, limit) as Row[];
  return rows.map((r) => ({ id: String(r.id), kind: String(r.kind), name: String(r.name), links: Number(r.links), updatedAt: new Date(Number(r.updated_at)).toISOString() }));
}

/** Everything stored about one entity: attributes, neighbors, signals that name it and recent observations. */
export function entityProfile(o: Oculon, id: string) {
  const db = o.ctx.store.db;
  const e = db.prepare('SELECT * FROM entities WHERE id = ?').get(id) as Row | undefined;
  if (!e) return null;
  const name = String(e.name);
  const neighbors = o.ctx.graph.neighbors(id).slice(0, 80);
  const byKind: Record<string, number> = {};
  for (const n of neighbors) byKind[n.kind] = (byKind[n.kind] ?? 0) + 1;
  // Signals tied to the entity, plus signals whose title names it (short names only match whole titles loosely).
  const needle = name.length >= 3 ? `%${name.replace(/[%_]/g, '')}%` : null;
  const sigRows = db
    .prepare(`SELECT * FROM signals WHERE entity_id = ? ${needle ? 'OR title LIKE ?' : ''} ORDER BY created_at DESC LIMIT 40`)
    .all(...(needle ? [id, needle] : [id])) as Row[];
  const signals = sigRows.map((r) => ({ id: String(r.id), module: String(r.module), title: String(r.title), score: Number(r.score), evidence: JSON.parse(String(r.evidence)) as { source: string; text: string; url?: string }[], createdAt: new Date(Number(r.created_at)).toISOString() }));
  const observations = (db.prepare('SELECT module, kind, value, source, observed_at FROM observations WHERE entity_id = ? ORDER BY observed_at DESC LIMIT 60').all(id) as Row[]).map((r) => ({
    module: String(r.module),
    kind: String(r.kind),
    value: r.value === null ? null : Number(r.value),
    source: String(r.source),
    at: new Date(Number(r.observed_at)).toISOString(),
  }));
  const sources = [...new Set([...neighbors.map((n) => n.source), ...observations.map((x) => x.source), ...signals.flatMap((s) => s.evidence.map((ev) => ev.source))])].filter(Boolean);
  return {
    id,
    kind: String(e.kind),
    name,
    attrs: parse(e.attrs),
    firstSeen: new Date(Number(e.created_at)).toISOString(),
    lastSeen: new Date(Number(e.updated_at)).toISOString(),
    neighbors,
    neighborKinds: byKind,
    signals,
    observations,
    sources,
  };
}

/** Robinhood Chain deployers Heron has profiled, most prolific first. */
export function rhDeployers(o: Oculon, limit = 25) {
  const rows = o.ctx.store.db.prepare("SELECT name, attrs, updated_at FROM entities WHERE kind = 'event' AND name LIKE 'deployer:%'").all() as Row[];
  return rows
    .map((r) => {
      const a = parse(r.attrs) as { verdict?: string; tokens?: number; dead?: number; contracts?: number };
      return { address: String(r.name).slice('deployer:'.length), verdict: a.verdict ?? 'UNKNOWN', tokens: a.tokens ?? 0, dead: typeof a.dead === 'number' ? a.dead : null, contracts: a.contracts ?? null, checkedAt: new Date(Number(r.updated_at)).toISOString() };
    })
    .filter((d) => d.tokens > 0 || d.verdict !== 'UNKNOWN')
    .sort((x, y) => (y.dead ?? 0) - (x.dead ?? 0) || y.tokens - x.tokens)
    .slice(0, limit);
}

const KEY_GROUPS: [string, string[]][] = [
  ['LLM (ask, case, brief)', ['ANTHROPIC_API_KEY', 'GROQ_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY']],
  ['Web search', ['TAVILY_API_KEY', 'EXA_API_KEY', 'JINA_API_KEY', 'FIRECRAWL_API_KEY']],
  ['News', ['GNEWS_API_KEY', 'GUARDIAN_API_KEY', 'NYT_API_KEY']],
  ['Markets', ['FINNHUB_API_KEY', 'FRED_API_KEY', 'COINGECKO_API_KEY']],
  ['On-chain', ['ZERION_API_KEY', 'ETHERSCAN_API_KEY', 'WEBACY_API_KEY', 'HELIUS_API_KEY', 'ROBINHOOD_PUBLIC_RPC_URL']],
  ['Routing and outages', ['CLOUDFLARE_API_TOKEN']],
  ['Satellites and fires', ['COPERNICUS_CLIENT_ID', 'FIRMS_MAP_KEY', 'NASA_API_KEY']],
  ['Ships', ['GFW_API_TOKEN', 'AISSTREAM_API_KEY']],
  ['Sanctions', ['OPENSANCTIONS_API_KEY']],
  ['Companies', ['ADZUNA_APP_KEY', 'COURTLISTENER_TOKEN', 'COMPANIES_HOUSE_API_KEY', 'BRANDFETCH_API_KEY']],
  ['Social and audio', ['APIFY_TOKEN', 'YOUTUBE_API_KEY', 'BLUESKY_APP_PASSWORD', 'DEEPGRAM_API_KEY']],
  ['Web security', ['URLSCAN_API_KEY', 'SAFE_BROWSING_KEY']],
  ['Telegram bot', ['TELEGRAM_BOT_TOKEN']],
];

/** Which hosts answered recently (from the response cache), today's budget use, and which key groups are set. Key values are never returned. */
export function sourceHealth(o: Oculon) {
  const db = o.ctx.store.db;
  const rows = db.prepare("SELECT key, fetched_at FROM cache WHERE key LIKE 'http%'").all() as { key: string; fetched_at: number }[];
  const hosts = new Map<string, { host: string; responses: number; last: number }>();
  for (const r of rows) {
    let host: string;
    try {
      host = new URL(r.key).hostname.replace(/^www\./, '');
    } catch {
      continue;
    }
    const h = hosts.get(host) ?? { host, responses: 0, last: 0 };
    h.responses++;
    h.last = Math.max(h.last, r.fetched_at);
    hosts.set(host, h);
  }
  const now = Date.now();
  const list = [...hosts.values()]
    .sort((a, b) => b.last - a.last)
    .map((h) => ({ host: h.host, cachedResponses: h.responses, lastFetch: new Date(h.last).toISOString(), state: now - h.last < 3_600_000 ? 'fresh' : now - h.last < 86_400_000 ? 'today' : 'stale' }));
  const keys = KEY_GROUPS.map(([group, names]) => {
    const set = names.filter((n) => process.env[n]?.trim());
    return { group, set: set.length, total: names.length, missing: names.filter((n) => !set.includes(n)) };
  });
  return { hosts: list, quota: o.quota(), keys };
}

/** First-to-know lead times, the radar calibration and the forecast scoreboard in one place. */
export function accuracy(o: Oculon) {
  const cal = loadCalibration(o.ctx);
  return { scoops: o.scoops(), calibration: cal, forecasts: o.scoreboard() };
}

/** Signals from the last `hours` hours, oldest first, for the timeline. */
export function timeline(o: Oculon, hours: number) {
  const since = Date.now() - hours * 3_600_000;
  const rows = o.ctx.store.db.prepare('SELECT id, module, title, score, entity_id, created_at FROM signals WHERE created_at >= ? ORDER BY created_at ASC LIMIT 1500').all(since) as Row[];
  return rows.map((r) => ({ id: String(r.id), module: String(r.module), title: String(r.title), score: Number(r.score), entity: r.entity_id ? String(r.entity_id) : null, at: new Date(Number(r.created_at)).toISOString() }));
}

/** Signals stored after `sinceMs`, newest last (used by the live stream). */
export function signalsSince(o: Oculon, sinceMs: number) {
  const rows = o.ctx.store.db.prepare('SELECT * FROM signals WHERE created_at > ? ORDER BY created_at ASC LIMIT 50').all(sinceMs) as Row[];
  return rows.map((r) => ({ id: String(r.id), module: String(r.module), title: String(r.title), score: Number(r.score), entity: r.entity_id ? String(r.entity_id) : null, evidence: JSON.parse(String(r.evidence)) as unknown[], createdAt: new Date(Number(r.created_at)).toISOString(), ts: Number(r.created_at) }));
}
