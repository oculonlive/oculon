/**
 * Raven: forecasts on real prediction markets with a public, checkable track record.
 * Every forecast stores the crowd price at that moment, so skill is measured against the market
 * (Brier score), not in a vacuum. Forecasts are hashed so Tortoise can timestamp them before resolution.
 */
import type { Ctx } from '../core/context.js';
import { canonicalJson, sha256 } from '../core/merkle.js';
import { clamp } from '../core/stats.js';
import { overlap, keywords, signalId } from '../core/text.js';
import type { Evidence, ModuleResult, Provenance } from '../core/types.js';
import { marketBySlug, resolution, topMarkets, type Market } from '../sources/polymarket.js';
import { owl } from './owl.js';

export type Method = 'manual' | 'momentum-corroborated';

export interface Prediction {
  id: string;
  marketId: string;
  slug: string;
  question: string;
  outcome: string;
  pModel: number;
  pMarket: number;
  method: Method;
  rationale: string;
  evidence: Evidence[];
  createdAt: string;
  leaf: string;
  batchId: string | null;
  resolvedAt: string | null;
  result: 0 | 1 | null;
  brierModel: number | null;
  brierMarket: number | null;
}

/** The exact fields that get hashed. Changing any of them after the fact breaks the proof. */
export function predictionCore(p: Pick<Prediction, 'id' | 'marketId' | 'slug' | 'question' | 'outcome' | 'pModel' | 'pMarket' | 'method' | 'rationale' | 'createdAt'>) {
  return { v: 1, id: p.id, marketId: p.marketId, slug: p.slug, question: p.question, outcome: p.outcome, pModel: p.pModel, pMarket: p.pMarket, method: p.method, rationale: p.rationale, createdAt: p.createdAt };
}

export const leafOf = (p: Parameters<typeof predictionCore>[0]) => sha256(canonicalJson(predictionCore(p))).toString('hex');

interface Row {
  id: string;
  market_id: string;
  slug: string;
  question: string;
  outcome: string;
  p_model: number;
  p_market: number;
  method: Method;
  rationale: string;
  evidence: string;
  created_at: number;
  leaf: string;
  batch_id: string | null;
  resolved_at: number | null;
  result: 0 | 1 | null;
  brier_model: number | null;
  brier_market: number | null;
}

const fromRow = (r: Row): Prediction => ({
  id: r.id,
  marketId: r.market_id,
  slug: r.slug,
  question: r.question,
  outcome: r.outcome,
  pModel: r.p_model,
  pMarket: r.p_market,
  method: r.method,
  rationale: r.rationale,
  evidence: JSON.parse(r.evidence) as Evidence[],
  createdAt: new Date(r.created_at).toISOString(),
  leaf: r.leaf,
  batchId: r.batch_id,
  resolvedAt: r.resolved_at ? new Date(r.resolved_at).toISOString() : null,
  result: r.result,
  brierModel: r.brier_model,
  brierMarket: r.brier_market,
});

export function getPrediction(ctx: Ctx, id: string): Prediction | null {
  const r = ctx.store.db.prepare('SELECT * FROM predictions WHERE id = ?').get(id) as Row | undefined;
  return r ? fromRow(r) : null;
}

export function listPredictions(ctx: Ctx, filter: 'all' | 'open' | 'resolved' = 'all', limit = 100): Prediction[] {
  const where = filter === 'open' ? 'WHERE resolved_at IS NULL' : filter === 'resolved' ? 'WHERE resolved_at IS NOT NULL' : '';
  return (ctx.store.db.prepare(`SELECT * FROM predictions ${where} ORDER BY created_at DESC LIMIT ?`).all(limit) as unknown as Row[]).map(fromRow);
}

function insert(ctx: Ctx, m: Market, pModel: number, method: Method, rationale: string, evidence: Evidence[]): Prediction {
  const createdAt = ctx.now().toISOString();
  const base = {
    id: signalId('raven', m.slug ?? m.id, method, createdAt),
    marketId: m.id,
    slug: m.slug ?? m.id,
    question: m.question,
    outcome: m.outcomes[0] ?? 'Yes',
    pModel: Math.round(pModel * 1000) / 1000,
    pMarket: Math.round((m.prices[0] ?? 0) * 1000) / 1000,
    method,
    rationale,
    createdAt,
  };
  const leaf = leafOf(base);
  ctx.store.db
    .prepare('INSERT INTO predictions (id, market_id, slug, question, outcome, p_model, p_market, method, rationale, evidence, created_at, leaf) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(base.id, base.marketId, base.slug, base.question, base.outcome, base.pModel, base.pMarket, method, rationale, JSON.stringify(evidence), Date.parse(createdAt), leaf);
  ctx.graph.link(ctx.graph.upsert('market', m.question, { url: m.url }), ctx.graph.upsert('event', `prediction:${base.id}`), 'forecast', 'raven');
  return getPrediction(ctx, base.id)!;
}

/** Record your own forecast for the first outcome of a market. */
export async function predict(ctx: Ctx, slug: string, p: number, rationale = ''): Promise<ModuleResult<Prediction>> {
  if (!(p > 0 && p < 1)) throw new Error('probability must be between 0 and 1 (exclusive)');
  const m = await marketBySlug(ctx, slug, 0);
  if (!m.data) throw new Error(`market not found: ${slug} (${m.prov.status} ${m.prov.note ?? ''})`);
  if (m.data.closed) throw new Error('market is already closed; forecasts must be made before resolution');
  const pred = insert(ctx, m.data, p, 'manual', rationale || 'manual forecast', [{ source: 'polymarket', text: `market price at forecast time ${m.data.prices[0]}`, url: m.data.url }]);
  return { module: 'raven', input: slug, generatedAt: pred.createdAt, result: pred, signals: [], provenance: [m.prov] };
}

/**
 * Automatic forecasts with one documented rule: when a market swings hard in 24h AND an independent
 * source (Wikipedia readers, Hacker News) is lighting up about the same subject, assume part of the move
 * is real information and has not finished: forecast = price + 25% of the 24h move.
 * Raven's Brier score against the market's own price tells us whether that rule has any skill.
 */
export const MOMENTUM_SHARE = 0.25;

export function momentumForecast(price: number, change1d: number): number {
  return clamp(price + MOMENTUM_SHARE * change1d, 0.01, 0.99);
}

export async function auto(ctx: Ctx): Promise<ModuleResult<{ created: Prediction[]; skipped: string[] }>> {
  const provenance: Provenance[] = [];
  const [radar, markets] = await Promise.all([owl(ctx), topMarkets(ctx, 200)]);
  provenance.push(...radar.provenance, markets.prov);
  const created: Prediction[] = [];
  const skipped: string[] = [];
  const since = ctx.now().getTime() - 86_400_000;

  for (const f of radar.result.fused) {
    const pm = f.blips.find((b) => b.source === 'polymarket');
    const others = f.blips.filter((b) => b.source !== 'polymarket');
    if (!pm || !others.length) continue;
    const m = markets.data?.find((x) => x.question === pm.title);
    if (!m || m.change1d === null || !m.slug) continue;
    const dup = ctx.store.db.prepare('SELECT 1 FROM predictions WHERE slug = ? AND created_at > ?').get(m.slug, since);
    if (dup) {
      skipped.push(`${m.question}: already forecast in the last 24h`);
      continue;
    }
    const p = momentumForecast(m.prices[0] ?? 0, m.change1d);
    const shared = overlap(keywords(pm.title), new Set(others.flatMap((o) => o.keys))).shared;
    created.push(
      insert(
        ctx,
        m,
        p,
        'momentum-corroborated',
        `24h move ${(m.change1d * 100).toFixed(0)}pp corroborated by ${[...new Set(others.map((o) => o.source))].join(', ')} on "${shared.join(' ')}"`,
        f.blips.map((b) => ({ source: b.source, text: `${b.title}: ${b.detail}`, url: b.url })),
      ),
    );
  }
  return { module: 'raven', input: 'auto', generatedAt: ctx.now().toISOString(), result: { created, skipped }, signals: [], provenance };
}

export const brier = (p: number, outcome: 0 | 1) => (p - outcome) ** 2;

/** Check every open forecast against Polymarket and score the ones that resolved. */
export async function resolve(ctx: Ctx): Promise<ModuleResult<{ checked: number; resolved: Prediction[] }>> {
  const open = listPredictions(ctx, 'open', 1000);
  const provenance: Provenance[] = [];
  const resolved: Prediction[] = [];
  for (const p of open) {
    const m = await marketBySlug(ctx, p.slug, 0);
    provenance.push(m.prov);
    const res = m.data ? resolution(m.data) : null;
    if (res === null) continue;
    ctx.store.db
      .prepare('UPDATE predictions SET resolved_at = ?, result = ?, brier_model = ?, brier_market = ? WHERE id = ?')
      .run(ctx.now().getTime(), res, brier(p.pModel, res), brier(p.pMarket, res), p.id);
    resolved.push(getPrediction(ctx, p.id)!);
  }
  return { module: 'raven', input: 'resolve', generatedAt: ctx.now().toISOString(), result: { checked: open.length, resolved }, signals: [], provenance };
}

export interface Scoreboard {
  total: number;
  open: number;
  resolved: number;
  brierModel: number | null;
  brierMarket: number | null;
  /** 1 - model/market. Positive means Raven beat the crowd price it saw. */
  skill: number | null;
  beatMarket: number;
  byMethod: Record<string, { resolved: number; brierModel: number | null; brierMarket: number | null }>;
}

export function scoreboard(ctx: Ctx): Scoreboard {
  const all = listPredictions(ctx, 'all', 100_000);
  const done = all.filter((p) => p.result !== null);
  const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
  const bm = avg(done.map((p) => p.brierModel!));
  const bk = avg(done.map((p) => p.brierMarket!));
  const byMethod: Scoreboard['byMethod'] = {};
  for (const method of new Set(all.map((p) => p.method))) {
    const d = done.filter((p) => p.method === method);
    byMethod[method] = { resolved: d.length, brierModel: avg(d.map((p) => p.brierModel!)), brierMarket: avg(d.map((p) => p.brierMarket!)) };
  }
  return {
    total: all.length,
    open: all.length - done.length,
    resolved: done.length,
    brierModel: bm,
    brierMarket: bk,
    skill: bm !== null && bk ? 1 - bm / bk : null,
    beatMarket: done.filter((p) => p.brierModel! < p.brierMarket!).length,
    byMethod,
  };
}
