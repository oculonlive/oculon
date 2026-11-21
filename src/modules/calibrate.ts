/**
 * Calibration: replay past days with the Time Machine, then check which of those radar items actually became
 * news in the following three days (at least two Guardian articles). From that, measure precision and recall
 * at each score threshold, pick the threshold with the best F1, and store it for the live radar to use.
 * A signal threshold that is measured beats one that is guessed.
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { keywords } from '../core/text.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { guardianCount } from '../sources/press.js';
import { rewind } from './rewind.js';

export interface CalibrationRow {
  threshold: number;
  flagged: number;
  hits: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

export interface Calibration {
  days: number;
  samples: number;
  materialized: number;
  rows: CalibrationRow[];
  best: CalibrationRow | null;
  bySource: Record<string, { samples: number; hits: number; rate: number }>;
  computedAt: string;
}

const KEY = 'derived:calibration:owl';
const THRESHOLDS = [40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90];

export function scoreThresholds(samples: { score: number; hit: boolean }[]): CalibrationRow[] {
  const totalHits = samples.filter((s) => s.hit).length;
  return THRESHOLDS.map((t) => {
    const flagged = samples.filter((s) => s.score >= t);
    const hits = flagged.filter((s) => s.hit).length;
    const precision = flagged.length ? hits / flagged.length : null;
    const recall = totalHits ? hits / totalHits : null;
    const f1 = precision !== null && recall !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
    const r = (x: number | null) => (x === null ? null : Math.round(x * 100) / 100);
    return { threshold: t, flagged: flagged.length, hits, precision: r(precision), recall: r(recall), f1: r(f1) };
  });
}

/** The stored calibration, if any. The live radar reads its threshold from here. */
export function loadCalibration(ctx: Ctx): Calibration | null {
  const c = ctx.store.cacheGet(KEY);
  return c ? (JSON.parse(c.body) as Calibration) : null;
}

/**
 * Per-source strength weights from calibration: a source whose items became news more often than average
 * counts a bit more. Bounded to 0.6-1.3 and only for sources with at least 10 calibration samples.
 */
export function sourceWeights(ctx: Ctx): Record<string, number> {
  const c = loadCalibration(ctx);
  if (!c || !c.samples) return {};
  const avg = c.materialized / c.samples;
  if (!avg) return {};
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(c.bySource)) if (v.samples >= 10 && k !== 'multi-source') out[k] = Math.min(1.3, Math.max(0.6, v.rate / avg));
  return out;
}

export function signalThreshold(ctx: Ctx, fallback = 55): number {
  const best = loadCalibration(ctx)?.best;
  // Only trust a calibration built on enough examples.
  return best && best.flagged >= 10 ? best.threshold : fallback;
}

export async function calibrate(ctx: Ctx, opts: { days?: number; perDay?: number; onDay?: (d: string) => void } = {}): Promise<ModuleResult<Calibration>> {
  const days = Math.min(21, Math.max(3, opts.days ?? 10));
  const perDay = opts.perDay ?? 12;
  const provenance: Provenance[] = [];
  const samples: { score: number; hit: boolean; sources: string[]; title: string; day: string }[] = [];
  const nowMs = ctx.now().getTime();

  // Start 4 days back so every replayed day has a full 3-day window after it.
  for (let i = 0; i < days; i++) {
    const day = new Date(nowMs - (4 + i) * DAY_MS).toISOString().slice(0, 10);
    opts.onDay?.(day);
    const r = await rewind(ctx, day, { wikiDepth: 15 });
    provenance.push(...r.provenance.filter((p) => p.status !== 'LIVE' && p.status !== 'CACHED'));
    const items = r.result.fused.filter((f) => f.sources.some((s) => s !== 'guardian')).slice(0, perDay);
    const from = new Date(Date.parse(day) + DAY_MS).toISOString().slice(0, 10);
    const to = new Date(Date.parse(day) + 3 * DAY_MS).toISOString().slice(0, 10);
    for (const f of items) {
      const subject = [...keywords(f.title)].slice(0, 4).join(' ');
      if (!subject) continue;
      const n = await guardianCount(ctx, subject, from, to);
      if (n.data === null) continue;
      samples.push({ score: f.score, hit: n.data >= 2, sources: f.sources.filter((s) => s !== 'guardian'), title: f.title, day });
    }
  }

  const rows = scoreThresholds(samples);
  const best = rows.filter((r) => r.f1 !== null && r.flagged >= 5).sort((a, b) => b.f1! - a.f1! || b.threshold - a.threshold)[0] ?? null;
  const bySource: Calibration['bySource'] = {};
  for (const s of samples) {
    const k = s.sources.length > 1 ? 'multi-source' : (s.sources[0] ?? 'unknown');
    const b = (bySource[k] ??= { samples: 0, hits: 0, rate: 0 });
    b.samples++;
    if (s.hit) b.hits++;
  }
  for (const b of Object.values(bySource)) b.rate = Math.round((b.hits / b.samples) * 100) / 100;

  const result: Calibration = { days, samples: samples.length, materialized: samples.filter((s) => s.hit).length, rows, best, bySource, computedAt: new Date(nowMs).toISOString() };
  ctx.store.cachePut(KEY, JSON.stringify(result));
  return { module: 'calibrate', input: `${days} days`, generatedAt: result.computedAt, result, signals: [], provenance };
}
