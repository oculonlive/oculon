/**
 * Feedback: alerts carry "Useful" / "Noise" buttons. Votes are stored per signal, and each module's alert bar
 * moves with them: a module people keep calling noise needs a higher score to alert, a useful one a lower score.
 * The shift only starts after 3 votes and is capped, so a couple of clicks cannot silence a module.
 */
import type { Ctx } from '../core/context.js';

export type Verdict = 'useful' | 'noise';

export function ensureFeedback(ctx: Ctx): void {
  ctx.store.db.exec(`CREATE TABLE IF NOT EXISTS feedback (
    signal_id TEXT NOT NULL,
    voter TEXT NOT NULL,
    module TEXT NOT NULL,
    verdict TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (signal_id, voter)
  )`);
}

export function recordFeedback(ctx: Ctx, signalId: string, verdict: Verdict, voter: string): { module: string; title: string } | null {
  ensureFeedback(ctx);
  const s = ctx.store.db.prepare('SELECT module, title FROM signals WHERE id = ?').get(signalId) as { module: string; title: string } | undefined;
  if (!s) return null;
  ctx.store.db
    .prepare('INSERT INTO feedback (signal_id, voter, module, verdict, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(signal_id, voter) DO UPDATE SET verdict = excluded.verdict, created_at = excluded.created_at')
    .run(signalId, voter, s.module, verdict, ctx.now().getTime());
  return s;
}

export interface ModuleFeedback {
  module: string;
  useful: number;
  noise: number;
  /** Points added to (or taken from) the alert bar for this module. */
  shift: number;
}

/** +3 per net noise vote, -2 per net useful vote, from the third vote on, capped to [-10, +20]. */
export function shiftFor(useful: number, noise: number): number {
  if (useful + noise < 3) return 0;
  const net = noise - useful;
  return Math.max(-10, Math.min(20, net > 0 ? net * 3 : net * 2));
}

export function feedbackStats(ctx: Ctx): ModuleFeedback[] {
  ensureFeedback(ctx);
  const rows = ctx.store.db.prepare("SELECT module, SUM(verdict = 'useful') AS useful, SUM(verdict = 'noise') AS noise FROM feedback GROUP BY module ORDER BY module").all() as { module: string; useful: number; noise: number }[];
  return rows.map((r) => ({ module: r.module, useful: Number(r.useful), noise: Number(r.noise), shift: shiftFor(Number(r.useful), Number(r.noise)) }));
}

/** Alert bar for a module given the base bar. */
export function alertBar(ctx: Ctx, module: string, base: number): number {
  const m = feedbackStats(ctx).find((x) => x.module === module);
  return base + (m?.shift ?? 0);
}
