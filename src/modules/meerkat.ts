/**
 * Meerkat: the watchlist. You register targets; Meerkat re-runs the right module on each one and reports
 * only what CHANGED since the previous run. The first run of a target records a baseline and reports nothing.
 */
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { Signal } from '../core/types.js';
import { lights } from './condor.js';
import { cricket } from './cricket.js';
import { track } from './falcon.js';
import { ferret } from './ferret.js';
import { rhTokenCheck } from './heron.js';
import { hound } from './hound.js';
import { token, wallet } from './magpie.js';
import { shipsNear } from './ships.js';
import { air } from './sky.js';

export const WATCH_KINDS = ['company', 'domain', 'wallet', 'token', 'plane', 'topic', 'lights', 'air', 'port'] as const;
export type WatchKind = (typeof WATCH_KINDS)[number];

export interface WatchItem {
  id: number;
  kind: WatchKind;
  target: string;
  label: string | null;
  createdAt: string;
  lastRun: string | null;
}

export interface WatchRun {
  item: WatchItem;
  baseline: boolean;
  changes: string[];
  error?: string;
}

type State = Record<string, unknown>;

interface Row {
  id: number;
  kind: WatchKind;
  target: string;
  label: string | null;
  created_at: number;
  last_run: number | null;
  last_state: string | null;
}

const toItem = (r: Row): WatchItem => ({ id: r.id, kind: r.kind, target: r.target, label: r.label, createdAt: new Date(r.created_at).toISOString(), lastRun: r.last_run ? new Date(r.last_run).toISOString() : null });

export function addWatch(ctx: Ctx, kind: string, target: string, label?: string): WatchItem {
  if (!WATCH_KINDS.includes(kind as WatchKind)) throw new Error(`kind must be one of: ${WATCH_KINDS.join(', ')}`);
  const t = target.trim();
  if (!t) throw new Error('missing target');
  ctx.store.db.prepare('INSERT INTO watchlist (kind, target, label, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(kind, target) DO UPDATE SET label = COALESCE(excluded.label, label)').run(kind, t, label ?? null, ctx.now().getTime());
  return toItem(ctx.store.db.prepare('SELECT * FROM watchlist WHERE kind = ? AND target = ?').get(kind, t) as unknown as Row);
}

export function listWatch(ctx: Ctx): WatchItem[] {
  return (ctx.store.db.prepare('SELECT * FROM watchlist ORDER BY id').all() as unknown as Row[]).map(toItem);
}

export function removeWatch(ctx: Ctx, id: number): boolean {
  return ctx.store.db.prepare('DELETE FROM watchlist WHERE id = ?').run(id).changes > 0;
}

const pct = (a: number, b: number) => (b ? (a - b) / Math.abs(b) : 0);
const fmtPct = (x: number) => `${x >= 0 ? '+' : ''}${Math.round(x * 100)}%`;
const newOnes = (now: string[], before: unknown) => {
  const prev = new Set(Array.isArray(before) ? (before as string[]) : []);
  return now.filter((x) => !prev.has(x));
};

/** Run the module for one item and return its state plus human-readable changes against the previous state. */
export async function observe(ctx: Ctx, item: WatchItem, prev: State | null): Promise<{ state: State; changes: string[] }> {
  const changes: string[] = [];
  switch (item.kind) {
    case 'company': {
      const d = (await hound(ctx, item.target)).result;
      const items = d.timeline.slice(0, 40).map((t) => `${t.source}|${t.text}`);
      const cases = (d.court?.cases ?? []).map((c) => c.name);
      const price = d.stock?.quote?.price ?? null;
      const openings = d.hiring ? d.hiring.reduce((a, h) => a + h.openings, 0) : null;
      const sells = (d.stock?.insiders ?? []).filter((t) => t.code === 'S').map((t) => `${t.name}|${t.date}|${t.change}`);
      if (prev) {
        for (const x of newOnes(cases, prev.cases)) changes.push(`new court case: ${x}`);
        for (const x of newOnes(sells, prev.sells).slice(0, 3)) changes.push(`insider sale: ${x.split('|')[0]} sold ${Math.abs(Number(x.split('|')[2])).toLocaleString('en-US')} shares (${x.split('|')[1]})`);
        if (price !== null && typeof prev.price === 'number' && Math.abs(pct(price, prev.price)) >= 0.05) changes.push(`stock ${fmtPct(pct(price, prev.price))} since last check (${prev.price.toFixed(2)} → ${price.toFixed(2)})`);
        if (openings !== null && typeof prev.openings === 'number' && prev.openings > 0 && Math.abs(pct(openings, prev.openings)) >= 0.15) changes.push(`job openings ${fmtPct(pct(openings, prev.openings))} (${prev.openings} → ${openings})`);
        const fresh = newOnes(items, prev.items);
        if (fresh.length) changes.push(`${fresh.length} new item(s): ${fresh.slice(0, 3).map((x) => x.split('|')[1]!.slice(0, 90)).join(' · ')}`);
      }
      return { state: { items, cases, price, openings, sells }, changes };
    }
    case 'domain': {
      const d = (await ferret(ctx, item.target)).result;
      const found = d.findings.map((f) => `${f.kind}:${f.value.split(' — ')[0]}`);
      const flagged = d.flagged.map((f) => f.url);
      if (prev) {
        for (const x of newOnes(found, prev.found).slice(0, 8)) changes.push(`new ${x.replace(':', ' ')}`);
        for (const x of newOnes(flagged, prev.flagged)) changes.push(`Safe Browsing now flags ${x}`);
      }
      return { state: { found, flagged }, changes };
    }
    case 'wallet': {
      const w = (await wallet(ctx, item.target)).result;
      const usd = w.portfolio?.totalUsd ?? null;
      const txs = w.recentTxs.map((t) => t.hash);
      if (prev) {
        if (usd !== null && typeof prev.usd === 'number' && prev.usd > 0 && Math.abs(pct(usd, prev.usd)) >= 0.1) changes.push(`portfolio ${fmtPct(pct(usd, prev.usd))} ($${Math.round(prev.usd).toLocaleString('en-US')} → $${Math.round(usd).toLocaleString('en-US')})`);
        const fresh = w.recentTxs.filter((t) => newOnes(txs, prev.txs).includes(t.hash));
        if (fresh.length) changes.push(`${fresh.length} new transaction(s), e.g. ${fresh[0]!.method} ${fresh[0]!.valueEth ? `${fresh[0]!.valueEth.toFixed(3)} ETH ` : ''}at ${fresh[0]!.time.slice(0, 16)}Z`);
        for (const x of newOnes(w.labels, prev.labels)) changes.push(`new risk label: ${x}`);
      }
      return { state: { usd, txs, labels: w.labels }, changes };
    }
    case 'token': {
      const [address, chain = 'eth'] = item.target.split('@') as [string, string?];
      let r: { verdict: string; reasons: string[] };
      let liq: number;
      if (chain === 'robinhood') {
        const rh = (await rhTokenCheck(ctx, address)).result;
        r = rh;
        liq = rh.pools.reduce((a, p) => a + p.pool.liquidityUsd, 0);
      } else {
        const t = (await token(ctx, address, chain)).result;
        r = t;
        liq = t.pairs.reduce((a, p) => a + (p.liquidityUsd ?? 0), 0);
      }
      if (prev) {
        if (prev.verdict !== r.verdict) changes.push(`verdict ${String(prev.verdict)} → ${r.verdict}${r.reasons.length ? ` (${r.reasons.slice(0, 2).join(', ')})` : ''}`);
        if (typeof prev.liq === 'number' && prev.liq > 1000 && Math.abs(pct(liq, prev.liq)) >= 0.3) changes.push(`DEX liquidity ${fmtPct(pct(liq, prev.liq))} ($${Math.round(prev.liq).toLocaleString('en-US')} → $${Math.round(liq).toLocaleString('en-US')})`);
      }
      return { state: { verdict: r.verdict, liq }, changes };
    }
    case 'plane': {
      const t = (await track(ctx, item.target)).result;
      if (prev && t.change) changes.push(t.change);
      else if (prev && prev.status !== t.status) changes.push(`status ${String(prev.status)} → ${t.status}${t.place ? `, ${t.place.relation} ${t.place.airport}` : ''}`);
      return { state: { status: t.status, place: t.place?.ident ?? null }, changes };
    }
    case 'topic': {
      const r = (await cricket(ctx, item.target)).result;
      if (prev && prev.phase !== r.phase) changes.push(`hype phase ${String(prev.phase)} → ${r.phase}`);
      return { state: { phase: r.phase }, changes };
    }
    case 'lights': {
      const r = (await lights(ctx, item.target)).result;
      if (prev && prev.verdict !== r.verdict && r.verdict !== 'INSUFFICIENT_DATA') changes.push(`night lights ${String(prev.verdict)} → ${r.verdict}${r.ratio ? ` (${fmtPct(r.ratio - 1)} vs baseline)` : ''}`);
      return { state: { verdict: r.verdict }, changes };
    }
    case 'port': {
      const r = (await shipsNear(ctx, item.target, 30)).result;
      // A window with no AIS reports says nothing about the port; keep the previous state.
      if (!r.total) return { state: prev ?? {}, changes };
      if (prev && typeof prev.stationary === 'number' && prev.stationary >= 3 && Math.abs(pct(r.stationary, prev.stationary)) >= 0.3)
        changes.push(`vessels waiting ${fmtPct(pct(r.stationary, prev.stationary))} (${prev.stationary} → ${r.stationary} anchored/moored of ${r.total})`);
      if (prev && typeof prev.military === 'number' && (r.byType.military ?? 0) > prev.military) changes.push(`military vessels ${prev.military} → ${r.byType.military}`);
      return { state: { stationary: r.stationary, total: r.total, military: r.byType.military ?? 0 }, changes };
    }
    case 'air': {
      const r = (await air(ctx, item.target)).result;
      if (prev && r.category && prev.category !== r.category) changes.push(`air quality ${String(prev.category)} → ${r.category} (PM2.5 ${r.median?.toFixed(0)})`);
      return { state: { category: r.category, median: r.median }, changes };
    }
  }
}

const KIND_WEIGHT: Record<WatchKind, number> = { company: 55, domain: 60, wallet: 60, token: 65, plane: 65, topic: 50, lights: 65, air: 50, port: 60 };

/** Run every watch item (or the given ids) one after another, so free-tier rate limits are respected. */
export async function runWatch(ctx: Ctx, ids?: number[]): Promise<{ runs: WatchRun[]; signals: Signal[] }> {
  const rows = (ctx.store.db.prepare('SELECT * FROM watchlist ORDER BY id').all() as unknown as Row[]).filter((r) => !ids || ids.includes(r.id));
  const runs: WatchRun[] = [];
  const signals: Signal[] = [];
  const nowIso = ctx.now().toISOString();
  for (const row of rows) {
    const item = toItem(row);
    const prev = row.last_state ? (JSON.parse(row.last_state) as State) : null;
    try {
      const { state, changes } = await observe(ctx, item, prev);
      ctx.store.db.prepare('UPDATE watchlist SET last_run = ?, last_state = ? WHERE id = ?').run(ctx.now().getTime(), JSON.stringify(state), row.id);
      runs.push({ item, baseline: !prev, changes });
      if (changes.length) {
        const name = item.label ?? item.target;
        signals.push({
          id: signalId('meerkat', String(row.id), changes.join('|')),
          module: 'meerkat',
          title: `Watch ${item.kind} ${name}: ${changes[0]}${changes.length > 1 ? ` (+${changes.length - 1} more)` : ''}`,
          score: clamp(KIND_WEIGHT[item.kind] + (changes.length - 1) * 5, 0, 90),
          evidence: changes.map((c) => ({ source: `watch:${item.kind}`, text: c })),
          createdAt: nowIso,
        });
      }
    } catch (e) {
      runs.push({ item, baseline: !prev, changes: [], error: (e as Error).message });
    }
  }
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { runs, signals };
}
