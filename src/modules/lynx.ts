/**
 * Lynx: cross-checks Polymarket against Kalshi and Manifold. Keyword matching proposes pairs; an LLM then
 * confirms each pair asks the same question (dates and thresholds included). Big gaps between venues on
 * the same question are signals: one crowd is wrong, or knows something first.
 */
import type { Ctx } from '../core/context.js';
import { availableProviders, chat } from '../core/llm.js';
import { keywords, overlap, signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { topMarkets, type Market } from '../sources/polymarket.js';
import { kalshiMarkets, manifoldSearch, type OtherMarket } from '../sources/predict.js';
import { isResolving, isSportsLine } from './owl.js';

export interface Comparison {
  polymarket: { question: string; probability: number; url: string; volume24h: number };
  other: OtherMarket;
  gapPp: number;
  similarity: number;
  verified: 'same' | 'unverified';
}

export interface LynxResult {
  checked: number;
  comparisons: Comparison[];
  disagreements: Comparison[];
}

/** Best keyword match for `q` among candidates, if it clears `min`. */
export function bestMatch<T extends { question: string }>(q: string, candidates: T[], min = 0.6): { item: T; score: number } | null {
  const kq = keywords(q);
  let best: { item: T; score: number } | null = null;
  for (const c of candidates) {
    const s = overlap(kq, keywords(c.question));
    if (s.shared.length < 3) continue;
    if (!best || s.score > best.score) best = { item: c, score: s.score };
  }
  return best && best.score >= min ? best : null;
}

/** Loose shortlist: the `k` candidates sharing the most keywords with `q` (at least two shared). */
export function shortlist<T extends { question: string }>(q: string, candidates: T[], k = 8): T[] {
  const kq = keywords(q);
  return candidates
    .map((c) => ({ c, s: overlap(kq, keywords(c.question)) }))
    .filter((x) => x.s.shared.length >= 2)
    .sort((a, b) => b.s.score - a.s.score)
    .slice(0, k)
    .map((x) => x.c);
}

/** Proper nouns and numbers from a question: the words that make a search specific. */
export function searchTerm(q: string): string {
  const words = q.replace(/[?'"]/g, ' ').split(/\s+/).filter((w) => /^[A-Z0-9$]/.test(w) && !/^(Will|What|Who|When|Which|How|The|A|An|In|On|By|Before|After)$/.test(w));
  return words.slice(0, 4).join(' ');
}

/**
 * The LLM picks, for each Polymarket question, the one option that asks exactly the same thing (same event,
 * deadline and threshold), or none. Returns option indexes (or -1) per market. Null when no LLM is configured.
 */
async function pickSame(groups: { question: string; options: string[] }[], fetchImpl?: typeof fetch): Promise<number[] | null> {
  if (!availableProviders().length) return null;
  const out: number[] = groups.map(() => -1);
  for (let start = 0; start < groups.length; start += 8) {
    const batch = groups.slice(start, start + 8);
    try {
      const r = await chat(
        [
          {
            role: 'system',
            content:
              'You match prediction markets. For each market, pick the option that resolves YES in exactly the same situations: same event, same deadline (or very close), same threshold. If none does, use -1. Reply JSON: {"matches":[{"market":n,"option":n}]}. When in doubt, -1.',
          },
          { role: 'user', content: batch.map((g, i) => `Market ${i}: ${g.question}\n${g.options.map((o, j) => `  option ${j}: ${o}`).join('\n')}`).join('\n\n') },
        ],
        { json: true, temperature: 0, maxTokens: 2000, ...(fetchImpl ? { fetch: fetchImpl } : {}) },
      );
      const ms = (JSON.parse(r.message.content ?? '{}') as { matches?: { market?: unknown; option?: unknown }[] }).matches ?? [];
      for (const m of ms) {
        const i = Number(m.market);
        const j = Number(m.option);
        if (Number.isInteger(i) && i >= 0 && i < batch.length && Number.isInteger(j) && j >= 0 && j < batch[i]!.options.length) out[start + i] = j;
      }
    } catch {
      // leave this batch unmatched
    }
  }
  return out;
}

export async function lynx(ctx: Ctx, opts: { limit?: number; minGapPp?: number; fetchImpl?: typeof fetch } = {}): Promise<ModuleResult<LynxResult>> {
  const nowMs = ctx.now().getTime();
  const provenance: Provenance[] = [];
  const [pm, ks] = await Promise.all([topMarkets(ctx, 200), kalshiMarkets(ctx)]);
  provenance.push(pm.prov, ...ks.provs);
  const pool = (pm.data ?? []).filter((m) => !isSportsLine(m) && !isResolving(m, nowMs) && m.volume24h >= 20_000 && m.prices.length === 2).slice(0, opts.limit ?? 40);

  // Per market: a loose shortlist from Kalshi, plus Manifold search results for the 12 highest-volume markets.
  const groups: { pm: Market; options: OtherMarket[] }[] = [];
  for (const [i, m] of pool.entries()) {
    const options = ks.data ? shortlist(m.question, ks.data, 8) : [];
    if (i < 12) {
      const term = searchTerm(m.question);
      if (term) {
        const r = await manifoldSearch(ctx, term, 6);
        provenance.push(r.prov);
        options.push(...(r.data ?? []));
      }
    }
    if (options.length) groups.push({ pm: m, options });
  }

  const picks = await pickSame(groups.map((g) => ({ question: g.pm.question, options: g.options.map((o) => `[${o.venue}] ${o.question}`) })), opts.fetchImpl);
  const comparisons: Comparison[] = [];
  groups.forEach((g, i) => {
    let other: OtherMarket | null = null;
    let verified: Comparison['verified'] = 'unverified';
    if (picks) {
      if (picks[i]! >= 0) {
        other = g.options[picks[i]!]!;
        verified = 'same';
      }
    } else other = bestMatch(g.pm.question, g.options)?.item ?? null;
    if (!other) return;
    comparisons.push({
      polymarket: { question: g.pm.question, probability: g.pm.prices[0]!, url: g.pm.url, volume24h: g.pm.volume24h },
      other,
      gapPp: Math.round(Math.abs((g.pm.prices[0] ?? 0) - other.probability) * 1000) / 10,
      similarity: Math.round(overlap(keywords(g.pm.question), keywords(other.question)).score * 100) / 100,
      verified,
    });
  });
  comparisons.sort((a, b) => b.gapPp - a.gapPp);
  const minGap = opts.minGapPp ?? 15;
  const disagreements = comparisons.filter((c) => c.gapPp >= minGap && c.verified === 'same');

  const nowIso = new Date(nowMs).toISOString();
  const signals: Signal[] = disagreements.slice(0, 8).map((d) => ({
    id: signalId('lynx', d.polymarket.url, d.other.url, nowIso.slice(0, 10)),
    module: 'lynx',
    title: `Markets disagree by ${d.gapPp}pp: ${d.polymarket.question.slice(0, 100)}`,
    score: Math.min(85, Math.round(45 + d.gapPp)),
    evidence: [
      { source: 'polymarket', text: `${Math.round(d.polymarket.probability * 100)}% on Polymarket`, url: d.polymarket.url },
      { source: d.other.venue, text: `${Math.round(d.other.probability * 100)}% on ${d.other.venue}: ${d.other.question.slice(0, 120)}`, url: d.other.url },
    ],
    createdAt: nowIso,
  }));
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { module: 'lynx', input: 'markets', generatedAt: nowIso, result: { checked: pool.length, comparisons, disagreements }, signals, provenance };
}
