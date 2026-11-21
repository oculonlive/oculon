/**
 * Company early-warning score: one 0-100 number from hiring momentum, new lawsuits, insider selling, news tone,
 * GitHub activity and today's stock move, each part shown with its contribution. Scored daily; a sharp drop
 * against the company's own recent average is a signal.
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { availableProviders, chat } from '../core/llm.js';
import { clamp, mean } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Signal } from '../core/types.js';
import { hound } from './hound.js';

export interface HealthPart {
  name: string;
  points: number;
  why: string;
}

export interface HealthResult {
  company: string;
  score: number;
  parts: HealthPart[];
  history: { day: string; score: number }[];
  change: number | null;
}

const NEG = /\b(lawsuit|sued|probe|investigation|resign|ousted|layoff|layoffs|fraud|plunge|slump|falls|fell|recall|breach|outage|fine|fined|scandal|downgrade|crisis|warning|ban|banned|delay|delayed)\b/i;
const POS = /\b(record|beats|surge|soar|launch|launches|partnership|deal|wins|approval|approved|upgrade|growth|expands|raises|profit)\b/i;

export function lexiconTone(titles: string[]): number {
  if (!titles.length) return 0;
  return mean(titles.map((t) => (NEG.test(t) ? -1 : 0) + (POS.test(t) ? 1 : 0)));
}

/** Mean tone of headlines in [-1, 1]: LLM when available, a word list otherwise. */
async function tone(titles: string[]): Promise<{ value: number; method: string }> {
  if (!titles.length) return { value: 0, method: 'none' };
  if (availableProviders().length) {
    try {
      const r = await chat(
        [
          { role: 'system', content: 'Rate each headline for how good or bad it is for the company: -1 bad, 0 neutral, 1 good. Reply JSON {"scores":[numbers in order]}.' },
          { role: 'user', content: titles.map((t, i) => `${i}. ${t}`).join('\n') },
        ],
        { json: true, temperature: 0, maxTokens: 600 },
      );
      const s = ((JSON.parse(r.message.content ?? '{}') as { scores?: unknown[] }).scores ?? []).map(Number).filter((x) => Number.isFinite(x));
      if (s.length) return { value: clamp(mean(s), -1, 1), method: 'llm' };
    } catch {}
  }
  return { value: lexiconTone(titles), method: 'lexicon' };
}

export async function health(ctx: Ctx, company: string): Promise<ModuleResult<HealthResult>> {
  const nowMs = ctx.now().getTime();
  const r = await hound(ctx, company);
  const d = r.result;
  const parts: HealthPart[] = [];

  const openings = d.hiring ? d.hiring.reduce((a, h) => a + h.openings, 0) : null;
  if (d.hiring?.change != null) {
    const p = Math.round(clamp(d.hiring.change * 40, -12, 12));
    parts.push({ name: 'hiring', points: p, why: `job openings ${d.hiring.change >= 0 ? '+' : ''}${Math.round(d.hiring.change * 100)}% since last check (${openings})` });
  } else if (openings !== null) parts.push({ name: 'hiring', points: 0, why: `${openings} open roles (no earlier check to compare)` });

  const recentCases = d.court?.cases.filter((c) => Date.parse(c.filed) >= nowMs - 14 * DAY_MS).length ?? 0;
  if (d.court) parts.push({ name: 'legal', points: -Math.min(15, recentCases * 4), why: `${recentCases} federal case(s) filed in 14 days` });

  const sells = d.stock?.insiders.filter((t) => t.code === 'S' && Date.parse(t.date) >= nowMs - 30 * DAY_MS).length ?? 0;
  const buys = d.stock?.insiders.filter((t) => t.code === 'P' && Date.parse(t.date) >= nowMs - 30 * DAY_MS).length ?? 0;
  if (d.stock) parts.push({ name: 'insiders', points: clamp(buys * 3 - sells * 2, -12, 8), why: `${sells} open-market sale(s), ${buys} purchase(s) by insiders in 30 days` });

  const titles = d.news.slice(0, 15).map((n) => n.title);
  const t = await tone(titles);
  parts.push({ name: 'news tone', points: Math.round(t.value * 15), why: `${titles.length} recent headlines, mean tone ${t.value.toFixed(2)} (${t.method})` });

  if (d.github) parts.push({ name: 'shipping', points: Math.min(6, d.github.repos.length * 2), why: `${d.github.repos.length} new public repo(s) in 14 days` });
  if (d.stock?.quote) parts.push({ name: 'stock', points: Math.round(clamp(d.stock.quote.changePct, -10, 10)), why: `${d.stock.symbol} ${d.stock.quote.changePct >= 0 ? '+' : ''}${d.stock.quote.changePct.toFixed(1)}% today` });

  const score = Math.round(clamp(50 + parts.reduce((a, p) => a + p.points, 0), 0, 100));
  const db = ctx.store.db;
  const day = new Date(nowMs).toISOString().slice(0, 10);
  db.prepare('INSERT INTO health (company, day, score, parts) VALUES (?, ?, ?, ?) ON CONFLICT(company, day) DO UPDATE SET score = excluded.score, parts = excluded.parts').run(company.toLowerCase(), day, score, JSON.stringify(parts));
  const history = (db.prepare('SELECT day, score FROM health WHERE company = ? ORDER BY day DESC LIMIT 30').all(company.toLowerCase()) as { day: string; score: number }[]).reverse();
  const prior = history.filter((h) => h.day !== day).slice(-7).map((h) => h.score);
  const change = prior.length ? score - mean(prior) : null;

  const signals: Signal[] = [];
  if (change !== null && change <= -15) {
    signals.push({
      id: signalId('health', company, day),
      module: 'health',
      title: `${company} health score fell ${Math.round(-change)} points to ${score}`,
      score: clamp(Math.round(55 - change), 0, 90),
      evidence: parts.filter((p) => p.points < 0).map((p) => ({ source: `health:${p.name}`, text: `${p.points} pts: ${p.why}` })),
      createdAt: new Date(nowMs).toISOString(),
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }
  return { module: 'health', input: company, generatedAt: new Date(nowMs).toISOString(), result: { company, score, parts, history, change: change === null ? null : Math.round(change) }, signals: [...signals, ...r.signals], provenance: r.provenance };
}
