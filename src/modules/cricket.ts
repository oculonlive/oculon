/**
 * Cricket: measures where a topic sits in its hype cycle by listening to several
 * independent channels (encyclopedia readers, developers, global news, the press, researchers, scholarly output, builders).
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { entityId } from '../core/graph.js';
import { bucketFromEnd, mean, trend, type Phase, type Trend } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { paperCount } from '../sources/arxiv.js';
import { coverageTimeline } from '../sources/gdelt.js';
import { repoCount } from '../sources/github.js';
import { weeklyStoryCounts } from '../sources/hackernews.js';
import { guardianCount } from '../sources/press.js';
import { openalexCount } from '../sources/social.js';
import { dailyViews, resolveTitle } from '../sources/wikimedia.js';

export const WEEKS = 8;

export interface Channel {
  channel: 'readers' | 'developers' | 'news' | 'research' | 'builders' | 'press' | 'scholarly';
  source: string;
  /** Weekly values, oldest first. Empty when the channel was unavailable. */
  weekly: number[];
  unit: string;
  trend: Trend | null;
  note?: string;
}

export interface CricketResult {
  topic: string;
  wikipediaTitle: string | null;
  phase: Phase;
  momentum: number;
  acceleration: number;
  /** Mean-normalized composite of all available channels, oldest first. */
  composite: number[];
  channels: Channel[];
  summary: string;
}

const WEIGHT: Record<Channel['channel'], number> = { readers: 1, developers: 1, news: 1, press: 0.8, research: 0.6, scholarly: 0.6, builders: 0.8 };

function weeklyFromDaily(values: number[], agg: (g: number[]) => number): number[] {
  return bucketFromEnd(values, 7, agg).slice(-WEEKS);
}

function channel(c: Omit<Channel, 'trend'>): Channel {
  return { ...c, trend: c.weekly.length >= 4 ? trend(c.weekly) : null };
}

/**
 * Mean-normalized weighted average across channels, aligned on the most recent week.
 * Channels with fewer than WEEKS buckets (e.g. GDELT's shorter window) contribute to the weeks they cover.
 */
export function composite(channels: Channel[]): number[] {
  const usable = channels.filter((c) => c.channel !== 'builders' && c.weekly.length >= 4 && mean(c.weekly) > 0);
  if (!usable.length) return [];
  return Array.from({ length: WEEKS }, (_, i) => {
    let acc = 0;
    let w = 0;
    for (const c of usable) {
      const j = i - (WEEKS - c.weekly.length);
      if (j < 0) continue;
      acc += (WEIGHT[c.channel] * c.weekly[j]!) / mean(c.weekly);
      w += WEIGHT[c.channel];
    }
    return w ? acc / w : 0;
  }).filter((_, i) => usable.some((c) => i - (WEEKS - c.weekly.length) >= 0));
}

const fmt = (x: number) => (Number.isFinite(x) ? `${x >= 1 ? '+' : ''}${Math.round((x - 1) * 100)}%` : 'new');

export async function cricket(ctx: Ctx, topicInput: string): Promise<ModuleResult<CricketResult>> {
  const topic = topicInput.trim();
  const provenance: Provenance[] = [];
  const nowMs = ctx.now().getTime();
  const days = WEEKS * 7;
  const iso = (ms: number) => new Date(ms).toISOString().slice(0, 10);

  const title = await resolveTitle(ctx, topic);
  provenance.push(title.prov);

  // Hour-aligned "now" keeps cache keys stable across runs within the same hour.
  const hourMs = Math.floor(nowMs / 3_600_000) * 3_600_000;
  const week = 7 * DAY_MS;
  // Whole-day weekly windows (oldest first) for date-based APIs.
  const dayWindows = Array.from({ length: WEEKS }, (_, i) => {
    const end = nowMs - DAY_MS - (WEEKS - 1 - i) * week;
    return [iso(end - week + DAY_MS), iso(end)] as const;
  });
  const [views, hn, news, papers, ghRecent, ghPrev, press, scholarly] = await Promise.all([
    title.data ? dailyViews(ctx, title.data, days) : Promise.resolve(null),
    weeklyStoryCounts(ctx, topic, WEEKS),
    coverageTimeline(ctx, topic, days),
    Promise.all(Array.from({ length: WEEKS }, (_, i) => paperCount(ctx, topic, hourMs - (WEEKS - i) * week, hourMs - (WEEKS - 1 - i) * week))),
    repoCount(ctx, `${topic} created:${iso(nowMs - 28 * DAY_MS)}..${iso(nowMs)}`),
    repoCount(ctx, `${topic} created:${iso(nowMs - 56 * DAY_MS)}..${iso(nowMs - 28 * DAY_MS - DAY_MS)}`),
    Promise.all(dayWindows.map(([from, to]) => guardianCount(ctx, topic, from, to))),
    Promise.all(dayWindows.map(([from, to]) => openalexCount(ctx, topic, from, to))),
  ]);

  const channels: Channel[] = [];

  if (views) provenance.push(views.prov);
  channels.push(
    channel({
      channel: 'readers',
      source: 'wikimedia-pageviews',
      unit: 'pageviews/week',
      weekly: views?.data ? weeklyFromDaily(views.data.map((v) => v.views), (g) => g.reduce((a, b) => a + b, 0)) : [],
      ...(title.data ? { note: `article: ${title.data}` } : { note: 'no matching Wikipedia article' }),
    }),
  );

  provenance.push(...hn.provs);
  channels.push(channel({ channel: 'developers', source: 'hackernews', unit: 'stories/week', weekly: hn.data ?? [] }));

  provenance.push(news.prov);
  channels.push(
    channel({
      channel: 'news',
      source: 'gdelt',
      unit: '% of global news (weekly avg)',
      weekly: news.data ? weeklyFromDaily(news.data.map((p) => p.value), mean) : [],
    }),
  );

  provenance.push(...papers.map((p) => p.prov));
  // arXiv indexes with a lag of a few days, so the newest week can read low; noted for the reader.
  channels.push(
    channel({
      channel: 'research',
      source: 'arxiv',
      unit: 'papers/week',
      weekly: papers.every((p) => p.data !== null) ? papers.map((p) => p.data!) : [],
      note: 'newest week may be incomplete (arXiv indexing lag)',
    }),
  );

  provenance.push(press[0]!.prov);
  if (press.some((p) => p.prov.status === 'ERROR')) provenance.push(...press.filter((p) => p.prov.status === 'ERROR').map((p) => p.prov));
  channels.push(
    channel({
      channel: 'press',
      source: 'guardian',
      unit: 'Guardian articles/week',
      weekly: press.every((p) => p.data !== null) ? press.map((p) => p.data!) : [],
      ...(press[0]!.prov.status === 'UNAVAILABLE' ? { note: press[0]!.prov.note ?? 'unavailable' } : {}),
    }),
  );

  provenance.push(...scholarly.map((p) => p.prov));
  channels.push(
    channel({
      channel: 'scholarly',
      source: 'openalex',
      unit: 'scholarly works/week',
      weekly: scholarly.every((p) => p.data !== null) ? scholarly.map((p) => p.data!) : [],
      note: 'all publishers incl. journals and preprints; recent weeks fill in as works are indexed',
    }),
  );

  provenance.push(ghRecent.prov, ghPrev.prov);
  const builders: Channel = {
    channel: 'builders',
    source: 'github-search',
    unit: 'new repos per 4 weeks',
    weekly: ghRecent.data !== null && ghPrev.data !== null ? [ghPrev.data, ghRecent.data] : [],
    trend: null,
    note: 'two 4-week buckets; shown for momentum, not used in the weekly composite',
  };
  if (builders.weekly.length === 2) {
    const [prev, recent] = builders.weekly as [number, number];
    const m = prev > 0 ? recent / prev : recent > 0 ? Infinity : 1;
    builders.trend = { phase: m >= 1.5 ? 'RISING' : m <= 0.75 ? 'COOLING' : 'STEADY', momentum: m, acceleration: m };
  }
  channels.push(builders);

  const comp = composite(channels);
  const t = comp.length ? trend(comp) : { phase: 'DORMANT' as Phase, momentum: 1, acceleration: 1 };
  const live = channels.filter((c) => c.weekly.length);
  const summary = live.length
    ? `${topic}: ${t.phase} (momentum ${fmt(t.momentum)} vs earlier weeks, last week ${fmt(t.acceleration)}). ` +
      live.map((c) => `${c.channel} ${c.trend ? `${c.trend.phase.toLowerCase()} ${fmt(c.trend.momentum)}` : 'n/a'}`).join(', ')
    : `${topic}: no channel returned data`;

  const id = ctx.graph.upsert('topic', topic, { lastPhase: t.phase });
  ctx.graph.observe(id, 'cricket', 'momentum', Number.isFinite(t.momentum) ? t.momentum : null, 'composite', { phase: t.phase });
  if (title.data) ctx.graph.link(id, ctx.graph.upsert('article', title.data), 'described_by', 'wikipedia');

  const createdAt = new Date(nowMs).toISOString();
  const signals: Signal[] = [];
  if (t.phase === 'RISING' || t.phase === 'EMERGING' || t.phase === 'PEAK') {
    const agreeing = live.filter((c) => c.trend && c.trend.phase === t.phase);
    signals.push({
      id: signalId('cricket', topic, t.phase, createdAt.slice(0, 10)),
      module: 'cricket',
      title: `${topic} is ${t.phase}`,
      score: Math.min(100, 40 + agreeing.length * 12 + (Number.isFinite(t.momentum) ? Math.min(20, (t.momentum - 1) * 20) : 20)),
      entity: id,
      evidence: live.map((c) => ({ source: c.source, text: `${c.channel}: ${c.trend?.phase ?? 'n/a'} ${c.trend ? fmt(c.trend.momentum) : ''}`.trim() })),
      createdAt,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }

  return {
    module: 'cricket',
    input: topic,
    generatedAt: createdAt,
    result: { topic, wikipediaTitle: title.data, phase: t.phase, momentum: t.momentum, acceleration: t.acceleration, composite: comp, channels, summary },
    signals,
    provenance,
  };
}
