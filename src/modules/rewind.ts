/**
 * Time Machine: rebuild what Oculon would have seen on a past date from sources that keep history:
 * Wikipedia readership spikes, the day's top Hacker News stories, strong earthquakes, natural events, and the
 * New York Times front page as archived by the Wayback Machine. Items are fused the same way the live radar
 * fuses them, and any signals Oculon itself recorded that day are listed alongside.
 */
import { DAY_MS, ymd, type Ctx } from '../core/context.js';
import { robustZ, spikeRatio, clamp } from '../core/stats.js';
import { articleTitle, keywords } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { guardianDay } from '../sources/press.js';
import { quakesBetween } from '../sources/usgs.js';
import { dailyViews, isNoiseArticle } from '../sources/wikimedia.js';
import { fuse, type Blip } from './owl.js';

export interface RewindResult {
  date: string;
  fused: ReturnType<typeof fuse>;
  headlines: { title: string; url: string; time: string }[];
  oculonSignals: Signal[];
}

const mk = (b: Omit<Blip, 'keys'>): Blip => ({ ...b, keys: [...keywords(b.title)] });

export async function rewind(ctx: Ctx, dateInput: string, opts: { wikiDepth?: number } = {}): Promise<ModuleResult<RewindResult>> {
  const date = dateInput.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('date must be YYYY-MM-DD');
  const day = Date.parse(`${date}T00:00:00Z`);
  if (!(day < ctx.now().getTime() - DAY_MS)) throw new Error('date must be at least two days ago');
  const provenance: Provenance[] = [];
  const blips: Blip[] = [];
  const [y, m, d] = date.split('-');

  // Wikipedia: that day's most-read articles, measured against their own previous four weeks.
  const top = await ctx.http.get<{ items?: { articles: { article: string; views: number }[] }[] }>(`https://wikimedia.org/api/rest_v1/metrics/pageviews/top/en.wikipedia/all-access/${y}/${m}/${d}`, {
    source: 'wikimedia-top',
    ttlSec: 30 * 86_400,
  });
  provenance.push(top.prov);
  const arts = (top.data?.items?.[0]?.articles ?? []).filter((a) => !isNoiseArticle(a.article)).slice(0, opts.wikiDepth ?? 20);
  const rewindCtx: Ctx = { ...ctx, now: () => new Date(day + DAY_MS) };
  const series = await Promise.all(arts.map((a) => dailyViews(rewindCtx, a.article, 30)));
  series.forEach((s, i) => {
    provenance.push(s.prov);
    const vals = s.data?.map((v) => v.views) ?? [];
    if (vals.length < 10) return;
    const last = vals[vals.length - 1]!;
    const base = vals.slice(0, -3);
    const ratio = spikeRatio(last, base);
    if (ratio < 3 || robustZ(last, base) < 4) return;
    blips.push(mk({ source: 'wikipedia', title: articleTitle(arts[i]!.article), url: `https://en.wikipedia.org/wiki/${encodeURIComponent(arts[i]!.article)}`, strength: clamp(Math.round(10 + 6 * Math.log2(Math.min(ratio, 256)) + 5 * Math.log10(Math.max(10, last))), 0, 90), detail: `${last.toLocaleString('en-US')} views, ${ratio.toFixed(1)}x usual`, value: ratio }));
  });

  // Hacker News: the day's highest-scoring stories.
  const from = Math.floor(day / 1000);
  const hn = await ctx.http.get<{ hits?: { objectID: string; title: string; points: number; num_comments: number }[] }>(
    `https://hn.algolia.com/api/v1/search?tags=story&hitsPerPage=40&numericFilters=${encodeURIComponent(`created_at_i>${from},created_at_i<${from + 86400},points>150`)}`,
    { source: 'hackernews', ttlSec: 30 * 86_400 },
  );
  provenance.push(hn.prov);
  for (const s of (hn.data?.hits ?? []).sort((a, b) => b.points - a.points).slice(0, 15)) {
    blips.push(mk({ source: 'hackernews', title: s.title, url: `https://news.ycombinator.com/item?id=${s.objectID}`, strength: clamp(Math.round(25 + 10 * Math.log2(Math.max(1, s.points / 24))), 0, 85), detail: `${s.points} points, ${s.num_comments} comments`, value: s.points }));
  }

  // Strong earthquakes that day.
  const q = await quakesBetween(ctx, date, ymd(new Date(day + DAY_MS)).replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'), 6);
  provenance.push(q.prov);
  for (const e of q.data ?? []) blips.push(mk({ source: 'usgs', title: `M${e.mag.toFixed(1)} earthquake ${e.place}`, url: e.url, strength: clamp(Math.round(20 + (e.mag - 5) * 20), 0, 95), detail: new Date(e.time).toISOString().slice(0, 16) + 'Z', value: e.mag }));

  // That day's news from the Guardian archive (real headlines with publication times; the archived NYT
  // homepage turned out to be mostly navigation once rendered, so it is not used).
  const gd = await guardianDay(ctx, date, 30);
  provenance.push(gd.prov);
  const headlines = (gd.data ?? []).map((n) => ({ title: n.title, url: n.url, time: n.date }));
  for (const h of headlines) blips.push(mk({ source: 'guardian', title: h.title, url: h.url, strength: 30, detail: `Guardian, ${h.time.slice(11, 16)} UTC`, value: 0 }));

  const fused = fuse(blips);
  const oculonSignals = ctx.graph.recentSignals(5000).filter((s) => s.createdAt.startsWith(date));
  return { module: 'rewind', input: date, generatedAt: ctx.now().toISOString(), result: { date, fused, headlines, oculonSignals }, signals: [], provenance };
}
