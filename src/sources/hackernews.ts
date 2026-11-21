import { DAY_MS, enc, type Ctx } from '../core/context.js';
import type { Provenance, Sourced } from '../core/types.js';

const HN = 'https://hn.algolia.com/api/v1';

export interface HnStory {
  objectID: string;
  title: string;
  url: string | null;
  points: number;
  num_comments: number;
  created_at_i: number;
}

async function countBetween(ctx: Ctx, query: string, from: number, to: number): Promise<Sourced<number>> {
  const url = `${HN}/search?query=${enc(query)}&tags=story&hitsPerPage=0&numericFilters=${enc(`created_at_i>${from},created_at_i<=${to}`)}`;
  const r = await ctx.http.get<{ nbHits?: number }>(url, { source: 'hackernews', ttlSec: 3 * 3600 });
  return { data: r.data?.nbHits ?? null, prov: r.prov };
}

/** Story counts per week for `weeks` weeks, oldest first. Null if any bucket failed. */
export async function weeklyStoryCounts(ctx: Ctx, query: string, weeks = 8): Promise<{ data: number[] | null; provs: Provenance[] }> {
  // Align bucket edges to whole hours so the cache key stays stable within a run.
  const nowSec = Math.floor(ctx.now().getTime() / 3_600_000) * 3600;
  const weekSec = (7 * DAY_MS) / 1000;
  const results = await Promise.all(
    Array.from({ length: weeks }, (_, i) => {
      const to = nowSec - (weeks - 1 - i) * weekSec;
      return countBetween(ctx, query, to - weekSec, to);
    }),
  );
  const provs = results.map((r) => r.prov);
  if (results.some((r) => r.data === null)) return { data: null, provs };
  return { data: results.map((r) => r.data!), provs };
}

/** Stories currently on the HN front page. */
export async function frontPage(ctx: Ctx): Promise<Sourced<HnStory[]>> {
  const r = await ctx.http.get<{ hits?: HnStory[] }>(`${HN}/search?tags=front_page&hitsPerPage=50`, {
    source: 'hackernews',
    ttlSec: 600,
  });
  return { data: r.data?.hits ?? null, prov: r.prov };
}

/** Most relevant/popular stories mentioning the query in the last `days` days. */
export async function recentMentions(ctx: Ctx, query: string, days = 14, max = 20): Promise<Sourced<HnStory[]>> {
  const since = Math.floor((ctx.now().getTime() - days * DAY_MS) / 3_600_000) * 3600;
  const url = `${HN}/search?query=${enc(query)}&tags=story&hitsPerPage=${max}&numericFilters=${enc(`created_at_i>${since}`)}`;
  const r = await ctx.http.get<{ hits?: HnStory[] }>(url, { source: 'hackernews', ttlSec: 1800 });
  return { data: r.data?.hits ?? null, prov: r.prov };
}

export const hnItemUrl =(id: string) => `https://news.ycombinator.com/item?id=${id}`;
