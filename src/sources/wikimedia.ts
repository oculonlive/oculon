import { DAY_MS, enc, ymd, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

const WM = 'https://wikimedia.org/api/rest_v1/metrics/pageviews';

export interface DailyViews {
  date: string;
  views: number;
}

export interface TopArticle {
  article: string;
  views: number;
  rank: number;
}

/** Find the best-matching English Wikipedia article title for a free-text query. */
export async function resolveTitle(ctx: Ctx, query: string): Promise<Sourced<string>> {
  const url = `https://en.wikipedia.org/w/api.php?action=opensearch&format=json&limit=1&namespace=0&search=${enc(query)}`;
  const r = await ctx.http.get<[string, string[]]>(url, { source: 'wikipedia', ttlSec: 86_400 });
  return { data: r.data?.[1]?.[0] ?? null, prov: r.prov };
}

/** Daily human pageviews for an article, ending yesterday (UTC). */
export async function dailyViews(ctx: Ctx, title: string, days = 56): Promise<Sourced<DailyViews[]>> {
  const end = new Date(ctx.now().getTime() - DAY_MS);
  const start = new Date(end.getTime() - (days - 1) * DAY_MS);
  const art = enc(title.replace(/ /g, '_'));
  const url = `${WM}/per-article/en.wikipedia/all-access/user/${art}/daily/${ymd(start)}00/${ymd(end)}00`;
  const r = await ctx.http.get<{ items?: { timestamp: string; views: number }[] }>(url, {
    source: 'wikimedia-pageviews',
    ttlSec: 3 * 3600,
  });
  const items = r.data?.items?.map((i) => ({ date: i.timestamp.slice(0, 8), views: i.views })) ?? null;
  return { data: items, prov: r.prov };
}

export interface Summary {
  title: string;
  description: string | null;
  extract: string;
  url: string;
}

export async function summary(ctx: Ctx, title: string): Promise<Sourced<Summary>> {
  const url = `https://en.wikipedia.org/api/rest_v1/page/summary/${enc(title.replace(/ /g, '_'))}`;
  const r = await ctx.http.get<{ title?: string; description?: string; extract?: string; content_urls?: { desktop?: { page?: string } } }>(url, {
    source: 'wikipedia',
    ttlSec: 86_400,
  });
  const d = r.data;
  return {
    data: d?.title ? { title: d.title, description: d.description ?? null, extract: d.extract ?? '', url: d.content_urls?.desktop?.page ?? `https://en.wikipedia.org/wiki/${enc(title)}` } : null,
    prov: r.prov,
  };
}

const NOISE =/^(Main_Page|Special:|Wikipedia:|Portal:|File:|Help:|Category:|Template:|Talk:|User:|-$|Cleopatra$|Undefined$|Search$)/i;

export function isNoiseArticle(article: string): boolean {
  return NOISE.test(article) || /\.(php|html?)$/i.test(article);
}

/** Most-viewed articles for the latest day that has published data (yesterday, else the day before). */
export async function topArticles(ctx: Ctx): Promise<Sourced<{ date: string; articles: TopArticle[] }>> {
  let last: Sourced<{ date: string; articles: TopArticle[] }> | undefined;
  for (const back of [1, 2]) {
    const d = new Date(ctx.now().getTime() - back * DAY_MS);
    const [y, m, dd] = d.toISOString().slice(0, 10).split('-');
    const url = `${WM}/top/en.wikipedia/all-access/${y}/${m}/${dd}`;
    const r = await ctx.http.get<{ items?: { articles: TopArticle[] }[] }>(url, { source: 'wikimedia-top', ttlSec: 3 * 3600 });
    const articles = r.data?.items?.[0]?.articles;
    last = { data: articles ? { date: ymd(d), articles } : null, prov: r.prov };
    if (articles) return last;
  }
  return last!;
}
