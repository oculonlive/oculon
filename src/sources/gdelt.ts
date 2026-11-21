import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

const GD = 'https://api.gdeltproject.org/api/v2/doc/doc';
const GDELT_LIMIT = /^Please limit requests/i;

export interface GdeltPoint {
  /** YYYYMMDD */
  date: string;
  /** Share of all monitored global news coverage, in percent. */
  value: number;
}

export interface GdeltArticle {
  url: string;
  title: string;
  seendate: string;
  domain: string;
  sourcecountry?: string;
}

export function gdeltQuery(q: string): string {
  const t = q.trim();
  return /\s/.test(t) && !t.startsWith('"') ? `"${t}"` : t;
}

/** Daily share of global news coverage mentioning the query. */
export async function coverageTimeline(ctx: Ctx, query: string, days = 56): Promise<Sourced<GdeltPoint[]>> {
  const url = `${GD}?query=${enc(gdeltQuery(query))}&mode=timelinevol&timespan=${days}d&timelinesmooth=0&format=json`;
  const r = await ctx.http.get<{ timeline?: { data: { date: string; value: number }[] }[] }>(url, {
    source: 'gdelt',
    ttlSec: 3 * 3600,
    timeoutMs: 30_000,
    rateLimitText: GDELT_LIMIT,
  });
  const raw = r.data?.timeline?.[0]?.data;
  if (!raw) return { data: null, prov: r.data && r.prov.status !== 'ERROR' ? { ...r.prov, status: 'UNAVAILABLE' } : r.prov };
  // Collapse to one value per day (GDELT may return sub-daily points).
  const byDay = new Map<string, number[]>();
  for (const p of raw) {
    const d = p.date.slice(0, 8);
    byDay.set(d, [...(byDay.get(d) ?? []), p.value]);
  }
  const data = [...byDay].map(([date, vs]) => ({ date, value: vs.reduce((a, b) => a + b, 0) / vs.length }));
  return { data, prov: r.prov };
}

export async function latestArticles(ctx: Ctx, query: string, max = 10): Promise<Sourced<GdeltArticle[]>> {
  const url = `${GD}?query=${enc(gdeltQuery(query))}&mode=artlist&maxrecords=${max}&sort=datedesc&timespan=3d&format=json`;
  const r = await ctx.http.get<{ articles?: GdeltArticle[] }>(url, { source: 'gdelt', ttlSec: 1800, timeoutMs: 30_000, rateLimitText: GDELT_LIMIT });
  return { data: r.data ? (r.data.articles ?? []) : null, prov: r.prov };
}
