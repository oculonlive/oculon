import type { Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface Market {
  id: string;
  slug: string | null;
  question: string;
  closed: boolean;
  url: string;
  outcomes: string[];
  prices: number[];
  volume24h: number;
  /** Change in the first outcome's price over 24h, in probability points (0.1 = +10pp). */
  change1d: number | null;
  endDate: string | null;
}

interface GammaMarket {
  id?: string | number;
  question?: string;
  slug?: string;
  outcomes?: string;
  outcomePrices?: string;
  volume24hr?: number | string;
  oneDayPriceChange?: number | string;
  endDate?: string;
  closed?: boolean;
}

function parseList(s: string | undefined): string[] {
  if (!s) return [];
  try {
    const v = JSON.parse(s) as unknown;
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}

const num = (v: unknown): number | null => {
  const n = typeof v === 'string' ? Number(v) : typeof v === 'number' ? v : NaN;
  return Number.isFinite(n) ? n : null;
};

export function toMarket(m: GammaMarket): Market | null {
  if (!m.question) return null;
  return {
    id: String(m.id ?? m.slug ?? m.question),
    slug: m.slug ?? null,
    question: m.question,
    closed: m.closed === true,
    url: m.slug ? `https://polymarket.com/market/${m.slug}` : 'https://polymarket.com',
    outcomes: parseList(m.outcomes),
    prices: parseList(m.outcomePrices).map(Number),
    volume24h: num(m.volume24hr) ?? 0,
    change1d: num(m.oneDayPriceChange),
    endDate: m.endDate ?? null,
  };
}

/** Open markets whose event matches a free-text query. */
export async function searchMarkets(ctx: Ctx, query: string, limit = 10): Promise<Sourced<Market[]>> {
  const url = `https://gamma-api.polymarket.com/public-search?q=${encodeURIComponent(query)}&limit_per_type=${limit}&events_status=active`;
  const r = await ctx.http.get<{ events?: { closed?: boolean; markets?: (GammaMarket & { closed?: boolean; active?: boolean })[] }[] }>(url, {
    source: 'polymarket',
    ttlSec: 600,
  });
  const data =
    r.data?.events
      ?.filter((e) => !e.closed)
      .flatMap((e) => e.markets ?? [])
      .filter((m) => m.active !== false && m.closed !== true)
      .map(toMarket)
      .filter((m): m is Market => m !== null)
      .sort((a, b) => b.volume24h - a.volume24h) ?? null;
  return { data, prov: r.prov };
}

/** One market by slug, open or closed. */
export async function marketBySlug(ctx: Ctx, slug: string, ttlSec = 300): Promise<Sourced<Market>> {
  const r = await ctx.http.get<GammaMarket[]>(`https://gamma-api.polymarket.com/markets?slug=${encodeURIComponent(slug)}`, { source: 'polymarket', ttlSec });
  const m = r.data?.[0];
  return { data: m ? toMarket(m) : null, prov: r.data && !m ? { ...r.prov, status: 'UNAVAILABLE', note: 'no market with that slug' } : r.prov };
}

/** 1 or 0 for the first outcome once the market is closed with a settled price; null while unresolved. */
export function resolution(m: Market): 0 | 1 | null {
  if (!m.closed || m.prices.length < 2) return null;
  if (m.prices[0] === 1 && m.prices[1] === 0) return 1;
  if (m.prices[0] === 0 && m.prices[1] === 1) return 0;
  return null;
}

/** Active markets ranked by 24h volume. */
export async function topMarkets(ctx: Ctx, limit = 100): Promise<Sourced<Market[]>> {
  const url = `https://gamma-api.polymarket.com/markets?active=true&closed=false&order=volume24hr&ascending=false&limit=${limit}`;
  const r = await ctx.http.get<GammaMarket[]>(url, { source: 'polymarket', ttlSec: 600 });
  const data = r.data?.map(toMarket).filter((m): m is Market => m !== null) ?? null;
  return { data, prov: r.prov };
}
