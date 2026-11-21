/** Other prediction markets: Kalshi (public market data) and Manifold (play-money, public API). Both keyless. */
import { enc, type Ctx } from '../core/context.js';
import type { Provenance, Sourced } from '../core/types.js';

export interface OtherMarket {
  venue: 'kalshi' | 'manifold';
  question: string;
  probability: number;
  volume: number | null;
  url: string;
  closes: string | null;
}

interface KalshiMarket {
  ticker: string;
  title?: string;
  yes_sub_title?: string;
  last_price_dollars?: string;
  yes_bid_dollars?: string;
  yes_ask_dollars?: string;
  volume_fp?: string | number;
  close_time?: string;
}

const num = (v: unknown) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

/** Open Kalshi markets with a usable price, excluding multi-leg sports parlays. Up to `pages` x 200 events. */
export async function kalshiMarkets(ctx: Ctx, pages = 10): Promise<{ data: OtherMarket[] | null; provs: Provenance[] }> {
  const out: OtherMarket[] = [];
  const provs: Provenance[] = [];
  let cursor = '';
  for (let i = 0; i < pages; i++) {
    const r = await ctx.http.get<{ events?: { event_ticker: string; title: string; markets?: KalshiMarket[] }[]; cursor?: string }>(
      `https://api.elections.kalshi.com/trade-api/v2/events?status=open&with_nested_markets=true&limit=200${cursor ? `&cursor=${enc(cursor)}` : ''}`,
      {
        source: 'kalshi',
        ttlSec: 1800,
        timeoutMs: 40_000,
        // Pages are megabytes of fields we never read; cache only these.
        keep: (d: { events?: { event_ticker: string; title: string; markets?: Record<string, unknown>[] }[]; cursor?: string }) => ({
          cursor: d.cursor,
          events: (d.events ?? []).map((e) => ({
            event_ticker: e.event_ticker,
            title: e.title,
            markets: e.event_ticker.startsWith('KXMVE') ? [] : (e.markets ?? []).map((m) => ({ title: m.title, yes_sub_title: m.yes_sub_title, last_price_dollars: m.last_price_dollars, yes_bid_dollars: m.yes_bid_dollars, yes_ask_dollars: m.yes_ask_dollars, volume_fp: m.volume_fp, close_time: m.close_time })),
          })),
        }),
      },
    );
    provs.push(r.prov);
    if (!r.data) return { data: i === 0 ? null : out, provs };
    for (const e of r.data.events ?? []) {
      if (e.event_ticker.startsWith('KXMVE')) continue;
      for (const m of e.markets ?? []) {
        const last = num(m.last_price_dollars);
        const bid = num(m.yes_bid_dollars);
        const ask = num(m.yes_ask_dollars);
        const p = last && last > 0 ? last : bid !== null && ask !== null && ask > 0 ? (bid + ask) / 2 : null;
        if (p === null || p <= 0 || p >= 1) continue;
        const sub = m.yes_sub_title && !e.title.includes(m.yes_sub_title) ? ` — ${m.yes_sub_title}` : '';
        out.push({ venue: 'kalshi', question: `${m.title ?? e.title}${sub}`, probability: p, volume: num(m.volume_fp), url: `https://kalshi.com/markets/${e.event_ticker.toLowerCase()}`, closes: m.close_time ?? null });
      }
    }
    cursor = r.data.cursor ?? '';
    if (!cursor) break;
  }
  return { data: out, provs };
}

/** Binary Manifold markets matching a search term. */
export async function manifoldSearch(ctx: Ctx, term: string, limit = 8): Promise<Sourced<OtherMarket[]>> {
  const r = await ctx.http.get<{ question: string; probability?: number; outcomeType: string; url: string; volume?: number; closeTime?: number }[]>(
    `https://api.manifold.markets/v0/search-markets?term=${enc(term)}&filter=open&contractType=BINARY&limit=${limit}`,
    { source: 'manifold', ttlSec: 3600 },
  );
  return {
    data:
      r.data
        ?.filter((m) => m.outcomeType === 'BINARY' && typeof m.probability === 'number')
        .map((m) => ({ venue: 'manifold' as const, question: m.question, probability: m.probability!, volume: m.volume ?? null, url: m.url, closes: m.closeTime ? new Date(m.closeTime).toISOString() : null })) ?? null,
    prov: r.prov,
  };
}
