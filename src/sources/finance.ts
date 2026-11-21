/** Markets: Finnhub (stocks, insiders, company news), FRED (macro), CoinGecko (crypto). */
import { DAY_MS, enc, type Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Sourced } from '../core/types.js';

const FH = 'https://finnhub.io/api/v1';
const fh = <T>(ctx: Ctx, path: string, ttlSec: number) => {
  const k = key('FINNHUB_API_KEY');
  if (!k) return Promise.resolve(noKey<T>('finnhub', 'FINNHUB_API_KEY'));
  return ctx.http.get<T>(`${FH}${path}${path.includes('?') ? '&' : '?'}token=${k}`, { source: 'finnhub', ttlSec });
};

export interface Quote {
  symbol: string;
  price: number;
  changePct: number;
  high: number;
  low: number;
  prevClose: number;
}

export interface CompanyProfile {
  name: string;
  ticker: string;
  exchange: string;
  industry: string;
  marketCapM: number;
  weburl: string;
  country: string;
}

export interface Insider {
  name: string;
  change: number;
  shares: number;
  date: string;
  code: string;
  price: number;
}

/** Best US common-stock symbol for a company name or ticker. */
export async function findSymbol(ctx: Ctx, q: string): Promise<Sourced<string>> {
  const r = await fh<{ result?: { symbol: string; type: string; description: string }[] }>(ctx, `/search?q=${enc(q)}`, 7 * 86_400);
  const hits = r.data?.result?.filter((x) => x.type === 'Common Stock' && !x.symbol.includes('.')) ?? [];
  const exact = hits.find((x) => x.symbol.toLowerCase() === q.toLowerCase());
  return { data: (exact ?? hits[0])?.symbol ?? null, prov: r.prov };
}

export async function quote(ctx: Ctx, symbol: string): Promise<Sourced<Quote>> {
  const r = await fh<{ c: number; dp: number; h: number; l: number; pc: number }>(ctx, `/quote?symbol=${enc(symbol)}`, 300);
  return { data: r.data && r.data.c ? { symbol, price: r.data.c, changePct: r.data.dp, high: r.data.h, low: r.data.l, prevClose: r.data.pc } : null, prov: r.prov };
}

export async function profile(ctx: Ctx, symbol: string): Promise<Sourced<CompanyProfile>> {
  const r = await fh<{ name?: string; ticker?: string; exchange?: string; finnhubIndustry?: string; marketCapitalization?: number; weburl?: string; country?: string }>(ctx, `/stock/profile2?symbol=${enc(symbol)}`, 7 * 86_400);
  const d = r.data;
  return {
    data: d?.name ? { name: d.name, ticker: d.ticker ?? symbol, exchange: d.exchange ?? '', industry: d.finnhubIndustry ?? '', marketCapM: d.marketCapitalization ?? 0, weburl: d.weburl ?? '', country: d.country ?? '' } : null,
    prov: r.prov,
  };
}

export async function insiders(ctx: Ctx, symbol: string, days = 30): Promise<Sourced<Insider[]>> {
  const from = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const r = await fh<{ data?: { name: string; change: number; share: number; transactionDate: string; transactionCode: string; transactionPrice: number }[] }>(ctx, `/stock/insider-transactions?symbol=${enc(symbol)}&from=${from}`, 6 * 3600);
  return { data: r.data?.data?.map((x) => ({ name: x.name, change: x.change, shares: x.share, date: x.transactionDate, code: x.transactionCode, price: x.transactionPrice })) ?? null, prov: r.prov };
}

export interface NewsItem {
  title: string;
  url: string;
  date: string;
  source: string;
}

export async function companyNews(ctx: Ctx, symbol: string, days = 7): Promise<Sourced<NewsItem[]>> {
  const to = ctx.now().toISOString().slice(0, 10);
  const from = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const r = await fh<{ headline: string; url: string; datetime: number; source: string }[]>(ctx, `/company-news?symbol=${enc(symbol)}&from=${from}&to=${to}`, 1800);
  return { data: r.data?.map((n) => ({ title: n.headline, url: n.url, date: new Date(n.datetime * 1000).toISOString(), source: n.source })) ?? null, prov: r.prov };
}

/* ---- Finnhub free-tier extras (live-checked 2026-11-19; price targets, upgrades, ownership, ESG, executives,
   supply chain, revenue breakdown, dividends, social sentiment, press releases and the economic calendar are premium). */

export interface Recommendation {
  period: string;
  strongBuy: number;
  buy: number;
  hold: number;
  sell: number;
  strongSell: number;
}

/** Monthly analyst recommendation counts, newest first. */
export async function recommendations(ctx: Ctx, symbol: string): Promise<Sourced<Recommendation[]>> {
  const r = await fh<Recommendation[]>(ctx, `/stock/recommendation?symbol=${enc(symbol)}`, 12 * 3600);
  return {
    data: Array.isArray(r.data) ? r.data.map((x) => ({ period: x.period, strongBuy: x.strongBuy, buy: x.buy, hold: x.hold, sell: x.sell, strongSell: x.strongSell })).sort((a, b) => b.period.localeCompare(a.period)) : null,
    prov: r.prov,
  };
}

/** Share of bullish ratings (strong buy + buy) in one month, 0-1. */
export const bullishShare = (r: Recommendation): number | null => {
  const n = r.strongBuy + r.buy + r.hold + r.sell + r.strongSell;
  return n ? (r.strongBuy + r.buy) / n : null;
};

export interface InsiderSentimentMonth {
  /** YYYY-MM. */
  month: string;
  /** Net shares bought (+) or sold (-) by insiders. */
  change: number;
  /** Monthly share purchase ratio, -100 (all selling) to +100 (all buying). */
  mspr: number;
}

export async function insiderSentiment(ctx: Ctx, symbol: string, months = 12): Promise<Sourced<InsiderSentimentMonth[]>> {
  const now = ctx.now();
  const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - months, 1)).toISOString().slice(0, 10);
  const r = await fh<{ data?: { year: number; month: number; change: number; mspr: number }[] }>(ctx, `/stock/insider-sentiment?symbol=${enc(symbol)}&from=${from}&to=${now.toISOString().slice(0, 10)}`, 12 * 3600);
  return {
    data: r.data?.data?.map((x) => ({ month: `${x.year}-${String(x.month).padStart(2, '0')}`, change: x.change, mspr: Math.round(x.mspr * 10) / 10 })).sort((a, b) => b.month.localeCompare(a.month)) ?? null,
    prov: r.prov,
  };
}

/** Companies Finnhub groups with this one (same industry), excluding itself. */
export async function peers(ctx: Ctx, symbol: string): Promise<Sourced<string[]>> {
  const r = await fh<string[]>(ctx, `/stock/peers?symbol=${enc(symbol)}`, 7 * 86_400);
  return { data: Array.isArray(r.data) ? r.data.filter((s) => s.toUpperCase() !== symbol.toUpperCase()) : null, prov: r.prov };
}

export interface Ipo {
  date: string;
  symbol: string;
  name: string;
  exchange: string;
  /** Single price or range, as Finnhub gives it, e.g. "10.00" or "17.00-19.00". */
  price: string;
  shares: number | null;
  valueUsd: number | null;
  status: string;
}

export async function ipoCalendar(ctx: Ctx, from: string, to: string): Promise<Sourced<Ipo[]>> {
  const r = await fh<{ ipoCalendar?: { date: string; symbol: string; name: string; exchange: string; price: string | null; numberOfShares: number | null; totalSharesValue: number | null; status: string }[] }>(ctx, `/calendar/ipo?from=${from}&to=${to}`, 6 * 3600);
  return {
    data: r.data?.ipoCalendar?.map((x) => ({ date: x.date, symbol: x.symbol ?? '', name: x.name, exchange: x.exchange ?? '', price: x.price ?? '', shares: x.numberOfShares ?? null, valueUsd: x.totalSharesValue ?? null, status: x.status ?? '' })) ?? null,
    prov: r.prov,
  };
}

/** A compact subset of Finnhub's ~130 basic-financial metrics (the raw response is ~250 KB of history). */
export interface KeyMetrics {
  peTTM: number | null;
  psTTM: number | null;
  pb: number | null;
  epsTTM: number | null;
  revenueGrowthTTMYoy: number | null;
  epsGrowthTTMYoy: number | null;
  grossMarginTTM: number | null;
  netMarginTTM: number | null;
  roeTTM: number | null;
  debtToEquity: number | null;
  currentRatio: number | null;
  dividendYield: number | null;
  beta: number | null;
  high52w: number | null;
  low52w: number | null;
  return52w: number | null;
  marketCapM: number | null;
}

export async function metrics(ctx: Ctx, symbol: string): Promise<Sourced<KeyMetrics>> {
  const k = key('FINNHUB_API_KEY');
  if (!k) return noKey('finnhub', 'FINNHUB_API_KEY');
  const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  const r = await ctx.http.get<KeyMetrics | null>(`${FH}/stock/metric?symbol=${enc(symbol)}&metric=all&token=${k}`, {
    source: 'finnhub',
    ttlSec: 24 * 3600,
    keep: (d: { metric?: Record<string, unknown> }): KeyMetrics | null => {
      const m = d.metric;
      if (!m || !Object.keys(m).length) return null;
      return {
        peTTM: n(m.peTTM ?? m.peBasicExclExtraTTM),
        psTTM: n(m.psTTM),
        pb: n(m.pb ?? m.pbQuarterly),
        epsTTM: n(m.epsTTM ?? m.epsBasicExclExtraItemsTTM),
        revenueGrowthTTMYoy: n(m.revenueGrowthTTMYoy),
        epsGrowthTTMYoy: n(m.epsGrowthTTMYoy),
        grossMarginTTM: n(m.grossMarginTTM),
        netMarginTTM: n(m.netProfitMarginTTM),
        roeTTM: n(m.roeTTM),
        debtToEquity: n(m['totalDebt/totalEquityQuarterly'] ?? m['totalDebt/totalEquityAnnual']),
        currentRatio: n(m.currentRatioQuarterly ?? m.currentRatioAnnual),
        dividendYield: n(m.currentDividendYieldTTM ?? m.dividendYieldIndicatedAnnual),
        beta: n(m.beta),
        high52w: n(m['52WeekHigh']),
        low52w: n(m['52WeekLow']),
        return52w: n(m['52WeekPriceReturnDaily']),
        marketCapM: n(m.marketCapitalization),
      };
    },
  });
  return { data: r.data ?? null, prov: r.prov };
}

export interface EarningsSurprise {
  period: string;
  actual: number | null;
  estimate: number | null;
  surprisePct: number | null;
}

/** Last four quarters of reported EPS against the consensus estimate. */
export async function earningsSurprises(ctx: Ctx, symbol: string): Promise<Sourced<EarningsSurprise[]>> {
  const r = await fh<{ period: string; actual: number | null; estimate: number | null; surprisePercent: number | null }[]>(ctx, `/stock/earnings?symbol=${enc(symbol)}`, 24 * 3600);
  return { data: Array.isArray(r.data) ? r.data.map((x) => ({ period: x.period, actual: x.actual, estimate: x.estimate, surprisePct: x.surprisePercent })) : null, prov: r.prov };
}

export interface Lobbying {
  /** Sum of reported lobbying income/expenses over the window (USD). */
  totalUsd: number;
  filings: number;
  byPeriod: { period: string; usd: number }[];
  latestUrl: string | null;
}

/** US Senate LDA lobbying disclosures linked to the company. */
export async function lobbying(ctx: Ctx, symbol: string, days = 730): Promise<Sourced<Lobbying>> {
  const k = key('FINNHUB_API_KEY');
  if (!k) return noKey('finnhub', 'FINNHUB_API_KEY');
  const to = ctx.now().toISOString().slice(0, 10);
  const from = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const r = await ctx.http.get<Lobbying | null>(`${FH}/stock/lobbying?symbol=${enc(symbol)}&from=${from}&to=${to}&token=${k}`, {
    source: 'finnhub',
    ttlSec: 7 * 86_400,
    keep: (d: { data?: { year: number; period: string; income: number | null; expenses: number | null; documentUrl: string }[] }): Lobbying | null => {
      const rows = d.data ?? [];
      if (!rows.length) return null;
      const per = new Map<string, number>();
      for (const x of rows) {
        const p = `${x.year}-${x.period}`;
        per.set(p, (per.get(p) ?? 0) + (x.income ?? 0) + (x.expenses ?? 0));
      }
      const byPeriod = [...per].map(([period, usd]) => ({ period, usd })).sort((a, b) => b.period.localeCompare(a.period));
      const latest = [...rows].sort((a, b) => `${b.year}-${b.period}`.localeCompare(`${a.year}-${a.period}`))[0];
      return { totalUsd: byPeriod.reduce((a, b) => a + b.usd, 0), filings: rows.length, byPeriod, latestUrl: latest?.documentUrl || null };
    },
  });
  return { data: r.data ?? null, prov: r.prov };
}

export interface GovContracts {
  /** Distinct awards with an action in the window (latest action per award). */
  awards: number;
  /** Cumulative obligated value of those awards (multi-year contracts count in full), not money spent in the window. */
  totalUsd: number;
  topAgencies: { agency: string; usd: number }[];
  latest: { date: string; agency: string; usd: number; description: string; url: string }[];
}

/** US federal contract awards (USASpending.gov) to the company. The raw response can exceed 1 MB, so it is summarized. */
export async function govContracts(ctx: Ctx, symbol: string, days = 365): Promise<Sourced<GovContracts>> {
  const k = key('FINNHUB_API_KEY');
  if (!k) return noKey('finnhub', 'FINNHUB_API_KEY');
  const to = ctx.now().toISOString().slice(0, 10);
  const from = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const r = await ctx.http.get<GovContracts | null>(`${FH}/stock/usa-spending?symbol=${enc(symbol)}&from=${from}&to=${to}&token=${k}`, {
    source: 'finnhub',
    ttlSec: 7 * 86_400,
    timeoutMs: 30_000,
    keep: (d: { data?: { actionDate: string; awardingAgencyName: string; totalValue: number | null; obligatedAmount: number | null; awardDescription?: string; permalink?: string }[] }): GovContracts | null => {
      // Each row is a contract action; obligated amounts are cumulative per award, so keep the latest action per award.
      const byAward = new Map<string, NonNullable<typeof d.data>[number]>();
      for (const x of d.data ?? []) {
        const k = x.permalink || `${x.awardingAgencyName}|${x.awardDescription ?? ''}|${x.actionDate}`;
        const prev = byAward.get(k);
        if (!prev || x.actionDate > prev.actionDate) byAward.set(k, x);
      }
      const rows = [...byAward.values()];
      if (!rows.length) return null;
      const val = (x: (typeof rows)[number]) => x.obligatedAmount ?? x.totalValue ?? 0;
      const ag = new Map<string, number>();
      for (const x of rows) ag.set(x.awardingAgencyName, (ag.get(x.awardingAgencyName) ?? 0) + val(x));
      return {
        awards: rows.length,
        totalUsd: rows.reduce((a, x) => a + val(x), 0),
        topAgencies: [...ag].map(([agency, usd]) => ({ agency, usd })).sort((a, b) => b.usd - a.usd).slice(0, 5),
        latest: [...rows]
          .sort((a, b) => b.actionDate.localeCompare(a.actionDate))
          .slice(0, 5)
          .map((x) => ({ date: x.actionDate, agency: x.awardingAgencyName, usd: val(x), description: (x.awardDescription ?? '').slice(0, 200), url: x.permalink ?? '' })),
      };
    },
  });
  return { data: r.data ?? null, prov: r.prov };
}

export interface VisaFilings {
  /** Finnhub returns at most 500 rows, so 500 means "500 or more". */
  applications: number;
  byClass: Record<string, number>;
  topTitles: { title: string; count: number }[];
  /** Median lower bound of the offered annual wage (USD). */
  medianWageFrom: number | null;
}

/** H-1B / PERM labor certification filings (US DOL); a proxy for which roles a company hires from abroad. */
export async function visaApplications(ctx: Ctx, symbol: string, days = 365): Promise<Sourced<VisaFilings>> {
  const k = key('FINNHUB_API_KEY');
  if (!k) return noKey('finnhub', 'FINNHUB_API_KEY');
  const to = ctx.now().toISOString().slice(0, 10);
  const from = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const r = await ctx.http.get<VisaFilings | null>(`${FH}/stock/visa-application?symbol=${enc(symbol)}&from=${from}&to=${to}&token=${k}`, {
    source: 'finnhub',
    ttlSec: 7 * 86_400,
    timeoutMs: 30_000,
    keep: (d: { data?: { visaClass: string; jobTitle: string; wageRangeFrom: number | null; wageUnitOfPay?: string }[] }): VisaFilings | null => {
      const rows = d.data ?? [];
      if (!rows.length) return null;
      const byClass: Record<string, number> = {};
      const titles = new Map<string, number>();
      for (const x of rows) {
        byClass[x.visaClass || 'unknown'] = (byClass[x.visaClass || 'unknown'] ?? 0) + 1;
        const t = (x.jobTitle ?? '').trim();
        if (t) titles.set(t, (titles.get(t) ?? 0) + 1);
      }
      const wages = rows
        .filter((x) => !x.wageUnitOfPay || x.wageUnitOfPay === 'Year')
        .map((x) => x.wageRangeFrom).filter((w): w is number => typeof w === 'number' && w > 0).sort((a, b) => a - b);
      return {
        applications: rows.length,
        byClass,
        topTitles: [...titles].map(([title, count]) => ({ title, count })).sort((a, b) => b.count - a.count).slice(0, 8),
        medianWageFrom: wages.length ? wages[Math.floor(wages.length / 2)]! : null,
      };
    },
  });
  return { data: r.data ?? null, prov: r.prov };
}

export interface Patents {
  /** Finnhub returns at most 250 rows, so 250 means "250 or more". */
  count: number;
  latest: { date: string; title: string; number: string; url: string }[];
}

/** USPTO patent applications and grants filed by the company. */
export async function patents(ctx: Ctx, symbol: string, days = 365): Promise<Sourced<Patents>> {
  const k = key('FINNHUB_API_KEY');
  if (!k) return noKey('finnhub', 'FINNHUB_API_KEY');
  const to = ctx.now().toISOString().slice(0, 10);
  const from = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const r = await ctx.http.get<Patents | null>(`${FH}/stock/uspto-patent?symbol=${enc(symbol)}&from=${from}&to=${to}&token=${k}`, {
    source: 'finnhub',
    ttlSec: 7 * 86_400,
    timeoutMs: 30_000,
    keep: (d: { data?: { applicationNumber: string; patentNumber?: string; description: string; filingDate: string; publicationDate?: string; url?: string }[] }): Patents | null => {
      const rows = d.data ?? [];
      if (!rows.length) return null;
      return {
        count: rows.length,
        latest: [...rows]
          .sort((a, b) => (b.publicationDate || b.filingDate).localeCompare(a.publicationDate || a.filingDate))
          .slice(0, 5)
          .map((x) => ({ date: (x.publicationDate || x.filingDate || '').slice(0, 10), title: x.description, number: x.patentNumber || x.applicationNumber, url: x.url ?? '' })),
      };
    },
  });
  return { data: r.data ?? null, prov: r.prov };
}

export interface FredPoint {
  date: string;
  value: number;
}

export async function fredSeries(ctx: Ctx, id: string, limit = 24): Promise<Sourced<FredPoint[]>> {
  const k = key('FRED_API_KEY');
  if (!k) return noKey('fred', 'FRED_API_KEY');
  const r = await ctx.http.get<{ observations?: { date: string; value: string }[] }>(
    `https://api.stlouisfed.org/fred/series/observations?series_id=${enc(id)}&file_type=json&sort_order=desc&limit=${limit}&api_key=${k}`,
    { source: 'fred', ttlSec: 6 * 3600 },
  );
  return { data: r.data?.observations?.filter((o) => o.value !== '.').map((o) => ({ date: o.date, value: Number(o.value) })) ?? null, prov: r.prov };
}

const cgHeaders = () => {
  const k = key('COINGECKO_API_KEY');
  return k ? { 'x-cg-demo-api-key': k } : undefined;
};

export interface TrendingCoin {
  id: string;
  name: string;
  symbol: string;
  rank: number | null;
  change24h: number | null;
}

export async function trendingCoins(ctx: Ctx): Promise<Sourced<TrendingCoin[]>> {
  const h = cgHeaders();
  const r = await ctx.http.get<{ coins?: { item: { id: string; name: string; symbol: string; market_cap_rank: number | null; data?: { price_change_percentage_24h?: { usd?: number } } } }[] }>(
    'https://api.coingecko.com/api/v3/search/trending',
    { source: 'coingecko', ttlSec: 900, ...(h ? { headers: h } : {}) },
  );
  return {
    data: r.data?.coins?.map(({ item }) => ({ id: item.id, name: item.name, symbol: item.symbol, rank: item.market_cap_rank, change24h: item.data?.price_change_percentage_24h?.usd ?? null })) ?? null,
    prov: r.prov,
  };
}

export async function coinByContract(ctx: Ctx, platform: string, address: string): Promise<Sourced<{ id: string; name: string; symbol: string; priceUsd: number | null; marketCapUsd: number | null; change24h: number | null }>> {
  const h = cgHeaders();
  const r = await ctx.http.get<{ id?: string; name?: string; symbol?: string; market_data?: { current_price?: { usd?: number }; market_cap?: { usd?: number }; price_change_percentage_24h?: number } }>(
    `https://api.coingecko.com/api/v3/coins/${enc(platform)}/contract/${enc(address.toLowerCase())}`,
    { source: 'coingecko', ttlSec: 600, ...(h ? { headers: h } : {}) },
  );
  const d = r.data;
  return {
    data: d?.id ? { id: d.id, name: d.name ?? '', symbol: d.symbol ?? '', priceUsd: d.market_data?.current_price?.usd ?? null, marketCapUsd: d.market_data?.market_cap?.usd ?? null, change24h: d.market_data?.price_change_percentage_24h ?? null } : null,
    prov: r.prov,
  };
}
