/**
 * Catalyst calendar: what is scheduled to move things in the next days.
 *   Earnings (Finnhub): watched companies first, then the largest by revenue estimate.
 *   Macro releases (FRED): only the ones markets care about (CPI, jobs, GDP, PCE, ...). FOMC is left out
 *     because FRED lists its press-release series on every day, which says nothing about meeting dates.
 *   IPOs (Finnhub): expected and priced listings in the window, largest offering first, watched names flagged.
 *   Prediction markets (Polymarket): high-volume markets that close in the window, flagged when Oculon
 *     has an open forecast on them.
 */
import { enc, type Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { ModuleResult, Provenance, Sourced } from '../core/types.js';
import { findSymbol, ipoCalendar } from '../sources/finance.js';
import { topMarkets } from '../sources/polymarket.js';
import { listWatch } from './meerkat.js';
import { upcomingRegDates } from './regs.js';

export interface CatalystItem {
  date: string;
  kind: 'earnings' | 'macro' | 'market' | 'ipo' | 'regulation';
  title: string;
  detail: string;
  url: string | null;
  watched: boolean;
}

export interface Calendar {
  from: string;
  to: string;
  items: CatalystItem[];
}

/** Releases worth a line; FRED lists hundreds of daily series that nobody trades on. */
export const KEY_RELEASES: [RegExp, string][] = [
  [/^Consumer Price Index$/, 'US CPI inflation'],
  [/^Employment Situation$/, 'US jobs report (nonfarm payrolls)'],
  [/^Gross Domestic Product$/, 'US GDP'],
  [/^Personal Income and Outlays$/, 'US PCE inflation and spending'],
  [/^Producer Price Index$/, 'US PPI'],
  [/^Advance Monthly Sales for Retail and Food Services$/, 'US retail sales'],
  [/^Job Openings and Labor Turnover Survey$/, 'US job openings (JOLTS)'],
  [/^ADP National Employment Report$/, 'ADP private payrolls'],
  [/^Surveys of Consumers$/, 'Michigan consumer sentiment'],
  [/^Industrial Production and Capacity Utilization$/, 'US industrial production'],
  [/^New Residential Construction$/, 'US housing starts'],
];

const ymd = (d: Date) => d.toISOString().slice(0, 10);

async function earnings(ctx: Ctx, from: string, to: string): Promise<Sourced<{ symbol: string; date: string; hour: string; epsEstimate: number | null; revenueEstimate: number | null }[]>> {
  const k = key('FINNHUB_API_KEY');
  if (!k) return noKey('finnhub', 'FINNHUB_API_KEY');
  const r = await ctx.http.get<{ earningsCalendar?: { symbol: string; date: string; hour: string; epsEstimate: number | null; revenueEstimate: number | null }[] }>(
    `https://finnhub.io/api/v1/calendar/earnings?from=${from}&to=${to}&token=${k}`,
    { source: 'finnhub', ttlSec: 6 * 3600 },
  );
  return { data: r.data?.earningsCalendar ?? null, prov: r.prov };
}

async function releases(ctx: Ctx, from: string, to: string): Promise<Sourced<{ release_name: string; date: string; release_id: number }[]>> {
  const k = key('FRED_API_KEY');
  if (!k) return noKey('fred', 'FRED_API_KEY');
  const r = await ctx.http.get<{ release_dates?: { release_name: string; date: string; release_id: number }[] }>(
    `https://api.stlouisfed.org/fred/releases/dates?file_type=json&realtime_start=${enc(from)}&realtime_end=${enc(to)}&include_release_dates_with_no_data=true&limit=1000&api_key=${k}`,
    { source: 'fred', ttlSec: 12 * 3600 },
  );
  return { data: r.data?.release_dates ?? null, prov: r.prov };
}

const money = (n: number) => (n >= 1e9 ? `$${(n / 1e9).toFixed(1)}B` : n >= 1e6 ? `$${(n / 1e6).toFixed(1)}M` : `$${Math.round(n / 1e3)}k`);

export async function catalysts(ctx: Ctx, days = 14): Promise<ModuleResult<Calendar>> {
  const now = ctx.now();
  const from = ymd(now);
  const to = ymd(new Date(now.getTime() + days * 86_400_000));
  const provenance: Provenance[] = [];
  const items: CatalystItem[] = [];
  const watched = listWatch(ctx).filter((w) => w.kind === 'company');

  const [e, rel, mk, ipo] = await Promise.all([earnings(ctx, from, to), releases(ctx, from, to), topMarkets(ctx, 200), ipoCalendar(ctx, from, to)]);
  provenance.push(e.prov, rel.prov, mk.prov, ipo.prov);

  if (e.data) {
    const symbols = new Map<string, string>();
    for (const w of watched.slice(0, 10)) {
      const s = await findSymbol(ctx, w.target);
      provenance.push(s.prov);
      if (s.data) symbols.set(s.data.toUpperCase(), w.target);
    }
    const inWindow = e.data.filter((x) => x.date >= from && x.date <= to);
    const mine = inWindow.filter((x) => symbols.has(x.symbol.toUpperCase()));
    const big = inWindow.filter((x) => !symbols.has(x.symbol.toUpperCase()) && (x.revenueEstimate ?? 0) > 0).sort((a, b) => (b.revenueEstimate ?? 0) - (a.revenueEstimate ?? 0)).slice(0, 12);
    for (const x of [...mine, ...big]) {
      const isMine = symbols.has(x.symbol.toUpperCase());
      const when = x.hour === 'bmo' ? 'before open' : x.hour === 'amc' ? 'after close' : '';
      items.push({
        date: x.date,
        kind: 'earnings',
        title: `${x.symbol} earnings${isMine ? ` (${symbols.get(x.symbol.toUpperCase())})` : ''}`,
        detail: [when, x.epsEstimate != null ? `EPS est ${x.epsEstimate.toFixed(2)}` : '', x.revenueEstimate ? `revenue est ${money(x.revenueEstimate)}` : ''].filter(Boolean).join(', '),
        url: `https://finnhub.io/quote/${enc(x.symbol)}`,
        watched: isMine,
      });
    }
  }

  if (ipo.data) {
    const names = watched.map((w) => w.target.toLowerCase());
    // Withdrawn offerings are not catalysts; keep the 12 largest by offering value.
    const list = ipo.data
      .filter((x) => x.date >= from && x.date <= to && !/withdrawn/i.test(x.status))
      .sort((a, b) => (b.valueUsd ?? 0) - (a.valueUsd ?? 0))
      .slice(0, 12);
    for (const x of list) {
      const mine = names.some((n) => x.name.toLowerCase().includes(n));
      items.push({
        date: x.date,
        kind: 'ipo',
        title: `IPO: ${x.name}${x.symbol ? ` (${x.symbol})` : ''}`,
        detail: [x.exchange, x.price ? `$${x.price} per share` : '', x.shares ? `${x.shares.toLocaleString('en-US')} shares` : '', x.valueUsd ? `up to ${money(x.valueUsd)}` : '', x.status].filter(Boolean).join(', '),
        url: x.symbol ? `https://finnhub.io/quote/${enc(x.symbol)}` : null,
        watched: mine,
      });
    }
  }

  if (rel.data) {
    const seen = new Set<string>();
    for (const r of rel.data) {
      if (r.date < from || r.date > to) continue;
      const hit = KEY_RELEASES.find(([re]) => re.test(r.release_name));
      if (!hit || seen.has(`${r.release_name}|${r.date}`)) continue;
      seen.add(`${r.release_name}|${r.date}`);
      items.push({ date: r.date, kind: 'macro', title: hit[1], detail: r.release_name, url: `https://fred.stlouisfed.org/releases/calendar?rid=${r.release_id}`, watched: false });
    }
  }

  if (mk.data) {
    const forecast = new Set((ctx.store.db.prepare('SELECT slug FROM predictions WHERE resolved_at IS NULL').all() as { slug: string }[]).map((r) => r.slug));
    // Single games and tweet-count brackets close every day and are not catalysts.
    const closing = mk.data.filter((m) => m.endDate && m.endDate.slice(0, 10) >= from && m.endDate.slice(0, 10) <= to && !/\bvs\.?\s|\bpost \d+-\d+ tweets\b|^spread:|\bO\/U\b|over\/under|^total (points|goals)/i.test(m.question));
    const names = watched.map((w) => w.target.toLowerCase());
    const priority = (m: (typeof closing)[number]) => Boolean(m.slug && forecast.has(m.slug)) || names.some((n) => m.question.toLowerCase().includes(n));
    const ranked = [...closing.filter(priority), ...closing.filter((m) => !priority(m)).sort((a, b) => b.volume24h - a.volume24h).slice(0, 10)];
    for (const m of ranked) {
      const mine = Boolean(m.slug && forecast.has(m.slug));
      const about = watched.find((w) => new RegExp(`\\b${w.target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(m.question));
      const p = m.prices[0];
      items.push({
        date: m.endDate!.slice(0, 10),
        kind: 'market',
        title: `Closes: ${m.question}`,
        detail: [p != null ? `${m.outcomes[0] ?? 'Yes'} ${Math.round(p * 100)}%` : '', `24h volume ${money(m.volume24h)}`, mine ? 'Oculon has an open forecast' : '', about ? `about watched ${about.target}` : ''].filter(Boolean).join(', '),
        url: m.url,
        watched: mine || Boolean(about),
      });
    }
  }

  // Federal Register: rules taking effect and comment periods closing. There are ~100 per fortnight, so keep
  // the ones about watched companies or from market-moving agencies, 10 at most.
  const regDates = await upcomingRegDates(ctx, days).catch(() => []);
  provenance.push({ source: 'federal-register', url: 'https://www.federalregister.gov', status: regDates.length ? 'LIVE' : 'UNAVAILABLE', fetchedAt: now.toISOString(), note: `${regDates.length} rule dates in window` });
  const KEY_AGENCY = /securities and exchange|treasury|commerce|federal trade|federal communications|federal reserve|energy|environmental protection|commodity futures|federal deposit|comptroller|consumer financial|food and drug|health and human/i;
  // Routine items that every agency publishes by the dozen.
  const ROUTINE = /airworthiness directives?|special conditions|safety zones?|drawbridge|correction|technical amendment|pesticide tolerance|approval and promulgation|state implementation plan|meeting/i;
  const watchedNames = watched.map((w) => w.target.toLowerCase());
  const regRank = (r: (typeof regDates)[number]) => (watchedNames.some((n) => r.title.toLowerCase().includes(n)) ? 2 : KEY_AGENCY.test(r.agency ?? '') && !ROUTINE.test(r.title) ? 1 : 0);
  for (const r of regDates.filter((x) => regRank(x) > 0).sort((a, b) => regRank(b) - regRank(a) || a.date.localeCompare(b.date)).slice(0, 10)) {
    items.push({ date: r.date, kind: 'regulation', title: `${r.kind === 'effective' ? 'Rule takes effect' : 'Comments close'}: ${r.title.slice(0, 140)}`, detail: r.agency ?? '', url: r.url, watched: regRank(r) === 2 });
  }

  items.sort((a, b) => a.date.localeCompare(b.date) || Number(b.watched) - Number(a.watched) || a.kind.localeCompare(b.kind));
  return { module: 'calendar', input: `${days}d`, generatedAt: now.toISOString(), result: { from, to, items }, signals: [], provenance };
}
