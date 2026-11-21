/**
 * DeFi risk radar (no keys): DefiLlama free endpoints plus the alternative.me Crypto Fear & Greed index.
 *   api.llama.fi/protocols            TVL with 1h/1d/7d change: large 1d drops are the classic exploit or bank-run tell.
 *   api.llama.fi/v2/chains            current chain TVL; compared with our own observation from about a day earlier.
 *   api.llama.fi/v2/historicalChainTvl total DeFi TVL, the market baseline for "is this drop just prices?".
 *   api.llama.fi/hacks                DefiLlama's hack database: recent exploits with amount, technique and chains.
 *   api.llama.fi/overview/dexs|fees|open-interest  24h DEX volume, fees and derivatives open interest, plus spikes.
 *   stablecoins.llama.fi/stablecoins  stablecoin price (depegs) and circulating supply (redemption runs).
 *   yields.llama.fi/pools             large stablecoin pools paying unusually high APY (unsustainable yield tell).
 *   api.llama.fi/protocol/<slug>      one protocol in depth: TVL history, chains, audits, oracles, hacks, raises.
 * Pro-only (HTTP 402 on the free API, checked 2026-11): bridges, raises, treasuries, emissions, oracles.
 * Every DefiLlama response is megabytes, so each request trims the JSON with `keep` before it is cached.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';

const LLAMA = 'https://api.llama.fi';
const PROTOCOLS_URL = `${LLAMA}/protocols`;
const OVERVIEW_QS = 'excludeTotalDataChart=true&excludeTotalDataChartBreakdown=true';

export interface DefiOpts {
  /** Minimum TVL (USD, before the drop) for a protocol drop to count. Default $50M. */
  minTvl?: number;
  /** 1d TVL drop in percent that counts as a drop. Default 20. */
  dropPct?: number;
  /** Minimum circulating supply (USD) for a stablecoin depeg to count. Default $50M. */
  minPegCap?: number;
  /** Distance from the peg in percent that counts as a depeg. Default 2. */
  depegPct?: number;
  /** Chain TVL drop in percent (versus our observation about a day earlier) that counts. Default 15. */
  chainMovePct?: number;
  /** Hacks reported within this many days become signals. Default 7. */
  hackDays?: number;
  /** Fetch yields.llama.fi pools (about 10 MB). Default true. */
  yields?: boolean;
}

export interface ProtocolMove {
  name: string;
  slug: string;
  category: string;
  chains: string[];
  tvl: number;
  prevTvl: number;
  lostUsd: number;
  change1h: number | null;
  change1d: number;
  change7d: number | null;
  /** The protocol's 1d change minus the whole market's 1d TVL change: separates a protocol event from a price move. */
  vsMarketPct: number | null;
  flags: string[];
  url: string;
}

export interface Depeg {
  name: string;
  symbol: string;
  mechanism: string;
  price: number;
  offPct: number;
  circulating: number;
  supplyChange1dPct: number | null;
  supplyChange7dPct: number | null;
  url: string;
}

export interface ChainMove {
  name: string;
  tvl: number;
  prevTvl: number;
  changePct: number;
  hoursBetween: number;
  vsMarketPct: number | null;
}

export interface Hack {
  date: string;
  name: string;
  amount: number;
  returnedFunds: number | null;
  classification: string;
  technique: string;
  chains: string[];
  bridgeHack: boolean;
  targetType: string;
  description: string;
  url: string;
}

export interface FearGreed {
  value: number;
  label: string;
  date: string;
  avg7d: number | null;
  avg30d: number | null;
  change7d: number | null;
  trend: 'rising' | 'falling' | 'flat' | 'unknown';
  series: { date: string; value: number }[];
}

export interface ActivitySpike {
  kind: 'dex-volume' | 'fees';
  name: string;
  category: string;
  total24h: number;
  change1d: number;
}

export interface YieldAnomaly {
  chain: string;
  project: string;
  symbol: string;
  tvlUsd: number;
  apy: number;
  apyBase: number | null;
  apyReward: number | null;
  apyChange7d: number | null;
}

export interface DefiTotals {
  defiTvl: number | null;
  defiTvlChange1d: number | null;
  defiTvlChange7d: number | null;
  stablecoinSupply: number | null;
  stablecoinSupplyChange1d: number | null;
  dexVolume24h: number | null;
  dexVolumeChange1d: number | null;
  dexVolumeChange7d: number | null;
  fees24h: number | null;
  feesChange1d: number | null;
  openInterest: number | null;
  openInterestChange1d: number | null;
}

export interface DefiOverview {
  totals: DefiTotals;
  tvlDrops: ProtocolMove[];
  depegs: Depeg[];
  /** Stablecoins whose circulating supply fell more than 10% in a day (mass redemption). */
  supplyShocks: Depeg[];
  chains: { top: { name: string; tvl: number }[]; moves: ChainMove[]; observed: number };
  hacks: Hack[];
  fearGreed: FearGreed | null;
  activitySpikes: ActivitySpike[];
  yieldAnomalies: YieldAnomaly[];
}

// ---------- shared fetchers (each one trims the response before it is cached) ----------

interface SlimProtocol {
  name: string;
  slug: string;
  category: string;
  chains: string[];
  tvl: number;
  change_1h: number | null;
  change_1d: number | null;
  change_7d: number | null;
  mcap: number | null;
  audits: string | null;
  audit_links: string[];
  url: string;
  twitter: string | null;
  parent: string | null;
  oracles: string[];
  forkedFrom: string[];
  listedAt: number | null;
  rugged: boolean;
  deadFrom: string | null;
  deprecated: boolean;
  misrepresentedTokens: boolean;
  wrongLiquidity: boolean;
  warnings: string[];
}

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const prevFrom = (tvl: number, pct: number | null) => (pct != null && pct > -100 ? tvl / (1 + pct / 100) : pct === -100 ? Infinity : tvl);

function slimProtocols(d: unknown): SlimProtocol[] {
  if (!Array.isArray(d)) return [];
  const out: SlimProtocol[] = [];
  for (const p of d as Record<string, any>[]) {
    const tvl = num(p.tvl) ?? 0;
    const c1d = num(p.change_1d);
    const prev = prevFrom(tvl, c1d);
    // Keep anything that matters now or did a day ago (a drained protocol can sit near zero today).
    if (tvl < 1e5 && !(Number.isFinite(prev) && prev >= 1e6)) continue;
    out.push({
      name: String(p.name ?? ''),
      slug: String(p.slug ?? ''),
      category: String(p.category ?? ''),
      chains: Array.isArray(p.chains) ? p.chains.slice(0, 30) : [],
      tvl,
      change_1h: num(p.change_1h),
      change_1d: c1d,
      change_7d: num(p.change_7d),
      mcap: num(p.mcap),
      audits: p.audits != null ? String(p.audits) : null,
      audit_links: Array.isArray(p.audit_links) ? p.audit_links.slice(0, 10) : [],
      url: String(p.url ?? ''),
      twitter: p.twitter ?? null,
      parent: p.parentProtocolSlug ?? null,
      oracles: Array.isArray(p.oracles) ? p.oracles : Array.isArray(p.oraclesBreakdown) ? p.oraclesBreakdown.map((o: { name: string }) => o.name) : [],
      forkedFrom: Array.isArray(p.forkedFrom) ? p.forkedFrom : [],
      listedAt: num(p.listedAt),
      rugged: p.rugged === true,
      deadFrom: p.deadFrom ?? null,
      deprecated: p.deprecated === true,
      misrepresentedTokens: p.misrepresentedTokens === true,
      wrongLiquidity: p.wrongLiquidity === true,
      warnings: Array.isArray(p.warningBanners) ? p.warningBanners.map((w: { message?: string }) => String(w.message ?? '')).filter(Boolean) : [],
    });
  }
  return out;
}

export function protocolList(ctx: Ctx) {
  return ctx.http.get<SlimProtocol[]>(PROTOCOLS_URL, { source: 'defillama', ttlSec: 600, timeoutMs: 60_000, keep: slimProtocols });
}

function flagsOf(p: SlimProtocol): string[] {
  const f: string[] = [];
  if (p.rugged) f.push('marked rugged by DefiLlama');
  if (p.deadFrom) f.push(`dead since ${p.deadFrom}`);
  if (p.deprecated) f.push('deprecated');
  if (p.misrepresentedTokens) f.push('misrepresented tokens');
  if (p.wrongLiquidity) f.push('liquidity figures flagged as unreliable');
  for (const w of p.warnings) f.push(`warning: ${w.slice(0, 160)}`);
  return f;
}

function slimHacks(d: unknown) {
  if (!Array.isArray(d)) return [];
  return [...(d as Record<string, any>[])]
    .sort((a, b) => (b.date ?? 0) - (a.date ?? 0))
    .slice(0, 60)
    .map((h) => ({
      date: Number(h.date) || 0,
      name: String(h.name ?? ''),
      amount: num(h.amount) ?? 0,
      returnedFunds: num(h.returnedFunds),
      classification: String(h.classification ?? ''),
      technique: String(h.technique ?? ''),
      chain: Array.isArray(h.chain) ? h.chain : [],
      bridgeHack: h.bridgeHack === true,
      targetType: String(h.targetType ?? ''),
      source: String(h.source ?? ''),
      description: String(h.description ?? '').slice(0, 400),
    }));
}

type SlimHack = ReturnType<typeof slimHacks>[number];

function toHack(h: SlimHack): Hack {
  return {
    date: new Date(h.date * 1000).toISOString().slice(0, 10),
    name: h.name,
    amount: h.amount,
    returnedFunds: h.returnedFunds,
    classification: h.classification,
    technique: h.technique,
    chains: h.chain,
    bridgeHack: h.bridgeHack,
    targetType: h.targetType,
    description: h.description,
    url: /^https?:\/\//.test(h.source) ? h.source : 'https://defillama.com/hacks',
  };
}

function slimOverview(d: any) {
  const pick = (p: any) => ({ name: String(p.displayName ?? p.name ?? ''), category: String(p.category ?? ''), total24h: num(p.total24h) ?? 0, change_1d: num(p.change_1d) });
  return {
    total24h: num(d?.total24h),
    change_1d: num(d?.change_1d),
    change_7d: num(d?.change_7d),
    protocols: Array.isArray(d?.protocols) ? (d.protocols as any[]).filter((p) => (num(p.total24h) ?? 0) >= 1e6).map(pick) : [],
  };
}

const STABLE_YIELD_MIN_TVL = 10e6;
const STABLE_YIELD_MIN_APY = 20;

function slimYields(d: any): YieldAnomaly[] {
  const pools: any[] = Array.isArray(d?.data) ? d.data : [];
  return pools
    .filter((p) => p.stablecoin === true && (num(p.tvlUsd) ?? 0) >= STABLE_YIELD_MIN_TVL && (num(p.apy) ?? 0) >= STABLE_YIELD_MIN_APY)
    .sort((a, b) => b.apy - a.apy)
    .slice(0, 25)
    .map((p) => ({ chain: String(p.chain), project: String(p.project), symbol: String(p.symbol), tvlUsd: p.tvlUsd, apy: Math.round(p.apy * 100) / 100, apyBase: num(p.apyBase), apyReward: num(p.apyReward), apyChange7d: num(p.apyPct7D) }));
}

const pct = (a: number, b: number) => (b ? ((a - b) / b) * 100 : null);
const round = (v: number | null, d = 2) => (v == null ? null : Math.round(v * 10 ** d) / 10 ** d);
const usd = (v: number) => (v >= 1e9 ? `$${(v / 1e9).toFixed(2)}B` : v >= 1e6 ? `$${(v / 1e6).toFixed(1)}M` : `$${Math.round(v / 1e3)}K`);
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, Math.round(v)));

export function dropScore(lostUsd: number, dropPct: number): number {
  return clamp(50 + 10 * Math.log10(Math.max(lostUsd, 1e6) / 1e6) + (dropPct - 20) / 2, 50, 92);
}

export function depegScore(circulating: number, offPct: number): number {
  return clamp(50 + 8 * Math.log10(Math.max(circulating, 5e7) / 5e7) + 3 * offPct, 50, 92);
}

export function hackScore(amount: number, bridge: boolean): number {
  return clamp(50 + 10 * Math.log10(Math.max(amount, 1e6) / 1e6) + (bridge ? 5 : 0), 50, 90);
}

function dropSignal(m: ProtocolMove, now: Date): Signal {
  return {
    id: signalId('defi', 'tvl-drop', m.slug, now.toISOString().slice(0, 10)),
    module: 'defi',
    title: `${m.name} TVL down ${Math.abs(m.change1d).toFixed(1)}% in 24h (${usd(m.prevTvl)} to ${usd(m.tvl)})`,
    score: m.change1d <= -95 ? Math.min(dropScore(m.lostUsd, -m.change1d), 70) : dropScore(m.lostUsd, -m.change1d),
    entity: m.name,
    evidence: [
      {
        source: 'defillama',
        text: `${m.category || 'protocol'} on ${m.chains.slice(0, 5).join(', ') || 'unknown chains'}; 1h ${m.change1h?.toFixed(1) ?? 'n/a'}%, 7d ${m.change7d?.toFixed(1) ?? 'n/a'}%${m.vsMarketPct != null ? `, ${m.vsMarketPct.toFixed(1)} points worse than the whole market` : ''}. TVL is USD value, so token price moves count too.${m.change1d <= -95 ? ' A near-total drop can also be a data adapter gap.' : ''}${m.flags.length ? ` Flags: ${m.flags.join('; ')}` : ''}`,
        url: `https://defillama.com/protocol/${m.slug}`,
        value: m.lostUsd,
      },
    ],
    createdAt: now.toISOString(),
  };
}

function toMove(p: SlimProtocol, marketChange1d: number | null): ProtocolMove {
  const c1d = p.change_1d ?? 0;
  const prev = prevFrom(p.tvl, c1d);
  const prevTvl = Number.isFinite(prev) ? prev : p.tvl;
  return {
    name: p.name,
    slug: p.slug,
    category: p.category,
    chains: p.chains,
    tvl: Math.round(p.tvl),
    prevTvl: Math.round(prevTvl),
    lostUsd: Math.round(prevTvl - p.tvl),
    change1h: round(p.change_1h),
    change1d: round(c1d)!,
    change7d: round(p.change_7d),
    vsMarketPct: marketChange1d != null ? round(c1d - marketChange1d) : null,
    flags: flagsOf(p),
    url: p.url,
  };
}

// ---------- defi(): the market-wide scan ----------

export async function defi(ctx: Ctx, opts: DefiOpts = {}): Promise<ModuleResult<DefiOverview>> {
  const now = ctx.now();
  const nowMs = now.getTime();
  const minTvl = opts.minTvl ?? 50e6;
  const dropPct = opts.dropPct ?? 20;
  const minPegCap = opts.minPegCap ?? 50e6;
  const depegPct = opts.depegPct ?? 2;
  const chainMovePct = opts.chainMovePct ?? 15;
  const hackDays = opts.hackDays ?? 7;
  const provenance: Provenance[] = [];

  const [protocols, chains, hist, hacks, stables, dexs, fees, oi, fng, yields] = await Promise.all([
    protocolList(ctx),
    ctx.http.get<{ name: string; tvl: number }[]>(`${LLAMA}/v2/chains`, {
      source: 'defillama',
      ttlSec: 900,
      keep: (d) => (Array.isArray(d) ? d.filter((c: any) => (num(c.tvl) ?? 0) > 0).map((c: any) => ({ name: String(c.name), tvl: c.tvl })) : []),
    }),
    ctx.http.get<{ date: number; tvl: number }[]>(`${LLAMA}/v2/historicalChainTvl`, { source: 'defillama', ttlSec: 3600, keep: (d) => (Array.isArray(d) ? d.slice(-10) : []) }),
    ctx.http.get<SlimHack[]>(`${LLAMA}/hacks`, { source: 'defillama', ttlSec: 3600, timeoutMs: 45_000, keep: slimHacks }),
    ctx.http.get<{ name: string; symbol: string; pegType: string; mech: string; price: number | null; circ: number; prevDay: number | null; prevWeek: number | null }[]>(
      'https://stablecoins.llama.fi/stablecoins?includePrices=true',
      {
        source: 'defillama-stablecoins',
        ttlSec: 900,
        timeoutMs: 45_000,
        keep: (d: any) =>
          (Array.isArray(d?.peggedAssets) ? d.peggedAssets : []).map((a: any) => {
            const key = String(a.pegType ?? 'peggedUSD');
            return { name: String(a.name), symbol: String(a.symbol), pegType: key, mech: String(a.pegMechanism ?? ''), price: num(a.price), circ: num(a.circulating?.[key]) ?? 0, prevDay: num(a.circulatingPrevDay?.[key]), prevWeek: num(a.circulatingPrevWeek?.[key]) };
          }),
      },
    ),
    ctx.http.get<ReturnType<typeof slimOverview>>(`${LLAMA}/overview/dexs?${OVERVIEW_QS}`, { source: 'defillama', ttlSec: 1800, timeoutMs: 45_000, keep: slimOverview }),
    ctx.http.get<ReturnType<typeof slimOverview>>(`${LLAMA}/overview/fees?${OVERVIEW_QS}`, { source: 'defillama', ttlSec: 1800, timeoutMs: 60_000, keep: slimOverview }),
    ctx.http.get<ReturnType<typeof slimOverview>>(`${LLAMA}/overview/open-interest?${OVERVIEW_QS}`, { source: 'defillama', ttlSec: 1800, timeoutMs: 45_000, keep: slimOverview }),
    ctx.http.get<{ data?: { value: string; value_classification: string; timestamp: string }[] }>('https://api.alternative.me/fng/?limit=30', { source: 'alternative-me', ttlSec: 3600 }),
    opts.yields === false ? Promise.resolve(null) : ctx.http.get<YieldAnomaly[]>('https://yields.llama.fi/pools', { source: 'defillama-yields', ttlSec: 3600, timeoutMs: 60_000, keep: slimYields }),
  ]);
  for (const r of [protocols, chains, hist, hacks, stables, dexs, fees, oi, fng, yields]) if (r) provenance.push(r.prov);

  // Market baseline: total DeFi TVL, last point versus one and seven days earlier.
  const h = hist.data ?? [];
  const last = h.at(-1);
  const at = (days: number) => (last ? [...h].reverse().find((p) => last.date - p.date >= days * 86_400 - 3600) : undefined);
  const defiTvlChange1d = last && at(1) ? round(pct(last.tvl, at(1)!.tvl)) : null;
  const defiTvlChange7d = last && at(7) ? round(pct(last.tvl, at(7)!.tvl)) : null;

  // Protocol TVL drops.
  const tvlDrops = (protocols.data ?? [])
    .filter((p) => p.change_1d != null && p.change_1d <= -dropPct)
    .map((p) => toMove(p, defiTvlChange1d))
    .filter((m) => m.prevTvl >= minTvl)
    .sort((a, b) => b.lostUsd - a.lostUsd);

  // Stablecoins: USD-pegged only (other pegs need an FX rate to judge).
  const usdStables = (stables.data ?? []).filter((s) => s.pegType === 'peggedUSD');
  const asDepeg = (s: (typeof usdStables)[number]): Depeg => ({
    name: s.name,
    symbol: s.symbol,
    mechanism: s.mech,
    price: s.price ?? NaN,
    offPct: s.price != null ? round(Math.abs(s.price - 1) * 100)! : NaN,
    circulating: Math.round(s.circ),
    supplyChange1dPct: s.prevDay ? round(pct(s.circ, s.prevDay)) : null,
    supplyChange7dPct: s.prevWeek ? round(pct(s.circ, s.prevWeek)) : null,
    url: 'https://defillama.com/stablecoins',
  });
  const depegs = usdStables
    .filter((s) => s.circ >= minPegCap && s.price != null && Math.abs(s.price - 1) * 100 > depegPct)
    .map(asDepeg)
    .sort((a, b) => b.offPct * Math.log10(b.circulating) - a.offPct * Math.log10(a.circulating));
  const supplyShocks = usdStables
    .filter((s) => (s.prevDay ?? 0) >= minPegCap && s.prevDay && pct(s.circ, s.prevDay)! <= -10)
    .map(asDepeg)
    .sort((a, b) => (a.supplyChange1dPct ?? 0) - (b.supplyChange1dPct ?? 0));
  const stablecoinSupply = usdStables.length ? usdStables.reduce((t, s) => t + s.circ, 0) : null;
  const stablePrev = usdStables.reduce((t, s) => t + (s.prevDay ?? s.circ), 0);

  // Chain TVL: compare with our own observation from 20-48 hours ago.
  const chainList = (chains.data ?? []).sort((a, b) => b.tvl - a.tvl);
  const moves: ChainMove[] = [];
  let observed = 0;
  for (const c of chainList.filter((c) => c.tvl >= 100e6)) {
    const entity = `chain:${c.name}`;
    const base = ctx.graph.history(entity, 'chain_tvl', 20).find((o) => o.value != null && nowMs - o.observedAt >= 20 * 3600_000 && nowMs - o.observedAt <= 48 * 3600_000);
    ctx.graph.observe(entity, 'defi', 'chain_tvl', c.tvl, 'defillama', {}, nowMs);
    observed++;
    if (!base?.value) continue;
    const ch = pct(c.tvl, base.value)!;
    moves.push({ name: c.name, tvl: Math.round(c.tvl), prevTvl: Math.round(base.value), changePct: round(ch)!, hoursBetween: Math.round((nowMs - base.observedAt) / 3600_000), vsMarketPct: defiTvlChange1d != null ? round(ch - defiTvlChange1d) : null });
  }
  moves.sort((a, b) => a.changePct - b.changePct);

  // Hacks reported recently.
  const recentHacks = (hacks.data ?? []).filter((x) => nowMs - x.date * 1000 <= hackDays * 86_400_000 + 86_400_000).map(toHack);

  // Fear & Greed (newest first).
  let fearGreed: FearGreed | null = null;
  const fs = (fng.data?.data ?? []).map((x) => ({ date: new Date(Number(x.timestamp) * 1000).toISOString().slice(0, 10), value: Number(x.value), label: x.value_classification })).filter((x) => Number.isFinite(x.value));
  if (fs.length) {
    const avg = (n: number) => (fs.length >= n ? round(fs.slice(0, n).reduce((t, x) => t + x.value, 0) / n, 1) : null);
    const change7d = fs[7] ? fs[0]!.value - fs[7].value : null;
    fearGreed = { value: fs[0]!.value, label: fs[0]!.label, date: fs[0]!.date, avg7d: avg(7), avg30d: avg(30), change7d, trend: change7d == null ? 'unknown' : change7d >= 5 ? 'rising' : change7d <= -5 ? 'falling' : 'flat', series: fs.map(({ date, value }) => ({ date, value })) };
  }

  // Unusual activity: DEX volume or fees more than tripling in a day on a protocol already doing $10M+.
  const activitySpikes: ActivitySpike[] = [];
  for (const [kind, r] of [['dex-volume', dexs], ['fees', fees]] as const) {
    for (const p of r.data?.protocols ?? []) if (p.total24h >= 10e6 && (p.change_1d ?? 0) >= 200) activitySpikes.push({ kind, name: p.name, category: p.category, total24h: Math.round(p.total24h), change1d: p.change_1d! });
  }
  activitySpikes.sort((a, b) => b.change1d - a.change1d);

  const totals: DefiTotals = {
    defiTvl: last ? Math.round(last.tvl) : null,
    defiTvlChange1d,
    defiTvlChange7d,
    stablecoinSupply: stablecoinSupply != null ? Math.round(stablecoinSupply) : null,
    stablecoinSupplyChange1d: stablecoinSupply != null && stablePrev ? round(pct(stablecoinSupply, stablePrev), 3) : null,
    dexVolume24h: dexs.data?.total24h ?? null,
    dexVolumeChange1d: dexs.data?.change_1d ?? null,
    dexVolumeChange7d: dexs.data?.change_7d ?? null,
    fees24h: fees.data?.total24h ?? null,
    feesChange1d: fees.data?.change_1d ?? null,
    openInterest: oi.data?.total24h ?? null,
    openInterestChange1d: oi.data?.change_1d ?? null,
  };

  // Signals.
  const day = now.toISOString().slice(0, 10);
  const signals: Signal[] = [];
  for (const m of tvlDrops.slice(0, 10)) signals.push(dropSignal(m, now));
  for (const d of depegs.slice(0, 8)) {
    signals.push({
      id: signalId('defi', 'depeg', d.symbol, d.name, day),
      module: 'defi',
      title: `${d.name} (${d.symbol}) off its USD peg: $${d.price.toFixed(4)} (${d.offPct.toFixed(1)}% away)`,
      score: depegScore(d.circulating, d.offPct),
      entity: d.name,
      evidence: [{ source: 'defillama-stablecoins', text: `${d.mechanism || 'unknown mechanism'} stablecoin, ${usd(d.circulating)} circulating; supply ${d.supplyChange1dPct ?? 'n/a'}% in 1d, ${d.supplyChange7dPct ?? 'n/a'}% in 7d`, url: d.url, value: d.price }],
      createdAt: now.toISOString(),
    });
  }
  for (const d of supplyShocks.slice(0, 5)) {
    signals.push({
      id: signalId('defi', 'supply', d.symbol, d.name, day),
      module: 'defi',
      title: `${d.name} (${d.symbol}) supply down ${Math.abs(d.supplyChange1dPct ?? 0).toFixed(1)}% in 24h`,
      score: clamp(50 + Math.abs(d.supplyChange1dPct ?? 0) / 2 + 5 * Math.log10(Math.max(d.circulating, 5e7) / 5e7), 50, 80),
      entity: d.name,
      evidence: [{ source: 'defillama-stablecoins', text: `Mass redemption or burn: ${usd(d.circulating)} circulating now, price $${Number.isFinite(d.price) ? d.price.toFixed(4) : 'n/a'}`, url: d.url, value: d.supplyChange1dPct ?? undefined }],
      createdAt: now.toISOString(),
    });
  }
  for (const c of moves.filter((m) => m.prevTvl >= 500e6 && m.changePct <= -chainMovePct && (m.vsMarketPct == null || m.vsMarketPct <= -10)).slice(0, 5)) {
    signals.push({
      id: signalId('defi', 'chain', c.name, day),
      module: 'defi',
      title: `${c.name} chain TVL down ${Math.abs(c.changePct).toFixed(1)}% in ${c.hoursBetween}h (${usd(c.prevTvl)} to ${usd(c.tvl)})`,
      score: dropScore(c.prevTvl - c.tvl, -c.changePct) - 5,
      entity: c.name,
      evidence: [{ source: 'defillama', text: `Compared with Oculon's own reading ${c.hoursBetween}h earlier${c.vsMarketPct != null ? `; ${c.vsMarketPct.toFixed(1)} points worse than total DeFi TVL` : ''}`, url: `https://defillama.com/chain/${encodeURIComponent(c.name)}`, value: c.changePct }],
      createdAt: now.toISOString(),
    });
  }
  for (const x of recentHacks.filter((x) => x.amount >= 1e6).slice(0, 8)) {
    signals.push({
      id: signalId('defi', 'hack', x.name, x.date),
      module: 'defi',
      title: `${x.name} hacked for ${usd(x.amount)} (${x.technique || x.classification || 'exploit'})`,
      score: hackScore(x.amount, x.bridgeHack),
      entity: x.name,
      evidence: [{ source: 'defillama', text: `${x.date}, ${x.chains.join(', ') || 'unknown chain'}, ${x.targetType}${x.returnedFunds ? `, ${usd(x.returnedFunds)} returned` : ''}: ${x.description.slice(0, 220)}`, url: x.url, value: x.amount }],
      createdAt: now.toISOString(),
    });
  }
  for (const s of signals) ctx.graph.saveSignal(s);

  return {
    module: 'defi',
    input: 'defillama + fear & greed',
    generatedAt: now.toISOString(),
    result: {
      totals,
      tvlDrops,
      depegs,
      supplyShocks,
      chains: { top: chainList.slice(0, 15).map((c) => ({ name: c.name, tvl: Math.round(c.tvl) })), moves, observed },
      hacks: recentHacks,
      fearGreed,
      activitySpikes: activitySpikes.slice(0, 15),
      yieldAnomalies: yields?.data ?? [],
    },
    signals,
    provenance,
  };
}

// ---------- protocol(): one protocol in depth ----------

export interface ProtocolDetail {
  name: string;
  slug: string;
  category: string;
  description: string;
  url: string;
  twitter: string | null;
  github: string[];
  isParent: boolean;
  parent: string | null;
  otherProtocols: string[];
  chains: { chain: string; tvl: number }[];
  tvl: number | null;
  mcap: number | null;
  mcapToTvl: number | null;
  change: { d1: number | null; d7: number | null; d30: number | null; d90: number | null; d365: number | null };
  ath: { tvl: number; date: string } | null;
  drawdownFromAthPct: number | null;
  /** Daily TVL for the last 90 days, oldest first. */
  series: { date: string; tvl: number }[];
  audits: string | null;
  auditLinks: string[];
  oracles: string[];
  forkedFrom: string[];
  listedAt: string | null;
  hacks: Hack[];
  raises: { count: number; totalUsd: number; last: { date: string; round: string; amountUsd: number | null; leads: string[] } | null };
  hallmarks: { date: string; event: string }[];
  flags: string[];
}

function slimProtocolDetail(d: any) {
  if (!d || typeof d !== 'object') return null;
  const raw: any[] = Array.isArray(d.tvl) ? d.tvl : [];
  // One point per UTC day (the last one), which keeps a multi-year history to a few KB.
  const byDay = new Map<string, number>();
  for (const p of raw) if (num(p?.totalLiquidityUSD) != null) byDay.set(new Date(p.date * 1000).toISOString().slice(0, 10), p.totalLiquidityUSD);
  const chains = Object.entries((d.currentChainTvls ?? {}) as Record<string, number>)
    .filter(([k, v]) => !k.includes('-') && /^[A-Z0-9]/.test(k) && num(v) != null)
    .map(([chain, tvl]) => ({ chain, tvl: Math.round(tvl) }))
    .sort((a, b) => b.tvl - a.tvl);
  return {
    name: String(d.name ?? ''),
    category: d.category ?? null,
    description: String(d.description ?? '').slice(0, 500),
    url: String(d.url ?? ''),
    twitter: d.twitter ?? null,
    github: Array.isArray(d.github) ? d.github : [],
    isParent: d.isParentProtocol === true,
    parent: d.parentProtocolSlug ?? null,
    otherProtocols: Array.isArray(d.otherProtocols) ? d.otherProtocols.slice(0, 20) : [],
    chainList: Array.isArray(d.chains) ? d.chains : [],
    chains,
    mcap: num(d.mcap),
    series: [...byDay.entries()].map(([date, tvl]) => ({ date, tvl: Math.round(tvl) })),
    audits: d.audits != null ? String(d.audits) : null,
    auditLinks: Array.isArray(d.audit_links) ? d.audit_links : [],
    oracles: Array.isArray(d.oraclesBreakdown) ? d.oraclesBreakdown.map((o: { name: string }) => o.name) : Array.isArray(d.oracles) ? d.oracles : [],
    forkedFrom: Array.isArray(d.forkedFrom) ? d.forkedFrom : [],
    listedAt: num(d.listedAt),
    hacks: slimHacks(d.hacks),
    raises: (Array.isArray(d.raises) ? d.raises : []).map((r: any) => ({ date: Number(r.date) || 0, round: String(r.round ?? ''), amount: num(r.amount), leads: Array.isArray(r.leadInvestors) ? r.leadInvestors.slice(0, 5) : [] })),
    hallmarks: (Array.isArray(d.hallmarks) ? d.hallmarks : []).filter((x: unknown) => Array.isArray(x)).map((x: [number | number[], string]) => ({ date: Number(Array.isArray(x[0]) ? x[0][0] : x[0]) || 0, event: String(x[1]) })),
    rugged: d.rugged === true,
    deadFrom: d.deadFrom ?? null,
    misrepresentedTokens: d.misrepresentedTokens === true,
    wrongLiquidity: d.wrongLiquidity === true,
  };
}

export const slugify = (s: string) => s.trim().toLowerCase().replace(/[^a-z0-9.]+/g, '-').replace(/^-+|-+$/g, '');

/** Resolve a name or slug against the protocol list: exact slug, exact name, then parent slug, then a slugified guess. */
export function resolveSlug(list: SlimProtocol[], name: string): { slug: string; entry: SlimProtocol | null } {
  const q = name.trim().toLowerCase();
  const s = slugify(name);
  const bySlug = list.find((p) => p.slug === q || p.slug === s);
  if (bySlug) return { slug: bySlug.slug, entry: bySlug };
  const byName = list.find((p) => p.name.toLowerCase() === q);
  if (byName) return { slug: byName.slug, entry: byName };
  if (list.some((p) => p.parent === s)) return { slug: s, entry: null };
  return { slug: s, entry: null };
}

export async function protocol(ctx: Ctx, name: string): Promise<ModuleResult<ProtocolDetail | null>> {
  const now = ctx.now();
  const nowMs = now.getTime();
  const provenance: Provenance[] = [];
  const list = await protocolList(ctx);
  provenance.push(list.prov);
  const { slug, entry } = resolveSlug(list.data ?? [], name);
  const r = await ctx.http.get<ReturnType<typeof slimProtocolDetail>>(`${LLAMA}/protocol/${encodeURIComponent(slug)}`, { source: 'defillama', ttlSec: 1800, timeoutMs: 90_000, keep: slimProtocolDetail });
  provenance.push(r.prov);
  const d = r.data;
  if (!d) return { module: 'defi', input: name, generatedAt: now.toISOString(), result: null, signals: [], provenance };

  const series = d.series;
  const lastPt = series.at(-1);
  const back = (days: number) => {
    if (!lastPt) return null;
    const target = Date.parse(lastPt.date) - days * 86_400_000;
    const p = [...series].reverse().find((x) => Date.parse(x.date) <= target);
    return p ? round(pct(lastPt.tvl, p.tvl)) : null;
  };
  const athPt = series.reduce<{ date: string; tvl: number } | null>((m, x) => (!m || x.tvl > m.tvl ? x : m), null);
  const tvl = entry?.tvl != null ? Math.round(entry.tvl) : lastPt?.tvl ?? null;
  const children = (list.data ?? []).filter((p) => p.parent === slug);
  const audits = entry?.audits ?? d.audits ?? (children.find((c) => c.audits)?.audits ?? null);
  const auditLinks = [...new Set([...(entry?.audit_links ?? []), ...d.auditLinks, ...children.flatMap((c) => c.audit_links)])].slice(0, 15);
  const oracles = [...new Set([...d.oracles, ...(entry?.oracles ?? []), ...children.flatMap((c) => c.oracles)])];

  const flags = entry ? flagsOf(entry) : [];
  if (!entry) {
    if (d.rugged) flags.push('marked rugged by DefiLlama');
    if (d.deadFrom) flags.push(`dead since ${d.deadFrom}`);
    if (d.misrepresentedTokens) flags.push('misrepresented tokens');
    if (d.wrongLiquidity) flags.push('liquidity figures flagged as unreliable');
  }
  if (!audits || audits === '0') flags.push('no audit listed on DefiLlama');
  const hacks = d.hacks.map(toHack);
  if (hacks.length) flags.push(`${hacks.length} hack${hacks.length > 1 ? 's' : ''} on record (${usd(hacks.reduce((t, x) => t + x.amount, 0))})`);

  const lastRaise = [...d.raises].sort((a, b) => b.date - a.date)[0];
  const detail: ProtocolDetail = {
    name: d.name,
    slug,
    category: entry?.category ?? d.category ?? children[0]?.category ?? '',
    description: d.description,
    url: d.url,
    twitter: d.twitter,
    github: d.github,
    isParent: d.isParent,
    parent: entry?.parent ?? d.parent,
    otherProtocols: d.otherProtocols,
    chains: d.chains.length ? d.chains : d.chainList.map((c: string) => ({ chain: c, tvl: 0 })),
    tvl,
    mcap: d.mcap,
    mcapToTvl: d.mcap && tvl ? round(d.mcap / tvl) : null,
    change: { d1: entry?.change_1d != null ? round(entry.change_1d) : back(1), d7: entry?.change_7d != null ? round(entry.change_7d) : back(7), d30: back(30), d90: back(90), d365: back(365) },
    ath: athPt ? { tvl: athPt.tvl, date: athPt.date } : null,
    drawdownFromAthPct: athPt && tvl != null ? round(pct(tvl, athPt.tvl)) : null,
    series: series.slice(-90),
    audits,
    auditLinks,
    oracles,
    forkedFrom: [...new Set([...(entry?.forkedFrom ?? []), ...d.forkedFrom])],
    listedAt: d.listedAt ? new Date(d.listedAt * 1000).toISOString().slice(0, 10) : entry?.listedAt ? new Date(entry.listedAt * 1000).toISOString().slice(0, 10) : null,
    hacks,
    raises: { count: d.raises.length, totalUsd: Math.round(d.raises.reduce((t: number, x: { amount: number | null }) => t + (x.amount ?? 0), 0) * 1e6), last: lastRaise ? { date: new Date(lastRaise.date * 1000).toISOString().slice(0, 10), round: lastRaise.round, amountUsd: lastRaise.amount != null ? Math.round(lastRaise.amount * 1e6) : null, leads: lastRaise.leads } : null },
    hallmarks: d.hallmarks.map((x: { date: number; event: string }) => ({ date: new Date(x.date * 1000).toISOString().slice(0, 10), event: x.event })),
    flags,
  };

  const signals: Signal[] = [];
  const d1 = detail.change.d1;
  if (d1 != null && d1 <= -20 && tvl != null) {
    const prev = prevFrom(tvl, d1);
    if (Number.isFinite(prev) && prev >= 50e6) {
      const m: ProtocolMove = { name: detail.name, slug, category: detail.category, chains: detail.chains.map((c) => c.chain), tvl, prevTvl: Math.round(prev), lostUsd: Math.round(prev - tvl), change1h: entry?.change_1h ?? null, change1d: d1, change7d: detail.change.d7, vsMarketPct: null, flags, url: detail.url };
      signals.push(dropSignal(m, now));
    }
  }
  for (const x of hacks.filter((x) => nowMs - Date.parse(x.date) <= 31 * 86_400_000 && x.amount >= 1e5).slice(0, 3)) {
    signals.push({
      id: signalId('defi', 'hack', x.name, x.date),
      module: 'defi',
      title: `${x.name} hacked for ${usd(x.amount)} (${x.technique || x.classification || 'exploit'})`,
      score: hackScore(x.amount, x.bridgeHack),
      entity: detail.name,
      evidence: [{ source: 'defillama', text: `${x.date}, ${x.chains.join(', ')}: ${x.description.slice(0, 220)}`, url: x.url, value: x.amount }],
      createdAt: now.toISOString(),
    });
  }
  for (const s of signals) ctx.graph.saveSignal(s);
  return { module: 'defi', input: name, generatedAt: now.toISOString(), result: detail, signals, provenance };
}
