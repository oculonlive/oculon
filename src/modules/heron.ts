/**
 * Heron: Robinhood Chain watcher.
 *   overview(): chain activity, trending pools, and pools born in the last hours with quick risk flags.
 *   rhTokenCheck(): risk read on one token. GoPlus does not cover chain 4663, so the rules are Oculon's own:
 *     unverified contract, top-10 holder concentration, pool age, liquidity, and buys-without-sells (honeypot shape).
 */
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { addressInfo, chainStats, contractCreator, createdContracts, isVerified, launchesVia, txParties, newPools, rhToken, tokenPools, tokensMarket, topHolderShare, trendingPools, type ChainStats, type Pool } from '../sources/robinhood.js';

export interface PoolFlags {
  pool: Pool;
  ageHours: number;
  flags: string[];
}

/** Flags that need no extra calls: from pool data alone. */
export function poolFlags(p: Pool, nowMs: number): PoolFlags {
  const ageHours = Math.max(0, (nowMs - Date.parse(p.createdAt)) / 3_600_000);
  const flags: string[] = [];
  if (p.liquidityUsd < 5_000) flags.push(`thin liquidity $${Math.round(p.liquidityUsd).toLocaleString('en-US')}`);
  if (p.buys24h >= 20 && p.sells24h === 0) flags.push(`${p.buys24h} buys and no sells (honeypot shape)`);
  else if (p.buys24h >= 30 && p.sells24h / p.buys24h < 0.05) flags.push(`sells only ${p.sells24h} vs ${p.buys24h} buys`);
  if (p.change1h !== null && p.change1h <= -60) flags.push(`price ${p.change1h.toFixed(0)}% in 1h (possible rug)`);
  if (p.fdvUsd && p.liquidityUsd && p.liquidityUsd < 100_000 && p.fdvUsd / p.liquidityUsd > 200) flags.push('valuation far above liquidity');
  return { pool: p, ageHours, flags };
}

export interface OverviewResult {
  stats: ChainStats | null;
  trending: PoolFlags[];
  fresh: PoolFlags[];
}

export async function overview(ctx: Ctx): Promise<ModuleResult<OverviewResult>> {
  const nowMs = ctx.now().getTime();
  const nowIso = new Date(nowMs).toISOString();
  const [st, tr, nw] = await Promise.all([chainStats(ctx), trendingPools(ctx), newPools(ctx)]);
  const trending = (tr.data ?? []).slice(0, 15).map((p) => poolFlags(p, nowMs));
  const fresh = (nw.data ?? []).slice(0, 20).map((p) => poolFlags(p, nowMs));

  const signals: Signal[] = [];
  // A trending pool that moves hard with real liquidity is worth a signal; so is a fresh pool with real traction.
  for (const t of trending) {
    const ch = t.pool.change24h ?? 0;
    if (Math.abs(ch) >= 40 && t.pool.liquidityUsd >= 50_000) {
      signals.push({
        id: signalId('heron', t.pool.address, nowIso.slice(0, 10)),
        module: 'heron',
        title: `${t.pool.name} ${ch > 0 ? '+' : ''}${ch.toFixed(0)}% in 24h on Robinhood Chain`,
        score: clamp(Math.round(45 + Math.abs(ch) / 4), 0, 85),
        evidence: [{ source: 'geckoterminal', text: `liquidity $${Math.round(t.pool.liquidityUsd).toLocaleString('en-US')}, volume $${Math.round(t.pool.volume24h).toLocaleString('en-US')}${t.flags.length ? `; ${t.flags.join(', ')}` : ''}`, url: t.pool.url }],
        createdAt: nowIso,
      });
    }
  }
  for (const f of fresh) {
    if (f.ageHours <= 6 && f.pool.volume24h >= 50_000 && f.pool.buyers24h >= 50) {
      signals.push({
        id: signalId('heron', 'fresh', f.pool.address),
        module: 'heron',
        title: `New Robinhood Chain pool ${f.pool.name} drew $${Math.round(f.pool.volume24h).toLocaleString('en-US')} volume in ${f.ageHours.toFixed(1)}h`,
        score: f.flags.length ? 50 : 62,
        evidence: [{ source: 'geckoterminal', text: `${f.pool.buyers24h} buyers, ${f.pool.sellers24h} sellers, liquidity $${Math.round(f.pool.liquidityUsd).toLocaleString('en-US')}${f.flags.length ? `; flags: ${f.flags.join(', ')}` : ''}`, url: f.pool.url }],
        createdAt: nowIso,
      });
    }
  }
  signals.forEach((s) => ctx.graph.saveSignal(s));
  if (st.data) ctx.graph.observe(ctx.graph.upsert('event', 'chain:robinhood'), 'heron', 'tx_today', st.data.transactionsToday, 'blockscout');

  return { module: 'heron', input: 'robinhood', generatedAt: nowIso, result: { stats: st.data, trending, fresh }, signals, provenance: [st.prov, tr.prov, nw.prov] };
}

export interface DeployerProfile {
  deployer: string;
  contracts: number;
  tokens: { address: string; symbol: string | null; createdAt: string; reserveUsd: number; dead: boolean }[];
  dead: number;
  verdict: 'DANGER' | 'CAUTION' | 'OK' | 'UNKNOWN';
  reasons: string[];
}

/** Pools under $100 of liquidity after a day are treated as dead (abandoned or drained). */
const DEAD_RESERVE = 100;

export function deployerVerdict(tokens: DeployerProfile['tokens']): { verdict: DeployerProfile['verdict']; reasons: string[] } {
  const dead = tokens.filter((t) => t.dead).length;
  if (!tokens.length) return { verdict: 'UNKNOWN', reasons: ['no traded tokens from this deployer'] };
  if (tokens.length >= 3 && dead / tokens.length >= 0.7) return { verdict: 'DANGER', reasons: [`serial launcher: ${dead} of ${tokens.length} tokens from this deployer are dead`] };
  if (dead >= 2) return { verdict: 'CAUTION', reasons: [`${dead} of ${tokens.length} earlier tokens from this deployer are dead`] };
  return { verdict: 'OK', reasons: [`${tokens.length} traded token(s), ${dead} dead`] };
}

/** Everything one address deployed on Robinhood Chain, and how those tokens are doing now. Accepts a token or a deployer. */
export async function deployerProfile(ctx: Ctx, address: string): Promise<ModuleResult<DeployerProfile>> {
  const nowMs = ctx.now().getTime();
  const provenance: Provenance[] = [];
  const cr = await contractCreator(ctx, address);
  provenance.push(cr.prov);
  let deployer = cr.data?.creator ?? address;
  let via: string | null = null;
  // Launchpad tokens are created by a factory contract; the real deployer is the wallet that called it.
  if (cr.data) {
    const info = await addressInfo(ctx, cr.data.creator);
    provenance.push(info.prov);
    if (info.data?.isContract && cr.data.creationTx) {
      const tx = await txParties(ctx, cr.data.creationTx);
      provenance.push(tx.prov);
      if (tx.data?.from && tx.data.to) {
        deployer = tx.data.from;
        via = tx.data.to;
      }
    }
  }
  const created = via ? await launchesVia(ctx, deployer, via) : await createdContracts(ctx, deployer);
  provenance.push(created.prov);
  const contracts = created.data ?? [];
  const market = await tokensMarket(
    ctx,
    contracts.map((c) => c.address),
  );
  provenance.push(market.prov);
  const tokens = contracts
    .filter((c) => market.data?.has(c.address.toLowerCase()))
    .map((c) => {
      const m = market.data!.get(c.address.toLowerCase())!;
      const ageH = (nowMs - Date.parse(c.createdAt)) / 3_600_000;
      return { address: c.address, symbol: m.symbol, createdAt: c.createdAt, reserveUsd: Math.round(m.reserveUsd), dead: ageH > 24 && m.reserveUsd < DEAD_RESERVE };
    });
  const { verdict, reasons } = deployerVerdict(tokens);
  const id = ctx.graph.upsert('event', `deployer:${deployer.toLowerCase()}`, { verdict, tokens: tokens.length, dead: tokens.filter((t) => t.dead).length, contracts: contracts.length });
  for (const t of tokens) ctx.graph.link(id, ctx.graph.upsert('event', `token:robinhood:${t.address.toLowerCase()}`, { symbol: t.symbol }), 'deployed', 'blockscout');
  const nowIso = new Date(nowMs).toISOString();
  const signals: Signal[] = [];
  if (verdict === 'DANGER') {
    signals.push({ id: signalId('heron', 'deployer', deployer), module: 'heron', title: `Robinhood Chain deployer ${deployer.slice(0, 10)}…: ${reasons[0]}`, score: 80, entity: id, evidence: tokens.slice(0, 6).map((t) => ({ source: 'heron', text: `${t.symbol ?? t.address.slice(0, 10)}: liquidity $${t.reserveUsd}${t.dead ? ' (dead)' : ''}` })), createdAt: nowIso });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }
  return { module: 'heron', input: address, generatedAt: nowIso, result: { deployer, contracts: contracts.length, tokens, dead: tokens.filter((t) => t.dead).length, verdict, reasons }, signals, provenance };
}

export interface RhTokenResult {
  address: string;
  deployer: { address: string; otherTokens: number; dead: number };
  name: string | null;
  symbol: string | null;
  holders: number | null;
  verified: boolean | null;
  top10Share: number | null;
  pools: PoolFlags[];
  verdict: 'DANGER' | 'CAUTION' | 'OK' | 'UNKNOWN';
  reasons: string[];
}

export function rhVerdict(input: { verified: boolean | null; top10Share: number | null; holders: number | null; pools: PoolFlags[] }): { verdict: RhTokenResult['verdict']; reasons: string[] } {
  const reasons: string[] = [];
  let level = 0;
  if (input.verified === false) {
    reasons.push('contract source not verified on Blockscout');
    level = Math.max(level, 1);
  }
  if (input.top10Share !== null && input.top10Share >= 0.9) {
    reasons.push(`top 10 holders own ${Math.round(input.top10Share * 100)}% of supply`);
    level = Math.max(level, input.top10Share >= 0.97 && (input.holders ?? 0) < 200 ? 2 : 1);
  }
  for (const p of input.pools.slice(0, 3)) {
    for (const f of p.flags) {
      reasons.push(`${p.pool.name}: ${f}`);
      level = Math.max(level, /honeypot|rug/.test(f) ? 2 : 1);
    }
    if (p.ageHours < 24) {
      reasons.push(`${p.pool.name}: pool is ${p.ageHours.toFixed(1)}h old`);
      level = Math.max(level, 1);
    }
  }
  if (input.verified === null && input.top10Share === null && !input.pools.length) return { verdict: 'UNKNOWN', reasons: ['no explorer or pool data'] };
  return { verdict: level === 2 ? 'DANGER' : level === 1 ? 'CAUTION' : 'OK', reasons };
}

export async function rhTokenCheck(ctx: Ctx, address: string): Promise<ModuleResult<RhTokenResult>> {
  const nowMs = ctx.now().getTime();
  const nowIso = new Date(nowMs).toISOString();
  const provenance: Provenance[] = [];
  const [tok, ver, pl] = await Promise.all([rhToken(ctx, address), isVerified(ctx, address), tokenPools(ctx, address)]);
  provenance.push(tok.prov, ver.prov, pl.prov);
  const share = tok.data ? await topHolderShare(ctx, address, tok.data.totalSupply) : null;
  if (share) provenance.push(share.prov);
  const pools = (pl.data ?? []).map((p) => poolFlags(p, nowMs)).sort((a, b) => b.pool.liquidityUsd - a.pool.liquidityUsd);
  const base = rhVerdict({ verified: ver.data, top10Share: share?.data ?? null, holders: tok.data?.holders ?? null, pools });
  // The deployer's track record: other tokens it launched, and how many are dead now.
  const dep = await deployerProfile(ctx, address);
  provenance.push(...dep.provenance);
  const others = dep.result.tokens.filter((t) => t.address.toLowerCase() !== address.toLowerCase());
  const depVerdict = deployerVerdict(others);
  const rank = { UNKNOWN: -1, OK: 0, CAUTION: 1, DANGER: 2 } as const;
  const verdict = others.length && rank[depVerdict.verdict] > rank[base.verdict] ? depVerdict.verdict : base.verdict;
  const reasons = [...base.reasons, ...(others.length && depVerdict.verdict !== 'OK' ? depVerdict.reasons.map((r) => `deployer: ${r}`) : [])];
  const name = tok.data?.symbol || address.slice(0, 10);
  const signals: Signal[] = [];
  if (verdict === 'DANGER') {
    signals.push({ id: signalId('heron', 'token', address, nowIso.slice(0, 10)), module: 'heron', title: `${name} on Robinhood Chain: DANGER (${reasons.slice(0, 2).join(', ')})`, score: 80, evidence: reasons.map((r) => ({ source: 'heron', text: r })), createdAt: nowIso });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }
  return {
    module: 'heron',
    input: address,
    generatedAt: nowIso,
    result: {
      address,
      name: tok.data?.name ?? null,
      symbol: tok.data?.symbol ?? null,
      holders: tok.data?.holders ?? null,
      verified: ver.data,
      top10Share: share?.data ?? null,
      pools: pools.slice(0, 6),
      deployer: { address: dep.result.deployer, otherTokens: others.length, dead: others.filter((t) => t.dead).length },
      verdict,
      reasons,
    },
    signals,
    provenance,
  };
}
