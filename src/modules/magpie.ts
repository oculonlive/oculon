/**
 * Magpie: on-chain intelligence.
 *   wallet(): portfolio (Zerion), recent and first transactions (Etherscan), risk labels (GoPlus, Webacy),
 *             native balance on Robinhood Chain, or SOL balance for Solana addresses (Helius).
 *   token():  contract risk (GoPlus: honeypot, taxes, owner powers), DEX pairs and liquidity (DexScreener),
 *             price and market cap (CoinGecko).
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { Evidence, ModuleResult, Provenance, Signal } from '../core/types.js';
import { coinByContract } from '../sources/finance.js';
import { describeLabels, ensureLabels, labelsFor } from '../sources/labels.js';
import { screen } from './sanctions.js';
import {
  addressSecurity,
  CHAINS,
  dexPairs,
  etherscanTxs,
  isEvmAddress,
  isSolanaAddress,
  robinhoodAccount,
  solanaAccount,
  tokenSecurity,
  webacyRisk,
  zerionPortfolio,
  type Pair,
  type Portfolio,
  type TokenRisk,
  type Tx,
} from '../sources/onchain.js';

export interface WalletResult {
  address: string;
  kind: 'evm' | 'solana';
  portfolio: Portfolio | null;
  recentTxs: Tx[];
  firstSeen: string | null;
  ageDays: number | null;
  labels: string[];
  /** Who this address is, from the open eth-labels dataset (exchange, protocol, bridge...). */
  knownAs: string | null;
  /** Labeled counterparties among the recent transactions. */
  counterparties: { address: string; knownAs: string; txs: number }[];
  riskScore: number | null;
  riskIssues: string[];
  /** OFAC screening: listed itself, or transacted directly with a listed address. */
  sanctions: { verdict: string; hits: { kind: string; entry: { name: string; program: string } }[] } | null;
  robinhood: { balanceEth: number; txCount: number; isContract: boolean } | null;
  solana: { sol: number; tokens: number } | null;
}

export async function wallet(ctx: Ctx, addressInput: string): Promise<ModuleResult<WalletResult>> {
  const address = addressInput.trim();
  const nowMs = ctx.now().getTime();
  const nowIso = new Date(nowMs).toISOString();
  const provenance: Provenance[] = [];
  const signals: Signal[] = [];

  if (isSolanaAddress(address)) {
    const sol = await solanaAccount(ctx, address);
    provenance.push(sol.prov);
    return {
      module: 'magpie',
      input: address,
      generatedAt: nowIso,
      result: { address, kind: 'solana', portfolio: null, recentTxs: [], firstSeen: null, ageDays: null, labels: [], knownAs: null, counterparties: [], riskScore: null, riskIssues: [], robinhood: null, solana: sol.data, sanctions: null },
      signals,
      provenance,
    };
  }
  if (!isEvmAddress(address)) throw new Error('not an EVM (0x...) or Solana address');

  const sanc = await screen(ctx, address);
  const [pf, recent, first, labels, risk, rh] = await Promise.all([
    zerionPortfolio(ctx, address),
    etherscanTxs(ctx, address, 1, 'desc', 15),
    etherscanTxs(ctx, address, 1, 'asc', 1),
    addressSecurity(ctx, address),
    webacyRisk(ctx, address),
    robinhoodAccount(ctx, address),
  ]);
  provenance.push(pf.prov, recent.prov, first.prov, labels.prov, risk.prov, rh.prov);
  provenance.push(await ensureLabels(ctx));
  const knownAs = describeLabels(labelsFor(ctx, address));
  const cp = new Map<string, number>();
  for (const t of recent.data ?? []) for (const a of [t.from, t.to]) if (a && a.toLowerCase() !== address.toLowerCase()) cp.set(a.toLowerCase(), (cp.get(a.toLowerCase()) ?? 0) + 1);
  const counterparties = [...cp].flatMap(([a, txs]) => {
    const k = describeLabels(labelsFor(ctx, a));
    return k ? [{ address: a, knownAs: k, txs }] : [];
  }).sort((x, y) => y.txs - x.txs).slice(0, 10);

  const firstSeen = first.data?.[0]?.time ?? null;
  const ageDays = firstSeen ? Math.floor((nowMs - Date.parse(firstSeen)) / DAY_MS) : null;
  const id = ctx.graph.upsert('event', `wallet:${address.toLowerCase()}`, { totalUsd: pf.data?.totalUsd ?? null });
  if (pf.data) ctx.graph.observe(id, 'magpie', 'wallet_usd', pf.data.totalUsd, 'zerion');

  const ev: Evidence[] = [];
  if (labels.data?.length) ev.push({ source: 'goplus', text: `flagged: ${labels.data.join(', ')}` });
  if (risk.data?.score != null && risk.data.score >= 50) ev.push({ source: 'webacy', text: `risk score ${risk.data.score}${risk.data.issues.length ? ` (${risk.data.issues.slice(0, 4).join(', ')})` : ''}` });
  if (pf.data && pf.data.totalUsd >= 10_000_000) ev.push({ source: 'zerion', text: `whale wallet: $${Math.round(pf.data.totalUsd).toLocaleString('en-US')}` });
  if (ev.length) {
    signals.push({
      id: signalId('magpie', address, nowIso.slice(0, 10)),
      module: 'magpie',
      title: `Wallet ${address.slice(0, 8)}…: ${ev.map((e) => e.text.split(':')[0]).join(', ')}`,
      score: clamp(40 + (labels.data?.length ? 30 : 0) + ((risk.data?.score ?? 0) >= 75 ? 15 : 0), 0, 95),
      entity: id,
      evidence: ev,
      createdAt: nowIso,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }

  return {
    module: 'magpie',
    input: address,
    generatedAt: nowIso,
    result: {
      address,
      kind: 'evm',
      portfolio: pf.data,
      recentTxs: recent.data ?? [],
      firstSeen,
      ageDays,
      labels: labels.data ?? [],
      knownAs,
      counterparties,
      riskScore: risk.data?.score ?? null,
      riskIssues: risk.data?.issues ?? [],
      sanctions: sanc ? { verdict: sanc.result.verdict, hits: sanc.result.hits } : null,
      robinhood: rh.data,
      solana: null,
    },
    signals,
    provenance,
  };
}

export interface TokenResult {
  address: string;
  chain: string;
  security: TokenRisk | null;
  pairs: Pair[];
  market: { name: string; symbol: string; priceUsd: number | null; marketCapUsd: number | null; change24h: number | null } | null;
  verdict: 'DANGER' | 'CAUTION' | 'OK' | 'UNKNOWN';
  reasons: string[];
}

const DANGER = new Set(['honeypot', 'cannot sell all', 'hidden owner', 'owner can change balances', 'can take back ownership', 'self-destruct']);

export function tokenVerdict(sec: TokenRisk | null, pairs: Pair[], marketCapUsd: number | null = null): { verdict: TokenResult['verdict']; reasons: string[] } {
  const reasons: string[] = [];
  if (!sec && !pairs.length) return { verdict: 'UNKNOWN', reasons: ['no security data and no DEX pairs'] };
  let level = 0;
  for (const f of sec?.flags ?? []) {
    reasons.push(f);
    level = Math.max(level, DANGER.has(f) ? 2 : 1);
  }
  if ((sec?.sellTax ?? 0) >= 0.1) {
    reasons.push(`sell tax ${Math.round((sec!.sellTax ?? 0) * 100)}%`);
    level = Math.max(level, (sec!.sellTax ?? 0) >= 0.3 ? 2 : 1);
  }
  const liq = pairs.reduce((a, p) => a + (p.liquidityUsd ?? 0), 0);
  // DEX liquidity only tells the story for small tokens; large caps trade mostly elsewhere.
  if (pairs.length && liq < 10_000 && (marketCapUsd ?? 0) < 100_000_000) {
    reasons.push(`thin liquidity ($${Math.round(liq).toLocaleString('en-US')})`);
    level = Math.max(level, 1);
  }
  const youngest = pairs.map((p) => p.createdAt).filter(Boolean).sort().pop();
  if (youngest && Date.now() - Date.parse(youngest) < 2 * DAY_MS) {
    reasons.push('pair created in the last 48h');
    level = Math.max(level, 1);
  }
  // Widely held tokens (USDT, USDC, ...) carry issuer controls by design; flag them, but do not call them scams.
  if (level === 2 && (sec?.holders ?? 0) >= 100_000) {
    level = 1;
    reasons.push(`widely held (${sec!.holders!.toLocaleString('en-US')} holders): flags describe issuer controls, not a rug`);
  }
  return { verdict: level === 2 ? 'DANGER' : level === 1 ? 'CAUTION' : 'OK', reasons };
}

export async function token(ctx: Ctx, addressInput: string, chainName = 'eth'): Promise<ModuleResult<TokenResult>> {
  const address = addressInput.trim();
  const chain = CHAINS[chainName] ? chainName : 'eth';
  const meta = CHAINS[chain]!;
  if (!isEvmAddress(address)) throw new Error('token address must be an EVM contract address (0x...)');
  const nowIso = ctx.now().toISOString();
  const [sec, pairs, cg] = await Promise.all([
    meta.goplus ? tokenSecurity(ctx, meta.goplus, address) : Promise.resolve(null),
    dexPairs(ctx, address, chain),
    meta.coingecko ? coinByContract(ctx, meta.coingecko, address) : Promise.resolve(null),
  ]);
  const provenance: Provenance[] = [pairs.prov, ...(sec ? [sec.prov] : []), ...(cg ? [cg.prov] : [])];
  const usePairs = pairs.data ?? [];
  const { verdict, reasons } = tokenVerdict(sec?.data ?? null, usePairs, cg?.data?.marketCapUsd ?? null);
  const name = sec?.data?.symbol || cg?.data?.symbol || usePairs[0]?.pair.split('/')[0] || address.slice(0, 10);
  const id = ctx.graph.upsert('event', `token:${chain}:${address.toLowerCase()}`, { symbol: name, verdict });

  const signals: Signal[] = [];
  if (verdict === 'DANGER' || verdict === 'CAUTION') {
    signals.push({
      id: signalId('magpie', 'token', chain, address, nowIso.slice(0, 10)),
      module: 'magpie',
      title: `${name} on ${meta.label}: ${verdict} (${reasons.slice(0, 3).join(', ')})`,
      score: verdict === 'DANGER' ? 85 : 55,
      entity: id,
      evidence: reasons.map((r) => ({ source: r.includes('liquidity') || r.includes('pair') ? 'dexscreener' : 'goplus', text: r })),
      createdAt: nowIso,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }
  return {
    module: 'magpie',
    input: address,
    generatedAt: nowIso,
    result: { address, chain, security: sec?.data ?? null, pairs: usePairs.slice(0, 10), market: cg?.data ?? null, verdict, reasons },
    signals,
    provenance,
  };
}
