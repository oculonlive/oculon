/**
 * Deployer record: who created this token, what else they created, and how much of it is dead.
 *   Creator and creation transaction from Etherscan, the creator's other contract deployments from its
 *   transaction list, and for each token its main pool today (DexScreener): no pool or under $1,000 of
 *   liquidity counts as dead. The wallet that first funded the creator is named when it is labeled (an exchange,
 *   a mixer) in the open eth-labels dataset.
 * Tokens made through a launchpad factory are created by the factory, not the wallet; those deployments are
 * not in the creator's own list, and the report says so when it finds none.
 * Ethereum, Arbitrum and Polygon (the chains Etherscan's free plan covers).
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { esTxList, etherscan, evmChain, isAddr, labelOf, tokenMeta } from '../sources/evm.js';
import { DEX_CHAIN } from '../sources/onchain.js';
import { describeLabels, ensureLabels, labelsFor } from '../sources/labels.js';

export interface Deployment { address: string; symbol: string | null; name: string | null; createdAt: string; liquidityUsd: number | null; dead: boolean; isToken: boolean }

export interface DeployerReport {
  token: string;
  chain: string;
  deployer: string | null;
  createdAt: string | null;
  verdict: 'serial rug deployer' | 'many dead tokens' | 'new deployer' | 'no bad record found' | 'deployer not found';
  risk: number;
  deployments: Deployment[];
  tokens: number;
  dead: number;
  fundedBy: { address: string; label: string | null } | null;
  reasons: string[];
  notes: string[];
  advice: string[];
}

export async function deployerCheck(ctx: Ctx, input: string, opts: { chain?: string } = {}): Promise<ModuleResult<DeployerReport>> {
  const token = input.trim().toLowerCase();
  if (!isAddr(token)) throw new Error('give a token contract address: 0x followed by 40 hex characters');
  const c = evmChain(opts.chain, 'creation');
  const provenance: Provenance[] = [];
  const cr = await etherscan<{ contractAddress: string; contractCreator: string; txHash: string; timestamp?: string }[]>(ctx, c, { module: 'contract', action: 'getcontractcreation', contractaddresses: token }, 86_400);
  provenance.push(cr.prov);
  const row = cr.data?.[0];
  const now = ctx.now();
  const base = { token, chain: c.label };
  if (!row?.contractCreator) {
    return { module: 'deployer', input: token, generatedAt: now.toISOString(), signals: [], provenance, result: { ...base, deployer: null, createdAt: null, verdict: 'deployer not found', risk: 0, deployments: [], tokens: 0, dead: 0, fundedBy: null, reasons: [], notes: ['Etherscan has no creator for this address: it may not be a contract on this chain.'], advice: [] } };
  }
  const deployer = row.contractCreator.toLowerCase();
  const createdAt = row.timestamp ? new Date(Number(row.timestamp) * 1000).toISOString() : null;
  const txs = await esTxList(ctx, c, deployer, 1000, 'asc');
  provenance.push(txs.prov);
  const list = txs.data ?? [];
  const created = list.filter((t) => !t.to && t.contractAddress && t.from.toLowerCase() === deployer).map((t) => ({ address: t.contractAddress!.toLowerCase(), at: new Date(Number(t.timeStamp) * 1000).toISOString() }));
  if (!created.some((x) => x.address === token)) created.push({ address: token, at: createdAt ?? now.toISOString() });
  const recent = created.slice(-30);

  // Pools today, 30 tokens per DexScreener call.
  const liq = new Map<string, number>();
  for (let i = 0; i < recent.length; i += 30) {
    const r = await ctx.http.get<{ baseToken?: { address?: string }; liquidity?: { usd?: number } }[]>(`https://api.dexscreener.com/tokens/v1/${DEX_CHAIN[c.key] ?? c.key}/${recent.slice(i, i + 30).map((x) => x.address).join(',')}`, { source: 'dexscreener', ttlSec: 900 });
    if (i === 0) provenance.push(r.prov);
    for (const p of Array.isArray(r.data) ? r.data : []) { const a = p.baseToken?.address?.toLowerCase(); if (a) liq.set(a, Math.max(liq.get(a) ?? 0, p.liquidity?.usd ?? 0)); }
  }
  const deployments: Deployment[] = [];
  for (const d of recent) {
    const m = await tokenMeta(ctx, c, d.address);
    const isToken = Boolean(m.symbol && m.decimals !== null);
    const l = liq.has(d.address) ? liq.get(d.address)! : null;
    deployments.push({ address: d.address, symbol: m.symbol, name: m.name, createdAt: d.at, liquidityUsd: l, dead: isToken && (l === null || l < 1000), isToken });
  }
  const tokens = deployments.filter((d) => d.isToken), dead = tokens.filter((d) => d.dead && d.address !== token);
  const others = tokens.filter((d) => d.address !== token);

  // Who funded the deployer first.
  let fundedBy: DeployerReport['fundedBy'] = null;
  const first = list.find((t) => t.to?.toLowerCase() === deployer && BigInt(t.value || '0') > 0n);
  if (first) {
    try { provenance.push(await ensureLabels(ctx)); } catch {}
    const a = first.from.toLowerCase();
    fundedBy = { address: a, label: labelOf(a) ?? describeLabels(labelsFor(ctx, a)) };
  }

  const reasons: string[] = [], notes: string[] = [];
  let risk = 0;
  if (others.length) {
    const share = dead.length / others.length;
    reasons.push(`the deployer made ${others.length} other token${others.length > 1 ? 's' : ''}; ${dead.length} ${dead.length === 1 ? 'has' : 'have'} no pool or under $1,000 of liquidity today`);
    if (others.length >= 3 && share >= 0.7) risk += 70; else if (dead.length >= 2) risk += 35;
  }
  const age = list[0] ? (now.getTime() - Number(list[0].timeStamp) * 1000) / 86_400_000 : null;
  if (age !== null && age < 7) { risk += 15; reasons.push(`the deployer wallet is ${Math.max(0, Math.round(age))} days old`); }
  if (fundedBy?.label && /tornado|mixer|railgun/i.test(fundedBy.label)) { risk += 30; reasons.push(`the deployer was first funded from a mixer (${fundedBy.label})`); }
  else if (fundedBy?.label) notes.push(`First funded by ${fundedBy.label}.`);
  if (!others.length) notes.push('No other deployments in the creator\'s own transactions. Tokens made through a launchpad factory are created by the factory and do not show here.');
  if (list.length >= 1000) notes.push('The deployer has more than 1,000 transactions; only the first 1,000 were read.');
  risk = Math.min(100, risk);
  const verdict: DeployerReport['verdict'] = risk >= 70 ? 'serial rug deployer' : risk >= 35 ? 'many dead tokens' : age !== null && age < 7 ? 'new deployer' : 'no bad record found';
  const advice = risk >= 35 ? ['Most of this deployer\'s earlier tokens are dead. Expect the same unless something is clearly different this time.', 'Check what the owner can still do: oculon contract <token>'] : ['Nothing in the deployer\'s record stands out. Check the contract too: oculon contract <token>'];
  const signals: Signal[] = risk >= 70 ? [{ id: signalId('deployer', deployer, c.key), module: 'deployer', title: `Deployer ${deployer.slice(0, 10)}: ${dead.length} of ${others.length} earlier tokens dead`, score: risk, entity: `deployer:${deployer}`, evidence: [{ source: 'etherscan', text: reasons[0] ?? '' }], createdAt: now.toISOString() }] : [];
  return { module: 'deployer', input: token, generatedAt: now.toISOString(), signals, provenance, result: { ...base, deployer, createdAt, verdict, risk, deployments: deployments.reverse(), tokens: tokens.length, dead: dead.length, fundedBy, reasons, notes, advice } };
}
