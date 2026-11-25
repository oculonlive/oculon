/**
 * Can this token be sold? honeypot.is (keyless) simulates a buy and a sell on the token's main pool and
 * replays recent holders' sells, which catches honeypots, sell taxes that eat the position, and contracts
 * that only let some wallets out. Supported chains: Ethereum, BNB Chain and Base.
 * A simulation that passes today can fail tomorrow if the owner changes the contract.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';

export const HONEYPOT_CHAINS: Record<string, [number, string]> = { eth: [1, 'Ethereum'], ethereum: [1, 'Ethereum'], bsc: [56, 'BNB Chain'], bnb: [56, 'BNB Chain'], base: [8453, 'Base'] };

export interface HoneypotReport {
  address: string;
  chain: string;
  name: string | null;
  symbol: string | null;
  verdict: 'honeypot' | 'high risk' | 'caution' | 'sellable';
  simulated: boolean;
  isHoneypot: boolean | null;
  buyTax: number | null;
  sellTax: number | null;
  transferTax: number | null;
  holders: { checked: number; failed: number; siphoned: number; highestTax: number | null } | null;
  openSource: boolean | null;
  proxy: boolean | null;
  pair: string | null;
  flags: string[];
  reasons: string[];
  advice: string[];
}

interface Raw {
  token?: { name?: string; symbol?: string; totalHolders?: number };
  summary?: { risk?: string; riskLevel?: number; flags?: (string | { flag?: string; description?: string })[] };
  simulationSuccess?: boolean;
  simulationError?: string;
  honeypotResult?: { isHoneypot?: boolean; honeypotReason?: string };
  simulationResult?: { buyTax?: number; sellTax?: number; transferTax?: number };
  holderAnalysis?: { holders?: string; successful?: string; failed?: string; siphoned?: string; highestTax?: number };
  contractCode?: { openSource?: boolean; isProxy?: boolean };
  pair?: { pair?: { name?: string } };
  flags?: (string | { flag?: string; description?: string })[];
  error?: string;
}

const flagText = (f: string | { flag?: string; description?: string }) => (typeof f === 'string' ? f : f.description || f.flag || '');

export async function honeypotCheck(ctx: Ctx, address: string, opts: { chain?: string } = {}): Promise<ModuleResult<HoneypotReport>> {
  const a = address.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error('give a token contract address: 0x followed by 40 hex characters');
  const key = (opts.chain ?? 'eth').toLowerCase();
  if (key === 'robinhood' || key === 'rh') throw new Error('not a supported chain for sell simulation: use "oculon token <address> --chain robinhood" for Robinhood Chain tokens');
  const chain = HONEYPOT_CHAINS[key];
  if (!chain) throw new Error(`not a supported chain: ${key} (use eth, bsc or base)`);
  const r = await ctx.http.get<Raw>(`https://api.honeypot.is/v2/IsHoneypot?address=${a}&chainID=${chain[0]}`, { source: 'honeypot-is', ttlSec: 900, timeoutMs: 30_000, retries: 1 });
  if (!r.data) throw new Error(r.prov.note === 'HTTP 404' || r.prov.note === 'HTTP 400' ? `no pool found for ${a} on ${chain[1]}` : `honeypot.is is not answering right now (${r.prov.note ?? r.prov.status})`);
  const d = r.data;
  const sim = d.simulationResult ?? {};
  const h = d.holderAnalysis;
  const holders = h ? { checked: Number(h.holders ?? 0), failed: Number(h.failed ?? 0), siphoned: Number(h.siphoned ?? 0), highestTax: typeof h.highestTax === 'number' ? h.highestTax : null } : null;
  const flags = [...(d.summary?.flags ?? []), ...(d.flags ?? [])].map(flagText).filter(Boolean);
  const reasons: string[] = [];
  const isHp = d.honeypotResult?.isHoneypot ?? null;
  if (isHp) reasons.push(`sells fail in simulation${d.honeypotResult?.honeypotReason ? `: ${d.honeypotResult.honeypotReason}` : ''}`);
  if (d.simulationSuccess === false) reasons.push(`the buy and sell could not be simulated${d.simulationError ? ` (${d.simulationError})` : ''}`);
  const st = sim.sellTax ?? null, bt = sim.buyTax ?? null;
  if (st !== null && st >= 10) reasons.push(`sell tax ${st.toFixed(1)}%`);
  if (bt !== null && bt >= 10) reasons.push(`buy tax ${bt.toFixed(1)}%`);
  if (holders && holders.checked && holders.failed / holders.checked > 0.05) reasons.push(`${holders.failed} of ${holders.checked} recent holders could not sell`);
  if (holders?.siphoned) reasons.push(`${holders.siphoned} holder wallets had tokens taken out`);
  if (d.contractCode?.openSource === false) reasons.push('contract source is not published');
  if (d.contractCode?.isProxy) reasons.push('upgradeable proxy: the owner can change the code');
  const risk = (d.summary?.riskLevel ?? 0);
  const verdict: HoneypotReport['verdict'] = isHp ? 'honeypot' : (st ?? 0) >= 30 || risk >= 60 ? 'high risk' : reasons.length || risk >= 20 ? 'caution' : 'sellable';
  const advice = verdict === 'sellable'
    ? ['Sells work in simulation today. That says nothing about the project itself, and the owner can still change the contract.']
    : ['Do not buy. If you hold it, try a small sell first and do not approve unlimited spending.'];
  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = verdict === 'honeypot' ? [{ id: signalId('honeypot', a.toLowerCase(), chain[1]), module: 'honeypot', title: `${d.token?.symbol ?? a.slice(0, 10)} on ${chain[1]}: sells fail in simulation`, score: 70, entity: a.toLowerCase(), evidence: [{ source: 'honeypot.is', text: reasons[0] ?? 'honeypot', url: `https://honeypot.is/?address=${a}` }], createdAt: nowIso }] : [];
  return {
    module: 'honeypot', input: a, generatedAt: nowIso,
    result: { address: a, chain: chain[1], name: d.token?.name ?? null, symbol: d.token?.symbol ?? null, verdict, simulated: d.simulationSuccess === true, isHoneypot: isHp, buyTax: bt, sellTax: st, transferTax: sim.transferTax ?? null, holders, openSource: d.contractCode?.openSource ?? null, proxy: d.contractCode?.isProxy ?? null, pair: d.pair?.pair?.name ?? null, flags, reasons, advice },
    signals, provenance: [{ ...r.prov, note: 'buy and sell simulated on the main pool' }],
  };
}
