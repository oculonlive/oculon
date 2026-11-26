/**
 * Fund trace: follow where money went from an address, a few hops out.
 * At each hop the largest outgoing flows (native coin and tokens, from Etherscan) are followed. A branch stops
 * when it reaches an exchange, a bridge or a mixer (named by the open eth-labels dataset), a contract, a
 * sanctioned address, or the hop limit. Exchanges are where stolen funds can be frozen: the report lists them
 * first, with the transaction hashes to give the exchange or the police.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { alchemyPrices, codeAt, esTokenTx, esTxList, evmChain, isAddr, labelOf } from '../sources/evm.js';
import { describeLabels, ensureLabels, labelsFor } from '../sources/labels.js';
import { screen } from './sanctions.js';
import { DEX_CHAIN } from '../sources/onchain.js';

export interface TraceNode {
  address: string;
  hop: number;
  label: string | null;
  kind: 'exchange' | 'mixer' | 'bridge' | 'scam' | 'contract' | 'sanctioned' | 'wallet' | 'start';
  receivedFrom: string | null;
  amount: string | null;
  firstTx: string | null;
  at: string | null;
  stop: string | null;
}

export interface TraceReport {
  address: string;
  chain: string;
  verdict: 'reached sanctioned address' | 'reached mixer' | 'reached exchange' | 'funds still in wallets' | 'no outgoing funds found';
  /** How bad the destinations are: sanctioned or mixer high, scam labels medium; an exchange is where funds can be frozen. */
  risk: number;
  hops: number;
  nodes: TraceNode[];
  exchanges: TraceNode[];
  reasons: string[];
  advice: string[];
}


function kindOf(label: string | null): TraceNode['kind'] | null {
  if (!label) return null;
  if (/tornado|mixer|railgun|samourai|wasabi|sinbad|blender/i.test(label)) return 'mixer';
  if (/phish|scam|hack|exploit|heist|drainer|fake/i.test(label)) return 'scam';
  if (/bridge|wormhole|stargate|hop protocol|across|synapse|multichain|layerzero/i.test(label)) return 'bridge';
  if (/binance|coinbase|kraken|okx|okex|bybit|kucoin|bitfinex|huobi|htx|gate\.?io|crypto\.com|gemini|bitstamp|mexc|bitget|upbit|bithumb|exchange|deposit|hot wallet|cex/i.test(label)) return 'exchange';
  return null;
}

interface Out { to: string; score: number; amount: string; tx: string; at: string }

const WRAPPED: Record<string, string> = { eth: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', arbitrum: '0x82af49447d8a07e3bd95bd0d56f35241523fbab1', polygon: '0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270', optimism: '0x4200000000000000000000000000000000000006', base: '0x4200000000000000000000000000000000000006', bsc: '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c' };

/** USD price and pool liquidity of tokens, 30 per DexScreener call. Tokens without a real pool are spam here. */
async function prices(ctx: Ctx, chain: string, tokens: string[]): Promise<Map<string, { price: number; liq: number }>> {
  const out = new Map<string, { price: number; liq: number }>();
  for (let i = 0; i < tokens.length && i < 60; i += 30) {
    const r = await ctx.http.get<{ baseToken?: { address?: string }; priceUsd?: string; liquidity?: { usd?: number } }[]>(`https://api.dexscreener.com/tokens/v1/${DEX_CHAIN[chain] ?? chain}/${tokens.slice(i, i + 30).join(',')}`, { source: 'dexscreener', ttlSec: 900 });
    for (const p of Array.isArray(r.data) ? r.data : []) {
      const a = p.baseToken?.address?.toLowerCase();
      if (!a || !p.priceUsd) continue;
      const liq = p.liquidity?.usd ?? 0;
      if ((out.get(a)?.liq ?? -1) < liq) out.set(a, { price: Number(p.priceUsd), liq });
    }
  }
  // Tokens DexScreener does not know: Alchemy's price feed, which only lists tokens with a real market.
  const missing = tokens.filter((t) => !out.has(t));
  if (missing.length) for (const [a, price] of await alchemyPrices(ctx, evmChain(chain), missing)) out.set(a, { price, liq: 10_000 });
  return out;
}

async function outflows(ctx: Ctx, c: ReturnType<typeof evmChain>, a: string, prov: Provenance[]): Promise<Out[]> {
  const [t, k] = await Promise.all([esTxList(ctx, c, a, 200), esTokenTx(ctx, c, a, 300)]);
  if (!prov.length) prov.push(t.prov, k.prov);
  const outs = (k.data ?? []).filter((x) => x.from.toLowerCase() === a && x.to && BigInt(x.value || '0') > 0n);
  const px = await prices(ctx, c.key, [...new Set([...outs.map((x) => x.contractAddress.toLowerCase()), WRAPPED[c.key] ?? ''])].filter(Boolean));
  const nativeUsd = px.get(WRAPPED[c.key] ?? '')?.price ?? 0;
  const by = new Map<string, { score: number; parts: Map<string, number>; tx: string; at: string }>();
  const add = (to: string, sym: string, amt: number, usd: number, tx: string, ts: string) => {
    const e = by.get(to) ?? { score: 0, parts: new Map(), tx, at: ts };
    e.score += usd; e.parts.set(sym, (e.parts.get(sym) ?? 0) + amt);
    by.set(to, e);
  };
  for (const x of t.data ?? []) {
    if (x.from.toLowerCase() !== a || x.isError === '1' || !x.to) continue;
    const v = Number(BigInt(x.value || '0') / 10n ** 12n) / 1e6;
    if (v > 0) add(x.to.toLowerCase(), c.native, v, v * (nativeUsd || 1), x.hash, new Date(Number(x.timeStamp) * 1000).toISOString());
  }
  // Token transfers: spam tokens fake transfers from any wallet, so only tokens with a real pool count.
  for (const x of outs) {
    const p = px.get(x.contractAddress.toLowerCase());
    if (!p || p.liq < 10_000) continue;
    const dec = Number(x.tokenDecimal || 18);
    const raw = BigInt(x.value || '0');
    const v = dec >= 6 ? Number(raw / 10n ** BigInt(dec - 6)) / 1e6 : Number(raw) / 10 ** dec;
    const usd = v * p.price;
    if (!(usd >= 1)) continue;
    add(x.to.toLowerCase(), x.tokenSymbol || 'token', v, usd, x.hash, new Date(Number(x.timeStamp) * 1000).toISOString());
  }
  return [...by].map(([to, e]) => ({ to, score: e.score, amount: [...e.parts].map(([s, v]) => `${v.toLocaleString('en-US', { maximumFractionDigits: 4 })} ${s}`).join(' + ') + (nativeUsd ? ` (about $${Math.round(e.score).toLocaleString('en-US')})` : ''), tx: e.tx, at: e.at }))
    .filter((o) => o.score >= 1)
    .sort((x, y) => y.score - x.score);
}

export async function traceFunds(ctx: Ctx, input: string, opts: { chain?: string; hops?: number; width?: number } = {}): Promise<ModuleResult<TraceReport>> {
  const start = input.trim().toLowerCase();
  if (!isAddr(start)) throw new Error('give an address: 0x followed by 40 hex characters');
  const c = evmChain(opts.chain, 'transfers');
  const hops = Math.max(1, Math.min(4, Math.round(opts.hops ?? 3)));
  const width = Math.max(1, Math.min(4, Math.round(opts.width ?? 3)));
  const provenance: Provenance[] = [];
  try { provenance.push(await ensureLabels(ctx)); } catch {}
  const nodes: TraceNode[] = [{ address: start, hop: 0, label: describeLabels(labelsFor(ctx, start)), kind: 'start', receivedFrom: null, amount: null, firstTx: null, at: null, stop: null }];
  const seen = new Set([start]);
  let frontier = [start];
  const esProv: Provenance[] = [];
  let calls = 0;
  for (let h = 1; h <= hops && frontier.length; h++) {
    const next: string[] = [];
    for (const from of frontier) {
      if (calls++ > 14) break;
      const outs = (await outflows(ctx, c, from, esProv)).filter((o) => !seen.has(o.to)).slice(0, width);
      for (const o of outs) {
        seen.add(o.to);
        const lab = labelOf(o.to) ?? describeLabels(labelsFor(ctx, o.to));
        let kind = kindOf(lab);
        let stop: string | null = kind ? `reached ${kind}` : null;
        if (!kind) {
          let sanctioned = false;
          try { sanctioned = (await screen(ctx, o.to)).result.verdict === 'SANCTIONED'; } catch {}
          if (sanctioned) { kind = 'sanctioned'; stop = 'on the US OFAC sanctions list'; }
        }
        if (!kind) {
          const code = await codeAt(ctx, c, o.to);
          if (code && code !== '0x' && !/^0xef0100/i.test(code)) { kind = 'contract'; stop = lab ? `contract: ${lab}` : 'contract (swap, pool or app)'; }
        }
        kind ??= 'wallet';
        nodes.push({ address: o.to, hop: h, label: lab, kind, receivedFrom: from, amount: o.amount, firstTx: o.tx, at: o.at, stop });
        if (kind === 'wallet') next.push(o.to);
      }
    }
    frontier = next;
  }
  provenance.push(...esProv);
  const exchanges = nodes.filter((n) => n.kind === 'exchange');
  const mixers = nodes.filter((n) => n.kind === 'mixer'), sanc = nodes.filter((n) => n.kind === 'sanctioned');
  const reasons: string[] = [];
  for (const n of [...sanc, ...mixers, ...exchanges].slice(0, 6)) reasons.push(`hop ${n.hop}: ${n.amount} to ${n.label ?? n.address} (${n.kind})`);
  const open = nodes.filter((n) => n.kind === 'wallet' && n.hop === hops).length;
  if (open) reasons.push(`${open} branch${open > 1 ? 'es' : ''} still in plain wallets after ${hops} hops`);
  const verdict: TraceReport['verdict'] = nodes.length === 1 ? 'no outgoing funds found' : sanc.length ? 'reached sanctioned address' : mixers.length ? 'reached mixer' : exchanges.length ? 'reached exchange' : 'funds still in wallets';
  const advice = exchanges.length
    ? [`Report to ${[...new Set(exchanges.map((e) => e.label?.split(' (')[0] ?? 'the exchange'))].join(', ')} right away with the transaction hashes below: exchanges can freeze deposits.`, 'File a police report and keep the replay link of this check as evidence.']
    : mixers.length ? ['Funds went through a mixer: tracing past it is not possible with public data. Report the hashes to the police and to the wallet app you used.']
      : ['Follow the open branches again later: funds often wait in wallets before they move to an exchange.', 'Report the theft to the police with the addresses and hashes in this report.'];
  const now = ctx.now().toISOString();
  const signals: Signal[] = sanc.length ? [{ id: signalId('trace', start, c.key), module: 'trace', title: `Funds from ${start.slice(0, 10)} reached a sanctioned address`, score: 70, entity: `wallet:${start}`, evidence: sanc.slice(0, 2).map((n) => ({ source: 'etherscan', text: `hop ${n.hop}: ${n.address}` })), createdAt: now }] : [];
  return { module: 'trace', input: start, generatedAt: now, result: { address: start, chain: c.label, verdict, risk: sanc.length ? 90 : mixers.length ? 70 : nodes.some((n) => n.kind === 'scam') ? 60 : 0, hops, nodes, exchanges, reasons, advice }, signals, provenance };
}
