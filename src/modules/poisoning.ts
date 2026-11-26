/**
 * Address poisoning check: has someone planted lookalike addresses in this wallet's history?
 * Attackers send zero-value transfers, dust or fake tokens from an address that starts and ends like one the
 * victim really pays, hoping the victim copies it from the history next time. This check takes the addresses
 * the wallet really sent to (transactions it signed itself, Etherscan), then looks through recent token
 * transfers for other addresses that share the first and last characters, zero-value "transfers" the wallet
 * never signed, and tokens posing as USDT or USDC.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { esTokenTx, esTxList, evmChain, historySource, isAddr, rpcCall } from '../sources/evm.js';

export interface Lookalike {
  fake: string;
  real: string;
  matched: string;
  seen: number;
  lastSeen: string;
  how: string[];
}

export interface PoisoningReport {
  address: string;
  chain: string;
  verdict: 'poisoned' | 'suspicious transfers' | 'no poisoning found';
  risk: number;
  lookalikes: Lookalike[];
  fakeTokens: { contract: string; symbol: string; transfers: number }[];
  zeroValue: number;
  realCounterparties: number;
  checkedTransfers: number;
  reasons: string[];
  advice: string[];
}

const OFFICIAL: Record<string, Record<string, string[]>> = {
  eth: { USDT: ['0xdac17f958d2ee523a2206206994597c13d831ec7'], USDC: ['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'], WETH: ['0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'], DAI: ['0x6b175474e89094c44da98b954eedeac495271d0f'] },
  optimism: { USDT: ['0x94b008aa00579c1307b0ef2c499ad98a8ce58e58'], USDC: ['0x0b2c639c533813f4aa9d7837caf62653d097ff85', '0x7f5c764cbc14f9669b88837ca1490cca17c31607'], WETH: ['0x4200000000000000000000000000000000000006'] },
  base: { USDC: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'], USDT: ['0xfde4c96c8593536e31f229ea8f37b2ada2699bb2'], WETH: ['0x4200000000000000000000000000000000000006'] },
  bsc: { USDT: ['0x55d398326f99059ff775485246999027b3197955'], USDC: ['0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d'], WETH: ['0x2170ed0880ac9a755fd29b2688956bd959f933f8'] },
  arbitrum: { USDT: ['0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9'], USDC: ['0xaf88d065e77c8cc2239327c5edb3a432268e5831', '0xff970a61a04b1ca14834a43f5de4533ebddb5cc8'], WETH: ['0x82af49447d8a07e3bd95bd0d56f35241523fbab1'] },
  polygon: { USDT: ['0xc2132d05d31c914a87c6611c10748aeb04b58e8f'], USDC: ['0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', '0x2791bca1f2de4661ed88a30c99a7a9449aa84174'], WETH: ['0x7ceb23fd6bc0add59e62ac25578270cff1b9f619'] },
};

/** How many characters two addresses share at the start (after 0x) and at the end. */
export function sharedEnds(a: string, b: string): { head: number; tail: number } {
  const x = a.toLowerCase().slice(2), y = b.toLowerCase().slice(2);
  let head = 0, tail = 0;
  while (head < 40 && x[head] === y[head]) head++;
  while (tail < 40 && x[39 - tail] === y[39 - tail]) tail++;
  return { head, tail };
}

export async function poisoningCheck(ctx: Ctx, input: string, opts: { chain?: string } = {}): Promise<ModuleResult<PoisoningReport>> {
  const address = input.trim().toLowerCase();
  if (!isAddr(address)) throw new Error('give a wallet address: 0x followed by 40 hex characters');
  const c = evmChain(opts.chain, 'transfers');
  const provenance: Provenance[] = [];
  const [txs, toks] = await Promise.all([esTxList(ctx, c, address, 500), esTokenTx(ctx, c, address, 500)]);
  provenance.push(txs.prov, toks.prov);
  if (txs.data === null && toks.data === null) throw new Error(`could not read the wallet history (${txs.prov.note ?? txs.prov.status})`);

  // Addresses the wallet really paid: transactions it signed, and token transfers inside them.
  const signed = new Set((txs.data ?? []).filter((t) => t.from.toLowerCase() === address).map((t) => t.hash.toLowerCase()));
  // Alchemy lists only value transactions, so token transfers out of the wallet are confirmed by asking the chain
  // who sent each transaction (the newest 40).
  if (historySource(c) === 'alchemy') {
    const open = [...new Set((toks.data ?? []).filter((t) => t.from.toLowerCase() === address && !signed.has(t.hash.toLowerCase())).map((t) => t.hash.toLowerCase()))].slice(0, 40);
    for (let i = 0; i < open.length; i += 10) {
      const got = await Promise.all(open.slice(i, i + 10).map((h) => rpcCall<{ from: string }>(ctx, c, 'eth_getTransactionByHash', [h], 86_400).then((r) => [h, r.data?.from?.toLowerCase()] as const)));
      for (const [h, from] of got) if (from === address) signed.add(h);
    }
  }
  const real = new Set<string>();
  for (const t of txs.data ?? []) if (t.from.toLowerCase() === address && t.to && BigInt(t.value || '0') > 0n) real.add(t.to.toLowerCase());
  for (const t of toks.data ?? []) if (signed.has(t.hash.toLowerCase()) && t.from.toLowerCase() === address && BigInt(t.value || '0') > 0n) real.add(t.to.toLowerCase());
  // Received from: also addresses people copy (exchange deposit, a friend).
  for (const t of toks.data ?? []) if (t.to.toLowerCase() === address && BigInt(t.value || '0') > 0n && OFFICIAL[c.key]?.[t.tokenSymbol]?.includes(t.contractAddress.toLowerCase())) real.add(t.from.toLowerCase());

  const official = OFFICIAL[c.key] ?? {};
  const fakeTok = new Map<string, { contract: string; symbol: string; transfers: number }>();
  const found = new Map<string, Lookalike>();
  let zero = 0;
  for (const t of toks.data ?? []) {
    const from = t.from.toLowerCase(), to = t.to.toLowerCase(), ca = t.contractAddress.toLowerCase();
    const isZero = BigInt(t.value || '0') === 0n;
    const notSigned = !signed.has(t.hash.toLowerCase());
    if (isZero && notSigned) zero++;
    const sym = (t.tokenSymbol ?? '').toUpperCase().replace(/[^A-Z]/g, '');
    const fake = Boolean(official[sym] && !official[sym]!.includes(ca));
    if (fake) { const f = fakeTok.get(ca) ?? { contract: ca, symbol: t.tokenSymbol, transfers: 0 }; f.transfers++; fakeTok.set(ca, f); }
    const other = from === address ? to : from;
    if (real.has(other)) continue;
    for (const r of real) {
      const { head, tail } = sharedEnds(other, r);
      if (head + tail >= 7 && head >= 3 && tail >= 3) {
        const l = found.get(other) ?? { fake: other, real: r, matched: `0x${r.slice(2, 2 + head)}...${r.slice(-tail)}`, seen: 0, lastSeen: '', how: [] };
        l.seen++;
        const ts = new Date(Number(t.timeStamp) * 1000).toISOString();
        if (ts > l.lastSeen) l.lastSeen = ts;
        const how = isZero && notSigned ? 'zero-value transfer you never signed' : fake ? `fake ${t.tokenSymbol} token` : from === address ? 'tokens sent to it' : 'dust sent to you';
        if (!l.how.includes(how)) l.how.push(how);
        found.set(other, l);
        break;
      }
    }
  }
  const lookalikes = [...found.values()].sort((a, b) => b.seen - a.seen).slice(0, 20);
  const sentToFake = lookalikes.filter((l) => l.how.includes('tokens sent to it'));
  const reasons: string[] = [];
  for (const l of lookalikes.slice(0, 5)) reasons.push(`${l.fake} looks like ${l.real} (same ${l.matched}): ${l.how.join(', ')}`);
  if (sentToFake.length) reasons.unshift(`you already sent funds to ${sentToFake.length} lookalike address${sentToFake.length > 1 ? 'es' : ''}`);
  if (fakeTok.size) reasons.push(`${fakeTok.size} fake token${fakeTok.size > 1 ? 's' : ''} posing as ${[...new Set([...fakeTok.values()].map((f) => f.symbol))].join(', ')}`);
  if (zero >= 3 && !lookalikes.length) reasons.push(`${zero} zero-value transfers this wallet never signed`);
  const risk = Math.min(100, (sentToFake.length ? 60 : 0) + lookalikes.length * 20 + fakeTok.size * 10 + (zero >= 3 ? 10 : 0));
  const verdict: PoisoningReport['verdict'] = lookalikes.length ? 'poisoned' : fakeTok.size || zero >= 3 ? 'suspicious transfers' : 'no poisoning found';
  const advice = lookalikes.length
    ? ['Never copy an address from your transaction history. Use your address book, or copy it from the exchange or the person each time.', 'Compare the whole address, not just the first and last characters.', 'The lookalike transfers cannot move your funds by themselves; they only wait for you to copy the wrong address.']
    : ['Nothing planted found in the recent history. Keep using an address book for addresses you pay often.'];
  const now = ctx.now().toISOString();
  const signals: Signal[] = sentToFake.length ? [{ id: signalId('poisoning', address, c.key), module: 'poisoning', title: `${address.slice(0, 10)} sent funds to a lookalike address`, score: 75, entity: `wallet:${address}`, evidence: sentToFake.slice(0, 2).map((l) => ({ source: 'etherscan', text: `${l.fake} posing as ${l.real}` })), createdAt: now }] : [];
  return {
    module: 'poisoning', input: address, generatedAt: now,
    result: { address, chain: c.label, verdict, risk, lookalikes, fakeTokens: [...fakeTok.values()], zeroValue: zero, realCounterparties: real.size, checkedTransfers: (toks.data ?? []).length, reasons, advice },
    signals, provenance,
  };
}
