/**
 * Transaction explainer: paste a transaction hash and read what happened, in plain words.
 * Reads the transaction and its receipt from a public RPC, names the function called (signature databases),
 * decodes every token transfer, approval and NFT approval in its logs, and says who sent what to whom.
 * Flags the patterns behind most "my tokens disappeared" questions: tokens leaving a wallet in a transaction
 * someone else sent (an approval being used), approvals to plain wallets or unverified contracts, and NFT
 * collections handed over with setApprovalForAll.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { alchemyPrices, codeAt, EVM_CHAINS, evmChain, formatUnits, labelOf, rpcCall, sourcify, tokenMeta, TOPIC, topicAddr, UNLIMITED, wordInt, type EvmChain } from '../sources/evm.js';
import { decodeSelectors } from '../sources/signatures.js';
import { DEX_CHAIN } from '../sources/onchain.js';

const STABLES = /^(USDT|USDC|DAI|WETH|WBTC|USDC\.E|USDE|PYUSD)$/i;

export interface TxMove { kind: 'token' | 'nft' | 'approval' | 'nft approval' | 'native'; token: string | null; symbol: string | null; from: string; to: string; amount: string; text: string }

export interface TxReport {
  hash: string;
  chain: string;
  status: 'success' | 'failed' | 'pending';
  verdict: 'tokens taken by someone else' | 'risky approval given' | 'failed transaction' | 'pending' | 'normal transaction';
  risk: number;
  from: string;
  to: string | null;
  function: string | null;
  value: string;
  fee: string | null;
  time: string | null;
  summary: string[];
  moves: TxMove[];
  reasons: string[];
  advice: string[];
  explorer: string;
}

interface RpcTx { from: string; to: string | null; value: string; input: string; blockNumber: string | null; gasPrice?: string }
interface RpcReceipt { status: string; gasUsed: string; effectiveGasPrice?: string; logs: { address: string; topics: string[]; data: string }[]; contractAddress?: string | null }

async function find(ctx: Ctx, hash: string, prefer?: string): Promise<{ c: EvmChain; tx: RpcTx; prov: Provenance } | null> {
  const order = prefer ? [evmChain(prefer)] : ['eth', 'base', 'arbitrum', 'bsc', 'polygon', 'optimism'].map((k) => EVM_CHAINS[k]!);
  for (const c of order) {
    const r = await rpcCall<RpcTx>(ctx, c, 'eth_getTransactionByHash', [hash], 60);
    if (r.data) return { c, tx: r.data, prov: r.prov };
  }
  return null;
}

export async function explainTx(ctx: Ctx, input: string, opts: { chain?: string } = {}): Promise<ModuleResult<TxReport>> {
  const hash = input.trim().toLowerCase().replace(/^.*\/tx\//, '').split(/[?#/]/)[0]!;
  if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error('give a transaction hash: 0x followed by 64 hex characters (or an explorer link to it)');
  const f = await find(ctx, hash, opts.chain);
  if (!f) throw new Error(`transaction ${hash.slice(0, 12)}... not found on ${opts.chain ?? 'Ethereum, Base, Arbitrum, BNB Chain or Polygon'}`);
  const { c, tx } = f;
  const provenance: Provenance[] = [f.prov];
  const explorer = `${c.explorer}/tx/${hash}`;
  const from = tx.from.toLowerCase(), to = tx.to?.toLowerCase() ?? null;
  const value = BigInt(tx.value || '0');
  const base = { hash, chain: c.label, from, to, value: `${formatUnits(value, 18)} ${c.native}`, explorer };
  if (!tx.blockNumber) return { module: 'tx', input: hash, generatedAt: ctx.now().toISOString(), signals: [], provenance, result: { ...base, status: 'pending', verdict: 'pending', risk: 0, function: null, fee: null, time: null, summary: ['The transaction is waiting to be included in a block.'], moves: [], reasons: [], advice: ['A pending transaction can still be replaced: send a new one with the same nonce and a higher fee to cancel it.'] } };

  const [rc, blk] = await Promise.all([rpcCall<RpcReceipt>(ctx, c, 'eth_getTransactionReceipt', [hash], 3600), rpcCall<{ timestamp: string }>(ctx, c, 'eth_getBlockByNumber', [tx.blockNumber, false], 86_400)]);
  provenance.push(rc.prov);
  const receipt = rc.data;
  const status: TxReport['status'] = receipt?.status === '0x1' ? 'success' : 'failed';
  const time = blk.data?.timestamp ? new Date(Number(BigInt(blk.data.timestamp)) * 1000).toISOString() : null;
  const fee = receipt ? `${formatUnits(BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice ?? tx.gasPrice ?? '0'), 18, 6)} ${c.native}` : null;
  const sel = tx.input && tx.input.length >= 10 ? tx.input.slice(0, 10).toLowerCase() : null;
  const fn = sel ? ((await decodeSelectors(ctx, [sel]).catch(() => ({}) as Record<string, string | null>))[sel] ?? sel) : null;

  const metas = new Map<string, Awaited<ReturnType<typeof tokenMeta>>>();
  const meta = async (t: string) => { if (!metas.has(t)) metas.set(t, await tokenMeta(ctx, c, t)); return metas.get(t)!; };
  const kinds = new Map<string, string>();
  const kindOf = async (a: string) => {
    if (kinds.has(a)) return kinds.get(a)!;
    const known = labelOf(a);
    let k = known ?? 'unknown';
    if (!known) { const code = await codeAt(ctx, c, a); k = code === '0x' || (code && /^0xef0100/i.test(code)) ? 'wallet' : code ? ((await sourcify(ctx, c, a)).data ? 'verified contract' : 'unverified contract') : 'unknown'; }
    kinds.set(a, k);
    return k;
  };
  const who = (a: string) => (a === from ? 'you (the sender)' : labelOf(a) ?? `${a.slice(0, 8)}...${a.slice(-4)}`);

  const moves: TxMove[] = [];
  const reasons: [string, number][] = [];
  const taken: { token: string; text: string }[] = [];
  if (value > 0n && to) moves.push({ kind: 'native', token: null, symbol: c.native, from, to, amount: formatUnits(value, 18), text: `${who(from)} sent ${formatUnits(value, 18)} ${c.native} to ${who(to)}` });
  for (const l of (receipt?.logs ?? []).slice(0, 60)) {
    const t0 = l.topics[0]?.toLowerCase();
    const tok = l.address.toLowerCase();
    if (t0 === TOPIC.transfer && l.topics.length === 3) {
      const m = await meta(tok);
      const a = topicAddr(l.topics[1]!), b = topicAddr(l.topics[2]!);
      const amt = formatUnits(wordInt(l.data, 0), m.decimals);
      moves.push({ kind: 'token', token: tok, symbol: m.symbol, from: a, to: b, amount: amt, text: `${amt} ${m.symbol ?? 'tokens'} moved from ${who(a)} to ${who(b)}` });
      if (a !== from && a !== '0x0000000000000000000000000000000000000000' && to !== a && (await kindOf(a)) === 'wallet') taken.push({ token: tok, text: `${amt} ${m.symbol ?? 'tokens'} left ${a} in a transaction that ${a.slice(0, 8)}... did not send: an earlier approval or permit was used` });
    } else if (t0 === TOPIC.transfer && l.topics.length === 4) {
      const a = topicAddr(l.topics[1]!), b = topicAddr(l.topics[2]!);
      const m = await meta(tok);
      const id = BigInt(l.topics[3]!).toString();
      moves.push({ kind: 'nft', token: tok, symbol: m.symbol, from: a, to: b, amount: `#${id.slice(0, 20)}`, text: `NFT ${m.symbol ?? tok.slice(0, 10)} #${id.slice(0, 20)} moved from ${who(a)} to ${who(b)}` });
      if (a !== from && a !== '0x0000000000000000000000000000000000000000' && (await kindOf(a)) === 'wallet') reasons.push([`an NFT left ${a} in a transaction it did not send`, 40]);
    } else if (t0 === TOPIC.approval && l.topics.length === 3) {
      const m = await meta(tok);
      const owner = topicAddr(l.topics[1]!), spender = topicAddr(l.topics[2]!);
      const v = wordInt(l.data, 0);
      if (v === 0n) { moves.push({ kind: 'approval', token: tok, symbol: m.symbol, from: owner, to: spender, amount: '0', text: `${who(owner)} removed the ${m.symbol ?? 'token'} approval of ${who(spender)}` }); continue; }
      const amt = v >= UNLIMITED ? 'unlimited' : formatUnits(v, m.decimals);
      moves.push({ kind: 'approval', token: tok, symbol: m.symbol, from: owner, to: spender, amount: amt, text: `${who(owner)} allowed ${who(spender)} to take ${amt} ${m.symbol ?? 'tokens'}` });
      const k = await kindOf(spender);
      if (k === 'wallet') reasons.push([`the approval goes to a plain wallet (${spender}), not an app contract`, 45]);
      else if (k === 'unverified contract' && v >= UNLIMITED) reasons.push([`unlimited approval to a contract with unpublished code (${spender})`, 30]);
    } else if (t0 === TOPIC.approvalForAll) {
      const owner = topicAddr(l.topics[1]!), op = topicAddr(l.topics[2]!);
      const on = wordInt(l.data, 0) !== 0n;
      const m = await meta(tok);
      moves.push({ kind: 'nft approval', token: tok, symbol: m.symbol, from: owner, to: op, amount: on ? 'all' : 'removed', text: on ? `${who(owner)} let ${who(op)} move every ${m.symbol ?? 'NFT'} in the collection` : `${who(owner)} removed ${who(op)} as operator` });
      if (on && (await kindOf(op)) === 'wallet') reasons.push([`all NFTs of the collection handed to a plain wallet (${op})`, 50]);
    }
  }
  // Spam tokens emit fake transfers out of famous wallets; only tokens with a real market count as taken.
  if (taken.length) {
    const toks = [...new Set(taken.map((t) => t.token))].slice(0, 30);
    const r = await ctx.http.get<{ baseToken?: { address?: string }; liquidity?: { usd?: number } }[]>(`https://api.dexscreener.com/tokens/v1/${DEX_CHAIN[c.key] ?? c.key}/${toks.join(',')}`, { source: 'dexscreener', ttlSec: 900 });
    provenance.push(r.prov);
    const liq = new Map<string, number>();
    for (const p of Array.isArray(r.data) ? r.data : []) { const a = p.baseToken?.address?.toLowerCase(); if (a) liq.set(a, Math.max(liq.get(a) ?? 0, p.liquidity?.usd ?? 0)); }
    // Alchemy prices only tokens with a real market: a price there also counts.
    const unknown = toks.filter((t) => (liq.get(t) ?? 0) < 10_000);
    for (const [a] of await alchemyPrices(ctx, c, unknown)) liq.set(a, 10_000);
    for (const t of taken) {
      if ((liq.get(t.token) ?? 0) >= 10_000 || STABLES.test(metas.get(t.token)?.symbol ?? '')) reasons.push([t.text, 45]);
      else reasons.push([`${t.text.split(' left ')[0]} "left" a wallet that did not send this transaction, but the token has no real market: most likely a spam token faking a transfer, not a theft`, 0]);
    }
  }
  if (status === 'failed') reasons.push(['the transaction failed: nothing moved except the network fee', 0]);
  const risk = Math.min(100, reasons.reduce((s, [, w]) => s + w, 0));
  const isTaken = reasons.some(([r, w]) => w > 0 && /did not send/.test(r));
  const verdict: TxReport['verdict'] = status === 'failed' ? 'failed transaction' : isTaken ? 'tokens taken by someone else' : risk >= 30 ? 'risky approval given' : 'normal transaction';
  const summary = [`${who(from)} called ${fn ? fn.split('(')[0] : 'a plain transfer'}${to ? ` on ${who(to)}` : ''}${time ? ` on ${time.slice(0, 16).replace('T', ' ')} UTC` : ''}; ${status}${fee ? `, fee ${fee}` : ''}.`, ...moves.slice(0, 12).map((m) => m.text)];
  const advice = verdict === 'tokens taken by someone else'
    ? ['The owner signed an approval or permit earlier. Revoke every approval on that wallet now (oculon approvals <wallet>) and move what is left to a new wallet.', 'Follow the funds: oculon trace <receiving address>']
    : verdict === 'risky approval given' ? ['Revoke this approval unless you meant it: oculon approvals <wallet>'] : ['Nothing unusual in this transaction.'];
  return { module: 'tx', input: hash, generatedAt: ctx.now().toISOString(), signals: [], provenance, result: { ...base, status, verdict, risk, function: fn, fee, time, summary, moves, reasons: reasons.map(([r]) => r), advice } };
}
