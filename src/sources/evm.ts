/**
 * EVM reads for the wallet-safety checks.
 *   RPC: public endpoints (publicnode), with Alchemy (ALCHEMY_API_KEY, free) as the fallback when one fails.
 *   History: an explorer API for logs, transaction lists and token transfers: Etherscan v2 (free key: Ethereum,
 *     Arbitrum, Polygon) or Blockscout (BLOCKSCOUT_API_KEY, free: Optimism, Robinhood Chain). Where neither
 *     covers a chain (Base, BNB Chain), Alchemy's transfers API gives transfers and value transactions, but not
 *     logs, so approvals stay unavailable there and the checks say so.
 *   Verified code: Sourcify, then the explorer.
 */
import { enc, type Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import type { Provenance, Sourced } from '../core/types.js';
import { postJson } from './press.js';

export interface EvmChain {
  key: string;
  id: number;
  label: string;
  native: string;
  rpc: string | null;
  /** Explorer API that answers logs, transaction lists and token transfers for free on this chain. */
  scan: 'etherscan' | 'blockscout' | null;
  /** Alchemy network name (transfers, prices, RPC fallback). */
  alchemy: string | null;
  explorer: string;
}

/** What a check needs from a chain: event logs (approvals), transfers (poisoning, trace), contract creation (creator). */
export type Need = 'logs' | 'transfers' | 'creation';

export const EVM_CHAINS: Record<string, EvmChain> = {
  eth: { key: 'eth', id: 1, label: 'Ethereum', native: 'ETH', rpc: 'https://ethereum-rpc.publicnode.com', scan: 'etherscan', alchemy: 'eth-mainnet', explorer: 'https://etherscan.io' },
  arbitrum: { key: 'arbitrum', id: 42161, label: 'Arbitrum', native: 'ETH', rpc: 'https://arbitrum-one-rpc.publicnode.com', scan: 'etherscan', alchemy: 'arb-mainnet', explorer: 'https://arbiscan.io' },
  polygon: { key: 'polygon', id: 137, label: 'Polygon', native: 'POL', rpc: 'https://polygon-bor-rpc.publicnode.com', scan: 'etherscan', alchemy: 'polygon-mainnet', explorer: 'https://polygonscan.com' },
  optimism: { key: 'optimism', id: 10, label: 'Optimism', native: 'ETH', rpc: 'https://optimism-rpc.publicnode.com', scan: 'blockscout', alchemy: 'opt-mainnet', explorer: 'https://optimistic.etherscan.io' },
  base: { key: 'base', id: 8453, label: 'Base', native: 'ETH', rpc: 'https://base-rpc.publicnode.com', scan: null, alchemy: 'base-mainnet', explorer: 'https://basescan.org' },
  bsc: { key: 'bsc', id: 56, label: 'BNB Chain', native: 'BNB', rpc: 'https://bsc-rpc.publicnode.com', scan: null, alchemy: 'bnb-mainnet', explorer: 'https://bscscan.com' },
  robinhood: { key: 'robinhood', id: 4663, label: 'Robinhood Chain', native: 'ETH', rpc: null, scan: 'blockscout', alchemy: null, explorer: 'https://robinhood.blockscout.com' },
};
const ALIAS: Record<string, string> = { ethereum: 'eth', mainnet: 'eth', arb: 'arbitrum', matic: 'polygon', pol: 'polygon', op: 'optimism', bnb: 'bsc', rh: 'robinhood' };

const scanKey = (c: EvmChain) => (c.scan === 'etherscan' ? key('ETHERSCAN_API_KEY') : c.scan === 'blockscout' ? key('BLOCKSCOUT_API_KEY') : undefined);

/** Can this install answer `need` on chain `c` with the keys it has? */
export function chainCan(c: EvmChain, need: Need): boolean {
  if (need === 'transfers') return Boolean((c.scan && scanKey(c)) || (c.alchemy && key('ALCHEMY_API_KEY')));
  return Boolean(c.scan && scanKey(c));
}

export function evmChain(name: string | undefined, need?: Need): EvmChain {
  const k = (name ?? 'eth').trim().toLowerCase();
  const c = EVM_CHAINS[ALIAS[k] ?? k];
  const ok = Object.values(EVM_CHAINS).filter((x) => !need || chainCan(x, need));
  if (!c) throw new Error(`not a supported chain: ${k} (use ${ok.map((x) => x.key).join(', ')})`);
  if (need && !chainCan(c, need)) throw new Error(`${c.label} is not covered for this check by the free data sources (${need === 'logs' ? 'it needs event logs' : need === 'creation' ? 'it needs contract creation data' : 'it needs transaction history'}); supported here: ${ok.map((x) => x.label).join(', ')}`);
  return c;
}

export const isAddr = (s: string) => /^0x[0-9a-fA-F]{40}$/.test(s.trim());
export const ZERO = '0x0000000000000000000000000000000000000000';
export const DEAD = /^0x0{40}$|^0x0{36}dead$|^0x000000000000000000000000000000000000dead$/i;

export const TOPIC = {
  transfer: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
  approval: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
  approvalForAll: '0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31',
};
export const MAX_UINT = (1n << 256n) - 1n;
/** Treat anything above 2^200 as "unlimited": wallets send max uint256 or max uint160 (Permit2). */
export const UNLIMITED = 1n << 150n;

export const pad = (a: string) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
export const topicAddr = (t: string) => `0x${t.slice(-40)}`.toLowerCase();
export const wordAt = (hex: string, i: number) => hex.replace(/^0x/, '').slice(i * 64, i * 64 + 64);
export const wordAddr = (hex: string, i: number) => `0x${wordAt(hex, i).slice(24)}`.toLowerCase();
export const wordInt = (hex: string, i: number) => { const w = wordAt(hex, i); return w ? BigInt(`0x${w}`) : 0n; };

/** Decode an ABI-encoded string return (name(), symbol()), or a bytes32 one some old tokens use. */
export function abiString(hex: string | null): string | null {
  if (!hex || hex === '0x') return null;
  const h = hex.replace(/^0x/, '');
  try {
    if (h.length >= 128) {
      const off = Number(BigInt(`0x${h.slice(0, 64)}`)) * 2;
      const len = Number(BigInt(`0x${h.slice(off, off + 64)}`));
      if (len < 200) return Buffer.from(h.slice(off + 64, off + 64 + len * 2), 'hex').toString('utf8').replace(/\0/g, '').trim() || null;
    }
    if (h.length === 64) return Buffer.from(h, 'hex').toString('utf8').replace(/\0/g, '').trim() || null;
  } catch {}
  return null;
}

function rpcUrl(c: EvmChain): string | null {
  return c.key === 'robinhood' ? key('ROBINHOOD_PUBLIC_RPC_URL') ?? null : c.rpc;
}

export async function rpcCall<T>(ctx: Ctx, c: EvmChain, method: string, params: unknown[], ttlSec = 60): Promise<Sourced<T>> {
  const url = rpcUrl(c);
  const source = `rpc-${c.key}`;
  if (!url) return { data: null, prov: { source, url: 'rpc', status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: 'no RPC configured for this chain' } };
  const r = await postJson<{ result?: T; error?: { message: string } }>(ctx, url, { jsonrpc: '2.0', id: 1, method, params }, {}, source, ttlSec);
  const failed = !r.data || (r.data.error && !/execution reverted|invalid opcode|out of gas/i.test(r.data.error.message));
  // The public endpoint is down or refuses: ask Alchemy instead when a key is set.
  const ak = key('ALCHEMY_API_KEY');
  if (failed && c.alchemy && ak) {
    const a = await postJson<{ result?: T; error?: { message: string } }>(ctx, `https://${c.alchemy}.g.alchemy.com/v2/${ak}`, { jsonrpc: '2.0', id: 1, method, params }, {}, `alchemy-${c.key}`, ttlSec);
    const prov = { ...a.prov, url: a.prov.url.replace(/\/v2\/[^/?]+/, '/v2/***') };
    if (a.data && !a.data.error) return { data: a.data.result ?? null, prov };
  }
  if (r.data?.error) return { data: null, prov: { ...r.prov, status: 'ERROR', note: r.data.error.message.slice(0, 120) } };
  return { data: r.data?.result ?? null, prov: r.prov };
}

export const ethCall = (ctx: Ctx, c: EvmChain, to: string, data: string, ttlSec = 60) => rpcCall<string>(ctx, c, 'eth_call', [{ to, data }, 'latest'], ttlSec);

export async function codeAt(ctx: Ctx, c: EvmChain, a: string): Promise<string | null> {
  return (await rpcCall<string>(ctx, c, 'eth_getCode', [a, 'latest'], 3600)).data;
}

/** name, symbol and decimals of a token; null fields when the call fails. */
export async function tokenMeta(ctx: Ctx, c: EvmChain, token: string): Promise<{ name: string | null; symbol: string | null; decimals: number | null }> {
  const [n, s, d] = await Promise.all([ethCall(ctx, c, token, '0x06fdde03', 86_400), ethCall(ctx, c, token, '0x95d89b41', 86_400), ethCall(ctx, c, token, '0x313ce567', 86_400)]);
  const dec = d.data && d.data.length >= 66 ? Number(BigInt(d.data.slice(0, 66))) : null;
  return { name: abiString(n.data), symbol: abiString(s.data), decimals: dec !== null && dec <= 36 ? dec : null };
}

export function formatUnits(v: bigint, decimals: number | null, digits = 4): string {
  if (v >= UNLIMITED) return 'unlimited';
  const d = decimals ?? 18;
  const whole = v / 10n ** BigInt(d);
  const frac = Number(v % 10n ** BigInt(d)) / 10 ** d;
  const n = Number(whole) + frac;
  return n >= 1e9 ? `${(n / 1e9).toFixed(2)}B` : n >= 1e6 ? `${(n / 1e6).toFixed(2)}M` : n.toLocaleString('en-US', { maximumFractionDigits: n < 1 ? 6 : digits });
}

/* ---------- Etherscan v2 ---------- */

type EsResult<T> = { status?: string; message?: string; result?: T | string };

/** Etherscan-style explorer API: Etherscan v2 or Blockscout, whichever covers the chain for free. */
export async function etherscan<T>(ctx: Ctx, c: EvmChain, params: Record<string, string>, ttlSec = 600): Promise<Sourced<T>> {
  const k = scanKey(c);
  const qs = Object.entries(params).map(([a, b]) => `${a}=${enc(b)}`).join('&');
  const source = c.scan === 'blockscout' ? 'blockscout' : 'etherscan';
  const url = c.scan === 'blockscout' ? `https://api.blockscout.com/${c.id}/api?${qs}` : `https://api.etherscan.io/v2/api?chainid=${c.id}&${qs}`;
  if (!c.scan) return { data: null, prov: { source, url, status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: `no free explorer API covers ${c.label}` } };
  if (!k) return { data: null, prov: { source, url, status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: `set ${c.scan === 'blockscout' ? 'BLOCKSCOUT_API_KEY' : 'ETHERSCAN_API_KEY'} (free)` } };
  const r = await ctx.http.get<EsResult<T>>(`${url}&apikey=${k}`, { source, ttlSec });
  const prov: Provenance = { ...r.prov, url: r.prov.url.replace(/apikey=[^&]+/, 'apikey=***') };
  const res = r.data?.result;
  if (typeof res === 'string' || res === undefined) {
    // "No records found" style answers are an empty list, not a failure.
    if (/no (transactions|records|logs) found/i.test(r.data?.message ?? '') || /no (transactions|records|logs) found/i.test(String(res ?? ''))) return { data: [] as unknown as T, prov };
    return { data: null, prov: { ...prov, status: r.data ? 'ERROR' : prov.status, note: String(res ?? r.data?.message ?? prov.note ?? '').slice(0, 120) } };
  }
  return { data: res, prov };
}

export interface EsLog { address: string; topics: string[]; data: string; blockNumber: string; timeStamp: string; transactionHash: string }
export interface EsTokenTx { hash: string; timeStamp: string; from: string; to: string; value: string; contractAddress: string; tokenSymbol: string; tokenName: string; tokenDecimal: string }
export interface EsTx { hash: string; timeStamp: string; from: string; to: string; value: string; isError: string; functionName?: string; methodId?: string; contractAddress?: string }

export const esLogs = (ctx: Ctx, c: EvmChain, topic0: string, topic1: string) =>
  etherscan<EsLog[]>(ctx, c, { module: 'logs', action: 'getLogs', fromBlock: '0', toBlock: 'latest', topic0, topic1, topic0_1_opr: 'and', page: '1', offset: '1000' }, 600);
/** Where a chain's transfer history comes from: an explorer API, or Alchemy's transfers API. */
export const historySource = (c: EvmChain): 'explorer' | 'alchemy' | null => (c.scan && scanKey(c) ? 'explorer' : c.alchemy && key('ALCHEMY_API_KEY') ? 'alchemy' : null);

export const esTokenTx = (ctx: Ctx, c: EvmChain, address: string, n = 200): Promise<Sourced<EsTokenTx[]>> =>
  historySource(c) === 'alchemy'
    ? alchemyTransfers(ctx, c, address, ['erc20'], n).then((r) => ({ data: r.data as EsTokenTx[] | null, prov: r.prov }))
    : etherscan<EsTokenTx[]>(ctx, c, { module: 'account', action: 'tokentx', address, page: '1', offset: String(n), sort: 'desc' }, 600);
/** Transactions of an address. From Alchemy only value transfers are listed (no zero-value contract calls). */
export const esTxList = (ctx: Ctx, c: EvmChain, address: string, n = 100, sort: 'asc' | 'desc' = 'desc'): Promise<Sourced<EsTx[]>> =>
  historySource(c) === 'alchemy'
    ? alchemyTransfers(ctx, c, address, ['external'], n, sort).then((r) => ({ data: r.data as EsTx[] | null, prov: r.prov }))
    : etherscan<EsTx[]>(ctx, c, { module: 'account', action: 'txlist', address, page: '1', offset: String(n), sort }, 600);

/* ---------- Alchemy ---------- */

interface AlTransfer { hash: string; from: string; to: string | null; asset: string | null; category: string; rawContract?: { value?: string | null; address?: string | null; decimal?: string | null }; metadata?: { blockTimestamp?: string } }

/**
 * Transfers in and out of an address (alchemy_getAssetTransfers), shaped like Etherscan's tokentx / txlist rows,
 * newest first. Two requests: one for each direction.
 */
export async function alchemyTransfers(ctx: Ctx, c: EvmChain, address: string, category: ('erc20' | 'external' | 'erc721' | 'erc1155')[], n = 200, sort: 'asc' | 'desc' = 'desc'): Promise<Sourced<(EsTokenTx & EsTx)[]>> {
  const k = key('ALCHEMY_API_KEY');
  const url = `https://${c.alchemy}.g.alchemy.com/v2/${k}`;
  const shown = url.replace(/\/v2\/.*$/, '/v2/***');
  if (!k || !c.alchemy) return { data: null, prov: { source: 'alchemy', url: shown, status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: 'set ALCHEMY_API_KEY (free)' } };
  const max = `0x${Math.min(1000, n).toString(16)}`;
  const q = (dir: 'fromAddress' | 'toAddress') => postJson<{ result?: { transfers: AlTransfer[] }; error?: { message: string } }>(ctx, url, { jsonrpc: '2.0', id: 1, method: 'alchemy_getAssetTransfers', params: [{ [dir]: address, category, maxCount: max, order: sort, withMetadata: true, excludeZeroValue: false }] }, {}, `alchemy-${c.key}`, 600);
  const [a, b] = await Promise.all([q('fromAddress'), q('toAddress')]);
  const prov = { ...a.prov, url: shown };
  if (!a.data?.result && !b.data?.result) return { data: null, prov: { ...prov, status: 'ERROR', note: (a.data?.error ?? b.data?.error)?.message?.slice(0, 120) ?? prov.note } };
  const rows = [...(a.data?.result?.transfers ?? []), ...(b.data?.result?.transfers ?? [])].map((t) => {
    const raw = t.rawContract?.value ?? '0x0';
    const dec = t.rawContract?.decimal ? String(Number(BigInt(t.rawContract.decimal))) : '18';
    return { hash: t.hash, timeStamp: String(Math.floor(Date.parse(t.metadata?.blockTimestamp ?? '1970-01-01') / 1000)), from: t.from, to: t.to ?? '', value: BigInt(raw || '0x0').toString(), contractAddress: t.category === 'external' ? '' : (t.rawContract?.address ?? ''), tokenSymbol: t.asset ?? '', tokenName: t.asset ?? '', tokenDecimal: dec, isError: '0' };
  });
  const seen = new Set<string>();
  const uniq = rows.filter((r) => { const id = `${r.hash}|${r.from}|${r.to}|${r.contractAddress}|${r.value}`; if (seen.has(id)) return false; seen.add(id); return true; });
  uniq.sort((x, y) => (sort === 'desc' ? Number(y.timeStamp) - Number(x.timeStamp) : Number(x.timeStamp) - Number(y.timeStamp)));
  return { data: uniq.slice(0, n), prov };
}

/** Alchemy marks NFT collections it considers spam. Null when unknown or without a key. */
export async function alchemyIsSpam(ctx: Ctx, c: EvmChain, contract: string): Promise<boolean | null> {
  const k = key('ALCHEMY_API_KEY');
  if (!k || !c.alchemy) return null;
  const r = await ctx.http.get<{ isSpamContract?: boolean }>(`https://${c.alchemy}.g.alchemy.com/nft/v3/${k}/isSpamContract?contractAddress=${contract}`, { source: `alchemy-${c.key}`, ttlSec: 86_400, retries: 0 });
  return typeof r.data?.isSpamContract === 'boolean' ? r.data.isSpamContract : null;
}

/** USD prices of tokens on a chain (Alchemy Prices API), by lower-case address. */
export async function alchemyPrices(ctx: Ctx, c: EvmChain, tokens: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const k = key('ALCHEMY_API_KEY');
  if (!k || !c.alchemy || !tokens.length) return out;
  for (let i = 0; i < tokens.length && i < 75; i += 25) {
    const r = await postJson<{ data?: { address: string; prices?: { value: string }[] }[] }>(ctx, `https://api.g.alchemy.com/prices/v1/${k}/tokens/by-address`, { addresses: tokens.slice(i, i + 25).map((address) => ({ network: c.alchemy, address })) }, {}, 'alchemy-prices', 900);
    for (const d of r.data?.data ?? []) { const v = Number(d.prices?.[0]?.value); if (Number.isFinite(v) && v > 0) out.set(d.address.toLowerCase(), v); }
  }
  return out;
}

/* ---------- Sourcify ---------- */

export interface AbiItem { type: string; name?: string; inputs?: { name: string; type: string }[]; stateMutability?: string }
export interface Verified { name: string | null; abi: AbiItem[]; compiler: string | null; proxy: { isProxy: boolean; type: string | null; implementations: { address: string; name: string | null }[] } | null; source: 'sourcify' | 'etherscan' }

export async function sourcify(ctx: Ctx, c: EvmChain, a: string): Promise<Sourced<Verified>> {
  const r = await ctx.http.get<{ abi?: AbiItem[]; compilation?: { name?: string; compilerVersion?: string }; proxyResolution?: { isProxy?: boolean; proxyType?: string; implementations?: { address: string; name?: string }[] } }>(
    `https://sourcify.dev/server/v2/contract/${c.id}/${a}?fields=abi,compilation,proxyResolution`, { source: 'sourcify', ttlSec: 86_400, retries: 1 });
  if (!r.data?.abi) return { data: null, prov: r.prov.note === 'HTTP 404' ? { ...r.prov, status: 'LIVE', note: 'not verified on Sourcify' } : r.prov };
  const p = r.data.proxyResolution;
  return {
    data: { name: r.data.compilation?.name ?? null, abi: r.data.abi, compiler: r.data.compilation?.compilerVersion ?? null, proxy: p ? { isProxy: Boolean(p.isProxy), type: p.proxyType ?? null, implementations: (p.implementations ?? []).map((i) => ({ address: i.address, name: i.name ?? null })) } : null, source: 'sourcify' },
    prov: r.prov,
  };
}

/** Verified source from Etherscan (Ethereum, Arbitrum, Polygon on the free plan). */
export async function etherscanSource(ctx: Ctx, c: EvmChain, a: string): Promise<Sourced<Verified>> {
  if (!chainCan(c, 'logs')) return { data: null, prov: { source: 'etherscan', url: 'https://api.etherscan.io/v2/api', status: 'UNAVAILABLE', fetchedAt: ctx.now().toISOString(), note: `no free explorer API for ${c.label}` } };
  const r = await etherscan<{ ContractName?: string; ABI?: string; CompilerVersion?: string; Proxy?: string; Implementation?: string }[]>(ctx, c, { module: 'contract', action: 'getsourcecode', address: a }, 86_400);
  const d = r.data?.[0];
  if (!d?.ABI || !d.ABI.startsWith('[')) return { data: null, prov: d ? { ...r.prov, note: 'not verified on Etherscan' } : r.prov };
  let abi: AbiItem[] = [];
  try { abi = JSON.parse(d.ABI) as AbiItem[]; } catch {}
  return { data: { name: d.ContractName || null, abi, compiler: d.CompilerVersion || null, proxy: d.Proxy === '1' ? { isProxy: true, type: null, implementations: d.Implementation ? [{ address: d.Implementation, name: null }] : [] } : null, source: 'etherscan' }, prov: r.prov };
}

/** Function selectors pushed in deployed bytecode (PUSH4 operands), for contracts without verified source. */
export function bytecodeSelectors(code: string): string[] {
  const h = code.replace(/^0x/, '');
  const out = new Set<string>();
  for (let i = 0; i < h.length; i += 2) {
    const op = parseInt(h.slice(i, i + 2), 16);
    if (op === 0x63) out.add(`0x${h.slice(i + 2, i + 10)}`);
    if (op >= 0x60 && op <= 0x7f) i += (op - 0x5f) * 2;
  }
  return [...out].filter((s) => s.length === 10 && s !== '0xffffffff' && s !== '0x00000000');
}

/** Names of well known spenders and routers, so an approval to them reads as what it is. */
export const KNOWN: Record<string, string> = {
  '0x000000000022d473030f116ddee9f6b43ac78ba3': 'Uniswap Permit2',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': 'Uniswap Universal Router',
  '0x66a9893cc07d91d95644aedd05d03f95e1dba8af': 'Uniswap Universal Router (v4)',
  '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b': 'Uniswap Universal Router (old)',
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router',
  '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3 Router',
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'Uniswap V3 Router 02',
  '0x1111111254eeb25477b68fb85ed929f73a960582': '1inch Router v5',
  '0x111111125421ca6dc452d289314280a0f8842a65': '1inch Router v6',
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff': '0x Exchange Proxy',
  '0xc92e8bdf79f0507f65a392b0ab4667716bfe0110': 'CoW Protocol Vault Relayer',
  '0x0000000000000068f116a894984e2db1123eb395': 'OpenSea Seaport 1.6',
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': 'OpenSea Seaport 1.5',
  '0x1e0049783f008a0085193e00003d00cd54003c71': 'OpenSea Conduit',
  '0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f': 'SushiSwap Router',
  '0x881d40237659c251811cec9c364ef91dc08d300c': 'MetaMask Swap Router',
  '0x6131b5fae19ea4f9d964eac0408e4408b66337b5': 'KyberSwap Router',
  '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2': 'Aave V3 Pool',
  '0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9': 'Aave V2 Pool',
  '0xba12222222228d8ba445958a75a0704d566bf2c8': 'Balancer Vault',
  '0x9008d19f58aabd9ed0d60971565aa8510560ab41': 'CoW Protocol Settlement',
  '0x00000000006c3852cbef3e08e8df289169ede581': 'OpenSea Seaport 1.1',
};

export const labelOf = (a: string) => KNOWN[a.toLowerCase()] ?? null;
