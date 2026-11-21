/**
 * On-chain sources: Zerion (portfolio), Etherscan v2 (transactions, multi-chain), GoPlus (token/address security),
 * (public endpoints; GoPlus keys are not needed for these calls), Webacy (address risk), DexScreener (pairs, keyless), Helius (Solana), Robinhood Chain RPC + Blockscout.
 */
import { enc, type Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Sourced } from '../core/types.js';
import { postJson } from './press.js';
import { decodeSelectors, methodName } from './signatures.js';

export const isEvmAddress = (s: string) => /^0x[0-9a-fA-F]{40}$/.test(s.trim());
export const isSolanaAddress = (s: string) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s.trim()) && !isEvmAddress(s);

export const CHAINS: Record<string, { id: number; goplus: string | null; coingecko: string | null; label: string }> = {
  eth: { id: 1, goplus: '1', coingecko: 'ethereum', label: 'Ethereum' },
  base: { id: 8453, goplus: '8453', coingecko: 'base', label: 'Base' },
  arbitrum: { id: 42161, goplus: '42161', coingecko: 'arbitrum-one', label: 'Arbitrum' },
  bsc: { id: 56, goplus: '56', coingecko: 'binance-smart-chain', label: 'BNB Chain' },
  polygon: { id: 137, goplus: '137', coingecko: 'polygon-pos', label: 'Polygon' },
  robinhood: { id: 4663, goplus: null, coingecko: null, label: 'Robinhood Chain' },
};

export interface Portfolio {
  totalUsd: number;
  change1dPct: number | null;
  byChain: Record<string, number>;
  top: { name: string; symbol: string; chain: string; valueUsd: number }[];
}

export async function zerionPortfolio(ctx: Ctx, address: string): Promise<Sourced<Portfolio>> {
  const k = key('ZERION_API_KEY');
  if (!k) return noKey('zerion', 'ZERION_API_KEY');
  const auth = { authorization: `Basic ${Buffer.from(`${k}:`).toString('base64')}` };
  const [p, pos] = await Promise.all([
    ctx.http.get<{ data?: { attributes?: { total?: { positions?: number }; changes?: { percent_1d?: number }; positions_distribution_by_chain?: Record<string, number> } } }>(
      `https://api.zerion.io/v1/wallets/${enc(address)}/portfolio`,
      { source: 'zerion', ttlSec: 600, headers: auth },
    ),
    ctx.http.get<{ data?: { attributes: { value?: number | null; fungible_info?: { name?: string; symbol?: string } }; relationships?: { chain?: { data?: { id?: string } } } }[] }>(
      `https://api.zerion.io/v1/wallets/${enc(address)}/positions/?filter[positions]=only_simple&filter[trash]=only_non_trash&currency=usd&sort=-value`,
      {
        source: 'zerion',
        ttlSec: 600,
        headers: auth,
        // Big wallets return thousands of positions; only the 50 largest are ever shown.
        keep: (d: { data?: { attributes: { value?: number | null; fungible_info?: { name?: string; symbol?: string } }; relationships?: { chain?: { data?: { id?: string } } } }[] }) => ({
          data: (d.data ?? [])
            .sort((x, y) => (y.attributes.value ?? 0) - (x.attributes.value ?? 0))
            .slice(0, 50)
            .map((x) => ({ attributes: { value: x.attributes.value, fungible_info: { name: x.attributes.fungible_info?.name, symbol: x.attributes.fungible_info?.symbol } }, relationships: { chain: { data: { id: x.relationships?.chain?.data?.id } } } })),
        }),
      },
    ),
  ]);
  const a = p.data?.data?.attributes;
  if (!a) return { data: null, prov: p.prov };
  return {
    data: {
      totalUsd: a.total?.positions ?? 0,
      change1dPct: a.changes?.percent_1d ?? null,
      byChain: a.positions_distribution_by_chain ?? {},
      top: (pos.data?.data ?? [])
        .filter((x) => (x.attributes.value ?? 0) >= 1)
        .sort((x, y) => (y.attributes.value ?? 0) - (x.attributes.value ?? 0))
        .slice(0, 10)
        .map((x) => ({ name: x.attributes.fungible_info?.name ?? '?', symbol: x.attributes.fungible_info?.symbol ?? '?', chain: x.relationships?.chain?.data?.id ?? '?', valueUsd: x.attributes.value ?? 0 })),
    },
    prov: p.prov,
  };
}

export interface Tx {
  hash: string;
  time: string;
  from: string;
  to: string;
  valueEth: number;
  method: string;
}

export async function etherscanTxs(ctx: Ctx, address: string, chainId = 1, sort: 'asc' | 'desc' = 'desc', n = 20): Promise<Sourced<Tx[]>> {
  const k = key('ETHERSCAN_API_KEY');
  if (!k) return noKey('etherscan', 'ETHERSCAN_API_KEY');
  const r = await ctx.http.get<{ status?: string; message?: string; result?: { hash: string; timeStamp: string; from: string; to: string; value: string; functionName?: string; methodId?: string }[] | string }>(
    `https://api.etherscan.io/v2/api?chainid=${chainId}&module=account&action=txlist&address=${enc(address)}&page=1&offset=${n}&sort=${sort}&apikey=${k}`,
    { source: 'etherscan', ttlSec: 600 },
  );
  const res = r.data?.result;
  const prov = { ...r.prov, url: r.prov.url.replace(/apikey=[^&]+/, 'apikey=***') };
  if (!Array.isArray(res)) return { data: r.data?.message === 'No transactions found' ? [] : null, prov: Array.isArray(res) ? prov : { ...prov, ...(typeof res === 'string' ? { note: res.slice(0, 80) } : {}) } };
  // Unverified contracts come back without a function name: decode the 4-byte selector instead.
  const unknown = [...new Set(res.filter((t) => !t.functionName && t.methodId && t.methodId !== '0x').map((t) => t.methodId!.toLowerCase()))];
  const decoded = unknown.length ? await decodeSelectors(ctx, unknown).catch(() => ({}) as Record<string, string | null>) : {};
  return {
    data: res.map((t) => {
      const sig = t.functionName || (t.methodId ? decoded[t.methodId.toLowerCase()] : null) || '';
      return { hash: t.hash, time: new Date(Number(t.timeStamp) * 1000).toISOString(), from: t.from, to: t.to, valueEth: Number(t.value) / 1e18, method: sig ? methodName(sig)! : t.methodId && t.methodId !== '0x' ? t.methodId : 'transfer' };
    }),
    prov,
  };
}

export interface TokenRisk {
  name: string;
  symbol: string;
  flags: string[];
  buyTax: number | null;
  sellTax: number | null;
  holders: number | null;
  ownerPercent: number | null;
  inDex: boolean;
}

const RISK_FLAGS: [string, string][] = [
  ['is_honeypot', 'honeypot'],
  ['cannot_sell_all', 'cannot sell all'],
  ['is_blacklisted', 'blacklist function'],
  ['hidden_owner', 'hidden owner'],
  ['can_take_back_ownership', 'can take back ownership'],
  ['owner_change_balance', 'owner can change balances'],
  ['selfdestruct', 'self-destruct'],
  ['is_mintable', 'mintable'],
  ['transfer_pausable', 'transfers pausable'],
  ['is_proxy', 'upgradeable proxy'],
  ['slippage_modifiable', 'tax modifiable'],
  ['external_call', 'external calls'],
];

export async function tokenSecurity(ctx: Ctx, chain: string, address: string): Promise<Sourced<TokenRisk>> {
  const r = await ctx.http.get<{ result?: Record<string, Record<string, unknown>> }>(
    `https://api.gopluslabs.io/api/v1/token_security/${enc(chain)}?contract_addresses=${enc(address.toLowerCase())}`,
    { source: 'goplus', ttlSec: 1800 },
  );
  const d = r.data?.result?.[address.toLowerCase()];
  if (!d) return { data: null, prov: r.data ? { ...r.prov, status: 'UNAVAILABLE', note: 'token not indexed by GoPlus' } : r.prov };
  const num = (v: unknown) => (v === undefined || v === '' ? null : Number(v));
  return {
    data: {
      name: String(d.token_name ?? ''),
      symbol: String(d.token_symbol ?? ''),
      flags: RISK_FLAGS.filter(([k]) => d[k] === '1').map(([, label]) => label),
      buyTax: num(d.buy_tax),
      sellTax: num(d.sell_tax),
      holders: num(d.holder_count),
      ownerPercent: num(d.owner_percent),
      inDex: d.is_in_dex === '1',
    },
    prov: r.prov,
  };
}

/** GoPlus malicious-address labels (phishing, sanctioned, stealing attack, ...). */
export async function addressSecurity(ctx: Ctx, address: string, chainId = '1'): Promise<Sourced<string[]>> {
  const r = await ctx.http.get<{ result?: Record<string, string> }>(`https://api.gopluslabs.io/api/v1/address_security/${enc(address)}?chain_id=${chainId}`, {
    source: 'goplus',
    ttlSec: 3600,
  });
  const d = r.data?.result;
  return { data: d ? Object.entries(d).filter(([k, v]) => v === '1' && k !== 'contract_address' && k !== 'data_source').map(([k]) => k.replace(/_/g, ' ')) : null, prov: r.prov };
}

export async function webacyRisk(ctx: Ctx, address: string, chain = 'eth'): Promise<Sourced<{ score: number | null; issues: string[] }>> {
  const k = key('WEBACY_API_KEY');
  if (!k) return noKey('webacy', 'WEBACY_API_KEY');
  const r = await ctx.http.get<{ overallRisk?: number; issues?: { tags?: { name?: string; key?: string }[] }[] }>(`https://api.webacy.com/addresses/${enc(address)}?chain=${enc(chain)}`, {
    source: 'webacy',
    ttlSec: 3600,
    headers: { 'x-api-key': k },
  });
  return {
    data: r.data ? { score: r.data.overallRisk ?? null, issues: [...new Set((r.data.issues ?? []).flatMap((i) => (i.tags ?? []).map((t) => t.name ?? t.key ?? '')).filter(Boolean))].slice(0, 10) } : null,
    prov: r.prov,
  };
}

export interface Pair {
  chain: string;
  dex: string;
  pair: string;
  priceUsd: number | null;
  liquidityUsd: number | null;
  volume24h: number | null;
  change24h: number | null;
  createdAt: string | null;
  url: string;
}

/** DexScreener chain ids for our chain names. */
export const DEX_CHAIN: Record<string, string> = { eth: 'ethereum', base: 'base', arbitrum: 'arbitrum', bsc: 'bsc', polygon: 'polygon', robinhood: 'robinhood' };

type DexPair = { chainId: string; dexId: string; baseToken: { symbol: string }; quoteToken: { symbol: string }; priceUsd?: string; liquidity?: { usd?: number }; volume?: { h24?: number }; priceChange?: { h24?: number }; pairCreatedAt?: number; url: string };

/** Pairs for a token on one chain only (same contract addresses exist on forks such as PulseChain). */
export async function dexPairs(ctx: Ctx, token: string, chain = 'eth'): Promise<Sourced<Pair[]>> {
  const r = await ctx.http.get<DexPair[] | { pairs?: DexPair[] | null }>(`https://api.dexscreener.com/tokens/v1/${enc(DEX_CHAIN[chain] ?? chain)}/${enc(token)}`, { source: 'dexscreener', ttlSec: 300 });
  const list = Array.isArray(r.data) ? r.data : (r.data?.pairs ?? null);
  return {
    data:
      list
        ?.map((p) => ({
          chain: p.chainId,
          dex: p.dexId,
          pair: `${p.baseToken.symbol}/${p.quoteToken.symbol}`,
          priceUsd: p.priceUsd ? Number(p.priceUsd) : null,
          liquidityUsd: p.liquidity?.usd ?? null,
          volume24h: p.volume?.h24 ?? null,
          change24h: p.priceChange?.h24 ?? null,
          createdAt: p.pairCreatedAt ? new Date(p.pairCreatedAt).toISOString() : null,
          url: p.url,
        }))
        .sort((a, b) => (b.liquidityUsd ?? 0) - (a.liquidityUsd ?? 0)) ?? (r.data ? [] : null),
    prov: r.prov,
  };
}

async function rpc<T>(ctx: Ctx, url: string, method: string, params: unknown[], source: string, ttlSec = 30): Promise<Sourced<T>> {
  const r = await postJson<{ result?: T; error?: { message: string } }>(ctx, url, { jsonrpc: '2.0', id: 1, method, params }, {}, source, ttlSec);
  const prov = { ...r.prov, url: r.prov.url.replace(/api-key=[^&]+/, 'api-key=***').replace(/\/v2\/[^/]+$/, '/v2/***') };
  if (r.data?.error) return { data: null, prov: { ...prov, status: 'ERROR', note: r.data.error.message } };
  return { data: r.data?.result ?? null, prov };
}

/** Native balance and transaction count on Robinhood Chain (public RPC). */
export async function robinhoodAccount(ctx: Ctx, address: string): Promise<Sourced<{ balanceEth: number; txCount: number; isContract: boolean }>> {
  const url = key('ROBINHOOD_PUBLIC_RPC_URL');
  if (!url) return noKey('robinhood-rpc', 'ROBINHOOD_PUBLIC_RPC_URL');
  const [bal, n, code] = await Promise.all([
    rpc<string>(ctx, url, 'eth_getBalance', [address, 'latest'], 'robinhood-rpc'),
    rpc<string>(ctx, url, 'eth_getTransactionCount', [address, 'latest'], 'robinhood-rpc'),
    rpc<string>(ctx, url, 'eth_getCode', [address, 'latest'], 'robinhood-rpc', 3600),
  ]);
  if (bal.data === null) return { data: null, prov: bal.prov };
  return { data: { balanceEth: Number(BigInt(bal.data)) / 1e18, txCount: n.data ? Number(BigInt(n.data)) : 0, isContract: Boolean(code.data && code.data !== '0x') }, prov: bal.prov };
}

export async function solanaAccount(ctx: Ctx, address: string): Promise<Sourced<{ sol: number; tokens: number }>> {
  const k = key('HELIUS_API_KEY');
  if (!k) return noKey('helius', 'HELIUS_API_KEY');
  const url = `https://mainnet.helius-rpc.com/?api-key=${k}`;
  const [bal, toks] = await Promise.all([
    rpc<{ value: number }>(ctx, url, 'getBalance', [address], 'helius'),
    rpc<{ value: unknown[] }>(ctx, url, 'getTokenAccountsByOwner', [address, { programId: 'TokenkegQfeZyiNwAJbNbGywRYdTXJ8ZqKt8kXq6S' }, { encoding: 'jsonParsed' }], 'helius'),
  ]);
  if (!bal.data) return { data: null, prov: bal.prov };
  return { data: { sol: bal.data.value / 1e9, tokens: toks.data?.value?.length ?? 0 }, prov: bal.prov };
}
