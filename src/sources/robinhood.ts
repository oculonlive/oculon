/** Robinhood Chain (id 4663) data: GeckoTerminal pools (keyless) and Blockscout explorer API. */
import { enc, type Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import type { Sourced } from '../core/types.js';

export const RH_CHAIN_ID = 4663;
const GT = 'https://api.geckoterminal.com/api/v2/networks/robinhood';

export interface Pool {
  name: string;
  address: string;
  token: string;
  createdAt: string;
  liquidityUsd: number;
  volume24h: number;
  change1h: number | null;
  change24h: number | null;
  buys24h: number;
  sells24h: number;
  buyers24h: number;
  sellers24h: number;
  fdvUsd: number | null;
  url: string;
}

interface GtPool {
  id: string;
  attributes: {
    name: string;
    address: string;
    pool_created_at: string;
    reserve_in_usd?: string;
    fdv_usd?: string | null;
    volume_usd?: { h24?: string };
    price_change_percentage?: { h1?: string; h24?: string };
    transactions?: { h24?: { buys?: number; sells?: number; buyers?: number; sellers?: number } };
  };
  relationships?: { base_token?: { data?: { id?: string } } };
}

const n = (v: string | number | null | undefined) => (v === null || v === undefined || v === '' ? null : Number(v));

export function toPool(p: GtPool): Pool {
  const a = p.attributes;
  const tx = a.transactions?.h24 ?? {};
  return {
    name: a.name,
    address: a.address,
    token: (p.relationships?.base_token?.data?.id ?? '').replace(/^robinhood_/, ''),
    createdAt: a.pool_created_at,
    liquidityUsd: n(a.reserve_in_usd) ?? 0,
    volume24h: n(a.volume_usd?.h24) ?? 0,
    change1h: n(a.price_change_percentage?.h1),
    change24h: n(a.price_change_percentage?.h24),
    buys24h: tx.buys ?? 0,
    sells24h: tx.sells ?? 0,
    buyers24h: tx.buyers ?? 0,
    sellers24h: tx.sellers ?? 0,
    fdvUsd: n(a.fdv_usd),
    url: `https://www.geckoterminal.com/robinhood/pools/${a.address}`,
  };
}

async function pools(ctx: Ctx, path: string, ttlSec: number): Promise<Sourced<Pool[]>> {
  const r = await ctx.http.get<{ data?: GtPool[] }>(`${GT}${path}`, { source: 'geckoterminal', ttlSec });
  return { data: r.data?.data?.map(toPool) ?? null, prov: r.prov };
}

export const newPools = (ctx: Ctx) => pools(ctx, '/new_pools?page=1', 120);
export const trendingPools = (ctx: Ctx) => pools(ctx, '/trending_pools?page=1', 300);
export const tokenPools = (ctx: Ctx, token: string) => pools(ctx, `/tokens/${enc(token)}/pools?page=1`, 300);

const bs = (path: string) => {
  const k = key('BLOCKSCOUT_API_KEY');
  return `https://api.blockscout.com/${RH_CHAIN_ID}/api/v2${path}${k ? `${path.includes('?') ? '&' : '?'}apikey=${k}` : ''}`;
};

export interface ChainStats {
  blocks: number;
  transactions: number;
  addresses: number;
  transactionsToday: number;
  gasAverage: number | null;
}

export async function chainStats(ctx: Ctx): Promise<Sourced<ChainStats>> {
  const r = await ctx.http.get<{ total_blocks?: string; total_transactions?: string; total_addresses?: string; transactions_today?: string; gas_prices?: { average?: number } }>(bs('/stats'), {
    source: 'blockscout',
    ttlSec: 600,
  });
  const d = r.data;
  return {
    data: d?.total_blocks ? { blocks: Number(d.total_blocks), transactions: Number(d.total_transactions), addresses: Number(d.total_addresses), transactionsToday: Number(d.transactions_today ?? 0), gasAverage: d.gas_prices?.average ?? null } : null,
    prov: r.prov,
  };
}

export interface RhToken {
  name: string;
  symbol: string;
  holders: number;
  totalSupply: number;
  decimals: number;
}

export async function rhToken(ctx: Ctx, address: string): Promise<Sourced<RhToken>> {
  const r = await ctx.http.get<{ name?: string; symbol?: string; holders_count?: string; holders?: string; total_supply?: string; decimals?: string }>(bs(`/tokens/${enc(address)}`), { source: 'blockscout', ttlSec: 600 });
  const d = r.data;
  return {
    data: d?.symbol !== undefined ? { name: d.name ?? '', symbol: d.symbol ?? '', holders: Number(d.holders_count ?? d.holders ?? 0), totalSupply: Number(d.total_supply ?? 0), decimals: Number(d.decimals ?? 18) } : null,
    prov: r.prov,
  };
}

interface Holder { value: string; address?: { hash?: string; is_contract?: boolean; proxy_type?: string | null } }

/**
 * Wallets that can sell: pools, the Uniswap v4 PoolManager, launchpad lockers and burn addresses hold tokens
 * nobody can dump, so they are left out. EIP-7702 accounts are wallets even though the explorer calls them contracts.
 */
export function sellerHolder(h: Holder): boolean {
  const a = h.address;
  if (!a?.hash) return true;
  if (/^0x0{40}$|^0x0{36}dead$/i.test(a.hash)) return false;
  return !a.is_contract || a.proxy_type === 'eip7702';
}

/** Share of supply held by the 10 largest wallets that can sell (0-1). */
export async function topHolderShare(ctx: Ctx, address: string, totalSupply: number): Promise<Sourced<number>> {
  const r = await ctx.http.get<{ items?: Holder[] }>(bs(`/tokens/${enc(address)}/holders`), { source: 'blockscout', ttlSec: 600 });
  if (!r.data?.items || !totalSupply) return { data: null, prov: r.prov };
  const top = r.data.items.filter(sellerHolder).slice(0, 10).reduce((a, h) => a + Number(h.value), 0);
  return { data: Math.min(1, top / totalSupply), prov: r.prov };
}

/** Who deployed a contract (null for a plain wallet). */
export async function contractCreator(ctx: Ctx, address: string): Promise<Sourced<{ creator: string; creationTx: string | null } | null>> {
  const r = await ctx.http.get<{ creator_address_hash?: string | null; creation_transaction_hash?: string | null; creation_tx_hash?: string | null; is_contract?: boolean }>(bs(`/addresses/${enc(address)}`), {
    source: 'blockscout',
    ttlSec: 86_400,
  });
  const d = r.data;
  if (!d) return { data: null, prov: r.prov };
  return { data: d.creator_address_hash ? { creator: d.creator_address_hash, creationTx: d.creation_transaction_hash ?? d.creation_tx_hash ?? null } : null, prov: r.prov };
}

export interface CreatedContract {
  address: string;
  name: string | null;
  createdAt: string;
}

/** Contracts deployed by an address, from its most recent transactions (one page, newest first). */
export async function createdContracts(ctx: Ctx, deployer: string): Promise<Sourced<CreatedContract[]>> {
  const r = await ctx.http.get<{ items?: { created_contract?: { hash: string; name?: string | null } | null; timestamp?: string }[] }>(bs(`/addresses/${enc(deployer)}/transactions`), {
    source: 'blockscout',
    ttlSec: 3600,
  });
  return {
    data: r.data?.items?.filter((t) => t.created_contract?.hash).map((t) => ({ address: t.created_contract!.hash, name: t.created_contract!.name ?? null, createdAt: t.timestamp ?? '' })) ?? null,
    prov: r.prov,
  };
}

export async function addressInfo(ctx: Ctx, address: string): Promise<Sourced<{ isContract: boolean; name: string | null }>> {
  const r = await ctx.http.get<{ is_contract?: boolean; name?: string | null }>(bs(`/addresses/${enc(address)}`), { source: 'blockscout', ttlSec: 86_400 });
  return { data: r.data ? { isContract: Boolean(r.data.is_contract), name: r.data.name ?? null } : null, prov: r.prov };
}

export async function txParties(ctx: Ctx, hash: string): Promise<Sourced<{ from: string; to: string | null; method: string | null }>> {
  const r = await ctx.http.get<{ from?: { hash: string }; to?: { hash: string } | null; method?: string | null }>(bs(`/transactions/${enc(hash)}`), { source: 'blockscout', ttlSec: 30 * 86_400 });
  return { data: r.data?.from ? { from: r.data.from.hash, to: r.data.to?.hash ?? null, method: r.data.method ?? null } : null, prov: r.prov };
}

/**
 * Tokens a wallet launched through a launchpad/factory contract: its transactions to the launcher, then the
 * contracts each one created internally. Limited to the most recent `max` launches.
 */
export async function launchesVia(ctx: Ctx, wallet: string, launcher: string, max = 15): Promise<Sourced<CreatedContract[]>> {
  const txs = await ctx.http.get<{ items?: { hash: string; to?: { hash: string } | null; timestamp?: string }[] }>(bs(`/addresses/${enc(wallet)}/transactions`), { source: 'blockscout', ttlSec: 3600 });
  if (!txs.data) return { data: null, prov: txs.prov };
  const calls = (txs.data.items ?? []).filter((t) => t.to?.hash?.toLowerCase() === launcher.toLowerCase()).slice(0, max);
  const out: CreatedContract[] = [];
  for (const t of calls) {
    const it = await ctx.http.get<{ items?: { type?: string; created_contract?: { hash: string; name?: string | null } | null }[] }>(bs(`/transactions/${enc(t.hash)}/internal-transactions`), { source: 'blockscout', ttlSec: 30 * 86_400 });
    for (const x of it.data?.items ?? []) if ((x.type === 'create' || x.type === 'create2') && x.created_contract?.hash) out.push({ address: x.created_contract.hash, name: x.created_contract.name ?? null, createdAt: t.timestamp ?? '' });
  }
  return { data: out, prov: txs.prov };
}

export interface TokenMarket {
  symbol: string;
  reserveUsd: number;
  volume24h: number;
}

/** Market data for up to 30 tokens in one GeckoTerminal call. Tokens without pools are simply absent. */
export async function tokensMarket(ctx: Ctx, addresses: string[], ttlSec = 900): Promise<Sourced<Map<string, TokenMarket>>> {
  const list = addresses.slice(0, 30);
  if (!list.length) return { data: new Map(), prov: { source: 'geckoterminal', url: '', status: 'LIVE', fetchedAt: new Date().toISOString(), note: 'nothing to look up' } };
  const r = await ctx.http.get<{ data?: { attributes: { address: string; symbol: string; total_reserve_in_usd?: string | null; volume_usd?: { h24?: string } } }[] }>(`${GT}/tokens/multi/${list.join(',')}`, { source: 'geckoterminal', ttlSec });
  const m = new Map<string, TokenMarket>();
  for (const t of r.data?.data ?? []) m.set(t.attributes.address.toLowerCase(), { symbol: t.attributes.symbol, reserveUsd: Number(t.attributes.total_reserve_in_usd ?? 0), volume24h: Number(t.attributes.volume_usd?.h24 ?? 0) });
  return { data: r.data ? m : null, prov: r.prov };
}

export async function isVerified(ctx: Ctx, address: string): Promise<Sourced<boolean>> {
  const r = await ctx.http.get<{ is_verified?: boolean }>(bs(`/smart-contracts/${enc(address)}`), { source: 'blockscout', ttlSec: 3600 });
  if (r.prov.status === 'UNAVAILABLE') return { data: false, prov: { ...r.prov, status: 'LIVE', note: 'no verified source' } };
  return { data: r.data ? Boolean(r.data.is_verified) : null, prov: r.prov };
}
