/**
 * Token burns for /thetoken, read straight from the chain: every Transfer of the token to the dead address or
 * the zero address since the deploy block, with the block time. The total is the dead address balance plus
 * everything sent to the zero address. Callers cache the result so page views do not hit the RPC.
 */

export interface Burn { tx: string; time: string; amount: string }
/** `supply` is what is left after burns, as a plain decimal number (for supply APIs such as CoinGecko's). */
export interface BurnInfo { total: string; percent: string | null; burns: Burn[]; checkedAt: string; supply?: string }

/** A raw amount as a plain decimal number without separators, trailing zeros dropped. */
export function plainUnits(raw: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals);
  const frac = (raw % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${raw / base}${frac ? `.${frac}` : ''}`;
}

const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const DEAD = '0x000000000000000000000000000000000000dead';
const ZERO = '0x0000000000000000000000000000000000000000';
const pad = (a: string) => `0x${a.slice(2).toLowerCase().padStart(64, '0')}`;

/** Whole tokens with thousands separators, plus two decimals when there are any. */
export function formatUnits(raw: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals);
  const whole = raw / base;
  const cents = decimals >= 2 ? (raw % base) / 10n ** BigInt(decimals - 2) : 0n;
  return `${whole.toLocaleString('en-US')}${cents ? `.${cents.toString().padStart(2, '0')}` : ''}`;
}

export type Rpc = <T>(method: string, params: unknown[]) => Promise<T>;

export function rpcClient(url: string, fetchImpl: typeof fetch = fetch): Rpc {
  let id = 0;
  return async <T>(method: string, params: unknown[]) => {
    const r = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }), signal: AbortSignal.timeout(15_000) });
    const j = (await r.json()) as { result?: T; error?: { message?: string } };
    if (j.error || j.result === undefined) throw new Error(`rpc ${method}: ${j.error?.message ?? `HTTP ${r.status}`}`);
    return j.result;
  };
}

interface Log { transactionHash: string; blockNumber: string; data: string; logIndex: string }

export async function readBurns(rpc: Rpc, token: string, fromBlock: number, now = new Date()): Promise<BurnInfo> {
  const call = (data: string) => rpc<string>('eth_call', [{ to: token, data }, 'latest']);
  const [decHex, supplyHex, deadHex] = await Promise.all([call('0x313ce567'), call('0x18160ddd'), call(`0x70a08231${pad(DEAD).slice(2)}`)]);
  const decimals = Number(BigInt(decHex));
  const query = (to: string) => rpc<Log[]>('eth_getLogs', [{ address: token, fromBlock: `0x${fromBlock.toString(16)}`, toBlock: 'latest', topics: [TRANSFER, null, pad(to)] }]);
  const [toDead, toZero] = await Promise.all([query(DEAD), query(ZERO)]);
  const logs = [...toDead, ...toZero];
  const times = new Map<string, string>();
  await Promise.all([...new Set(logs.map((l) => l.blockNumber))].map(async (b) => {
    const blk = await rpc<{ timestamp: string }>('eth_getBlockByNumber', [b, false]);
    times.set(b, new Date(Number(BigInt(blk.timestamp)) * 1000).toISOString());
  }));
  const burns = logs
    .map((l) => ({ l, order: Number(BigInt(l.blockNumber)) * 1e4 + Number(BigInt(l.logIndex)) }))
    .sort((a, b) => b.order - a.order)
    .map(({ l }) => ({ tx: l.transactionHash, time: times.get(l.blockNumber)!, amount: formatUnits(BigInt(l.data), decimals) }));
  const zeroRaw = toZero.reduce((s, l) => s + BigInt(l.data), 0n);
  const totalRaw = BigInt(deadHex) + zeroRaw;
  // A burn to the zero address lowers totalSupply, so add it back to compare against the supply at launch.
  const supply = BigInt(supplyHex) + zeroRaw;
  return {
    total: formatUnits(totalRaw, decimals),
    percent: supply > 0n ? `${(Number((totalRaw * 1_000_000n) / supply) / 10_000).toFixed(2)}%` : null,
    burns,
    checkedAt: now.toISOString(),
    supply: plainUnits(supply - totalRaw, decimals),
  };
}
