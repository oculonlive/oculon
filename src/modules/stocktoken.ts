/**
 * Robinhood Stock Tokens: the official list, live prices and corporate actions from Robinhood's read-only API
 * (api.robinhood.com/rhj, keyless), plus the token's supply on Robinhood Chain.
 *   A symbol (TSLA): the official contract, ISIN, status, which sessions trade, the live bid and ask (adjusted
 *     by the corporate-action multiplier), daily range and volume, upcoming dividends and splits.
 *   An address: whether it is an official Robinhood Stock Token. A token that copies a stock's ticker or calls
 *     itself a Robinhood token but is not on the official list is flagged as fake.
 *   Nothing: the list size and the corporate actions coming up.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { EVM_CHAINS, ethCall, isAddr, tokenMeta, wordInt } from '../sources/evm.js';

const API = 'https://api.robinhood.com/rhj';

interface Deployment { contractAddress: string; chainId: number; networkName: string }
interface Asset { tokenSymbol: string; tokenName: string; deployments: Deployment[]; currentMultiplier: string; pendingMultiplier: string; status: string; tradingCapabilities?: Record<string, { whole?: string; fractional?: string }>; tokenDecimals: number; isin?: string; logoUrl?: string }
interface CorpAction { type: string; status: string; processDate?: { year: number; month: number; day: number }; tokenSymbol: string; details?: Record<string, Record<string, string>> }
interface Quote { bid?: string; ask?: string; dailyHigh?: string; dailyLow?: string; dailyTradingVolume?: string; isTradingHalt?: boolean; generatedAt?: string; mintBurnUsdVolume?: string }

export interface StockTokenReport {
  query: string;
  verdict: 'official Robinhood stock token' | 'fake stock token' | 'not a stock token' | 'trading halted' | 'stock tokens overview';
  risk: number;
  symbol: string | null;
  name: string | null;
  isin: string | null;
  contract: string | null;
  chain: string | null;
  status: string | null;
  multiplier: number | null;
  pendingMultiplier: number | null;
  price: { bid: number | null; ask: number | null; tokenBid: number | null; tokenAsk: number | null; dailyHigh: number | null; dailyLow: number | null; volume: number | null; halted: boolean; at: string | null } | null;
  sessions: Record<string, string>;
  supply: number | null;
  corporateActions: { symbol: string; type: string; date: string | null; status: string; detail: string | null }[];
  tokens: number;
  reasons: string[];
  advice: string[];
}

const nOrNull = (v: unknown) => { const n = Number(v); return v === undefined || v === null || v === '' || !Number.isFinite(n) ? null : n; };
const ymd = (d?: { year: number; month: number; day: number }) => (d ? `${d.year}-${String(d.month).padStart(2, '0')}-${String(d.day).padStart(2, '0')}` : null);
const kind = (t: string) => t.replace(/^CORPORATE_ACTION_TYPE_/, '').toLowerCase().replace(/_/g, ' ');
const detailOf = (c: CorpAction) => {
  const d = Object.values(c.details ?? {})[0];
  if (!d) return null;
  return Object.entries(d).filter(([k]) => k !== 'underlyingSymbol').map(([k, v]) => `${k.replace(/([A-Z])/g, ' $1').toLowerCase()} ${v}`).join(', ') || null;
};

export async function stockToken(ctx: Ctx, input = ''): Promise<ModuleResult<StockTokenReport>> {
  const q = input.trim();
  const provenance: Provenance[] = [];
  const [a, c] = await Promise.all([
    ctx.http.get<{ assets?: Asset[] }>(`${API}/assets`, { source: 'robinhood-rhj', ttlSec: 6 * 3600 }),
    ctx.http.get<{ corpActions?: CorpAction[] }>(`${API}/corporate-actions`, { source: 'robinhood-rhj', ttlSec: 3600 }),
  ]);
  provenance.push(a.prov, c.prov);
  const assets = a.data?.assets ?? [];
  if (!assets.length) throw new Error(`the Robinhood Stock Token API is not answering (${a.prov.note ?? a.prov.status})`);
  const actions = (c.data?.corpActions ?? []).map((x) => ({ symbol: x.tokenSymbol, type: kind(x.type), date: ymd(x.processDate), status: x.status.replace(/^CORPORATE_ACTION_STATUS_/, '').toLowerCase().replace(/_/g, ' '), detail: detailOf(x) }));
  const base: StockTokenReport = { query: q, verdict: 'stock tokens overview', risk: 0, symbol: null, name: null, isin: null, contract: null, chain: null, status: null, multiplier: null, pendingMultiplier: null, price: null, sessions: {}, supply: null, corporateActions: [], tokens: assets.length, reasons: [], advice: [] };
  const today = ctx.now().toISOString().slice(0, 10);
  const done = (r: StockTokenReport): ModuleResult<StockTokenReport> => ({ module: 'stocktoken', input: q || 'overview', generatedAt: ctx.now().toISOString(), signals: [], provenance, result: r });

  if (!q) {
    const upcoming = actions.filter((x) => (x.date ?? '') >= today).sort((x, y) => (x.date ?? '').localeCompare(y.date ?? ''));
    return done({ ...base, corporateActions: upcoming.slice(0, 20), reasons: [`${assets.filter((x) => /ACTIVE/.test(x.status)).length} of ${assets.length} Robinhood Stock Tokens are active`, ...upcoming.slice(0, 5).map((x) => `${x.date}: ${x.symbol} ${x.type}${x.detail ? ` (${x.detail})` : ''}`)], advice: ['Ask about one token: oculon stocktoken TSLA, or check an address someone sent you: oculon stocktoken 0x...'] });
  }

  // An address: official or not.
  if (isAddr(q)) {
    const addr = q.toLowerCase();
    const hit = assets.find((x) => x.deployments.some((d) => d.contractAddress.toLowerCase() === addr));
    if (!hit) {
      const rh = EVM_CHAINS.robinhood!;
      let meta = await tokenMeta(ctx, rh, addr);
      let where = rh.label;
      if (!meta.symbol) { for (const k of ['eth', 'base', 'arbitrum', 'bsc']) { const m = await tokenMeta(ctx, EVM_CHAINS[k]!, addr); if (m.symbol) { meta = m; where = EVM_CHAINS[k]!.label; break; } } }
      const sym = (meta.symbol ?? '').toUpperCase().replace(/^(R|X|S|B|D|T)?([A-Z.]{1,6})$/, '$2');
      const copies = assets.find((x) => x.tokenSymbol.toUpperCase() === (meta.symbol ?? '').toUpperCase() || x.tokenSymbol.toUpperCase() === sym);
      const claims = /robinhood/i.test(`${meta.name ?? ''} ${meta.symbol ?? ''}`);
      if (copies || claims) {
        const real = copies ?? null;
        return done({ ...base, verdict: 'fake stock token', risk: 85, symbol: meta.symbol, name: meta.name, contract: addr, chain: where, reasons: [`this token (${meta.symbol ?? '?'}${meta.name ? `, "${meta.name}"` : ''} on ${where}) is not on Robinhood's official Stock Token list`, ...(real ? [`the official ${real.tokenSymbol} Stock Token is ${real.deployments[0]?.contractAddress} on ${real.deployments[0]?.networkName}`] : []), ...(claims ? ['it calls itself a Robinhood token'] : [])], advice: ['Do not buy it as a stock token. Only the contract on the official list is backed by the share.', ...(real ? [`Use the official contract: ${real.deployments[0]?.contractAddress}`] : [])] });
      }
      return done({ ...base, verdict: 'not a stock token', symbol: meta.symbol, name: meta.name, contract: addr, chain: meta.symbol ? where : null, reasons: ['this address is not an official Robinhood Stock Token and does not copy one'], advice: ['For other token risks: oculon contract <address> and oculon honeypot <address>'] });
    }
    return describe(ctx, hit, q, base, actions, provenance, today).then(done);
  }

  const sym = q.toUpperCase().replace(/^\$/, '');
  const hit = assets.find((x) => x.tokenSymbol.toUpperCase() === sym) ?? assets.find((x) => x.tokenName.toLowerCase().startsWith(q.toLowerCase()));
  if (!hit) throw new Error(`no Robinhood Stock Token for "${q}" (the list has ${assets.length}; try a ticker like TSLA)`);
  return describe(ctx, hit, q, base, actions, provenance, today).then(done);
}

async function describe(ctx: Ctx, x: Asset, q: string, base: StockTokenReport, actions: StockTokenReport['corporateActions'], provenance: Provenance[], today: string): Promise<StockTokenReport> {
  const dep = x.deployments[0];
  const p = await ctx.http.get<{ quotes?: Quote[] }>(`${API}/prices/${encodeURIComponent(x.tokenSymbol)}`, { source: 'robinhood-rhj', ttlSec: 30 });
  provenance.push(p.prov);
  const qt = p.data?.quotes?.[0];
  const mult = nOrNull(x.currentMultiplier) ?? 1;
  const bid = nOrNull(qt?.bid), ask = nOrNull(qt?.ask);
  let supply: number | null = null;
  if (dep && dep.chainId === 4663) {
    const s = await ethCall(ctx, EVM_CHAINS.robinhood!, dep.contractAddress, '0x18160ddd', 300);
    if (s.data && s.data.length >= 66) supply = Number(wordInt(s.data, 0) / 10n ** BigInt(Math.max(0, (x.tokenDecimals ?? 18) - 4))) / 1e4;
  }
  const sessions: Record<string, string> = {};
  for (const [k, v] of Object.entries(x.tradingCapabilities ?? {})) sessions[k] = (v.whole ?? '').replace(/^TRADING_STATUS_/, '').toLowerCase().replace(/_/g, ' ');
  const mine = actions.filter((a) => a.symbol === x.tokenSymbol).sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''));
  const halted = Boolean(qt?.isTradingHalt);
  const reasons = [
    `official Robinhood Stock Token: ${dep?.contractAddress ?? '?'} on ${dep?.networkName ?? '?'}`,
    ...(bid !== null && ask !== null ? [`bid $${(bid * mult).toFixed(2)} / ask $${(ask * mult).toFixed(2)} per token${mult !== 1 ? ` (share price times the ${mult.toFixed(6)} multiplier from past corporate actions)` : ''}`] : []),
    ...(halted ? ['trading is halted right now'] : []),
    ...(nOrNull(x.pendingMultiplier) ? [`a corporate action will change the multiplier to ${x.pendingMultiplier}`] : []),
    ...mine.filter((a) => (a.date ?? '') >= today).slice(0, 3).map((a) => `${a.date}: ${a.type}${a.detail ? ` (${a.detail})` : ''}`),
  ];
  return {
    ...base, verdict: halted ? 'trading halted' : 'official Robinhood stock token', risk: halted ? 30 : 0,
    symbol: x.tokenSymbol, name: x.tokenName, isin: x.isin ?? null, contract: dep?.contractAddress ?? null, chain: dep?.networkName ?? null, status: x.status.replace(/^ASSET_STATUS_/, '').toLowerCase(),
    multiplier: mult, pendingMultiplier: nOrNull(x.pendingMultiplier),
    price: qt ? { bid, ask, tokenBid: bid !== null ? bid * mult : null, tokenAsk: ask !== null ? ask * mult : null, dailyHigh: nOrNull(qt.dailyHigh), dailyLow: nOrNull(qt.dailyLow), volume: nOrNull(qt.dailyTradingVolume), halted, at: qt.generatedAt ?? null } : null,
    sessions, supply, corporateActions: mine.slice(0, 10), reasons,
    advice: [`Only ${dep?.contractAddress ?? 'the official contract'} is the Robinhood ${x.tokenSymbol} token. Tokens with the same ticker elsewhere are not backed by the share.`],
  };
}
