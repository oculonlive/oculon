import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createContext } from '../src/core/context.js';
import { loadPhishList, phishDomain } from '../src/sources/phishlists.js';
import { alchemyTransfers, chainCan, EVM_CHAINS, evmChain } from '../src/sources/evm.js';
import { urlCheck } from '../src/modules/urlcheck.js';
import { stockToken } from '../src/modules/stocktoken.js';
import { hashCheck } from '../src/modules/hashcheck.js';
import { addressCheck } from '../src/modules/address.js';
import { NOW } from './helpers.js';

type Body = { method?: string; params?: unknown[] } | null;
function ctxWith(answer: (url: string, body: Body, headers: Record<string, string>) => unknown) {
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    let body: Body = null;
    try { body = init?.body ? JSON.parse(Buffer.from(init.body as Uint8Array).toString('utf8')) : null; } catch {}
    const out = answer(url, body, (init?.headers ?? {}) as Record<string, string>);
    if (out === undefined) return new Response('not found', { status: 404 });
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof globalThis.fetch;
  return createContext({ dbPath: ':memory:', fetch, throttle: false, retryDelayMs: 1, now: () => NOW });
}

test('chain coverage follows the keys: explorer logs, Alchemy transfers', () => {
  const keep = { e: process.env.ETHERSCAN_API_KEY, b: process.env.BLOCKSCOUT_API_KEY, a: process.env.ALCHEMY_API_KEY };
  process.env.ETHERSCAN_API_KEY = 'e'; process.env.BLOCKSCOUT_API_KEY = 'b'; delete process.env.ALCHEMY_API_KEY;
  assert.ok(chainCan(EVM_CHAINS.optimism!, 'logs'));
  assert.ok(!chainCan(EVM_CHAINS.base!, 'transfers'));
  assert.throws(() => evmChain('base', 'logs'), /Base is not covered/);
  process.env.ALCHEMY_API_KEY = 'a';
  assert.ok(chainCan(EVM_CHAINS.base!, 'transfers'));
  assert.ok(!chainCan(EVM_CHAINS.base!, 'logs'));
  assert.equal(evmChain('op').key, 'optimism');
  Object.assign(process.env, { ETHERSCAN_API_KEY: keep.e ?? '', BLOCKSCOUT_API_KEY: keep.b ?? '', ALCHEMY_API_KEY: keep.a ?? '' });
});

test('Alchemy transfers come back shaped like explorer rows, both directions, newest first', async () => {
  process.env.ALCHEMY_API_KEY = 'a';
  const W = '0x' + 'a'.repeat(40);
  const ctx = ctxWith((url, b) => {
    if (!url.includes('alchemy.com')) return undefined;
    const p = (b!.params as Record<string, unknown>[])[0]!;
    const out = p.fromAddress
      ? [{ hash: '0x1', from: W, to: '0x' + 'b'.repeat(40), asset: 'USDC', category: 'erc20', rawContract: { value: '0x0f4240', address: '0x' + 'c'.repeat(40), decimal: '0x6' }, metadata: { blockTimestamp: '2026-11-10T00:00:00Z' } }]
      : [{ hash: '0x2', from: '0x' + 'd'.repeat(40), to: W, asset: 'USDC', category: 'erc20', rawContract: { value: '0x01', address: '0x' + 'c'.repeat(40), decimal: '0x6' }, metadata: { blockTimestamp: '2026-11-12T00:00:00Z' } }];
    return { jsonrpc: '2.0', id: 1, result: { transfers: out } };
  });
  const r = await alchemyTransfers(ctx, EVM_CHAINS.base!, W, ['erc20']);
  assert.deepEqual(r.data!.map((x) => [x.hash, x.value, x.tokenDecimal]), [['0x2', '1', '6'], ['0x1', '1000000', '6']]);
  assert.match(r.prov.url, /\/v2\/\*\*\*/);
});

test('phishing blocklists: parent domains match, the allowlist wins, the URL check says so', async () => {
  const ctx = ctxWith((url) => {
    if (url.includes('scam-database/main/blacklist/domains.json')) return ['drainer-claim.xyz'];
    if (url.includes('scam-database/main/blacklist/address.json')) return [];
    if (url.includes('eth-phishing-detect')) return { blacklist: ['fake-uniswap.app'], whitelist: ['good.fake-uniswap.app'] };
    return undefined;
  });
  loadPhishList(ctx, 'phish_domains', 'scamsniffer', ['drainer-claim.xyz']);
  assert.deepEqual(phishDomain(ctx, 'app.drainer-claim.xyz').listed, ['ScamSniffer blocklist']);
  assert.deepEqual(phishDomain(ctx, 'example.com').listed, []);
  const r = await urlCheck(ctx, 'https://www.fake-uniswap.app/claim');
  assert.equal(r.result.verdict, 'malicious');
  assert.match(r.result.reasons[0]!, /MetaMask phishing list/);
  assert.deepEqual(phishDomain(ctx, 'good.fake-uniswap.app').listed, []);
});

test('Robinhood stock tokens: official token with price, a fake copy of its ticker', async () => {
  const TSLA = '0x322F0929c4625eD5bAd873c95208D54E1c003b2d', FAKE = '0x' + '7'.repeat(40);
  const word = (h: string) => h.replace(/^0x/, '').padStart(64, '0');
  const abiStr = (s: string) => '0x' + word('20') + word(s.length.toString(16)) + Buffer.from(s).toString('hex').padEnd(64, '0');
  process.env.ROBINHOOD_PUBLIC_RPC_URL = 'https://rpc.robinhood.test';
  const ctx = ctxWith((url, b) => {
    if (url.endsWith('/rhj/assets')) return { assets: [{ tokenSymbol: 'TSLA', tokenName: 'Tesla • Robinhood Token', deployments: [{ contractAddress: TSLA, chainId: 4663, networkName: 'Robinhood Chain' }], currentMultiplier: '1.5', pendingMultiplier: '', status: 'ASSET_STATUS_ACTIVE', tradingCapabilities: { market: { whole: 'TRADING_STATUS_TRADABLE' } }, tokenDecimals: 18, isin: 'US88160R1014' }] };
    if (url.endsWith('/rhj/corporate-actions')) return { corpActions: [{ type: 'CORPORATE_ACTION_TYPE_CASH_DIVIDEND', status: 'CORPORATE_ACTION_STATUS_PENDING', processDate: { year: 2026, month: 12, day: 1 }, tokenSymbol: 'TSLA', details: { cashDividend: { underlyingSymbol: 'TSLA', rate: '0.10' } } }] };
    if (url.includes('/rhj/prices/TSLA')) return { quotes: [{ bid: '100', ask: '101', isTradingHalt: false }] };
    if (b?.method === 'eth_call') {
      const p = (b.params as { to: string; data: string }[])[0]!;
      if (p.data === '0x18160ddd') return { jsonrpc: '2.0', id: 1, result: '0x' + word((1000n * 10n ** 18n).toString(16)) };
      if (p.to.toLowerCase() === FAKE && p.data === '0x95d89b41') return { jsonrpc: '2.0', id: 1, result: abiStr('TSLA') };
      if (p.to.toLowerCase() === FAKE && p.data === '0x06fdde03') return { jsonrpc: '2.0', id: 1, result: abiStr('Tesla Robinhood') };
      return { jsonrpc: '2.0', id: 1, result: '0x' };
    }
    return undefined;
  });
  const t = await stockToken(ctx, 'tsla');
  assert.equal(t.result.verdict, 'official Robinhood stock token');
  assert.equal(t.result.price?.tokenBid, 150, 'bid times the 1.5 multiplier');
  assert.equal(t.result.supply, 1000);
  assert.equal(t.result.corporateActions[0]?.type, 'cash dividend');
  const f = await stockToken(ctx, FAKE);
  assert.equal(f.result.verdict, 'fake stock token');
  assert.match(f.result.reasons.join(' '), new RegExp(TSLA));
});

test('hash check adds the Hybrid Analysis sandbox verdict', async () => {
  process.env.HYBRID_ANALYSIS_KEY = 'k';
  const H = 'a'.repeat(64);
  const ctx = ctxWith((url, _b, h) => (url.includes('hybrid-analysis.com/api/v2/overview/') && h['api-key'] === 'k' ? { verdict: 'malicious', threat_score: 92, vx_family: 'Agent Tesla', tags: ['stealer'] } : undefined));
  const r = await hashCheck(ctx, H);
  assert.equal(r.result.verdict, 'malicious');
  assert.equal(r.result.hybrid?.family, 'Agent Tesla');
  assert.match(r.result.reasons.join(' '), /Hybrid Analysis sandbox: malicious \(Agent Tesla\), threat score 92\/100/);
});

test('address check: victim reports from Chainabuse warn only when verified or repeated', async () => {
  process.env.CHAINABUSE_API_KEY = 'ca_test';
  const A = '0x' + '5'.repeat(40);
  const reports = (n: number, trusted: boolean) => ({ count: n, reports: Array.from({ length: n }, () => ({ createdAt: '2026-11-01T00:00:00Z', scamCategory: 'PHISHING', trusted })) });
  let answer = reports(1, false);
  const ctx = ctxWith((url) => (url.includes('api.chainabuse.com') ? answer : url.includes('blockscout') ? { coin_balance: '0', is_contract: false } : undefined));
  const one = await addressCheck(ctx, A);
  assert.equal(one.result.reports?.count, 1);
  assert.ok(!one.result.warnings.some((w) => /Chainabuse/.test(w)));
  answer = reports(3, false);
  const ctx2 = ctxWith((url) => (url.includes('api.chainabuse.com') ? answer : url.includes('blockscout') ? { coin_balance: '0', is_contract: false } : undefined));
  const three = await addressCheck(ctx2, A);
  assert.match(three.result.warnings[0]!, /3 scam reports filed by victims on Chainabuse \(phishing\)/);
});
