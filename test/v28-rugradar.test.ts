import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { alertText, followUp, launchSymbol, postAlerts, quickVerdict, radarList, radarScan, radarStats, type Launch } from '../src/modules/rugradar.js';
import { sellerHolder, type Pool } from '../src/sources/robinhood.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW, testContext } from './helpers.js';

const T = (n: number) => `0x${String(n).padStart(40, '0').replace(/^0/, 'a')}`;
const pool = (o: Partial<Pool> = {}): Pool => ({ name: 'KURO / WETH', address: '0xpool', token: T(1), createdAt: new Date(NOW.getTime() - 3600_000).toISOString(), liquidityUsd: 20_000, volume24h: 5_000, change1h: 2, change24h: null, buys24h: 40, sells24h: 30, buyers24h: 30, sellers24h: 20, fdvUsd: 100_000, url: 'https://www.geckoterminal.com/robinhood/pools/0xpool', ...o });
const launch = (o: Partial<Launch> = {}): Launch => ({ token: T(1), symbol: 'KURO', name: 'KURO', pool: '0xpool', dex: 'Uniswap v4', poolUrl: 'https://x', createdAt: new Date(NOW.getTime() - 3600_000).toISOString(), firstSeen: NOW.getTime(), liquidityUsd: 20_000, peakLiquidityUsd: 20_000, volume24h: 0, buyers24h: 0, sellers24h: 0, change1h: null, fdvUsd: null, verdict: 'OK', checked: 'full', reasons: ['clean'], holders: 100, top10Share: 0.2, verified: true, deployer: null, deployerTokens: 0, deployerDead: 0, ruggedAt: null, updatedAt: NOW.getTime(), ...o });

test('rug radar: pool-only read and the symbol from a pool name', () => {
  assert.equal(launchSymbol('KURO / WETH 0.3%'), 'KURO');
  assert.equal(quickVerdict(pool(), NOW.getTime()).verdict, 'UNKNOWN');
  const hp = quickVerdict(pool({ buys24h: 50, sells24h: 0 }), NOW.getTime());
  assert.equal(hp.verdict, 'DANGER');
  assert.match(hp.reasons.join(), /honeypot shape/);
  assert.equal(quickVerdict(pool({ liquidityUsd: 900 }), NOW.getTime()).verdict, 'UNKNOWN', 'thin liquidity alone is how launches start');
  assert.equal(quickVerdict(pool({ change1h: -70 }), NOW.getTime()).verdict, 'DANGER');
  assert.equal(quickVerdict(pool({ buys24h: 100, sells24h: 3 }), NOW.getTime()).verdict, 'CAUTION');
});

test('rug radar: liquidity that held $3,000 and lost 80% is a rug; an empty launch after a day is dead', () => {
  const now = NOW.getTime();
  const r = followUp(launch({ peakLiquidityUsd: 40_000 }), 2_000, now);
  assert.equal(r.verdict, 'RUGGED');
  assert.equal(r.ruggedAt, now);
  assert.match(r.reasons[0]!, /from \$40,000 to \$2,000/);
  assert.equal(followUp(r, 50_000, now + 1).verdict, 'RUGGED', 'a rug stays a rug');
  assert.equal(followUp(launch(), 15_000, now).verdict, 'OK', 'a 25% dip is not a rug');
  const old = launch({ createdAt: new Date(now - 30 * 3600_000).toISOString(), peakLiquidityUsd: 400, liquidityUsd: 400, verdict: 'UNKNOWN' });
  assert.equal(followUp(old, 20, now).verdict, 'DEAD');
});

test('holder share leaves out pools, lockers and burns but keeps EIP-7702 wallets', () => {
  assert.equal(sellerHolder({ value: '1', address: { hash: '0x8366a39cc670b4001a1121b8f6a443a643e40951', is_contract: true } }), false);
  assert.equal(sellerHolder({ value: '1', address: { hash: '0x20b3c9938d5f01c0efaf16d83e7c24a9a4fde71d', is_contract: true, proxy_type: 'eip7702' } }), true);
  assert.equal(sellerHolder({ value: '1', address: { hash: '0x000000000000000000000000000000000000dEaD', is_contract: false } }), false);
  assert.equal(sellerHolder({ value: '1', address: { hash: '0x1111111111111111111111111111111111111111', is_contract: false } }), true);
});

test('rug radar scan: new pools are stored once, copies of a ticker are flagged, rugs raise one alert', async () => {
  const gt = (name: string, token: string, created: string, reserve: string) => ({ id: `robinhood_${token}`, attributes: { name, address: `0xp${token.slice(3, 10)}`, pool_created_at: created, reserve_in_usd: reserve, volume_usd: { h24: '100' }, price_change_percentage: { h1: '0' }, transactions: { h24: { buys: 5, sells: 5, buyers: 5, sellers: 5 } } }, relationships: { base_token: { data: { id: `robinhood_${token}` } }, dex: { data: { id: 'uniswap-v4-robinhood' } } } });
  const a = T(11), b = T(12), w = T(13);
  let reserveA = '800';
  const ctx = testContext([
    ['/new_pools?page=1', () => ({ body: { data: [gt('KURO / WETH', a, '2026-11-18T11:00:00Z', '800'), gt('KURO / WETH', b, '2026-11-18T11:30:00Z', '700'), gt('WETH / USDG', w, '2026-11-18T11:40:00Z', '5000')] } })],
    ['/tokens/multi/', () => ({ body: { data: [{ attributes: { address: a, symbol: 'KURO', total_reserve_in_usd: reserveA, volume_usd: { h24: '1' } } }, { attributes: { address: b, symbol: 'KURO', total_reserve_in_usd: '700', volume_usd: { h24: '1' } } }] } })],
  ]);
  const scan = () => radarScan(ctx, { marketTtlSec: 0 });
  const first = await scan();
  assert.equal(first.added, 2, 'quote-token pools are skipped');
  const list = radarList(ctx);
  const copy = list.find((l) => l.token === b)!;
  assert.match(copy.reasons[0]!, /copycat ticker: another KURO/);
  assert.equal(copy.verdict, 'CAUTION');
  assert.ok(!list.find((l) => l.token === a)!.reasons.some((r) => r.startsWith('copycat')), 'the earlier one is the original');
  assert.equal((await scan()).added, 0);

  reserveA = '12000';
  await scan();
  reserveA = '300';
  const rug = await scan();
  assert.deepEqual(rug.alerts.map((x) => x.kind), ['rug']);
  assert.equal(radarStats(ctx).rugged, 1);
  assert.equal(radarStats(ctx).lostUsd, 11_700);
  assert.equal((await scan()).alerts.length, 0, 'one alert per rug');
  assert.match(alertText(rug.alerts[0]!), /^<b>RUG on Robinhood Chain: KURO<\/b>/);
});

test('rug radar alerts go to the channel only when a bot token and chat are set', async () => {
  const sent: string[] = [];
  const f = (async (_u: string, init?: RequestInit) => { sent.push(String(init?.body)); return new Response('{}'); }) as typeof fetch;
  const a = { kind: 'danger' as const, launch: launch({ verdict: 'DANGER', symbol: 'B<A>D', reasons: ['top 10 wallets own 99%'] }) };
  assert.equal(await postAlerts([a], { token: '', chat: '', fetch: f }), 0);
  assert.equal(await postAlerts([a], { token: 'x', chat: '@chan', fetch: f }), 1);
  assert.match(sent[0]!, /B&lt;A&gt;D/);
});

test('/rugradar and /api/rh/launches are public', async () => {
  const { server, stop } = createWebServer({ port: 0, publicMode: true, rugRadar: false, burnRpcUrl: '', oculon: new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW }) });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const page = await fetch(`${base}/rugradar`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Rug <span>Radar<\/span>/);
    const api = await fetch(`${base}/api/rh/launches`);
    if (api.status === 404) return; // on-chain features off in this environment
    assert.equal(api.status, 200);
    const j = (await api.json()) as { stats: { launches: number }; launches: unknown[] };
    assert.equal(j.stats.launches, 0);
    assert.deepEqual(j.launches, []);
  } finally {
    await stop();
  }
});
