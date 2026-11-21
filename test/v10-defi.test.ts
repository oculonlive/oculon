import assert from 'node:assert/strict';
import { test } from 'node:test';
import { defi, protocol, resolveSlug } from '../src/modules/defi.js';
import { decodeEvents, decodeSelectors, methodName } from '../src/sources/signatures.js';
import { NOW, testContext } from './helpers.js';

const sec = (msAgo: number) => Math.floor((NOW.getTime() - msAgo) / 1000);
const DAY = 86_400_000;

// Shapes follow the live DefiLlama / alternative.me / openchain / 4byte responses (checked 2026-11); values are fictional.
const protocols = [
  { id: '1', name: 'Examplecoin Lend', slug: 'examplecoin-lend', category: 'Lending', chains: ['Ethereum', 'Arbitrum'], tvl: 30e6, change_1h: -2.1, change_1d: -70, change_7d: -71, mcap: 12e6, audits: '0', url: 'https://lend.example', twitter: 'example', listedAt: 1700000000, misrepresentedTokens: false, chainTvls: { Ethereum: { tvl: 1 } }, tokenBreakdowns: {} },
  { id: '2', name: 'ExampleSwap', slug: 'exampleswap', category: 'Dexs', chains: ['Ethereum'], tvl: 900e6, change_1h: 0.1, change_1d: -1.2, change_7d: -5, audits: '2', audit_links: ['https://exampleswap.example/audits'], parentProtocolSlug: 'example-group', oracles: ['Chainlink'], url: 'https://exampleswap.example', listedAt: 1600000000 },
  { id: '3', name: 'Tiny Vault', slug: 'tiny-vault', category: 'Yield', chains: ['Base'], tvl: 4e6, change_1h: 0, change_1d: -60, change_7d: -60, url: 'https://tiny.example' },
  { id: '4', name: 'Dust Farm', slug: 'dust-farm', category: 'Yield', chains: ['Base'], tvl: 5e3, change_1d: -1, url: '' },
  { id: '5', name: 'Surge Staking', slug: 'surge-staking', category: 'Liquid Staking', chains: ['Ethereum'], tvl: 200e6, change_1d: 40, change_7d: 41, url: '', rugged: true },
];

const stablecoins = {
  peggedAssets: [
    { id: '1', name: 'Tether', symbol: 'USDT', pegType: 'peggedUSD', pegMechanism: 'fiat-backed', circulating: { peggedUSD: 175e9 }, circulatingPrevDay: { peggedUSD: 175.2e9 }, circulatingPrevWeek: { peggedUSD: 175.6e9 }, chains: ['Ethereum'], chainCirculating: {}, price: 0.99886 },
    { id: '2', name: 'Example Dollar', symbol: 'EXUSD', pegType: 'peggedUSD', pegMechanism: 'crypto-backed', circulating: { peggedUSD: 255e6 }, circulatingPrevDay: { peggedUSD: 270e6 }, circulatingPrevWeek: { peggedUSD: 280e6 }, chains: ['Ethereum'], price: 0.9611 },
    { id: '3', name: 'Small Dollar', symbol: 'SMUSD', pegType: 'peggedUSD', pegMechanism: 'algorithmic', circulating: { peggedUSD: 5e6 }, circulatingPrevDay: { peggedUSD: 5e6 }, price: 0.7 },
    { id: '4', name: 'Example Euro', symbol: 'EXEUR', pegType: 'peggedEUR', pegMechanism: 'fiat-backed', circulating: { peggedEUR: 300e6 }, circulatingPrevDay: { peggedEUR: 300e6 }, price: 1.16 },
    { id: '5', name: 'Redeemed Dollar', symbol: 'RDUSD', pegType: 'peggedUSD', pegMechanism: 'crypto-backed', circulating: { peggedUSD: 20e6 }, circulatingPrevDay: { peggedUSD: 100e6 }, circulatingPrevWeek: { peggedUSD: 100e6 }, price: 0.994 },
  ],
  chains: [],
};

const hacks = [
  { date: sec(DAY), name: 'Examplecoin Bridge', classification: 'Bridge & Cross-Chain', technique: 'Private Key Compromised', amount: 40e6, chain: ['Ethereum', 'BSC'], bridgeHack: true, targetType: 'DeFi Protocol', source: 'https://news.example/bridge', returnedFunds: null, defillamaId: null, language: 'Solidity', description: 'An attacker drained the bridge reserves.' },
  { date: sec(2 * DAY), name: 'Pocket Change', classification: 'Logic', technique: 'Rounding', amount: 200_000, chain: ['Base'], bridgeHack: false, targetType: 'DeFi Protocol', source: '', returnedFunds: null, description: 'Small loss.' },
  { date: sec(90 * DAY), name: 'Old Hack', classification: 'Logic', technique: 'Reentrancy', amount: 90e6, chain: ['Ethereum'], bridgeHack: false, targetType: 'DeFi Protocol', source: '', returnedFunds: null, description: 'Long ago.' },
];

const overview = (protocols: { name: string; total24h: number; change_1d: number }[], total24h: number, change_1d: number) => ({
  totalDataChart: [],
  totalDataChartBreakdown: [],
  breakdown24h: null,
  chain: null,
  allChains: ['Ethereum'],
  total24h,
  total48hto24h: total24h * 0.9,
  change_1d,
  change_7d: -3.5,
  protocols: protocols.map((p) => ({ ...p, defillamaId: '1', displayName: p.name, module: 'x', category: 'Dexs', chains: ['Ethereum'], methodology: { Volume: 'long text' } })),
});

const fng = {
  name: 'Fear and Greed Index',
  data: Array.from({ length: 30 }, (_, i) => ({ value: String(10 + i * 2), value_classification: i < 5 ? 'Extreme Fear' : 'Fear', timestamp: String(sec(i * DAY)) })),
  metadata: { error: null },
};

const yields = {
  status: 'success',
  data: [
    { chain: 'Ethereum', project: 'example-vault', symbol: 'USDC', tvlUsd: 25e6, apyBase: 45, apyReward: null, apy: 45, stablecoin: true, apyPct7D: 20, pool: 'a' },
    { chain: 'Ethereum', project: 'lido', symbol: 'STETH', tvlUsd: 17e9, apy: 2.2, stablecoin: false, pool: 'b' },
    { chain: 'Base', project: 'small', symbol: 'USDC', tvlUsd: 1e6, apy: 90, stablecoin: true, pool: 'c' },
  ],
};

function routes() {
  return [
    ['api.llama.fi/protocols', () => ({ body: protocols })],
    ['api.llama.fi/v2/chains', () => ({ body: [{ gecko_id: 'ethereum', tvl: 37e9, tokenSymbol: 'ETH', name: 'Ethereum', chainId: 1 }, { gecko_id: null, tvl: 800e6, tokenSymbol: 'EXC', name: 'Examplechain', chainId: 9999 }, { tvl: 0, name: 'Ghost' }] })],
    ['api.llama.fi/v2/historicalChainTvl', () => ({ body: Array.from({ length: 10 }, (_, i) => ({ date: sec((9 - i) * DAY), tvl: 70e9 + (i === 9 ? -0.7e9 : 0) })) })],
    ['api.llama.fi/hacks', () => ({ body: hacks })],
    ['stablecoins.llama.fi/stablecoins', () => ({ body: stablecoins })],
    ['overview/dexs', () => ({ body: overview([{ name: 'ExampleSwap', total24h: 50e6, change_1d: 350 }, { name: 'Quiet DEX', total24h: 80e6, change_1d: 5 }], 7.7e9, 3.8) })],
    ['overview/fees', () => ({ body: overview([{ name: 'ExampleSwap', total24h: 1e6, change_1d: 900 }], 64e6, 3.7) })],
    ['overview/open-interest', () => ({ body: overview([], 14.4e9, -0.4) })],
    ['api.alternative.me/fng', () => ({ body: fng })],
    ['yields.llama.fi/pools', () => ({ body: yields })],
  ] as Parameters<typeof testContext>[0];
}

test('defi: TVL drops, depegs, supply shocks, hacks, chain moves, fear & greed, spikes and yields', async () => {
  const ctx = testContext(routes());
  // A reading from yesterday makes Examplechain's 800M a 20% drop from 1B.
  ctx.graph.observe('chain:Examplechain', 'defi', 'chain_tvl', 1e9, 'defillama', {}, NOW.getTime() - 24 * 3600_000);
  const r = await defi(ctx);
  const x = r.result;

  assert.deepEqual(x.tvlDrops.map((d) => d.slug), ['examplecoin-lend']);
  assert.equal(x.tvlDrops[0]!.prevTvl, 100e6);
  assert.equal(x.tvlDrops[0]!.lostUsd, 70e6);
  assert.equal(x.totals.defiTvlChange1d, -1);
  assert.equal(x.tvlDrops[0]!.vsMarketPct, -69);

  assert.deepEqual(x.depegs.map((d) => d.symbol), ['EXUSD']);
  assert.equal(x.depegs[0]!.offPct, 3.89);
  assert.deepEqual(x.supplyShocks.map((d) => d.symbol), ['RDUSD']);
  assert.equal(x.supplyShocks[0]!.supplyChange1dPct, -80);

  assert.deepEqual(x.hacks.map((h) => h.name), ['Examplecoin Bridge', 'Pocket Change']);
  assert.equal(x.hacks[0]!.url, 'https://news.example/bridge');

  assert.equal(x.chains.observed, 2);
  assert.deepEqual(x.chains.moves.map((m) => [m.name, m.changePct, m.hoursBetween]), [['Examplechain', -20, 24]]);
  assert.equal(x.chains.top[0]!.name, 'Ethereum');

  assert.equal(x.fearGreed!.value, 10);
  assert.equal(x.fearGreed!.label, 'Extreme Fear');
  assert.equal(x.fearGreed!.change7d, -14);
  assert.equal(x.fearGreed!.trend, 'falling');
  assert.equal(x.fearGreed!.avg7d, 16);
  assert.equal(x.fearGreed!.series.length, 30);

  assert.deepEqual(x.activitySpikes.map((s) => [s.kind, s.name]), [['dex-volume', 'ExampleSwap']]);
  assert.deepEqual(x.yieldAnomalies.map((y) => y.project), ['example-vault']);
  assert.equal(x.totals.dexVolume24h, 7.7e9);
  assert.equal(x.totals.openInterest, 14.4e9);

  const titles = r.signals.map((s) => s.title);
  assert.ok(titles.some((t) => /^Examplecoin Lend TVL down 70\.0% in 24h \(\$100\.0M to \$30\.0M\)/.test(t)));
  assert.ok(titles.some((t) => /Example Dollar \(EXUSD\) off its USD peg: \$0\.9611/.test(t)));
  assert.ok(titles.some((t) => /Redeemed Dollar \(RDUSD\) supply down 80\.0%/.test(t)));
  assert.ok(titles.some((t) => /Examplechain chain TVL down 20\.0% in 24h/.test(t)));
  assert.ok(titles.some((t) => /Examplecoin Bridge hacked for \$40\.0M/.test(t)));
  assert.ok(!titles.some((t) => /Pocket Change|Old Hack|Tiny Vault|Tether|Example Euro/.test(t)));
  for (const s of r.signals) assert.ok(s.score >= 50 && s.score <= 92, `${s.title} ${s.score}`);
  assert.equal(r.provenance.length, 10);
  assert.ok(r.provenance.every((p) => p.status === 'LIVE'));

  // A second run is served from the trimmed cache; yields can be skipped.
  const again = await defi(ctx, { yields: false });
  assert.ok(again.provenance.every((p) => p.status === 'CACHED'));
  assert.equal(again.result.yieldAnomalies.length, 0);
});

test('defi: endpoints failing degrade to empty sections', async () => {
  const ctx = testContext([['bridges.llama.fi', () => ({ status: 402, body: 'Upgrade to the paid API plan' })]]);
  const r = await defi(ctx);
  assert.equal(r.result.tvlDrops.length, 0);
  assert.equal(r.result.fearGreed, null);
  assert.equal(r.result.totals.defiTvl, null);
  assert.equal(r.signals.length, 0);
  assert.ok(r.provenance.every((p) => p.status !== 'LIVE'));
});

test('protocol: resolves by name, trends from TVL history, audits, hacks and flags', async () => {
  const series = Array.from({ length: 400 }, (_, i) => ({ date: sec((399 - i) * DAY), totalLiquidityUSD: i === 399 ? 30e6 : i === 398 ? 100e6 : 100e6 + i * 1e5 }));
  // A second point on the last day: only the last one per day is kept.
  series.splice(398, 0, { date: sec(DAY) - 3600, totalLiquidityUSD: 1 });
  const detail = {
    id: '1',
    name: 'Examplecoin Lend',
    url: 'https://lend.example',
    description: 'A fictional lending market.',
    chains: ['Ethereum', 'Arbitrum'],
    category: 'Lending',
    audits: '0',
    audit_links: [],
    oraclesBreakdown: [{ name: 'Chainlink', type: 'Primary', proof: [] }],
    twitter: 'example',
    github: ['example-org'],
    currentChainTvls: { Ethereum: 25e6, 'Ethereum-borrowed': 9e6, Arbitrum: 5e6, borrowed: 9e6, staking: 1e6 },
    chainTvls: { Ethereum: { tvl: [{ date: 1, totalLiquidityUSD: 1 }], tokens: [], tokensInUsd: [] } },
    tokens: [],
    tokensInUsd: [],
    tvl: series,
    mcap: 12e6,
    raises: [{ date: sec(800 * DAY), name: 'Examplecoin Lend', round: 'Seed', amount: 4, leadInvestors: ['Example Ventures'], otherInvestors: [] }],
    hacks: [{ date: sec(DAY), name: 'Examplecoin Lend', classification: 'Oracle Manipulation', technique: 'Price Oracle Manipulation', amount: 65e6, chain: ['Ethereum'], bridgeHack: false, targetType: 'DeFi Protocol', source: '', returnedFunds: 5e6, description: 'Oracle manipulated with a flash loan.' }],
    hallmarks: [[sec(DAY), 'Exploit'], [[sec(30 * DAY), sec(20 * DAY)], 'Incentive campaign']],
    otherProtocols: [],
  };
  const ctx = testContext([
    ['api.llama.fi/protocols', () => ({ body: protocols })],
    ['api.llama.fi/protocol/examplecoin-lend', () => ({ body: detail })],
  ]);
  const r = await protocol(ctx, 'Examplecoin Lend');
  const d = r.result!;
  assert.equal(d.slug, 'examplecoin-lend');
  assert.equal(d.category, 'Lending');
  assert.deepEqual(d.chains, [{ chain: 'Ethereum', tvl: 25e6 }, { chain: 'Arbitrum', tvl: 5e6 }]);
  assert.equal(d.tvl, 30e6);
  assert.equal(d.change.d1, -70);
  assert.equal(d.series.length, 90);
  assert.equal(d.series.at(-1)!.tvl, 30e6);
  assert.equal(d.ath!.tvl, 139.7e6);
  assert.equal(d.drawdownFromAthPct, -78.53);
  assert.deepEqual(d.oracles, ['Chainlink']);
  assert.equal(d.raises.totalUsd, 4e6);
  assert.deepEqual(d.raises.last!.leads, ['Example Ventures']);
  assert.equal(d.hallmarks.length, 2);
  assert.equal(d.mcapToTvl, 0.4);
  assert.ok(d.flags.includes('no audit listed on DefiLlama'));
  assert.ok(d.flags.some((f) => /1 hack on record \(\$65\.0M\)/.test(f)));
  assert.equal(d.hacks[0]!.returnedFunds, 5e6);
  assert.ok(r.signals.some((s) => /Examplecoin Lend TVL down 70\.0%/.test(s.title)));
  assert.ok(r.signals.some((s) => /Examplecoin Lend hacked for \$65\.0M \(Price Oracle Manipulation\)/.test(s.title)));
});

test('protocol: slug resolution and unknown protocol', async () => {
  const slim = protocols.map((p) => ({ ...p, parent: (p as { parentProtocolSlug?: string }).parentProtocolSlug ?? null })) as unknown as Parameters<typeof resolveSlug>[0];
  assert.equal(resolveSlug(slim, 'exampleswap').slug, 'exampleswap');
  assert.equal(resolveSlug(slim, 'ExampleSwap').entry?.slug, 'exampleswap');
  assert.deepEqual(resolveSlug(slim, 'Example Group'), { slug: 'example-group', entry: null });
  const ctx = testContext([['api.llama.fi/protocols', () => ({ body: protocols })]]);
  const r = await protocol(ctx, 'No Such Protocol');
  assert.equal(r.result, null);
  assert.equal(r.provenance.at(-1)!.status, 'UNAVAILABLE');
});

const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

test('signatures: openchain batch lookup, calldata, cache and spam filtering', async () => {
  const ctx = testContext([
    [
      'api.openchain.xyz',
      () => ({
        body: {
          ok: true,
          result: {
            function: {
              '0xa9059cbb': [{ name: 'transfer(address,uint256)', filtered: false, hasVerifiedContract: true }],
              '0x095ea7b3': [
                { name: 'spam_approve_xyz(bytes)', filtered: true, hasVerifiedContract: false },
                { name: 'approve(address,uint256)', filtered: false, hasVerifiedContract: true },
              ],
              '0x12345678': null,
            },
            event: { [TRANSFER_TOPIC]: [{ name: 'Transfer(address,address,uint256)', filtered: false, hasVerifiedContract: true }] },
          },
        },
      }),
    ],
    ['4byte.directory/api/v1/signatures/', () => ({ body: { count: 0, next: null, previous: null, results: [] } })],
  ]);
  const calldata = '0xa9059cbb000000000000000000000000000000000000000000000000000000000000dead';
  const r = await decodeSelectors(ctx, [calldata, '0x095EA7B3', '12345678', 'not-hex']);
  assert.deepEqual(r, { '0xa9059cbb': 'transfer(address,uint256)', '0x095ea7b3': 'approve(address,uint256)', '0x12345678': null, 'not-hex': null });
  assert.equal(ctx.calls.filter((u) => u.includes('openchain')).length, 1);
  assert.ok(ctx.calls.some((u) => u.includes('4byte.directory') && u.includes('0x12345678')));
  assert.equal(methodName(r['0xa9059cbb']), 'transfer');

  const before = ctx.calls.length;
  const again = await decodeSelectors(ctx, ['0xa9059cbb', '0x12345678']);
  assert.equal(again['0xa9059cbb'], 'transfer(address,uint256)');
  assert.equal(ctx.calls.length, before, 'answers and recent misses come from the derived cache');

  const ev = await decodeEvents(ctx, [TRANSFER_TOPIC, '0xabc']);
  assert.deepEqual(ev, { [TRANSFER_TOPIC]: 'Transfer(address,address,uint256)', '0xabc': null });
});

test('signatures: 4byte fallback when openchain is down, oldest submission wins', async () => {
  const ctx = testContext([
    ['api.openchain.xyz', () => ({ status: 503, body: 'down' })],
    [
      '4byte.directory/api/v1/signatures/?hex_signature=0xa9059cbb',
      () => ({ body: { count: 2, next: null, previous: null, results: [{ id: 31780, text_signature: 'many_msg_babbage(bytes1)', hex_signature: '0xa9059cbb' }, { id: 145, text_signature: 'transfer(address,uint256)', hex_signature: '0xa9059cbb' }] } }),
    ],
    ['4byte.directory/api/v1/event-signatures/', () => ({ body: { count: 1, next: null, previous: null, results: [{ id: 1, text_signature: 'Transfer(address,address,uint256)', hex_signature: TRANSFER_TOPIC }] } })],
  ]);
  const r = await decodeSelectors(ctx, ['0xa9059cbb', '0xffffffff']);
  assert.equal(r['0xa9059cbb'], 'transfer(address,uint256)');
  // Both services failed for 0xffffffff (4byte 404 from the mock): nothing cached, so it is asked again next time.
  assert.equal(r['0xffffffff'], null);
  assert.equal(ctx.store.cacheGet('derived:sig:function:0xffffffff'), undefined);
  const ev = await decodeEvents(ctx, [TRANSFER_TOPIC]);
  assert.equal(ev[TRANSFER_TOPIC], 'Transfer(address,address,uint256)');
});
