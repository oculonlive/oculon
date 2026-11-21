import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { scoreThresholds, signalThreshold, sourceWeights } from '../src/modules/calibrate.js';
import { lexiconTone } from '../src/modules/health.js';
import { quakeRadiusKm } from '../src/modules/impact.js';
import { screen } from '../src/modules/sanctions.js';
import { loadPlugins } from '../src/plugins.js';
import { buildIndex, normName, parseSdnCsv } from '../src/sources/ofac.js';
import { mockFetch, NOW, testContext } from './helpers.js';

const SDN = [
  '36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ',
  '9001,"MESRI, Behzad","individual","CYBER2",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - ETH 0x252a8bd2319d8a555b872990601221b3a2053bce; a.k.a. \'BEHZAD M\'."',
  '9002,"EBANO",-0- ,"CUBA","vessel",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Vessel Registration Identification IMO 7406784."',
].join('\n');

test('OFAC CSV parsing and index', () => {
  const entries = parseSdnCsv(SDN);
  assert.equal(entries.length, 3);
  const idx = buildIndex(entries, NOW.toISOString());
  assert.equal(idx.byAddress.get('0x252a8bd2319d8a555b872990601221b3a2053bce')?.uid, '9001');
  assert.equal(idx.byImo.get('7406784')?.name, 'EBANO');
  assert.ok(idx.byName.has(normName('Behzad M')), 'alias indexed');
  assert.equal(normName('Aerocaribbean Airlines, Ltd.'), 'AEROCARIBBEAN AIRLINES');
});

test('sanctions screening: listed address, counterparty exposure, IMO, name, clear', async () => {
  process.env.ETHERSCAN_API_KEY = 'test-etherscan-key-123456';
  try {
    const ctx = testContext([
      ['treasury.gov', () => ({ body: SDN })],
      [
        'api.etherscan.io',
        () => ({ body: { status: '1', result: [{ hash: '0xabc', timeStamp: String(NOW.getTime() / 1000), from: '0x252a8bd2319d8a555b872990601221b3a2053bce', to: '0x1111111111111111111111111111111111111111', value: '0', functionName: '' }] } }),
      ],
    ]);
    assert.equal((await screen(ctx, '0x252a8bd2319d8a555b872990601221b3a2053bce')).result.verdict, 'SANCTIONED');
    const exposed = await screen(ctx, '0x1111111111111111111111111111111111111111');
    assert.equal(exposed.result.verdict, 'EXPOSED');
    assert.match(exposed.result.hits[0]!.detail!, /received from a listed address/);
    assert.equal((await screen(ctx, 'IMO 7406784')).result.verdict, 'SANCTIONED');
    assert.equal((await screen(ctx, 'Aerocaribbean Airlines')).result.verdict, 'SANCTIONED');
    assert.equal((await screen(ctx, 'Nvidia')).result.verdict, 'CLEAR');
  } finally {
    delete process.env.ETHERSCAN_API_KEY;
  }
});

test('calibration math and thresholds', () => {
  const samples = [
    ...Array.from({ length: 10 }, () => ({ score: 80, hit: true })),
    ...Array.from({ length: 10 }, () => ({ score: 80, hit: false })),
    ...Array.from({ length: 30 }, () => ({ score: 45, hit: false })),
    ...Array.from({ length: 5 }, () => ({ score: 45, hit: true })),
  ];
  const rows = scoreThresholds(samples);
  const r50 = rows.find((r) => r.threshold === 50)!;
  assert.equal(r50.flagged, 20);
  assert.equal(r50.precision, 0.5);
  assert.equal(r50.recall, 0.67);
  const ctx = testContext([]);
  assert.equal(signalThreshold(ctx), 55, 'default before calibration');
  ctx.store.cachePut('derived:calibration:owl', JSON.stringify({ samples: 40, materialized: 10, best: { threshold: 65, flagged: 12 }, bySource: { wikipedia: { samples: 20, hits: 10, rate: 0.5 }, hackernews: { samples: 20, hits: 0, rate: 0 } } }));
  assert.equal(signalThreshold(ctx), 65);
  assert.deepEqual(sourceWeights(ctx), { wikipedia: 1.3, hackernews: 0.6 });
});

test('health tone lexicon and quake radius', () => {
  assert.ok(lexiconTone(['Company faces lawsuit over fraud', 'CEO resigns']) < 0);
  assert.ok(lexiconTone(['Record profit as company launches new chip']) > 0);
  assert.equal(quakeRadiusKm(6), 50);
  assert.equal(quakeRadiusKm(7), 120);
  assert.ok(quakeRadiusKm(9) <= 400);
});

test('plugins load from a folder, bad ones are reported not fatal, tools run with the api', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oculon-plugins-'));
  try {
    writeFileSync(join(dir, 'good.mjs'), "export default { name: 'good', description: 'd', tools: [{ name: 'hello', description: 'h', run: (api, a) => ({ hi: a.who, at: api.now().toISOString() }) }] };");
    writeFileSync(join(dir, 'bad.mjs'), 'export default { nope: true };');
    const { plugins, errors } = await loadPlugins(dir);
    assert.deepEqual(plugins.map((p) => p.name), ['good']);
    assert.equal(errors.length, 1);
    process.env.OCULON_PLUGINS = dir;
    const o = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
    assert.deepEqual(await o.pluginRun('good.hello', { who: 'x' }), { hi: 'x', at: NOW.toISOString() });
    await assert.rejects(o.pluginRun('good.missing'), /no plugin tool/);
    o.close();
  } finally {
    delete process.env.OCULON_PLUGINS;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('weekly report renders escaped HTML from stored data', async () => {
  const home = mkdtempSync(join(tmpdir(), 'oculon-report-'));
  process.env.OCULON_HOME = home;
  try {
    const o = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
    o.ctx.graph.saveSignal({ id: 's1', module: 'owl', title: 'Big <script>alert(1)</script> story', score: 80, evidence: [{ source: 'x', text: 't', url: 'https://e.test/a' }], createdAt: NOW.toISOString() });
    o.ctx.graph.saveSignal({ id: 's2', module: 'heron', title: 'TOKEN +1663% in 24h', score: 85, evidence: [], createdAt: NOW.toISOString() });
    o.ctx.graph.saveSignal({ id: 's3', module: 'heron', title: 'TOKEN +1851% in 24h', score: 85, evidence: [], createdAt: NOW.toISOString() });
    const r = await o.report(7);
    assert.ok(existsSync(r.file));
    const html = readFileSync(r.file, 'utf8');
    assert.ok(!html.includes('<script>alert'), 'escaped');
    assert.match(html, /Big &lt;script&gt;/);
    // Once in Top signals and once in the Robinhood Chain section; the near-duplicate is dropped in both.
    assert.equal((html.match(/TOKEN \+1\d{3}%/g) ?? []).length, 2, 'near-duplicate signals collapse');
    o.close();
  } finally {
    delete process.env.OCULON_HOME;
    rmSync(home, { recursive: true, force: true });
  }
});
