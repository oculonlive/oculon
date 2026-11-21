import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { makeBrief, pickSignals, templateBrief } from '../src/modules/brief.js';
import { poolFlags, rhVerdict } from '../src/modules/heron.js';
import { addWatch, listWatch, removeWatch, runWatch } from '../src/modules/meerkat.js';
import { toPool } from '../src/sources/robinhood.js';
import { markdownToTelegram } from '../src/telegram.js';
import { NOW, testContext, type Route } from './helpers.js';
import type { Signal } from '../src/core/types.js';

const gt = (name: string, created: string, liq: string, buys: number, sells: number, h1 = '1') =>
  toPool({ id: 'x', attributes: { name, address: '0xpool', pool_created_at: created, reserve_in_usd: liq, volume_usd: { h24: '1000' }, price_change_percentage: { h1, h24: '2' }, transactions: { h24: { buys, sells } } }, relationships: { base_token: { data: { id: 'robinhood_0xtok' } } } });

test('heron pool flags and token verdict', () => {
  const now = Date.parse('2026-11-19T06:00:00Z');
  const honey = poolFlags(gt('A / WETH', '2026-11-19T05:00:00Z', '8000', 30, 0), now);
  assert.equal(honey.ageHours, 1);
  assert.ok(honey.flags.some((f) => /honeypot/.test(f)));
  assert.equal(honey.pool.token, '0xtok');
  const fine = poolFlags(gt('B / WETH', '2026-10-01T00:00:00Z', '500000', 300, 280), now);
  assert.deepEqual(fine.flags, []);
  assert.equal(rhVerdict({ verified: true, top10Share: 0.5, holders: 10_000, pools: [fine] }).verdict, 'OK');
  assert.equal(rhVerdict({ verified: false, top10Share: 0.5, holders: 10_000, pools: [fine] }).verdict, 'CAUTION');
  assert.equal(rhVerdict({ verified: true, top10Share: 0.99, holders: 50, pools: [fine] }).verdict, 'DANGER');
  assert.equal(rhVerdict({ verified: true, top10Share: 0.2, holders: 1000, pools: [honey] }).verdict, 'DANGER');
  assert.equal(rhVerdict({ verified: null, top10Share: null, holders: null, pools: [] }).verdict, 'UNKNOWN');
});

test('meerkat: baseline first, then reports only real changes', async () => {
  let category = 0;
  const pm = [12, 80];
  const routes: Route[] = [
    ['nominatim', () => ({ body: [{ display_name: 'Testville', lat: '1', lon: '2', boundingbox: ['0.9', '1.1', '1.9', '2.1'], addresstype: 'city', importance: 0.5 }] })],
    ['api.openaq.org/v3/locations?', () => ({ body: { results: [{ id: 7, name: 'Station A', distance: 1000, datetimeLast: { utc: NOW.toISOString() }, sensors: [{ id: 70, parameter: { name: 'pm25', units: 'µg/m³' } }] }] } })],
    ['/locations/7/latest', () => ({ body: { results: [{ value: pm[category], sensorsId: 70, datetime: { utc: NOW.toISOString() } }] } })],
  ];
  process.env.OPENAQ_API_KEY = 'test-openaq-key-123456';
  try {
    const ctx = testContext(routes);
    const item = addWatch(ctx, 'air', 'Testville');
    assert.equal(listWatch(ctx).length, 1);
    assert.throws(() => addWatch(ctx, 'nope', 'x'), /kind must be one of/);

    const r1 = await runWatch(ctx);
    assert.equal(r1.runs[0]!.baseline, true);
    assert.equal(r1.signals.length, 0, 'baseline never alerts');

    const r2 = await runWatch(ctx);
    assert.equal(r2.runs[0]!.changes.length, 0, 'same data, no change');

    category = 1;
    ctx.store.db.prepare('DELETE FROM cache').run();
    const r3 = await runWatch(ctx);
    assert.deepEqual(r3.runs[0]!.changes, ['air quality moderate → unhealthy (PM2.5 80)']);
    assert.equal(r3.signals.length, 1);
    assert.match(r3.signals[0]!.title, /Watch air Testville/);
    assert.ok(removeWatch(ctx, item.id));
    assert.equal(listWatch(ctx).length, 0);
  } finally {
    delete process.env.OPENAQ_API_KEY;
  }
});

const sig = (module: string, title: string, score: number): Signal => ({ id: `${module}-${title}`, module, title, score, evidence: [{ source: 's', text: 't', url: 'https://e.test' }], createdAt: NOW.toISOString() });

test('brief picks watch changes first and caps any one module', () => {
  const all = [sig('meerkat', 'Watch company X: new court case', 60), ...Array.from({ length: 10 }, (_, i) => sig('owl', `owl ${i}`, 90 - i)), sig('heron', 'pool', 70)];
  const p = pickSignals(all);
  assert.equal(p[0]!.module, 'meerkat');
  assert.equal(p.filter((s) => s.module === 'owl').length, 5);
  assert.ok(p.some((s) => s.module === 'heron'));
  assert.match(templateBrief('2026-11-19', p), /## Watchlist changes/);
});

test('brief is stored once per day and falls back to a template without an LLM', async () => {
  const o = new Oculon({ dbPath: ':memory:', throttle: false, now: () => NOW });
  o.ctx.graph.saveSignal(sig('owl', 'Something happened', 70));
  const b1 = await makeBrief(o.ctx);
  assert.match(b1.markdown, /# Oculon brief, 2026-11-18/);
  assert.match(b1.markdown, /Something happened/);
  assert.equal(b1.model, null);
  const again = await makeBrief(o.ctx);
  assert.equal(again.createdAt, b1.createdAt, 'served from storage');
  o.close();
});

test('markdown to Telegram HTML is escaped and keeps links', () => {
  const html = markdownToTelegram('# Title\n- **Bold** <script> [source](https://e.test/a_b)');
  assert.equal(html, '<b>Title</b>\n• <b>Bold</b> &lt;script&gt; <a href="https://e.test/a_b">source</a>');
});

class FakeWs {
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  sent: string[] = [];
  constructor(_url: string) {
    setTimeout(() => {
      this.onopen?.();
      this.onmessage?.({ data: JSON.stringify({ MessageType: 'SubscriptionConfirmation' }) });
      const meta = (mmsi: number, name: string) => ({ MMSI: mmsi, ShipName: name, latitude: 51.9, longitude: 4.3, time_utc: '2026-11-18 11:59:00.0 +0000 UTC' });
      this.onmessage?.({ data: JSON.stringify({ MessageType: 'PositionReport', MetaData: meta(244000001, 'ALPHA'), Message: { PositionReport: { Sog: 0.1, NavigationalStatus: 1 } } }) });
      this.onmessage?.({ data: JSON.stringify({ MessageType: 'PositionReport', MetaData: meta(244000002, 'BRAVO'), Message: { PositionReport: { Sog: 12, NavigationalStatus: 0 } } }) });
      this.onmessage?.({ data: JSON.stringify({ MessageType: 'ShipStaticData', MetaData: meta(244000002, 'BRAVO'), Message: { ShipStaticData: { Type: 82, Destination: 'ANTWERP' } } }) });
    }, 1);
  }
  send(s: string) {
    this.sent.push(s);
  }
  close() {
    this.onerror?.();
    this.onclose?.();
  }
}

test('ships: AIS stream is parsed into vessels, types and anchored counts; key is required', async () => {
  const { shipsNear } = await import('../src/modules/ships.js');
  const ctx = testContext([['nominatim', () => ({ body: [{ display_name: 'Port of Testhaven', lat: '51.9', lon: '4.3', boundingbox: ['51.8', '52.0', '4.0', '4.6'], addresstype: 'harbour', importance: 0.5 }] })]]);
  const none = await shipsNear(ctx, 'Port of Testhaven', 10, FakeWs as unknown as typeof WebSocket);
  assert.equal(none.provenance.find((p) => p.source === 'aisstream')?.status, 'UNAVAILABLE');
  process.env.AISSTREAM_API_KEY = 'test-ais-key-1234567890';
  try {
    const orig = global.setTimeout;
    // Shorten the listening window for the test.
    (global as { setTimeout: typeof setTimeout }).setTimeout = ((fn: () => void, ms?: number) => orig(fn, Math.min(ms ?? 0, 20))) as typeof setTimeout;
    const r = await shipsNear(ctx, 'Port of Testhaven', 10, FakeWs as unknown as typeof WebSocket);
    global.setTimeout = orig;
    const d = r.result;
    assert.equal(d.total, 2);
    assert.equal(d.stationary, 1);
    assert.equal(d.byType.tanker, 1);
    assert.equal(d.vessels.find((v) => v.name === 'BRAVO')?.destination, 'ANTWERP');
    assert.equal(r.provenance.find((p) => p.source === 'aisstream')?.status, 'LIVE', 'closing the window is not an error');
  } finally {
    delete process.env.AISSTREAM_API_KEY;
  }
});

test('brief links: only URLs from the input survive, odd bracket styles are normalized', async () => {
  const { sanitizeLinks } = await import('../src/modules/brief.js');
  const allowed = new Set(['https://real.test/a']);
  const out = sanitizeLinks('A 【source】(https://real.test/a). B [source](https://invented.test). C [the docs](https://invented.test/x) and https://bare.test', allowed);
  assert.equal(out, 'A [source](https://real.test/a). B. C the docs and');
});

test('brief links: bracketed bare URLs become source links, bracketed labels are removed', async () => {
  const { sanitizeLinks } = await import('../src/modules/brief.js');
  const out = sanitizeLinks('A 【https://real.test/a】. B 【goplus】. C 【https://invented.test/x】.', new Set(['https://real.test/a']));
  assert.equal(out, 'A [source](https://real.test/a). B. C.');
});
