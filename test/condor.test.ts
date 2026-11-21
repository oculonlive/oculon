import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { test } from 'node:test';
import { brightness, decodePng } from '../src/core/png.js';
import { analysisBox, eventSeverity, events, lights } from '../src/modules/condor.js';
import { NIGHT_LIGHTS } from '../src/sources/earth.js';
import { NOW, testContext } from './helpers.js';

function crc32(buf: Buffer): number {
  let c = ~0;
  for (const b of buf) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
  }
  return ~c >>> 0;
}

function chunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

/** Build an RGBA PNG of a uniform gray `level`, using a different row filter per row to exercise the decoder. */
export function grayPng(level: number, size = 8, alpha = 255): Buffer {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const stride = size * 4;
  const rows: Buffer[] = [];
  for (let y = 0; y < size; y++) {
    const filter = y % 3 === 1 ? 1 : y % 3 === 2 ? 2 : 0;
    const row = Buffer.alloc(stride + 1);
    row[0] = filter;
    for (let x = 0; x < stride; x++) {
      const v = x % 4 === 3 ? alpha : level;
      const left = x >= 4 ? (x % 4 === 3 ? alpha : level) : 0;
      const up = y > 0 ? v : 0;
      row[x + 1] = (filter === 0 ? v : filter === 1 ? v - left : v - up) & 0xff;
    }
    rows.push(row);
  }
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', deflateSync(Buffer.concat(rows))), chunk('IEND', Buffer.alloc(0))]);
}

test('png decoder handles filters and transparency', () => {
  const img = decodePng(grayPng(120));
  assert.equal(img.width, 8);
  assert.deepEqual([...img.rgba.subarray(0, 4)], [120, 120, 120, 255]);
  assert.deepEqual([...img.rgba.subarray(img.rgba.length - 4)], [120, 120, 120, 255]);
  const b = brightness(img);
  assert.ok(Math.abs(b.mean - 120) < 0.01);
  assert.equal(b.coverage, 1);
  assert.equal(brightness(decodePng(grayPng(200, 8, 0))).coverage, 0);
});

test('analysis box crops big regions and widens tiny ones', () => {
  const big = analysisBox({ name: 'x', lat: 0, lon: 0, bbox: [-5, 5, -5, 5], type: 'state', importance: 1 });
  assert.ok(Math.abs(big[1] - big[0] - 1.2) < 1e-9);
  const tiny = analysisBox({ name: 'x', lat: 10, lon: 10, bbox: [10, 10.01, 10, 10.01], type: 'road', importance: 0 });
  assert.ok(Math.abs(tiny[1] - tiny[0] - 0.15) < 1e-9);
});

test('event severity rules', () => {
  const e = { id: '1', title: 't', date: '', lat: 0, lon: 0, url: '' };
  assert.equal(eventSeverity({ ...e, category: 'severeStorms', magnitude: 130, unit: 'kts' })?.score, 85);
  assert.equal(eventSeverity({ ...e, category: 'severeStorms', magnitude: 45, unit: 'kts' }), null);
  assert.equal(eventSeverity({ ...e, category: 'wildfires', magnitude: 2000, unit: 'acres' }), null);
  assert.ok((eventSeverity({ ...e, category: 'wildfires', magnitude: 50_000, unit: 'acres' })?.score ?? 0) >= 70);
});

test('condor events end to end', async () => {
  const ctx = testContext([
    ['eonet', () => ({ body: { events: [{ id: 'E1', title: 'Tropical Cyclone Xavier', categories: [{ id: 'severeStorms' }], geometry: [{ date: '2026-11-17T18:00:00Z', type: 'Point', coordinates: [-163.8, -9.6], magnitudeValue: 130, magnitudeUnit: 'kts' }] }] } })],
  ]);
  const r = await events(ctx);
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0]!.title, /major hurricane/);
});

test('condor lights detects a blackout against its baseline and skips nights without data', async () => {
  const day = 86_400_000;
  const newest = new Date(NOW.getTime() - 2 * day).toISOString().slice(0, 10);
  const recentCut = NOW.getTime() - 7 * day;
  const ctx = testContext([
    ['nominatim', () => ({ body: [{ display_name: 'Testville, Nowhere', lat: '10', lon: '20', boundingbox: ['9.9', '10.1', '19.9', '20.1'], addresstype: 'city', importance: 0.6 }] })],
    [
      NIGHT_LIGHTS,
      (url) => {
        const date = /TIME=(\d{4}-\d{2}-\d{2})/.exec(url)![1]!;
        if (date > newest) return { body: grayPng(0, 8, 0).toString('latin1') }; // not yet published
        return { body: grayPng(Date.parse(date) >= recentCut ? 40 : 100).toString('latin1') };
      },
    ],
  ]);
  const inner = (ctx.http as unknown as { cfg: { fetch: typeof fetch } }).cfg;
  const f = inner.fetch;
  inner.fetch = (async (i: string | URL | Request, init?: RequestInit) => {
    const res = await f(i, init);
    return String(i).includes('gibs') ? new Response(Buffer.from(await res.text(), 'latin1'), { status: res.status }) : res;
  }) as typeof fetch;

  const r = await lights(ctx, 'Testville');
  assert.equal(r.result.latestDate, newest);
  assert.equal(r.result.verdict, 'DROP');
  assert.ok(Math.abs(r.result.ratio! - 0.4) < 0.01);
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0]!.title, /down 60%/);
});

test('geocode keeps relevance order, prefers name matches, demotes streets', async () => {
  const { geocode, nameMatches } = await import('../src/sources/earth.js');
  assert.ok(nameMatches('Kyoto, Japan', 'Kyoto'));
  assert.ok(!nameMatches('Paris, Ile-de-France, France', 'Kyoto'));
  const ctx = (await import('./helpers.js')).testContext([
    ['nominatim', () => ({ body: [
      { display_name: 'Gaza Strip, Macleod, Melbourne, Australia', lat: '-37', lon: '145', boundingbox: ['0', '0', '0', '0'], addresstype: 'road', importance: 0.1 },
      { display_name: 'Gaza Strip', lat: '31.4', lon: '34.3', boundingbox: ['31.2', '31.6', '34.2', '34.6'], addresstype: 'territory', importance: 0.5 },
      { display_name: 'Paris, France', lat: '48', lon: '2', boundingbox: ['0', '0', '0', '0'], addresstype: 'city', importance: 0.9 },
    ] })],
  ]);
  const r = await geocode(ctx, 'Gaza Strip');
  assert.equal(r.data?.[0]?.name, 'Gaza Strip');
  assert.equal(r.data?.[2]?.name, 'Paris, France');
});
