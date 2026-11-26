import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodePng } from '../src/core/png.js';
import type { Signal } from '../src/core/types.js';
import { asciiOnly, deskOf, oneLine, wireCardPng, wirePostText, wireToday } from '../src/modules/wire.js';
import { NOW, testContext } from './helpers.js';

const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();
const sig = (id: string, module: string, title: string, score: number, h: number, source = 'src', url?: string): Signal => ({ id, module, title, score, evidence: [{ source, text: 'x', ...(url ? { url } : {}) }], createdAt: hoursAgo(h) });

function seeded() {
  const ctx = testContext([]);
  const all = [
    sig('bgp-1', 'bgp', 'BGP route leak by Example Net (AS64500): 120 prefixes, ongoing', 74, 2, 'cloudflare-radar', 'https://radar.cloudflare.com/routing/as64500'),
    sig('bgp-2', 'bgp', 'Possible BGP hijack: AS64501 announced 2 prefixes of AS64502', 70, 3, 'cloudflare-radar'),
    sig('bgp-3', 'blackout', 'Internet disruption in Haiti (technical problem), ongoing', 69, 4, 'cloudflare'),
    sig('fal-1', 'falcon', 'Military air traffic surge near Doha, QA: 7 aircraft (usual ~1)', 83, 5, 'adsb.lol'),
    sig('vul-1', 'vulns', 'Actively exploited: CVE-2026-0001 Example Router', 76, 6, 'cisa-kev', 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001'),
    sig('fire-1', 'fires', 'Large fire activity near California: 1 cluster(s), largest 10 detections, 96 MW', 58, 7, 'nasa-firms'),
    sig('con-1', 'condor', 'Solar flare M1.1 peaked 2026-11-18T09:00Z', 55, 8, 'noaa-swpc'),
    sig('owl-1', 'owl', 'Bitcoin dip predictions', 56, 9, 'polymarket'),
    sig('owl-2', 'owl', 'Some font on Hacker News', 99, 1, 'hackernews'),
    sig('live-1', 'live', 'Surging on Bluesky: "x"', 95, 1, 'bluesky-live'),
    sig('meer-1', 'meerkat', 'Watchlist change', 95, 1, 'watch'),
    sig('url-1', 'urlcheck', 'Malicious link: bad.example', 95, 1, 'urlhaus'),
    sig('old-1', 'vulns', 'Old one', 99, 30, 'cisa-kev'),
  ];
  for (const s of all) ctx.graph.saveSignal(s);
  return ctx;
}

test('wire: desks come from the module and, for mixed modules, from the lead source', () => {
  assert.equal(deskOf('bgp', '', []), 'internet');
  assert.equal(deskOf('squawk', '', []), 'transport');
  assert.equal(deskOf('ransomware', '', []), 'cyber');
  assert.equal(deskOf('condor', 'Solar flare X1.0', [{ source: 'noaa-swpc', text: '' }]), 'space');
  assert.equal(deskOf('condor', 'Wildfire in Chile', [{ source: 'eonet', text: '' }]), 'hazards');
  assert.equal(deskOf('owl', 'Some story', [{ source: 'hackernews', text: '' }, { source: 'polymarket', text: '' }]), null, 'a market source that is not the lead does not make it market news');
  assert.equal(deskOf('owl', 'Will X happen', [{ source: 'polymarket', text: '' }]), 'markets');
  for (const m of ['live', 'meerkat', 'fence', 'case', 'urlcheck', 'scam', 'sanctions']) assert.equal(deskOf(m, 'x', []), null, m);
});

test('wire: at most six, one per desk first, strongest first, only the last 24 hours and only wire desks', () => {
  const d = wireToday(seeded());
  assert.equal(d.items.length, 6);
  const desks = new Set(d.items.map((i) => i.desk));
  assert.deepEqual([...desks].sort(), ['cyber', 'hazards', 'internet', 'markets', 'space', 'transport']);
  assert.deepEqual(d.items.map((i) => i.score), [...d.items.map((i) => i.score)].sort((a, b) => b - a));
  const ids = d.items.map((i) => i.signalId);
  for (const bad of ['live-1', 'meer-1', 'url-1', 'owl-2', 'old-1']) assert.ok(!ids.includes(bad), bad);
  const bgp = d.items.find((i) => i.desk === 'internet')!;
  assert.equal(bgp.signalId, 'bgp-1');
  assert.deepEqual(bgp.sources, ['cloudflare-radar']);
  assert.equal(bgp.url, 'https://radar.cloudflare.com/routing/as64500');
  assert.equal(bgp.at, hoursAgo(2));
  assert.equal(d.considered, 8);
  assert.equal(d.day, '2026-11-18');
  assert.equal(d.note, null);
});

test('wire: a desk can hold two when the others are empty, and an empty day says so', () => {
  const ctx = testContext([]);
  for (let i = 0; i < 5; i++) ctx.graph.saveSignal(sig(`b${i}`, 'bgp', `Route leak number ${i}`, 60 + i, 1));
  const d = wireToday(ctx);
  assert.equal(d.items.length, 2, 'two per desk at most');
  assert.match(d.note!, /Only 2 signals/);
  const empty = wireToday(testContext([]));
  assert.equal(empty.items.length, 0);
  assert.match(empty.note!, /No stored signals/);
  assert.match(wirePostText(empty), /quiet day/);
});

test('wire: a past date reads that UTC day; a bad date is refused', () => {
  const ctx = seeded();
  const d = wireToday(ctx, '2026-11-17');
  assert.equal(d.from, '2026-11-17T00:00:00.000Z');
  assert.equal(d.to, '2026-11-18T00:00:00.000Z');
  assert.deepEqual(d.items.map((i) => i.signalId), ['old-1']);
  assert.throws(() => wireToday(ctx, '17-11-2026'), /YYYY-MM-DD/);
});

test('wire post: plain text, bullets, no emoji, under 600 characters, ends with the link', () => {
  const ctx = seeded();
  const long = 'A very long headline about a routing incident that keeps going and going with many networks and prefixes named '.repeat(3);
  for (let i = 0; i < 6; i++) ctx.graph.saveSignal(sig(`long${i}`, ['bgp', 'falcon', 'vulns', 'fires', 'condor', 'lynx'][i]!, `${long} ${i}`, 90 + i, 1, i === 4 ? 'noaa-swpc' : 'src'));
  const t = wirePostText(wireToday(ctx));
  assert.ok(t.length < 600, String(t.length));
  assert.ok(t.endsWith('oculon.live/today'));
  assert.match(t, /^Oculon Wire, 18 Nov 2026\n\n• /);
  assert.ok(!/\p{Extended_Pictographic}/u.test(t), 'no emoji');
  assert.equal(oneLine('a\n b   c'), 'a b c');
});

test('wire card: a valid 1200x675 PNG with a black background and cyan accents', () => {
  const png = wireCardPng(wireToday(seeded()));
  const img = decodePng(png);
  assert.equal(img.width, 1200);
  assert.equal(img.height, 675);
  const at = (x: number, y: number) => [...img.rgba.subarray((y * 1200 + x) * 4, (y * 1200 + x) * 4 + 3)];
  assert.deepEqual(at(3, 300), [0, 0, 0]);
  assert.deepEqual(at(600, 2), [0, 0xf0, 0xff], 'cyan top bar');
  const empty = decodePng(wireCardPng(wireToday(testContext([]))));
  assert.equal(empty.width, 1200);
  assert.equal(asciiOnly('Café — “ok” …'), 'Cafe - "ok" ...');
});
