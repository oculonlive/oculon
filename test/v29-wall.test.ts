import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const read = (f: string) => readFileSync(new URL(`../src/web/${f}`, import.meta.url), 'utf8');

/** Runs the wall's own placement code (country table and placeOf) outside the browser. */
function placeOf(): (s: { title: string; evidence?: { text?: string }[] }) => { lon: number; lat: number; exact: boolean } | null {
  const html = read('wall.html');
  const start = html.indexOf('// Country centroids');
  const end = html.indexOf('const sigs = new Map();');
  assert.ok(start > 0 && end > start, 'placement code is where the test expects it');
  const ctx: Record<string, unknown> = {};
  vm.runInNewContext(`${html.slice(start, end)}\nthis.placeOf = placeOf;`, ctx);
  const inner = ctx.placeOf as ReturnType<typeof placeOf>;
  // Objects from the sandbox have its own prototypes; copy them into this realm for deepEqual.
  return (s) => JSON.parse(JSON.stringify(inner(s)));
}

test('wall: a position written in the signal is used as is; a named country gives an approximate place; else none', () => {
  const p = placeOf();
  const squawk = p({ title: 'Squawk 7700 (general emergency): MSR781 40 km from Manchester Airport (MAN), GB', evidence: [{ text: 'MSR781 squawking 7700 at 8950 ft, 341 kt, position 53.156, -1.772, emergency flag "general"' }] });
  assert.deepEqual(squawk, { lon: -1.772, lat: 53.156, exact: true });
  const fire = p({ title: 'Large fire activity near California', evidence: [{ text: '10 hotspots at 36.146, -118.511 totaling 96 MW' }] });
  assert.deepEqual(fire, { lon: -118.511, lat: 36.146, exact: true });
  const iso = p({ title: 'Military air traffic surge near Doha, QA: 7 aircraft (usual ~1)', evidence: [{ text: '7 military-flagged aircraft vs median 1' }] })!;
  assert.equal(iso.exact, false);
  assert.deepEqual([iso.lon, iso.lat], [51.2, 25.3]);
  const named = p({ title: 'Internet disruption in Haiti (technical problem), ongoing', evidence: [] })!;
  assert.equal(named.exact, false);
  assert.equal(p({ title: 'Intel One Mono font (2023)', evidence: [{ text: '384 points, 215 comments in 9h' }] }), null);
  assert.equal(p({ title: 'Wikipedia readers 12.2x usual', evidence: [{ text: 'value 12.228915662650602' }] }), null, 'a lone decimal is not a position');
  assert.equal(p({ title: 'x', evidence: [{ text: 'position 123.456, 10.000' }] }), null, 'latitude out of range');
});

test('wall: kiosk mode, same-origin data, the stream, status, a UTC clock and no outside scripts beyond the site\'s own', () => {
  const html = read('wall.html');
  assert.match(html, /params\.get\('kiosk'\) === '1'/);
  assert.match(html, /\.kiosk header\{display:none\}/);
  for (const ep of ["new EventSource('/api/stream')", "fetch('/api/signals?limit=200')", "fetch('/api/status?hours=1')", "addEventListener('signal'"]) assert.ok(html.includes(ep), ep);
  assert.match(html, /toISOString\(\)\.slice\(11, 19\)/);
  const scripts = [...html.matchAll(/<script src="([^"]+)"/g)].map((m) => m[1]!);
  for (const s of scripts) assert.match(s, /^https:\/\/cdnjs\.cloudflare\.com\//, s);
  const fetched = [...html.matchAll(/fetch\('(https?:[^']+)'/g)].map((m) => m[1]!);
  assert.deepEqual(fetched, ['https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json'], 'only the map outline, as the overview page loads it');
});

test('pages: English, no emoji, phone-safe, and each calls its own endpoint', () => {
  for (const [f, ep] of [['today.html', '/api/wire'], ['trends.html', '/api/trends'], ['wall.html', '/api/signals']] as const) {
    const html = read(f);
    assert.ok(html.includes(ep), `${f} calls ${ep}`);
    assert.ok(!/\p{Extended_Pictographic}/u.test(html.replace(/©/g, '')), `${f} has no emoji`);
    assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
    assert.match(html, /overflow-x:clip/);
    assert.match(html, /@media \(max-width:820px\)/);
    assert.ok(!/\b(yang|dan|untuk|tidak|dengan)\b/i.test(html.replace(/<script[\s\S]*?<\/script>/g, '')), `${f} is English only`);
  }
  assert.match(read('today.html'), /\/wire\/today\.png/);
});
