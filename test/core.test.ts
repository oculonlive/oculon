import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Graph } from '../src/core/graph.js';
import { Http } from '../src/core/http.js';
import { bucketFromEnd, robustZ, spikeRatio, trend } from '../src/core/stats.js';
import { Store } from '../src/core/store.js';
import { keywords, overlap } from '../src/core/text.js';
import { mockFetch } from './helpers.js';

test('trend classifies hype phases', () => {
  assert.equal(trend([0, 0, 0, 0, 0, 0, 0, 0]).phase, 'DORMANT');
  assert.equal(trend([0, 0, 0, 0, 0, 0, 3, 5]).phase, 'EMERGING');
  assert.equal(trend([10, 10, 11, 10, 12, 11, 20, 30]).phase, 'RISING');
  assert.equal(trend([10, 10, 10, 10, 10, 10, 30, 18]).phase, 'PEAK');
  assert.equal(trend([30, 30, 28, 31, 30, 29, 15, 12]).phase, 'COOLING');
  assert.equal(trend([10, 11, 9, 10, 10, 11, 10, 10]).phase, 'STEADY');
});

test('robust stats detect a spike without being fooled by one outlier', () => {
  const base = [100, 110, 95, 105, 100, 98, 102, 900];
  assert.ok(robustZ(1000, base) > 10);
  assert.ok(Math.abs(robustZ(103, base)) < 1);
  assert.equal(spikeRatio(500, [100, 100, 100]), 5);
  assert.deepEqual(bucketFromEnd([1, 2, 3, 4, 5, 6, 7], 3), [9, 18]);
});

test('keywords and overlap', () => {
  const a = keywords('Will the Fed cut rates in December?');
  const b = keywords('Federal Reserve: Fed cut rates by 25bp in December');
  assert.ok(a.has('december') && a.has('fed'));
  assert.ok(overlap(a, b).score >= 0.5);
});

test('http labels LIVE, CACHED, UNAVAILABLE, ERROR and falls back to stale cache', async () => {
  let mode: 'ok' | 'down' = 'ok';
  const m = mockFetch([
    ['/ok', () => (mode === 'ok' ? { body: { v: 1 } } : { status: 503, body: 'down' })],
    ['/bad', () => ({ status: 500, body: 'boom' })],
    ['/text-limit', () => ({ body: 'Please limit requests to one every 5 seconds' })],
  ]);
  const store = new Store(':memory:');
  const http = new Http(store, { fetch: m.fetch, throttle: false, retryDelayMs: 1 });

  const live = await http.get<{ v: number }>('https://x.test/ok', { source: 't' });
  assert.equal(live.prov.status, 'LIVE');
  assert.equal(live.data?.v, 1);

  const cached = await http.get('https://x.test/ok', { source: 't' });
  assert.equal(cached.prov.status, 'CACHED');

  mode = 'down';
  const stale = await http.get<{ v: number }>('https://x.test/ok', { source: 't', ttlSec: 0, retries: 1 });
  assert.equal(stale.prov.status, 'CACHED');
  assert.match(stale.prov.note ?? '', /stale/);
  assert.equal(stale.data?.v, 1);

  assert.equal((await http.get('https://x.test/missing', { source: 't' })).prov.status, 'UNAVAILABLE');

  const before = m.calls.length;
  const err = await http.get('https://x.test/bad', { source: 't', retries: 2 });
  assert.equal(err.prov.status, 'ERROR');
  assert.equal(m.calls.length - before, 3, 'retries 5xx');

  const limited = await http.get('https://x.test/text-limit', { source: 't', retries: 0, rateLimitText: /^Please limit/ });
  assert.equal(limited.prov.status, 'ERROR');
  assert.equal(limited.prov.note, 'rate limited');
});

test('graph upserts, merges attrs, links and lists neighbors', () => {
  const g = new Graph(new Store(':memory:'));
  const d = g.upsert('domain', 'Example.com', { a: 1 });
  assert.equal(d, 'domain:example.com');
  g.upsert('domain', 'example.com', { b: 2 });
  assert.deepEqual(g.get(d)?.attrs, { a: 1, b: 2 });
  const s = g.upsert('subdomain', 'labs.example.com');
  g.link(d, s, 'has_subdomain', 'crt.sh');
  assert.deepEqual(g.neighbors(d).map((n) => [n.id, n.rel, n.direction]), [[s, 'has_subdomain', 'out']]);
  assert.equal(g.neighbors(s)[0]?.direction, 'in');
});

test('provenance never exposes API keys from the environment', async () => {
  process.env.TEST_SECRET_API_KEY = 'sk-super-secret-value-123456';
  const m = mockFetch([['/q', () => ({ status: 500, body: 'error for token sk-super-secret-value-123456' })]]);
  const http = new Http(new Store(':memory:'), { fetch: m.fetch, throttle: false, retryDelayMs: 1 });
  const r = await http.get('https://x.test/q?token=sk-super-secret-value-123456', { source: 't', retries: 0 });
  assert.ok(!JSON.stringify(r.prov).includes('sk-super-secret-value-123456'));
  assert.match(r.prov.url, /token=\*\*\*/);
  delete process.env.TEST_SECRET_API_KEY;
});

test('daily quota stops live calls and falls back to cache', async () => {
  process.env.OCULON_QUOTA_QTEST = '2';
  const m = mockFetch([['/q', () => ({ body: { ok: true } })]]);
  const http = new Http(new Store(':memory:'), { fetch: m.fetch, throttle: false, retryDelayMs: 1 });
  assert.equal((await http.get('https://x.test/q1', { source: 'qtest' })).prov.status, 'LIVE');
  assert.equal((await http.get('https://x.test/q2', { source: 'qtest' })).prov.status, 'LIVE');
  const third = await http.get('https://x.test/q3', { source: 'qtest' });
  assert.equal(third.prov.status, 'UNAVAILABLE');
  assert.match(third.prov.note ?? '', /quota/);
  const stale = await http.get('https://x.test/q1', { source: 'qtest', ttlSec: 0 });
  assert.equal(stale.prov.status, 'CACHED');
  assert.equal(m.calls.length, 2, 'no network call after the budget is spent');
  delete process.env.OCULON_QUOTA_QTEST;
});

test('contact email goes only to SEC, never to other APIs', async () => {
  process.env.OCULON_CONTACT = 'someone@example.test';
  const seen: Record<string, string> = {};
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    seen[new URL(String(input)).hostname] = String((init?.headers as Record<string, string>)['user-agent']);
    return new Response('{}', { status: 200 });
  }) as typeof fetch;
  const http = new Http(new Store(':memory:'), { fetch: f, throttle: false });
  await http.get('https://data.sec.gov/x', { source: 't' });
  await http.get('https://api.github.com/x', { source: 't' });
  await http.get('https://wikimedia.org/x', { source: 't' });
  assert.match(seen['data.sec.gov']!, /someone@example\.test/);
  assert.doesNotMatch(seen['api.github.com']!, /someone/);
  assert.doesNotMatch(seen['wikimedia.org']!, /someone/);
  delete process.env.OCULON_CONTACT;
});
