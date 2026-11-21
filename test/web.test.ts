import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW } from './helpers.js';

test('web server serves the UI and JSON API, validates input, stays on localhost', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  oculon.ctx.graph.upsert('domain', 'acme.com');
  oculon.ctx.graph.link('domain:acme.com', oculon.ctx.graph.upsert('subdomain', 'labs.acme.com'), 'has_subdomain', 'crt.sh');
  const { server, stop } = createWebServer({ port: 0, oculon });
  await new Promise((r) => server.once('listening', r));
  const addr = server.address() as AddressInfo;
  assert.equal(addr.address, '127.0.0.1');
  const base = `http://127.0.0.1:${addr.port}`;
  try {
    const html = await fetch(base + '/');
    assert.equal(html.status, 200);
    assert.match(await html.text(), /<title>Oculon<\/title>[\s\S]*id="console"/, 'landing at /');
    assert.match(await (await fetch(base + '/app')).text(), /role="tablist"/, 'dashboard at /app');
    assert.match(await (await fetch(base + '/docs')).text(), /<title>Oculon Docs<\/title>/);
    for (const p of ['/privacy', '/terms']) assert.match(await (await fetch(base + p)).text(), /id="privacy"[\s\S]*id="terms"/, p);
    assert.match(await (await fetch(base + '/', { headers: { host: 'app.oculon.test' } })).text(), /role="tablist"/, 'app.* host serves the dashboard');
    const img = await fetch(base + '/assets/night-emea.jpg');
    assert.equal(img.headers.get('content-type'), 'image/jpeg');
    assert.equal((await fetch(base + '/assets/..%2Fserver.ts')).status, 404);
    const readme = (await (await fetch(base + '/api/readme')).json()) as { markdown: string };
    assert.match(readme.markdown, /^# Oculon/);
    const meta = (await (await fetch(base + '/api/meta')).json()) as { mcpTools: number; modules: number };
    assert.ok(meta.mcpTools > 50 && meta.modules > 30);
    assert.equal((await fetch(base + '/api/console?cmd=watch%20add%20company%20x')).status, 400, 'console refuses commands outside the allowlist');

    assert.deepEqual(await (await fetch(base + '/api/signals')).json(), []);
    const fc = (await (await fetch(base + '/api/forecasts')).json()) as { scoreboard: { total: number } };
    assert.equal(fc.scoreboard.total, 0);

    const g = (await (await fetch(base + '/api/graph')).json()) as { nodes: unknown[]; edges: unknown[] };
    assert.equal(g.nodes.length, 2);
    assert.equal(g.edges.length, 1);

    const missing = await fetch(base + '/api/dossier');
    assert.equal(missing.status, 400);
    assert.match(((await missing.json()) as { error: string }).error, /missing parameter: name/);
    assert.equal((await fetch(base + `/api/dossier?name=${'x'.repeat(500)}`)).status, 400);
    assert.equal((await fetch(base + '/api/nope')).status, 404);
    assert.equal((await fetch(base + '/api/signals', { method: 'POST' })).status, 405);
    const headers = (await fetch(base + '/api/signals')).headers;
    assert.equal(headers.get('x-content-type-options'), 'nosniff');
  } finally {
    await stop();
    oculon.close();
  }
});

test('web console only maps read-only commands to argv', async () => {
  const { consoleArgv } = await import('../src/web/server.js');
  const addr = '0x666f7136be18a9be9adfa97d1d81b8e5ef32c78d';
  assert.deepEqual(consoleArgv('oculon bgp'), ['bgp']);
  // on-chain commands are paused by default
  assert.equal(consoleArgv('rh'), null);
  assert.equal(consoleArgv(`token ${addr} --chain robinhood`), null);
  assert.equal(consoleArgv(`deployer ${addr}`), null);
  process.env.OCULON_ONCHAIN = '1';
  try {
    assert.deepEqual(consoleArgv('rh'), ['rh']);
    assert.deepEqual(consoleArgv(`token ${addr} --chain robinhood`), ['token', addr, '--chain', 'robinhood']);
    assert.deepEqual(consoleArgv(`deployer ${addr}`), ['deployer', addr]);
  } finally {
    delete process.env.OCULON_ONCHAIN;
  }
  assert.deepEqual(consoleArgv('cve cve-2026-40217'), ['cve', 'CVE-2026-40217']);
  assert.deepEqual(consoleArgv('bgp as31452'), ['bgp', 'AS31452']);
  for (const bad of ['ask hello', 'watch add company x', 'case new "x"', 'token 0x12 --chain robinhood', `token ${addr} --out /etc/x`, 'bgp; rm -rf /', 'social x', 'serve', '']) assert.equal(consoleArgv(bad), null, bad);
});

test('public mode: visitors get the overview and a read-only API; the owner signs in for the app', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  oculon.ctx.graph.saveSignal({ id: 'pub-1', module: 'owl', title: 'public signal', score: 60, evidence: [], createdAt: new Date(NOW).toISOString() });
  oculon.ctx.graph.saveSignal({ id: 'priv-1', module: 'meerkat', title: 'watchlist change', score: 60, evidence: [], createdAt: new Date(NOW).toISOString() });
  const { server, stop } = createWebServer({ port: 0, oculon, publicMode: true, adminToken: 'owner-secret' });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    assert.match(await (await fetch(base + '/')).text(), /id="console"/);
    const app = await (await fetch(base + '/app')).text();
    assert.doesNotMatch(app, /role="tablist"/, 'dashboard is locked');
    assert.match(app, /runs on your own machine/);
    assert.equal((await fetch(base + '/api/watch')).status, 403, 'watchlist is private');
    assert.equal((await fetch(base + '/api/ask?q=hi')).status, 403, 'LLM endpoints are private');
    assert.equal((await fetch(base + '/api/fences', { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1' }, body: '{}' })).status, 403, 'no writes');
    const sigs = (await (await fetch(base + '/api/signals')).json()) as { id: string }[];
    assert.deepEqual(sigs.map((s) => s.id), ['pub-1'], 'watchlist signals are filtered out');
    const bad = await fetch(base + '/login', { method: 'POST', body: 'token=nope', headers: { 'content-type': 'application/x-www-form-urlencoded' }, redirect: 'manual' });
    assert.equal(bad.status, 401);
    const ok = await fetch(base + '/login', { method: 'POST', body: 'token=owner-secret', headers: { 'content-type': 'application/x-www-form-urlencoded' }, redirect: 'manual' });
    assert.equal(ok.status, 303);
    const cookie = (ok.headers.get('set-cookie') ?? '').split(';')[0]!;
    assert.doesNotMatch(cookie, /owner-secret/, 'the token itself is never sent back');
    assert.match(await (await fetch(base + '/app', { headers: { cookie } })).text(), /role="tablist"/, 'owner gets the app');
    assert.equal((await fetch(base + '/api/watch', { headers: { cookie } })).status, 200);
  } finally {
    await stop();
    oculon.close();
  }
});

test('public mode rate limits each client', async () => {
  const { RateLimiter } = await import('../src/web/public.js');
  const l = new RateLimiter(3, 1);
  assert.deepEqual([1, 2, 3, 4].map(() => l.allow('1.1.1.1', '/api/meta', 1000)), [true, true, true, false]);
  assert.equal(l.allow('2.2.2.2', '/api/meta', 1000), true, 'other clients are unaffected');
  assert.deepEqual([1, 2].map(() => l.allow('1.1.1.1', '/api/console', 1000)), [true, false], 'heavy endpoints have their own smaller budget');
  assert.equal(l.allow('1.1.1.1', '/api/meta', 62_000), true, 'the window resets after a minute');
});


test('pages drop on-chain blocks unless switched on, and point app and docs links at subdomains', async () => {
  const { renderPage } = await import('../src/web/server.js');
  const html = '<a href="/app">app</a><a href="/docs#cli">cli</a><a href="/">home</a><a href="/privacy">p</a><!--onchain--><b>chain</b><!--/onchain--><!--offchain--><i>plain</i><!--/offchain--><script>/*onchain*/const a = 1;/*/onchain*/</script>';
  const off = renderPage(html, null);
  assert.doesNotMatch(off, /chain<\/b>|const a/);
  assert.match(off, /<i>plain<\/i>/);
  assert.doesNotMatch(off, /onchain|offchain/, 'markers are removed');
  assert.match(off, /href="\/app"/, 'local links stay relative');
  process.env.OCULON_ONCHAIN = '1';
  try {
    const on = renderPage(html, 'example.org');
    assert.match(on, /<b>chain<\/b>/);
    assert.doesNotMatch(on, /<i>plain/);
    assert.match(on, /href="https:\/\/app\.example\.org\/"/);
    assert.match(on, /href="https:\/\/docs\.example\.org\/#cli"/);
    assert.match(on, /href="https:\/\/example\.org\/privacy"/);
    assert.match(on, /href="https:\/\/example\.org\/"/);
  } finally {
    delete process.env.OCULON_ONCHAIN;
  }
});

test('edge Worker headers pick the subdomain page only with the shared secret', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const { server, stop } = createWebServer({ port: 0, oculon, domain: 'example.org', edgeSecret: 'edge-secret' });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const viaEdge = await (await fetch(base + '/', { headers: { 'x-oculon-edge': 'edge-secret', 'x-oculon-site': 'app' } })).text();
    assert.match(viaEdge, /id="tab-overview"/, 'app.<domain> serves the dashboard');
    const docs = await (await fetch(base + '/', { headers: { 'x-oculon-edge': 'edge-secret', 'x-oculon-site': 'docs' } })).text();
    assert.match(docs, /<title>Oculon Docs<\/title>/);
    const forged = await (await fetch(base + '/', { headers: { 'x-oculon-edge': 'wrong', 'x-oculon-site': 'app' } })).text();
    assert.doesNotMatch(forged, /id="tab-overview"/, 'a forged header gets the overview page');
  } finally {
    await stop();
    oculon.close();
  }
});

test('public mode locks app.<domain> for visitors and the main domain redirects /app and /docs', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const { server, stop } = createWebServer({ port: 0, oculon, publicMode: true, adminToken: 'owner-token', domain: 'example.org', edgeSecret: 'edge-secret' });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const app = await (await fetch(base + '/', { headers: { 'x-oculon-edge': 'edge-secret', 'x-oculon-site': 'app' } })).text();
    assert.doesNotMatch(app, /id="tab-overview"/, 'visitors never get the dashboard on app.<domain>');
    const docs = await (await fetch(base + '/', { headers: { 'x-oculon-edge': 'edge-secret', 'x-oculon-site': 'docs' } })).text();
    assert.match(docs, /<title>Oculon Docs<\/title>/, 'docs stay public');
    for (const p of ['app', 'docs']) {
      const r = await new Promise<import('node:http').IncomingMessage>((ok, fail) => {
        import('node:http').then(({ get }) => get(`${base}/${p}`, { headers: { host: 'example.org' } }, (res) => { res.resume(); ok(res); }).on('error', fail));
      });
      assert.equal(r.statusCode, 301);
      assert.equal(r.headers.location, `https://${p}.example.org/`);
    }
  } finally {
    await stop();
    oculon.close();
  }
});
