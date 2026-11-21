import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { apexOf, normalizeUrl, urlCheck, urlHeuristics } from '../src/modules/urlcheck.js';
import { audit, parseManifest, resolveVersion } from '../src/modules/audit.js';
import { factCheck, ratingsVerdict } from '../src/modules/factcheck.js';
import { parseMonitorPattern } from '../src/modules/monitor.js';
import { splitQuakeTarget } from '../src/modules/meerkat.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW, testContext } from './helpers.js';

const LLM_KEYS = ['GROQ_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY', 'ANTHROPIC_API_KEY'];
const withEnv = async (vars: Record<string, string | undefined>, fn: () => Promise<void>) => {
  const old = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  try { await fn(); } finally { for (const [k, v] of Object.entries(old)) if (v === undefined) delete process.env[k]; else process.env[k] = v; }
};
const noLlm = Object.fromEntries(LLM_KEYS.map((k) => [k, undefined]));

test('URL helpers: normalize, registrable domain, warning signs', () => {
  assert.equal(normalizeUrl('example.com/x').href, 'http://example.com/x');
  assert.equal(apexOf('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(apexOf('login.paypal.com'), 'paypal.com');
  const signs = urlHeuristics(new URL('http://paypal-secure-login.account-verify.xyz/signin'));
  assert.ok(signs.some((s) => /paypal/.test(s)), 'brand on another domain');
  assert.ok(signs.some((s) => /\.xyz/.test(s)), 'risky TLD');
  assert.deepEqual(urlHeuristics(new URL('https://www.paypal.com/signin')), [], 'the real domain is clean');
  assert.ok(urlHeuristics(new URL('http://xn--pypal-4ve.com/')).some((s) => /punycode/.test(s)));
});

test('urlCheck: Safe Browsing and URLhaus hits make a link malicious; big platforms are not blamed for user uploads', async () => {
  await withEnv({ SAFE_BROWSING_KEY: 'sb', ABUSECH_AUTH_KEY: 'ah', URLSCAN_API_KEY: undefined }, async () => {
    const ctx = testContext([
      ['safebrowsing.googleapis.com', () => ({ body: { matches: [{ threat: { url: 'http://bad.example-files.top/x.exe' }, threatType: 'MALWARE' }] } })],
      ['urlhaus-api.abuse.ch/v1/url/', () => ({ body: { query_status: 'ok', url_status: 'online', threat: 'malware_download', tags: ['exe'], urlhaus_reference: 'https://urlhaus.abuse.ch/url/1/' } })],
      ['urlhaus-api.abuse.ch/v1/host/', () => ({ body: { query_status: 'no_results' } })],
      ['rdap.org', () => ({ body: { events: [{ eventAction: 'registration', eventDate: '2026-11-10T00:00:00Z' }] } })],
      ['urlscan.io', () => ({ body: { results: [] } })],
    ]);
    const r = await urlCheck(ctx, 'http://bad.example-files.top/x.exe');
    assert.equal(r.result.verdict, 'malicious');
    assert.equal(r.result.risk, 100);
    assert.equal(r.result.domainInfo?.ageDays, 8);
    assert.ok(r.result.reasons.some((x) => /registered 8 days ago/.test(x)));
    assert.equal(r.signals.length, 1);

    const big = testContext([
      ['safebrowsing.googleapis.com', () => ({ body: {} })],
      ['urlhaus-api.abuse.ch/v1/url/', () => ({ body: { query_status: 'no_results' } })],
      ['urlhaus-api.abuse.ch/v1/host/', () => ({ body: { query_status: 'ok', url_count: 6000, urls: [{ url_status: 'online' }] } })],
      ['rdap.org', () => ({ body: { events: [{ eventAction: 'registration', eventDate: '2007-10-09T00:00:00Z' }] } })],
      ['urlscan.io', () => ({ body: { results: [{ task: { time: '2026-11-01T00:00:00Z', tags: ['@phish_report'] }, page: { title: 'Sign in', country: 'US' }, _id: 'abc' }] } })],
    ]);
    const g = await urlCheck(big, 'https://github.com/login');
    assert.equal(g.result.verdict, 'no known threats', 'user-uploaded malware on an old platform does not flag the platform');
    assert.ok(!g.result.reasons.some((x) => /tagged/.test(x)), 'submitter handles are not findings');
  });
});

test('audit: manifests parse, versions resolve, and flags come from deps.dev data', async () => {
  const pj = parseManifest(JSON.stringify({ dependencies: { express: '^4.17.1' }, devDependencies: { typescript: '~5.4.0' } }));
  assert.equal(pj.kind, 'package.json');
  assert.deepEqual(pj.deps.map((d) => [d.name, d.dev]), [['express', false], ['typescript', true]]);
  const req = parseManifest('requests==2.19.0\n# comment\nflask>=2.0\n-r other.txt\nnumpy');
  assert.deepEqual(req.deps.map((d) => [d.name, d.spec]), [['requests', '==2.19.0'], ['flask', '>=2.0'], ['numpy', null]]);
  const list = parseManifest('npm:@scope/pkg@1.0.0 pypi:Requests==2.19.0');
  assert.deepEqual(list.deps.map((d) => [d.ecosystem, d.name, d.spec]), [['npm', '@scope/pkg', '1.0.0'], ['pypi', 'requests', '==2.19.0']]);

  const vs = ['4.16.0', '4.17.1', '4.18.2', '5.0.0', '5.1.0-beta.1'];
  assert.equal(resolveVersion('^4.17.1', vs, '5.0.0'), '4.18.2');
  assert.equal(resolveVersion('4.17.1', vs, '5.0.0'), '4.17.1');
  assert.equal(resolveVersion(null, vs, '5.0.0'), '5.0.0');
  assert.equal(resolveVersion('>=4.0', vs, '5.0.0'), '5.0.0');

  const ctx = testContext([
    [/packages\/left-pad\/versions\//, () => ({ body: { licenses: ['WTFPL'], isDeprecated: true, deprecatedReason: 'use padStart', advisoryKeys: [], relatedProjects: [{ projectKey: { id: 'github.com/x/left-pad' }, relationType: 'SOURCE_REPO' }] } })],
    [/packages\/left-pad$/, () => ({ body: { versions: [{ versionKey: { version: '1.3.0' }, publishedAt: '2018-04-09T00:00:00Z', isDefault: true }] } })],
    [/packages\/lodash\/versions\//, () => ({ body: { licenses: ['MIT'], advisoryKeys: [{ id: 'GHSA-1' }], relatedProjects: [] } })],
    [/packages\/lodash$/, () => ({ body: { versions: [{ versionKey: { version: '4.17.15' }, publishedAt: '2019-07-19T00:00:00Z' }, { versionKey: { version: '4.17.21' }, publishedAt: '2026-05-01T00:00:00Z', isDefault: true }] } })],
    [/advisories\/GHSA-1/, () => ({ body: { title: 'Command Injection in lodash', cvss3Score: 9.8, aliases: ['CVE-2021-23337'], url: 'https://osv.dev/vulnerability/GHSA-1' } })],
    [/projects\//, () => ({ body: { starsCount: 10, scorecard: { overallScore: 3.1, checks: [{ name: 'Maintained', score: 0 }] } } })],
  ]);
  const r = await audit(ctx, 'npm:left-pad npm:lodash@4.17.15');
  const lp = r.result.packages.find((p) => p.name === 'left-pad')!;
  assert.ok(lp.flags.some((f) => /deprecated/.test(f)) && lp.flags.some((f) => /no release in/.test(f)) && lp.flags.some((f) => /Scorecard/.test(f)));
  const lo = r.result.packages.find((p) => p.name === 'lodash')!;
  assert.equal(lo.version, '4.17.15');
  assert.equal(lo.advisories[0]?.aliases[0], 'CVE-2021-23337');
  assert.equal(r.result.summary.vulnerable, 1);
  assert.equal(r.signals.length, 1, 'a critical advisory becomes a signal');
});

test('fact check: published ratings decide the verdict when no LLM is configured', async () => {
  assert.equal(ratingsVerdict(['False', 'Pants on Fire!', 'Misleading']).verdict, 'false');
  assert.equal(ratingsVerdict(['Missing context', 'Partly false']).verdict, 'misleading');
  assert.equal(ratingsVerdict([]).verdict, 'unverified');
  await withEnv({ ...noLlm, GOOGLE_API_KEY: 'g', TAVILY_API_KEY: undefined, EXA_API_KEY: undefined }, async () => {
    const ctx = testContext([
      ['factchecktools.googleapis.com', () => ({ body: { claims: [
        { text: '5G spreads the coronavirus', claimant: 'social media', claimReview: [{ publisher: { name: 'Full Fact' }, url: 'https://fullfact.org/x', textualRating: 'False', reviewDate: '2020-04-01T00:00:00Z' }] },
        { text: '5G towers cause COVID-19', claimReview: [{ publisher: { name: 'AFP Fact Check' }, url: 'https://factcheck.afp.com/y', textualRating: 'False' }] },
      ] } })],
    ]);
    const r = await factCheck(ctx, '5G towers spread COVID-19');
    assert.equal(r.result.verdict, 'false');
    assert.equal(r.result.factChecks.length, 2);
    assert.equal(r.result.method, 'published ratings');
    assert.ok(!r.provenance.some((p) => p.url.includes('key=')), 'the API key stays out of provenance');
    assert.equal(r.signals.length, 1);
  });
});

test('monitor patterns read common phrasings without an LLM', () => {
  const cases: [string, string, string][] = [
    ['Tell me when there is an internet outage in Iran', 'outage', 'Iran'],
    ['Watch new critical CVEs for nginx', 'cve', 'nginx'],
    ['Alert me about earthquakes above 6 near Tokyo', 'quake', 'Tokyo|6'],
    ['Track news about OpenAI', 'news', 'OpenAI'],
    ['Ping me if the travel risk for Bangkok changes', 'travel', 'Bangkok'],
    ['Any cyclone or flood alerts for the Philippines', 'hazard', 'Philippines'],
    ['Watch npm:lodash for new vulnerabilities', 'package', 'npm:lodash'],
    ['Let me know if https://example.top/verify turns malicious', 'url', 'https://example.top/verify'],
    ['Notify me when the air quality in Delhi gets worse', 'air', 'Delhi'],
  ];
  for (const [text, kind, target] of cases) {
    const r = parseMonitorPattern(text);
    assert.equal(r?.kind, kind, text);
    assert.equal(r?.target, target, text);
  }
  assert.equal(parseMonitorPattern('make me a sandwich'), null);
  assert.deepEqual(splitQuakeTarget('Tokyo|6.5'), { place: 'Tokyo', min: 6.5 });
  assert.deepEqual(splitQuakeTarget('Lima'), { place: 'Lima', min: 5 });
});

test('monitor endpoint turns a sentence into a watch rule (pattern fallback without an LLM)', async () => {
  await withEnv(noLlm, async () => {
    const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
    const { server, stop } = createWebServer({ port: 0, oculon });
    await new Promise((r) => server.once('listening', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const post = (path: string, body: unknown) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1' }, body: JSON.stringify(body) });
    try {
      const r = await post('/api/monitor', { text: 'Tell me when there is an internet outage in Iran' });
      assert.equal(r.status, 200);
      const j = (await r.json()) as { item: { id: number; kind: string; target: string }; method: string };
      assert.equal(j.item.kind, 'outage');
      assert.equal(j.method, 'patterns');
      assert.equal(((await (await fetch(base + '/api/watch')).json()) as unknown[]).length, 1);
      assert.equal((await post('/api/monitor', { text: 'make me a sandwich' })).status, 400);
      assert.equal(((await (await post('/api/watch/delete', { id: j.item.id })).json()) as { removed: boolean }).removed, true);
    } finally {
      await stop();
      oculon.close();
    }
  });
});

test('remote MCP over HTTP: initialize, list tools, call a tool, notifications get 202', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const { server, stop } = createWebServer({ port: 0, oculon, publicMode: true, open: true, domain: 'example.org', edgeSecret: 's' });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const rpc = (body: unknown, headers: Record<string, string> = {}) => fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers }, body: JSON.stringify(body) });
  try {
    const init = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
    assert.equal(init.status, 200);
    assert.equal(init.headers.get('access-control-allow-origin'), '*');
    assert.equal(((await init.json()) as { result: { serverInfo: { name: string } } }).result.serverInfo.name, 'oculon');
    assert.equal((await rpc({ jsonrpc: '2.0', method: 'notifications/initialized' })).status, 202);
    const list = (await (await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list' })).json()) as { result: { tools: { name: string }[] } };
    const names = list.result.tools.map((t) => t.name);
    for (const n of ['oculon_url_check', 'oculon_audit', 'oculon_fact_check', 'oculon_travel', 'oculon_monitor']) assert.ok(names.includes(n), n);
    assert.ok(!names.includes('oculon_robinhood'), 'paused on-chain tools stay hidden');
    const call = (await (await rpc({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'oculon_monitor', arguments: { request: 'Watch new critical CVEs for nginx', dry_run: true } } })).json()) as { result: { content: { text: string }[] } };
    assert.match(call.result.content[0]!.text, /"kind":"cve"/);
    const batch = (await (await rpc([{ jsonrpc: '2.0', id: 4, method: 'ping' }, { jsonrpc: '2.0', method: 'notifications/cancelled' }])).json()) as unknown[];
    assert.equal(batch.length, 1);
    assert.equal((await fetch(base + '/mcp', { method: 'POST', body: '{nope' })).status, 400);
    assert.equal((await fetch(base + '/mcp', { method: 'OPTIONS' })).status, 204);
    const browser = await fetch(base + '/mcp', { headers: { accept: 'text/html' }, redirect: 'manual' });
    assert.equal(browser.status, 302);
    assert.equal(browser.headers.get('location'), 'https://docs.example.org/#remote-mcp');
    assert.equal((await fetch(base + '/mcp')).status, 405);
    // mcp.<domain> through the edge Worker answers at its root
    const viaEdge = await fetch(base + '/', { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon-edge': 's', 'x-oculon-site': 'mcp' }, body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'ping' }) });
    assert.deepEqual(await viaEdge.json(), { jsonrpc: '2.0', id: 9, result: {} });
  } finally {
    await stop();
    oculon.close();
  }
});

test('remote MCP stays closed on a locked public install', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const { server, stop } = createWebServer({ port: 0, oculon, publicMode: true, open: false, adminToken: 'x' });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    assert.equal((await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' })).status, 403);
  } finally {
    await stop();
    oculon.close();
  }
});
