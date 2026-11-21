import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cricket } from '../src/modules/cricket.js';
import { ferret, isNoiseHost } from '../src/modules/ferret.js';
import { fuse, isSportsLine, owl, type Blip } from '../src/modules/owl.js';
import { toMarket } from '../src/sources/polymarket.js';
import { daysAgo, NOW, testContext, type Route } from './helpers.js';

const ferretRoutes = (extraHost?: string): Route[] => [
  [
    'crt.sh',
    () => ({
      body: [
        { name_value: 'www.acme.com\nacme.com', not_before: '2024-01-01T00:00:00', issuer_name: 'C=US, O=Let\'s Encrypt, CN=R3' },
        { name_value: 'beta-agent.acme.com', not_before: daysAgo(2).slice(0, 19), issuer_name: 'C=US, O=Google Trust Services, CN=WR1' },
        { name_value: 'mail.acme.com', not_before: daysAgo(3).slice(0, 19), issuer_name: 'O=X' },
        { name_value: 'old.acme.com', not_before: daysAgo(90).slice(0, 19), issuer_name: 'O=X' },
        ...(extraHost ? [{ name_value: extraHost, not_before: daysAgo(1).slice(0, 19), issuer_name: 'O=X' }] : []),
      ],
    }),
  ],
  [
    /web\.archive\.org.*from=2026/,
    (url) =>
      url.includes('to=20261118')
        ? { body: [['original', 'timestamp'], ['https://acme.com/blog/hello', '20261110120000'], ['https://acme.com/preview/glasses', '20261115120000'], ['https://acme.com/app.js', '20261115120000']] }
        : { body: [['original', 'timestamp'], ['https://acme.com/blog/hello', '20260301120000']] },
  ],
  [/web\.archive\.org/, () => ({ body: [['original', 'timestamp'], ['https://acme.com/blog/hello', '20260301120000']] })],
  [
    'api.github.com/orgs/acme/repos',
    () => ({
      body: [
        { name: 'agent-sdk', full_name: 'acme/agent-sdk', html_url: 'https://github.com/acme/agent-sdk', description: 'Agent SDK preview', created_at: daysAgo(4), pushed_at: daysAgo(1), stargazers_count: 10, language: 'TypeScript', fork: false },
        { name: 'old', full_name: 'acme/old', html_url: 'https://github.com/acme/old', description: null, created_at: daysAgo(400), pushed_at: daysAgo(1), stargazers_count: 1, language: null, fork: false },
      ],
    }),
  ],
];

test('ferret finds recent subdomains, pages and repos, filters noise, and tracks novelty across scans', async () => {
  const ctx = testContext(ferretRoutes());
  const r1 = await ferret(ctx, 'https://www.acme.com/');
  assert.equal(r1.input, 'acme.com');
  assert.equal(r1.result.firstScan, true);
  const values = r1.result.findings.map((f) => f.value);
  assert.ok(values.includes('beta-agent.acme.com'));
  assert.ok(!values.includes('mail.acme.com'), 'mail is noise');
  assert.ok(!values.includes('old.acme.com'), 'outside window');
  assert.ok(values.includes('acme.com/preview/glasses'));
  assert.ok(!values.some((v) => v.includes('app.js') || v.endsWith('/blog/hello')), 'assets and previously seen pages are skipped');
  assert.ok(values.some((v) => v.startsWith('acme/agent-sdk')));
  assert.ok(r1.result.findings.every((f) => !f.newSinceLastScan), 'never claims novelty on a first scan');
  assert.ok(r1.signals.length >= 1);
  assert.ok(r1.provenance.filter((p) => ['crt.sh', 'wayback', 'github'].includes(p.source)).every((p) => p.status === 'LIVE'));
  assert.equal(r1.provenance.find((p) => p.source === 'safe-browsing')?.status, 'UNAVAILABLE', 'no key in tests');

  // Second scan, same DB, one extra host.
  const ctx2 = Object.assign(ctx, {});
  (ctx2 as { http: unknown }).http = testContext(ferretRoutes('lens.acme.com')).http;
  const r2 = await ferret(ctx2, 'acme.com');
  assert.equal(r2.result.firstScan, false);
  const lens = r2.result.findings.find((f) => f.value === 'lens.acme.com');
  assert.equal(lens?.newSinceLastScan, true);
  assert.equal(r2.result.findings.find((f) => f.value === 'beta-agent.acme.com')?.newSinceLastScan, false);
  assert.ok(ctx.graph.neighbors('domain:acme.com').some((n) => n.id === 'subdomain:lens.acme.com'));
});

test('ferret falls back to certspotter when crt.sh is down and labels it partial', async () => {
  const ctx = testContext([
    ['crt.sh', () => ({ status: 502, body: 'bad gateway' })],
    ['certspotter', () => ({ body: [{ dns_names: ['labs.acme.com'], not_before: daysAgo(1), issuer: { friendly_name: 'LE' } }] })],
  ]);
  const r = await ferret(ctx, 'acme.com', { org: false });
  assert.ok(r.result.findings.some((f) => f.value === 'labs.acme.com' && f.source === 'certspotter'));
  assert.equal(r.provenance.find((p) => p.source === 'crt.sh')?.status, 'ERROR');
  assert.match(r.provenance.find((p) => p.source === 'certspotter')?.note ?? '', /partial/);
});

test('noise host filter', () => {
  assert.ok(isNoiseHost('mail.acme.com'));
  assert.ok(isNoiseHost('cdn.acme.com'));
  assert.ok(isNoiseHost('a1b2c3d4e5f6a7.acme.com'));
  assert.ok(!isNoiseHost('labs.acme.com'));
});

test('cricket combines channels into a phase', async () => {
  const day = 86_400_000;
  const views = Array.from({ length: 56 }, (_, i) => ({ timestamp: `${new Date(NOW.getTime() - (56 - i) * day).toISOString().slice(0, 10).replace(/-/g, '')}00`, views: i >= 42 ? 5000 : 1000 }));
  const ctx = testContext([
    ['opensearch', () => ({ body: ['x', ['Widget']] })],
    ['per-article', () => ({ body: { items: views } })],
    ['hn.algolia.com', (url) => ({ body: { nbHits: Number(/created_at_i%3E(\d+)/.exec(url)?.[1] ?? 0) > NOW.getTime() / 1000 - 15 * 86400 ? 50 : 10 } })],
    ['gdeltproject', () => ({ body: { timeline: [{ data: views.map((v) => ({ date: `${v.timestamp.slice(0, 8)}T000000Z`, value: v.views / 1e5 })) }] } })],
    ['arxiv', () => ({ body: '<feed><opensearch:totalResults>0</opensearch:totalResults></feed>' })],
    ['search/repositories', (url) => ({ body: { total_count: decodeURIComponent(url).includes(`created:${new Date(NOW.getTime() - 28 * day).toISOString().slice(0, 10)}`) ? 300 : 100 } })],
  ]);
  const r = await cricket(ctx, 'widget');
  const res = r.result;
  assert.equal(res.wikipediaTitle, 'Widget');
  assert.equal(res.channels.find((c) => c.channel === 'readers')?.trend?.phase, 'RISING');
  assert.equal(res.channels.find((c) => c.channel === 'developers')?.trend?.phase, 'RISING');
  assert.equal(res.channels.find((c) => c.channel === 'builders')?.trend?.phase, 'RISING');
  assert.equal(res.channels.find((c) => c.channel === 'research')?.trend?.phase, 'DORMANT');
  assert.equal(res.phase, 'RISING');
  assert.equal(r.signals.length, 1);
});

test('owl fuses corroborating blips from different sources', () => {
  const b = (source: Blip['source'], title: string, strength: number): Blip => ({ source, title, strength, url: '', detail: '', value: 0, keys: [...new Set(title.toLowerCase().split(/\W+/).filter((w) => w.length >= 4))] });
  const fused = fuse([b('wikipedia', 'Robert Pattinson', 70), b('polymarket', 'Will Robert Pattinson be the next Bond?', 60), b('hackernews', 'Show HN: a tiny database', 50)]);
  assert.equal(fused[0]?.sources.length, 2);
  assert.equal(fused[0]?.score, 74);
  assert.equal(fused.length, 2);
});

test('owl end to end with mocked sources', async () => {
  const day = 86_400_000;
  const series = (spike: boolean) => ({ items: Array.from({ length: 30 }, (_, i) => ({ timestamp: `${new Date(NOW.getTime() - (30 - i) * day).toISOString().slice(0, 10).replace(/-/g, '')}00`, views: spike && i === 29 ? 90_000 : 3000 + (i % 3) * 100 })) });
  const ctx = testContext([
    ['/top/', () => ({ body: { items: [{ articles: [{ article: 'Main_Page', views: 1, rank: 1 }, { article: 'Volcano_Xyz', views: 90000, rank: 2 }, { article: 'Steady_Thing', views: 3000, rank: 3 }] }] } })],
    ['Volcano_Xyz', () => ({ body: series(true) })],
    ['Steady_Thing', () => ({ body: series(false) })],
    ['front_page', () => ({ body: { hits: [{ objectID: '1', title: 'Volcano Xyz erupts, flights grounded', url: null, points: 400, num_comments: 200, created_at_i: NOW.getTime() / 1000 - 4 * 3600 }] } })],
    ['gamma-api', () => ({ body: [{ id: 1, question: 'Spread: Lakers (-6.5)', outcomes: '["A","B"]', outcomePrices: '["0.4","0.6"]', volume24hr: 1e6, oneDayPriceChange: -0.3 }] })],
    ['earthquake.usgs.gov', () => ({ body: { features: [] } })],
    ['eonet', () => ({ body: { events: [] } })],
  ]);
  const r = await owl(ctx);
  assert.ok(!r.result.blips.some((b) => b.source === 'polymarket'), 'sports lines are ignored');
  assert.ok(!r.result.blips.some((b) => b.title === 'Steady Thing'));
  const top = r.result.fused[0]!;
  assert.deepEqual(top.sources.sort(), ['hackernews', 'wikipedia']);
  assert.ok(r.signals.length >= 1);
});

test('polymarket parsing and sports filter', () => {
  const m = toMarket({ id: 1, question: 'Will X happen?', slug: 'x', outcomes: '["Yes","No"]', outcomePrices: '["0.7","0.3"]', volume24hr: '1000', oneDayPriceChange: 0.12 })!;
  assert.deepEqual(m.prices, [0.7, 0.3]);
  assert.equal(m.change1d, 0.12);
  assert.ok(isSportsLine(toMarket({ question: 'Spread: Lakers (-6.5)' })!));
  assert.ok(!isSportsLine(m));
});
