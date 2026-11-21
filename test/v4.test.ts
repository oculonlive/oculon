import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { LiveMonitor, postTerms, TermCounter } from '../src/live.js';
import { catalysts } from '../src/modules/calendar.js';
import { connect, describePath, domainLabel, normEntityName, resolveEntities } from '../src/modules/connect.js';
import { alertBar, recordFeedback, shiftFor } from '../src/modules/feedback.js';
import { TelegramBot } from '../src/telegram.js';
import { mockFetch, NOW, testContext } from './helpers.js';

const newOculon = () => new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });

test('post terms: names, acronyms and hashtags, not chatter', () => {
  const t = postTerms('Report: Jensen Huang returns to Nvidia as CEO, says the NVIDIA board. #nvidia');
  for (const x of ['jensen huang', 'nvidia', 'ceo', '#nvidia']) assert.ok(t.includes(x), x);
  assert.deepEqual(postTerms('i love my cat so much lol'), []);
  assert.deepEqual(postTerms('Thanks everyone. Good morning'), []);
});

test('term counter compares the last 10 minutes with the rest of the hour', () => {
  const c = new TermCounter();
  for (let m = 0; m < 50; m++) c.add('steady', m);
  for (let m = 40; m < 50; m++) for (let k = 0; k < 5; k++) c.add('spike', m);
  const s = Object.fromEntries(c.surge(49).map((x) => [x.term, x]));
  assert.equal(s.steady!.recent, 10);
  assert.equal(s.steady!.baseline, 10);
  assert.equal(s.spike!.recent, 50);
  assert.equal(s.spike!.baseline, 0);
});

test('live monitor flags a Wikipedia edit surge once and a Bluesky surge against its baseline', async () => {
  const o = newOculon();
  const sent: string[] = [];
  const m = new LiveMonitor(o, { wiki: false, bluesky: false, watchTerms: () => [], onSignals: (s) => void sent.push(...s.map((x) => x.title)) });
  const now = NOW.getTime();
  for (let i = 0; i < 7; i++) m._wikiEdit('Example Volcano', `editor${i % 4}`, now - i * 60_000);
  for (let i = 0; i < 9; i++) m._wikiEdit('Quiet Article', 'one-person', now - i * 60_000);
  // 30 minutes of background chatter, then a burst in the last 10 minutes.
  for (let min = 40; min >= 0; min--) m._post('Weather update from Springfield today', now - min * 60_000);
  for (let i = 0; i < 40; i++) m._post(`Huge news about Zorblax Labs ${i}`, now - (i % 9) * 60_000);
  const first = await m.evaluate(now);
  const titles = first.map((s) => s.title);
  assert.ok(titles.some((t) => /Edit surge on Wikipedia: Example Volcano \(7 edits by 4 editors/.test(t)), titles.join('\n'));
  assert.ok(!titles.some((t) => /Quiet Article/.test(t)), 'one editor is not a surge');
  assert.ok(titles.some((t) => /Surging on Bluesky: "zorblax labs"/.test(t)), titles.join('\n'));
  assert.ok(!titles.some((t) => /springfield/.test(t)), 'steady terms stay quiet');
  assert.equal(o.signals(50).filter((s) => s.module === 'live').length, first.length);
  assert.equal((await m.evaluate(now + 60_000)).length, 0, 'not flagged again within 6 hours');
  assert.equal(sent.length, first.length);
  o.close();
});

test('feedback shift needs 3 votes, is capped, and moves the alert bar', () => {
  assert.equal(shiftFor(0, 2), 0);
  assert.equal(shiftFor(0, 3), 9);
  assert.equal(shiftFor(0, 50), 20);
  assert.equal(shiftFor(4, 0), -8);
  assert.equal(shiftFor(20, 0), -10);
  const ctx = testContext([]);
  for (let i = 0; i < 4; i++) ctx.graph.saveSignal({ id: `s${i}`, module: 'cricket', title: `t${i}`, score: 70, evidence: [], createdAt: NOW.toISOString() });
  assert.equal(recordFeedback(ctx, 'missing', 'noise', 'a'), null);
  for (let i = 0; i < 3; i++) recordFeedback(ctx, `s${i}`, 'noise', 'chat');
  recordFeedback(ctx, 's0', 'noise', 'chat'); // same voter again does not double count
  assert.equal(alertBar(ctx, 'cricket', 70), 79);
  assert.equal(alertBar(ctx, 'owl', 70), 70);
});

test('entity resolution and connection paths', () => {
  assert.equal(normEntityName('NVIDIA Corporation'), 'nvidia');
  assert.equal(normEntityName('Arm Holdings plc'), 'arm');
  assert.equal(domainLabel('www.nvidia.com'), 'nvidia');
  assert.equal(domainLabel('example.co.uk'), 'example');
  const ctx = testContext([]);
  const g = ctx.graph;
  const co = g.upsert('company', 'Nvidia');
  const org = g.upsert('org', 'NVIDIA');
  const dom = g.upsert('domain', 'nvidia.com');
  const arm = g.upsert('company', 'Arm');
  g.upsert('domain', 'arm.com');
  const repo = g.upsert('repo', 'NVIDIA/cuda-samples');
  const person = g.upsert('topic', 'Jane Example');
  g.link(org, repo, 'owns_repo', 'github');
  g.link(person, repo, 'contributes_to', 'github');
  g.link(dom, g.upsert('subdomain', 'dev.nvidia.com'), 'has_subdomain', 'crt.sh');
  const r = resolveEntities(ctx);
  const pairs = r.linked.map((l) => `${l.a}=${l.b}`);
  assert.ok(pairs.includes(`${co}=${org}`));
  assert.ok(pairs.includes(`${co}=${dom}`));
  assert.ok(!pairs.some((p) => p.includes('arm.com')), 'short names do not auto-link domains');
  assert.equal(resolveEntities(ctx).linked.length, 0, 'idempotent');
  const c = connect(ctx, 'Nvidia', 'Jane Example');
  assert.equal(c.path?.map((s) => s.id).join(' > '), `${co} > ${org} > ${repo} > ${person}`);
  assert.match(describePath(c.path!), /-\[same_as\]-> NVIDIA \(org\) -\[owns_repo\]-> NVIDIA\/cuda-samples \(repo\) <-\[contributes_to\]- Jane Example/);
  assert.equal(connect(ctx, 'Nvidia', 'Arm').path, null);
  assert.match(connect(ctx, 'Nvidia', 'Nobody Here').note!, /not in the graph/);
  void arm;
});

test('catalyst calendar merges earnings, key macro releases and closing markets', async () => {
  process.env.FINNHUB_API_KEY = 'test-finnhub-key';
  process.env.FRED_API_KEY = 'test-fred-key';
  try {
    const ctx = testContext([
      ['/search?q=Nvidia', () => ({ body: { result: [{ symbol: 'NVDA', type: 'Common Stock', description: 'NVIDIA CORP' }] } })],
      [
        'calendar/earnings',
        () => ({ body: { earningsCalendar: [
          { symbol: 'TINY', date: '2026-11-19', hour: 'amc', epsEstimate: 0.1, revenueEstimate: 1e6 },
          { symbol: 'NVDA', date: '2026-11-20', hour: 'amc', epsEstimate: 1.2, revenueEstimate: 5e10 },
          { symbol: 'WMT', date: '2026-11-19', hour: 'bmo', epsEstimate: 0.6, revenueEstimate: 1.8e11 },
        ] } }),
      ],
      [
        'releases/dates',
        () => ({ body: { release_dates: [
          { release_id: 10, release_name: 'Consumer Price Index', date: '2026-11-21' },
          { release_id: 101, release_name: 'FOMC Press Release', date: '2026-11-19' },
          { release_id: 999, release_name: 'Some Daily Index', date: '2026-11-19' },
        ] } }),
      ],
      [
        'gamma-api.polymarket.com',
        () => ({ body: [
          { id: 1, question: 'Will Nvidia close above $200 by Nov 25?', slug: 'nvda-200', outcomes: '["Yes","No"]', outcomePrices: '["0.4","0.6"]', volume24hr: 5000, endDate: '2026-11-25T00:00:00Z' },
          { id: 2, question: 'Team A vs. Team B', slug: 'game', outcomes: '["A","B"]', outcomePrices: '["0.5","0.5"]', volume24hr: 900000, endDate: '2026-11-19T00:00:00Z' },
          { id: 3, question: 'Will the ceasefire hold?', slug: 'cf', outcomes: '["Yes","No"]', outcomePrices: '["0.9","0.1"]', volume24hr: 300000, endDate: '2026-11-22T00:00:00Z' },
          { id: 4, question: 'Far future market', slug: 'far', outcomes: '["Yes","No"]', outcomePrices: '["0.5","0.5"]', volume24hr: 800000, endDate: '2027-06-01T00:00:00Z' },
        ] }),
      ],
    ]);
    ctx.store.db.prepare('INSERT INTO watchlist (kind, target, created_at) VALUES (?, ?, ?)').run('company', 'Nvidia', NOW.getTime());
    const r = await catalysts(ctx, 14);
    const titles = r.result.items.map((i) => `${i.date} ${i.kind} ${i.watched ? '*' : ''}${i.title}`);
    assert.ok(titles.includes('2026-11-20 earnings *NVDA earnings (Nvidia)'), titles.join('\n'));
    assert.ok(titles.includes('2026-11-19 earnings WMT earnings'));
    assert.ok(titles.includes('2026-11-21 macro US CPI inflation'));
    assert.ok(!titles.some((t) => /FOMC|Daily Index|Team A|Far future/.test(t)), titles.join('\n'));
    assert.ok(titles.includes('2026-11-25 market *Closes: Will Nvidia close above $200 by Nov 25?'), 'watched company in the question');
    assert.deepEqual(r.result.items.map((i) => i.date), [...r.result.items.map((i) => i.date)].sort());
  } finally {
    delete process.env.FINNHUB_API_KEY;
    delete process.env.FRED_API_KEY;
  }
});

test('telegram alerts carry feedback buttons and a tap records the vote', async () => {
  const sent: { method: string; body: Record<string, unknown> }[] = [];
  let updates: unknown[] = [];
  const tgFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const method = String(input).split('/').pop()!;
    sent.push({ method, body: typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : {} });
    return new Response(JSON.stringify({ ok: true, result: method === 'getUpdates' ? updates.splice(0) : true }));
  }) as typeof fetch;
  const o = newOculon();
  const bot = new TelegramBot({ token: '1:T', allowedChats: ['42'], oculon: o, fetch: tgFetch, alertMinScore: 60 });
  o.ctx.store.db.prepare('INSERT INTO telegram_subs (chat_id, created_at) VALUES (?, ?)').run('42', 0);
  const sig = { id: 'live-abc123', module: 'live', title: 'Edit surge on Wikipedia: X', score: 75, evidence: [], createdAt: NOW.toISOString() };
  o.ctx.graph.saveSignal(sig);
  assert.equal(await bot.pushAlerts([sig]), 1);
  const alert = sent.find((s) => s.method === 'sendMessage')!;
  assert.deepEqual((alert.body.reply_markup as { inline_keyboard: { callback_data: string }[][] }).inline_keyboard[0]!.map((b) => b.callback_data), ['fb:u:live-abc123', 'fb:n:live-abc123']);
  updates = [{ update_id: 5, callback_query: { id: 'q1', data: 'fb:n:live-abc123', from: { id: 42 }, message: { chat: { id: 42 }, message_id: 9 } } }];
  await bot.pollOnce();
  assert.match(String(sent.find((s) => s.method === 'answerCallbackQuery')!.body.text), /Marked noise\. live: 0 useful, 1 noise, alert bar 60/);
  assert.ok(sent.some((s) => s.method === 'editMessageReplyMarkup'));
  assert.equal(o.feedbackStats()[0]!.noise, 1);
  // Outsiders cannot vote.
  updates = [{ update_id: 6, callback_query: { id: 'q2', data: 'fb:u:live-abc123', from: { id: 7 }, message: { chat: { id: 7 }, message_id: 3 } } }];
  await bot.pollOnce();
  assert.equal(o.feedbackStats()[0]!.useful, 0);
  o.close();
});

test('http keep option caches only the slimmed document', async () => {
  const ctx = testContext([['registry.npmjs.org', () => ({ body: { time: { created: '2020-01-01' }, versions: { huge: 'x'.repeat(10_000) } } })]]);
  const r = await ctx.http.get<{ time: { created: string } }>('https://registry.npmjs.org/pkg', { source: 'npm', keep: (d: { time: { created: string } }) => ({ time: { created: d.time.created } }) });
  assert.equal(r.data?.time.created, '2020-01-01');
  assert.equal(ctx.store.cacheGet('https://registry.npmjs.org/pkg')!.body, '{"time":{"created":"2020-01-01"}}');
  ctx.store.cachePut('derived:x', '1', 0);
  ctx.store.cachePut('https://old.test/a', '1', 0);
  assert.equal(ctx.store.pruneCache(14).removed, 1, 'derived entries survive');
});

test('cli suggests the closest command for typos', async () => {
  const { closest } = await import('../src/cli/main.js');
  const names = ['calendar', 'connect', 'case', 'radar'];
  assert.equal(closest('calnedar', names), 'calendar');
  assert.equal(closest('conect', names), 'connect');
  assert.equal(closest('cal', names), 'calendar');
  assert.equal(closest('zzzzzz', names), null);
});
