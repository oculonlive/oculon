import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chat, setPaidQuota, toAnthropic, type ChatMessage } from '../src/core/llm.js';
import { pulse } from '../src/modules/pulse.js';
import { isoDate } from '../src/sources/apify.js';
import { describeLabels, labelsFor, loadLabels, parseCsvLine } from '../src/sources/labels.js';
import { NOW, testContext } from './helpers.js';

const withEnv = async (vars: Record<string, string>, fn: () => Promise<void>) => {
  const prev = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  Object.assign(process.env, vars);
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
};

test('history converts to the Messages API shape', () => {
  const msgs: ChatMessage[] = [
    { role: 'system', content: 'S' },
    { role: 'user', content: 'Q' },
    { role: 'assistant', content: 'checking', tool_calls: [{ id: 't1', type: 'function', function: { name: 'oculon_radar', arguments: '{"x":1}' } }, { id: 't2', type: 'function', function: { name: 'oculon_space_weather', arguments: '' } }] },
    { role: 'tool', tool_call_id: 't1', content: 'r1' },
    { role: 'tool', tool_call_id: 't2', content: 'r2' },
  ];
  const a = toAnthropic(msgs);
  assert.equal(a.system, 'S');
  assert.deepEqual(a.messages.map((m) => m.role), ['user', 'assistant', 'user']);
  assert.deepEqual(a.messages[1]!.content[1], { type: 'tool_use', id: 't1', name: 'oculon_radar', input: { x: 1 } });
  assert.equal(a.messages[2]!.content.length, 2, 'parallel tool results go in one user turn');
});

test('premium calls go to Claude first, then fall back to free tiers; plain calls skip Claude', async () => {
  const seen: { url: string; body: Record<string, unknown>; headers: Record<string, string> }[] = [];
  let claudeStatus = 200;
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, body: JSON.parse(String(init.body)) as Record<string, unknown>, headers: init.headers as Record<string, string> });
    if (url.includes('anthropic.com')) {
      return new Response(
        JSON.stringify({ model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'thinking', thinking: '', signature: 'sig' }, { type: 'text', text: 'Looking.' }, { type: 'tool_use', id: 'tu1', name: 'oculon_radar', input: { a: 1 } }] }),
        { status: claudeStatus },
      );
    }
    return new Response(JSON.stringify({ choices: [{ message: { content: 'free answer' } }] }));
  }) as unknown as typeof fetch;
  await withEnv({ ANTHROPIC_API_KEY: 'sk-ant-test-0000000000', GROQ_API_KEY: 'gsk-test-000000000000' }, async () => {
    setPaidQuota(() => true);
    const r = await chat([{ role: 'system', content: 'S' }, { role: 'user', content: 'Q' }], { premium: true, fetch: f, tools: [{ type: 'function', function: { name: 'oculon_radar', description: 'd', parameters: { type: 'object' } } }] });
    assert.equal(r.provider, 'anthropic');
    assert.equal(r.message.content, 'Looking.');
    assert.deepEqual(r.message.tool_calls, [{ id: 'tu1', type: 'function', function: { name: 'oculon_radar', arguments: '{"a":1}' } }]);
    const req = seen[0]!;
    assert.equal(req.body.model, 'claude-opus-5-5');
    assert.equal(req.body.temperature, undefined, 'sampling parameters are not sent');
    assert.deepEqual(req.body.thinking, { type: 'adaptive', block_binding: { prefix_mismatch_behavior: 'drop_block' } });
    assert.equal((req.body.tools as { input_schema: unknown }[])[0]!.input_schema !== undefined, true);
    // The raw blocks (thinking included) are replayed on the next turn.
    const next = toAnthropic([{ role: 'user', content: 'Q' }, r.message]);
    assert.equal(next.messages[1]!.content[0]!.type, 'thinking');

    const deep = await chat([{ role: 'user', content: 'Q' }], { premium: 'deep', fetch: f });
    assert.equal(seen.at(-1)!.body.model, 'claude-fable-5-2');
    void deep;

    claudeStatus = 529;
    const fb = await chat([{ role: 'user', content: 'Q' }], { premium: true, fetch: f });
    assert.equal(fb.provider, 'groq', 'falls back when Claude fails');

    seen.length = 0;
    await chat([{ role: 'user', content: 'Q' }], { fetch: f });
    assert.ok(!seen.some((s) => s.url.includes('anthropic.com')), 'background work stays on free tiers');

    setPaidQuota(() => false);
    seen.length = 0;
    claudeStatus = 200;
    const q = await chat([{ role: 'user', content: 'Q' }], { premium: true, fetch: f });
    assert.equal(q.provider, 'groq', 'spent daily budget skips Claude');
    setPaidQuota(() => true);
  });
});

test('dates from social actors in any shape', () => {
  assert.equal(isoDate(1763546400), '2025-11-19T10:00:00.000Z');
  assert.equal(isoDate(1763546400000), '2025-11-19T10:00:00.000Z');
  assert.equal(isoDate('1763546400'), '2025-11-19T10:00:00.000Z');
  assert.equal(isoDate('Thu Nov 19 10:12:30 +0000 2026'), '2026-11-19T10:12:30.000Z');
  assert.equal(isoDate('nope'), '');
});

test('social pulse merges platforms, ranks by engagement, measures Reddit pace only when the day is covered', async () => {
  const h = (hoursAgo: number) => new Date(NOW.getTime() - hoursAgo * 3_600_000).toISOString();
  // 12 Reddit posts in the last 6 hours, 6 in the 18 before, one older than a day.
  const reddit = [...Array.from({ length: 12 }, (_, i) => ({ kind: 'post', title: `r${i}`, author: 'u', created_utc: Date.parse(h(i * 0.4)) / 1000, score: i, num_comments: 0, permalink: `/r/x/${i}` })), ...Array.from({ length: 6 }, (_, i) => ({ kind: 'post', title: `old${i}`, author: 'u', created_utc: Date.parse(h(8 + i * 2)) / 1000, score: 1, num_comments: 0, permalink: `/r/x/o${i}` })), { kind: 'post', title: 'ancient', author: 'u', created_utc: Date.parse(h(40)) / 1000, score: 0, permalink: '/r/x/a' }];
  await withEnv({ APIFY_TOKEN: 'apify_api_test000000000000' }, async () => {
    const ctx = testContext([
      ['tweet-scraper', () => ({ body: [{ type: 'tweet', url: 'https://x.com/a/status/1', fullText: 'big', createdAt: h(1), likeCount: 900, retweetCount: 100, author: { userName: 'a' } }] })],
      ['reddit-scraper', () => ({ body: reddit })],
      ['tiktok-scraper', () => ({ body: [{ noResults: true }] })],
    ]);
    const r = await pulse(ctx, 'Example Co', ['x', 'reddit', 'tiktok']);
    assert.deepEqual(r.result.byPlatform, { x: 1, reddit: 19 });
    assert.equal(r.result.top[0]!.platform, 'x');
    assert.equal(r.result.top[0]!.engagement, 1000);
    assert.equal(r.result.acceleration, 6, '12 in 6h vs 6 per 18h (2 per 6h)');
    assert.equal(r.signals.length, 1);
    assert.match(r.signals[0]!.title, /accelerating: 12 in the last 6 hours \(6\.0x/);
    assert.equal(ctx.store.db.prepare("SELECT count(*) n FROM cache WHERE key LIKE '%tiktok%'").get()!.n, 0, 'empty actor answers are not cached');
  });
});

test('open address labels load from CSV and describe addresses', () => {
  assert.deepEqual(parseCsvLine('"0xab",1,"binance","Binance 14, hot"'), ['0xab', '1', 'binance', 'Binance 14, hot']);
  const ctx = testContext([]);
  const n = loadLabels(ctx, ['address,chainId,label,nameTag', '"0x28c6c06298d514db089934071355e5743bf21d60",1,"exchange","Binance 14"', '"0x28c6c06298d514db089934071355e5743bf21d60",1,"binance","Binance 14"', '"bad",1,"x","y"'].join('\n'));
  assert.equal(n, 2);
  const ls = labelsFor(ctx, '0x28C6c06298d514Db089934071355E5743bf21d60');
  assert.equal(describeLabels(ls), 'Binance 14 (binance, exchange)');
  assert.equal(describeLabels(labelsFor(ctx, '0x0000000000000000000000000000000000000001')), null);
});
