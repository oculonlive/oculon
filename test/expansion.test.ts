import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ask, condense, forModel } from '../src/agent.js';
import { chat } from '../src/core/llm.js';
import { Oculon } from '../src/index.js';
import { tokenVerdict } from '../src/modules/magpie.js';
import { mergeNews } from '../src/modules/hound.js';
import { gScale } from '../src/modules/sky.js';
import { flareFlux, pm25Category } from '../src/sources/space.js';
import { mockFetch, NOW } from './helpers.js';

const withKeys = async (keys: Record<string, string>, fn: () => Promise<void>) => {
  const old = Object.fromEntries(Object.keys(keys).map((k) => [k, process.env[k]]));
  const others = ['GROQ_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY'].filter((k) => !(k in keys));
  const oldOthers = Object.fromEntries(others.map((k) => [k, process.env[k]]));
  Object.assign(process.env, keys);
  for (const k of others) delete process.env[k];
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries({ ...old, ...oldOthers })) v === undefined ? delete process.env[k] : (process.env[k] = v);
  }
};

const llmReply = (message: object) => new Response(JSON.stringify({ choices: [{ message }] }), { status: 200 });

test('llm falls back to the next provider on errors and never leaks keys in errors', async () => {
  await withKeys({ GROQ_API_KEY: 'gk-secret-aaaaaaaaaaaa', GEMINI_API_KEY: 'gm-secret-bbbbbbbbbbbb' }, async () => {
    const seen: string[] = [];
    const f = (async (url: string | URL | Request) => {
      seen.push(String(url));
      if (String(url).includes('groq')) return new Response('rate limited for key gk-secret-aaaaaaaaaaaa', { status: 429 });
      return llmReply({ role: 'assistant', content: 'four' });
    }) as typeof fetch;
    const r = await chat([{ role: 'user', content: '2+2' }], { fetch: f });
    assert.equal(r.provider, 'gemini');
    assert.equal(r.message.content, 'four');
    const bad = (async () => new Response('nope gm-secret-bbbbbbbbbbbb', { status: 500 })) as unknown as typeof fetch;
    await assert.rejects(chat([{ role: 'user', content: 'x' }], { fetch: bad }), (e: Error) => !e.message.includes('secret-') && /all LLM providers failed/.test(e.message));
  });
});

test('agent calls tools, feeds results back, and answers; it cannot use write tools', async () => {
  await withKeys({ GROQ_API_KEY: 'gk-test-cccccccccccc' }, async () => {
    const o = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
    let round = 0;
    let toolNames: string[] = [];
    const f = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { tools?: { function: { name: string } }[]; messages: { role: string; content: string }[] };
      if (round === 0) toolNames = (body.tools ?? []).map((t) => t.function.name);
      round++;
      if (round === 1) return llmReply({ role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: 'oculon_scoreboard', arguments: '{}' } }] });
      const toolMsg = body.messages.find((m) => m.role === 'tool');
      assert.match(toolMsg!.content, /"total":0/);
      return llmReply({ role: 'assistant', content: 'No forecasts yet (per Oculon scoreboard).' });
    }) as typeof fetch;
    const r = await ask(o, 'how is the track record?', { fetch: f });
    assert.equal(r.answer, 'No forecasts yet (per Oculon scoreboard).');
    assert.deepEqual(r.steps.map((s) => [s.tool, s.ok]), [['oculon_scoreboard', true]]);
    assert.ok(toolNames.includes('oculon_dossier'));
    for (const banned of ['oculon_forecast', 'oculon_stamp_proofs', 'oculon_ask', 'oculon_auto_forecast']) assert.ok(!toolNames.includes(banned), banned);
    o.close();
  });
});

test('condense keeps every section within budget', () => {
  const big = { a: Array.from({ length: 50 }, (_, i) => ({ t: 'x'.repeat(1000), i })), timeline: [{ text: 'late section survives' }] };
  const c = condense(big) as { a: unknown[]; timeline: { text: string }[] };
  assert.equal(c.a.length, 11);
  assert.equal(c.timeline[0]!.text, 'late section survives');
  assert.ok(forModel(big).length < 14_100);
  assert.match(forModel(big), /late section survives/);
});

test('token verdict: danger flags, issuer-controlled majors, thin liquidity only for small caps', () => {
  const base = { name: 'T', symbol: 'T', buyTax: 0, sellTax: 0, ownerPercent: 0, inDex: true };
  assert.equal(tokenVerdict({ ...base, flags: ['honeypot'], holders: 50 }, []).verdict, 'DANGER');
  const usdt = tokenVerdict({ ...base, flags: ['owner can change balances'], holders: 16_000_000 }, []);
  assert.equal(usdt.verdict, 'CAUTION');
  assert.match(usdt.reasons.join(), /issuer controls/);
  const pair = { chain: 'ethereum', dex: 'uni', pair: 'X/WETH', priceUsd: 1, liquidityUsd: 500, volume24h: 10, change24h: 0, createdAt: null, url: '' };
  assert.equal(tokenVerdict({ ...base, flags: [], holders: 10 }, [pair], 1_000_000).verdict, 'CAUTION');
  assert.equal(tokenVerdict({ ...base, flags: [], holders: 10 }, [pair], 5_000_000_000).verdict, 'OK');
  assert.equal(tokenVerdict({ ...base, flags: [], holders: 10, sellTax: 0.5 }, []).verdict, 'DANGER');
  assert.equal(tokenVerdict(null, []).verdict, 'UNKNOWN');
});

test('space weather and air quality scales', () => {
  assert.equal(gScale(4), 'quiet');
  assert.equal(gScale(5), 'G1 minor storm');
  assert.equal(gScale(9), 'G5 extreme storm');
  assert.ok(flareFlux('X1.2') > flareFlux('M9.9'));
  assert.ok(Math.abs(flareFlux('M1.7') - 1.7e-5) < 1e-12);
  assert.equal(pm25Category(5), 'good');
  assert.equal(pm25Category(200), 'very unhealthy');
});

test('news merge drops duplicate headlines across outlets', () => {
  const merged = mergeNews([
    [{ title: 'Nvidia board weighs CEO change', url: 'a', date: '2026-11-18T10:00:00Z', source: 'A' }],
    [
      { title: 'Nvidia Board Weighs CEO Change!', url: 'b', date: '2026-11-18T09:00:00Z', source: 'B' },
      { title: 'Something else', url: 'c', date: '2026-11-17T09:00:00Z', source: 'B' },
    ],
  ]);
  assert.deepEqual(merged.map((m) => m.url), ['a', 'c']);
});

test('owl AI link merges same-event groups the model names, with its reason, and ignores bad indexes', async () => {
  const { aiLink, scoreGroup } = await import('../src/modules/owl.js');
  const b = (source: 'wikipedia' | 'polymarket' | 'hackernews', title: string, strength: number) => ({ source, title, strength, url: '', detail: '', value: 0, keys: [] as string[] });
  const fused = [scoreGroup([b('wikipedia', 'Robert Pattinson', 80)]), scoreGroup([b('wikipedia', 'Suki Waterhouse', 70)]), scoreGroup([b('hackernews', 'Unrelated database', 60)])];
  await withKeys({ GROQ_API_KEY: 'gk-test-dddddddddddd' }, async () => {
    const f = (async () => llmReply({ role: 'assistant', content: JSON.stringify({ links: [{ items: [0, 1], subject: 'Pattinson and Waterhouse wedding', why: 'Both spike on the same wedding news.' }, { items: [2, 99] }] }) })) as unknown as typeof fetch;
    const r = await aiLink(fused, { fetch: f });
    assert.equal(r.links.length, 1);
    assert.equal(r.fused.length, 2);
    const merged = r.fused.find((x) => x.linkedBy)!;
    assert.equal(merged.title, 'Pattinson and Waterhouse wedding');
    assert.equal(merged.blips.length, 2);
    assert.match(merged.linkedBy!, /same wedding/);
  });
  const none = await aiLink(fused);
  assert.equal(none.links.length, 0, 'no LLM key: unchanged');
});
