import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { esc, TelegramBot } from '../src/telegram.js';
import { mockFetch, NOW } from './helpers.js';

const TOKEN = '123456:TEST-TOKEN';

function setup() {
  const sent: { method: string; body: Record<string, unknown> }[] = [];
  let updates: unknown[] = [];
  const tgFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = url.split('/').pop()!;
    const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    sent.push({ method, body });
    const result = method === 'getUpdates' ? updates.splice(0) : method === 'getMe' ? { username: 'oculon_test_bot' } : true;
    return new Response(JSON.stringify({ ok: true, result }), { status: 200 });
  }) as typeof fetch;
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const bot = new TelegramBot({ token: TOKEN, allowedChats: ['42'], oculon, fetch: tgFetch, alertMinScore: 60 });
  return { bot, sent, oculon, push: (u: unknown[]) => (updates = u) };
}

test('escapes HTML for Telegram', () => {
  assert.equal(esc('<b>&</b>'), '&lt;b&gt;&amp;&lt;/b&gt;');
});

test('rejects chats outside the allowlist and tells them their chat id', async () => {
  const { bot, sent, push, oculon } = setup();
  push([{ update_id: 1, message: { chat: { id: 999, type: 'private' }, text: '/radar' } }]);
  await bot.pollOnce();
  const msg = sent.find((s) => s.method === 'sendMessage')!;
  assert.equal(msg.body.chat_id, '999');
  assert.match(String(msg.body.text), /private.*<code>999<\/code>/s);
  assert.ok(!sent.some((s) => s.method === 'sendMessage' && /Radar/.test(String(s.body.text))));
  oculon.close();
});

test('answers commands for allowed chats and advances the update offset', async () => {
  const { bot, sent, push, oculon } = setup();
  push([
    { update_id: 10, message: { chat: { id: 42, type: 'private' }, text: '/help' } },
    { update_id: 11, message: { chat: { id: 42, type: 'private' }, text: '/score' } },
    { update_id: 12, message: { chat: { id: 42, type: 'private' }, text: '/dossier' } },
  ]);
  await bot.pollOnce();
  const texts = sent.filter((s) => s.method === 'sendMessage').map((s) => String(s.body.text));
  // The help can run over Telegram's message limit and arrive in two parts.
  assert.ok(texts.some((t) => /\/dossier &lt;name&gt;/.test(t)));
  assert.ok(texts.some((t) => /0 total/.test(t)));
  assert.match(texts.at(-1)!, /Usage: \/dossier Nvidia/);
  await bot.pollOnce();
  const last = sent.filter((s) => s.method === 'getUpdates').pop()!;
  assert.equal(last.body.offset, 13);
  oculon.close();
});

test('alerts: subscribe, push each strong signal once, ignore weak ones', async () => {
  const { bot, sent, oculon } = setup();
  await bot.respond('42', '/alerts on');
  const strong = { id: 's1', module: 'owl', title: 'Big <thing>', score: 80, evidence: [{ source: 'x', text: 'y', url: 'https://e.test' }], createdAt: NOW.toISOString() };
  const weak = { ...strong, id: 's2', score: 30 };
  assert.equal(await bot.pushAlerts([strong, weak]), 1);
  assert.equal(await bot.pushAlerts([strong]), 0, 'not sent twice');
  const alert = sent.find((s) => s.method === 'sendMessage' && /ALERT/.test(String(s.body.text)))!;
  assert.match(String(alert.body.text), /Big &lt;thing&gt;/);
  assert.equal(alert.body.parse_mode, 'HTML');
  await bot.respond('42', '/alerts off');
  assert.equal(await bot.pushAlerts([{ ...strong, id: 's3' }]), 0);
  oculon.close();
});

test('long messages are split under the Telegram limit', async () => {
  const { bot, sent, oculon } = setup();
  await bot.send('42', Array.from({ length: 200 }, (_, i) => `line ${i} ${'x'.repeat(40)}`).join('\n'));
  const parts = sent.filter((s) => s.method === 'sendMessage');
  assert.ok(parts.length >= 2);
  assert.ok(parts.every((p) => String(p.body.text).length <= 4096));
  oculon.close();
});

test('refuses to start without a token', () => {
  assert.throws(() => new TelegramBot({ token: '', allowedChats: [] }), /TELEGRAM_BOT_TOKEN/);
});
