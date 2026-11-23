import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { extractParts, scamCheck } from '../src/modules/scam.js';
import { addPersonal, confirmEmail, emailDeliveries, emailStatus, listPersonal, personalAlerts, removePersonal, requestEmail, runPersonal, MAX_PER_OWNER } from '../src/modules/personal.js';
import { PUBLIC_COMMANDS, TelegramBot } from '../src/telegram.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW, testContext } from './helpers.js';

const LLM = ['GROQ_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY', 'ANTHROPIC_API_KEY'];
const withEnv = async (vars: Record<string, string | undefined>, fn: () => Promise<void>) => {
  const old = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  try { await fn(); } finally { for (const [k, v] of Object.entries(old)) if (v === undefined) delete process.env[k]; else process.env[k] = v; }
};
const quiet = { ...Object.fromEntries(LLM.map((k) => [k, undefined])), SAFE_BROWSING_KEY: undefined, ABUSECH_AUTH_KEY: undefined, URLSCAN_API_KEY: undefined };

test('scam check: links, sender, patterns and the "hi mum" pair', async () => {
  const p = extractParts('From: PayPal <service@paypa1-support.com>\nVerify now at paypal-login.top/verify or http://x.example.com/a. Call +1 (415) 555-0100');
  assert.ok(p.urls.includes('paypal-login.top/verify'));
  assert.ok(p.urls.includes('http://x.example.com/a'));
  assert.equal(p.sender, 'service@paypa1-support.com');
  assert.ok(p.phones.includes('+14155550100'));
  await withEnv(quiet, async () => {
    const ctx = testContext([[/rdap\.org/, () => ({ body: { events: [] } })], [/urlscan\.io/, () => ({ body: { results: [] } })]]);
    const parcel = await scamCheck(ctx, 'USPS: your package is on hold due to an unpaid customs fee. Pay within 24 hours: usps-redelivery-help.top/track');
    assert.equal(parcel.result.verdict, 'likely scam');
    const mum = await scamCheck(ctx, 'Hi mom, this is my new number, I lost my phone. Can you send me $400 for rent today?');
    assert.equal(mum.result.verdict, 'likely scam');
    const lunch = await scamCheck(ctx, 'Are we still on for lunch Thursday at 12? I booked a table.');
    assert.equal(lunch.result.verdict, 'no strong signs');
  });
});

test('personal monitors: per owner, limited, run, alerts and email', async () => {
  await withEnv({ ...quiet, RESEND_API_KEY: 're_test' }, async () => {
    const sent: { to: string; subject: string; text: string }[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.startsWith('https://api.resend.com/')) { const b = JSON.parse(String(init?.body)); sent.push({ to: b.to[0], subject: b.subject, text: b.text }); return new Response('{"id":"e1"}', { status: 200 }); }
      return realFetch(input, init);
    }) as typeof fetch;
    try {
      let n = 0;
      const ctx = testContext([[/vulnerabilities|kev/i, () => ({ body: { catalogVersion: '1', dateReleased: '2026-11-18', count: 1, vulnerabilities: n++ ? [{ cveID: 'CVE-2026-1', vendorProject: 'F5', product: 'nginx', vulnerabilityName: 'nginx bug', dateAdded: '2026-11-18', shortDescription: '', dueDate: '2026-12-01', knownRansomwareCampaignUse: 'Unknown', cwes: [] }] : [] } })]]);
      const a = await addPersonal(ctx, 'web:visitorA123', 'Watch new critical CVEs for nginx');
      assert.equal(a.monitor.kind, 'cve');
      assert.equal(listPersonal(ctx, 'web:visitorB456').length, 0, 'other visitors do not see it');
      for (let i = 0; i < MAX_PER_OWNER - 1; i++) await addPersonal(ctx, 'web:visitorA123', `news about topic${i}x`);
      await assert.rejects(addPersonal(ctx, 'web:visitorA123', 'news about one too many'), /up to 10/);
      for (const m of listPersonal(ctx, 'web:visitorA123').filter((x) => x.kind === 'news')) removePersonal(ctx, 'web:visitorA123', m.id);

      await requestEmail(ctx, 'web:visitorA123', 'Me@Example.com', 'https://oculon.test');
      assert.equal(sent[0]?.to, 'me@example.com');
      const token = /t=([\w-]+)/.exec(sent[0]!.text)![1]!;
      assert.equal(emailStatus(ctx, 'web:visitorA123').confirmed, false);
      assert.equal(confirmEmail(ctx, token), true);
      await assert.rejects(requestEmail(ctx, 'web:visitorA123', 'other@example.com', 'https://oculon.test'), /moment ago/, 'one confirmation per 10 minutes');

      assert.equal((await runPersonal(ctx, { everyMs: 0 })).length, 0, 'the first run records a baseline');
      ctx.store.db.exec('DELETE FROM cache');
      const d = await runPersonal(ctx, { everyMs: 0 });
      assert.equal(d.length, 1);
      assert.match(d[0]!.changes[0]!, /CVE-2026-1/);
      assert.equal(personalAlerts(ctx, 'web:visitorA123').length, 1);
      assert.equal(await emailDeliveries(ctx, d, 'https://oculon.test', 'https://app.oculon.test/#watch'), 1);
      assert.match(sent.at(-1)!.text, /CVE-2026-1[\s\S]*Unsubscribe: https:\/\/oculon\.test\/mail\/unsubscribe\?t=/);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

test('web: personal monitors live behind a visitor cookie; the shared watchlist needs the owner', async () => {
  await withEnv(quiet, async () => {
    const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
    const { server, stop } = createWebServer({ port: 0, oculon, publicMode: true, open: true, adminToken: 'owner-secret' });
    await new Promise((r) => server.once('listening', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const post = (path: string, body: unknown, cookie = '') => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
    try {
      const first = await fetch(base + '/api/my');
      const cookie = (first.headers.get('set-cookie') ?? '').split(';')[0]!;
      assert.match(cookie, /^oculon_uid=[\w-]{16,}$/);
      const add = await post('/api/my/monitors', { text: 'Tell me when there is an internet outage in Iran' }, cookie);
      assert.equal(add.status, 200);
      const mine = (await (await fetch(base + '/api/my', { headers: { cookie } })).json()) as { monitors: unknown[]; owner: boolean };
      assert.equal(mine.monitors.length, 1);
      assert.equal(mine.owner, false);
      const stranger = (await (await fetch(base + '/api/my')).json()) as { monitors: unknown[] };
      assert.equal(stranger.monitors.length, 0, 'another browser sees its own empty list');
      assert.equal((await post('/api/monitor', { text: 'news about OpenAI' }, cookie)).status, 403, 'visitors cannot add to the shared watchlist');
      const login = await fetch(base + '/login', { method: 'POST', body: 'token=owner-secret', headers: { 'content-type': 'application/x-www-form-urlencoded' }, redirect: 'manual' });
      const adminCookie = (login.headers.get('set-cookie') ?? '').split(';')[0]!;
      assert.equal((await post('/api/monitor', { text: 'news about OpenAI' }, adminCookie)).status, 200, 'the owner can');
      const spec = (await (await fetch(base + '/openapi.json')).json()) as { openapi: string; paths: Record<string, unknown> };
      assert.equal(spec.openapi, '3.1.0');
      assert.ok(spec.paths['/api/scam'] && spec.paths['/api/url']);
      const tools = (await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' })).json()) as { result: { tools: { name: string }[] } };
      const names = tools.result.tools.map((t) => t.name);
      assert.ok(names.includes('oculon_scam_check'));
      assert.ok(!names.includes('oculon_watch_add') && !names.includes('oculon_fence_add'), 'remote clients cannot change the shared watchlist');
    } finally {
      await stop();
      oculon.close();
    }
  });
});

test('public Telegram bot: anyone gets the public commands, rate limited; plain text is a scam check', async () => {
  await withEnv(quiet, async () => {
    const sent: { chat: string; text: string }[] = [];
    const fetchBot = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.includes('api.telegram.org')) {
        const body = typeof init?.body === 'string' ? JSON.parse(init.body) : {};
        if (url.endsWith('/sendMessage')) sent.push({ chat: String(body.chat_id), text: String(body.text) });
        return new Response('{"ok":true,"result":{}}', { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }) as typeof fetch;
    const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
    const bot = new TelegramBot({ token: 't', allowedChats: ['1'], oculon, fetch: fetchBot, publicMode: true });
    try {
      const msg = (chat: number, text: string, type = 'private') => bot.handle({ update_id: 1, message: { chat: { id: chat, type }, text } });
      await msg(99, '/start');
      assert.match(sent.at(-1)!.text, /check anything/i);
      await msg(99, '/dossier Nvidia');
      assert.match(sent.at(-1)!.text, /not available here/);
      await msg(99, 'Hi mom, this is my new number, I lost my phone. Can you send me $400 today?');
      assert.match(sent.at(-1)!.text, /LIKELY SCAM/);
      const before = sent.length;
      await msg(-500, 'just chatting in a group', 'group');
      assert.equal(sent.length, before, 'groups: only commands are answered');
      await msg(99, '/monitor Tell me when there is an internet outage in Iran');
      assert.match(sent.at(-1)!.text, /Monitoring #\d+/);
      await msg(99, '/monitors');
      assert.match(sent.at(-1)!.text, /internet outages in Iran/);
      for (let i = 0; i < 8; i++) await msg(77, '/scam you won a free iphone, claim your prize now');
      await msg(77, '/scam you won a free iphone, claim your prize now');
      assert.match(sent.at(-1)!.text, /hourly limit/);
      assert.ok(PUBLIC_COMMANDS.has('/url') && !PUBLIC_COMMANDS.has('/watch'));
    } finally {
      oculon.close();
    }
  });
});
