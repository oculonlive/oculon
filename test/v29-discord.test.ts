import assert from 'node:assert/strict';
import { test } from 'node:test';
import { BOT_PERMISSIONS, defang, DiscordGateway, DiscordRest, discordInfo, extractLinks, findImpersonation, guildSettings, INTENTS, normalizeName, Sentinel, startDiscordSentinel, type Protected } from '../src/modules/discord.js';
import { testContext } from './helpers.js';

const wait = (ms = 15) => new Promise((r) => setTimeout(r, ms));

test('names: look-alike letters, spacing and symbols fold to the same name', () => {
  assert.equal(normalizeName('Μ0D_Aԁmin'), normalizeName('mod admin'));
  assert.equal(normalizeName('rnoderator'), normalizeName('Moderator'));
  assert.equal(normalizeName('Ad.M1n!'), normalizeName('admin i'));
  assert.equal(normalizeName('Аdmіn'), normalizeName('admin'), 'Cyrillic a and i');
  assert.equal(normalizeName('Ｖitalik'), normalizeName('vitalik'), 'full-width letters');
  assert.notEqual(normalizeName('alice'), normalizeName('bob'));
  const staff: Protected[] = [{ id: '1', label: 'Mod Admin', role: 'admin', names: [normalizeName('Mod Admin')] }];
  assert.equal(findImpersonation({ user: { id: '2', username: 'M0D_ADMlN' } }, staff)?.id, '1');
  assert.equal(findImpersonation({ user: { id: '1', username: 'mod admin' } }, staff), null, 'the person themself');
  assert.equal(findImpersonation({ user: { id: '3', username: 'someone' }, nick: 'mod  admin' }, staff)?.id, '1', 'nickname counts');
  assert.equal(findImpersonation({ user: { id: '4', username: 'x' } }, staff), null, 'too short to compare');
});

test('links: common platforms are skipped, the rest deduplicated; notices carry no clickable link', () => {
  assert.deepEqual(extractLinks('see https://www.youtube.com/watch?v=1 and http://evil.example.xyz/claim, again http://evil.example.xyz/claim.'), ['http://evil.example.xyz/claim']);
  assert.equal(extractLinks('no links here').length, 0);
  assert.equal(defang('evil.example.xyz'), 'evil[.]example[.]xyz');
});

test('invite: built from DISCORD_CLIENT_ID with the listed permissions, none without it', () => {
  assert.equal(discordInfo(undefined).invite, null);
  assert.equal(discordInfo('not-an-id').invite, null);
  const i = discordInfo('123456789012345678');
  assert.equal(BOT_PERMISSIONS, '76800');
  assert.equal(i.invite, 'https://discord.com/oauth2/authorize?client_id=123456789012345678&permissions=76800&scope=bot%20applications.commands');
  assert.equal(startDiscordSentinel({ ctx: testContext([]) }, { token: '' }), null, 'nothing starts without a token');
});

test('REST: a 429 waits retry_after and tries again', async () => {
  const waits: number[] = [];
  let n = 0;
  const f = (async () => (++n === 1 ? new Response('{"retry_after":0.25,"global":false}', { status: 429 }) : new Response('{"id":"9"}', { status: 200 }))) as typeof fetch;
  const rest = new DiscordRest('tok', f, async (ms) => { waits.push(ms); });
  const r = await rest.call<{ id: string }>('POST', '/channels/1/messages', { content: 'x' });
  assert.equal(r.ok, true);
  assert.equal(r.data?.id, '9');
  assert.deepEqual(waits, [300]);
  assert.equal(n, 2);
});

class FakeWs {
  static all: FakeWs[] = [];
  readyState = 1;
  sent: { op: number; d: Record<string, unknown> | number | null }[] = [];
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) { FakeWs.all.push(this); }
  send(s: string) { this.sent.push(JSON.parse(s)); }
  close(code = 1000) { if (this.readyState === 3) return; this.readyState = 3; this.onclose?.({ code }); }
  emit(p: unknown) { this.onmessage?.({ data: JSON.stringify(p) }); }
}

test('gateway: identify, then resume after a dropped connection, and stop on a fatal close', async () => {
  FakeWs.all = [];
  const events: string[] = [];
  const logs: string[] = [];
  const gw = new DiscordGateway({ token: 'tok', WebSocket: FakeWs as unknown as new (u: string) => WebSocket, onDispatch: (t) => events.push(t), backoffMs: 1, random: () => 0.99, log: (m) => logs.push(m) });
  gw.start();
  const a = FakeWs.all[0]!;
  assert.match(a.url, /^wss:\/\/gateway\.discord\.gg\/\?v=10&encoding=json$/);
  a.emit({ op: 10, d: { heartbeat_interval: 60_000 } });
  assert.equal(a.sent[0]!.op, 2);
  assert.equal((a.sent[0]!.d as { intents: number }).intents, INTENTS);
  assert.equal(INTENTS, 33283);
  a.emit({ op: 0, t: 'READY', s: 1, d: { session_id: 'sess', resume_gateway_url: 'wss://resume.discord.gg', user: { id: 'bot' } } });
  a.emit({ op: 0, t: 'MESSAGE_CREATE', s: 2, d: {} });
  assert.deepEqual(events, ['READY', 'MESSAGE_CREATE']);
  a.emit({ op: 1 });
  assert.deepEqual(a.sent.at(-1), { op: 1, d: 2 }, 'a heartbeat request is answered at once with the last sequence');

  a.close(1006);
  await wait();
  const b = FakeWs.all[1]!;
  assert.match(b.url, /^wss:\/\/resume\.discord\.gg\//, 'resumes on the URL READY gave');
  b.emit({ op: 10, d: { heartbeat_interval: 60_000 } });
  assert.deepEqual(b.sent[0], { op: 6, d: { token: 'tok', session_id: 'sess', seq: 2 } });

  b.emit({ op: 9, d: false });
  await wait();
  const c = FakeWs.all[2]!;
  assert.match(c.url, /gateway\.discord\.gg/, 'a session that cannot be resumed starts over');
  c.emit({ op: 10, d: { heartbeat_interval: 60_000 } });
  assert.equal(c.sent[0]!.op, 2);

  c.close(4014);
  await wait();
  assert.equal(FakeWs.all.length, 3, 'no reconnect after disallowed intents');
  assert.ok(gw.stopped);
  assert.match(logs.join('\n'), /enable the Server Members and Message Content intents/);
  gw.stop();
});

interface Call { method: string; path: string; body: Record<string, unknown> | null }

function bot(opts: { verdicts?: Record<string, 'malicious' | 'suspicious' | 'no known threats'>; deleteStatus?: number } = {}) {
  const ctx = testContext([]);
  const calls: Call[] = [];
  const checked: string[] = [];
  const f = (async (u: string, init?: RequestInit) => {
    const path = u.replace('https://discord.com/api/v10', '');
    const method = init?.method ?? 'GET';
    calls.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : null });
    if (method === 'GET' && /^\/guilds\/g1\/members\?/.test(path)) return Response.json([
      { user: { id: 'owner', username: 'TheBoss' }, roles: [] },
      { user: { id: 'mod1', username: 'helper', global_name: 'Mod Admin' }, roles: ['rmod'] },
      { user: { id: 'u1', username: 'regular' }, roles: [] },
    ]);
    if (method === 'DELETE') return new Response(null, { status: opts.deleteStatus ?? 204 });
    return Response.json({ id: 'm1' });
  }) as typeof fetch;
  const s = new Sentinel(ctx, {
    token: 'tok', fetch: f, base: 'https://app.oculon.live',
    checkUrl: async (url) => { checked.push(url); const v = Object.entries(opts.verdicts ?? {}).find(([k]) => url.includes(k))?.[1] ?? 'no known threats'; return { verdict: v, reasons: v === 'no known threats' ? [] : [`listed as phishing for ${new URL(url).hostname}`, 'the domain was registered 2 days ago'] }; },
  });
  return { s, ctx, calls, checked };
}

const guild = { id: 'g1', owner_id: 'owner', system_channel_id: 'sys', roles: [{ id: 'g1', permissions: '0' }, { id: 'rmod', permissions: String(1 << 13) }], members: [] };
const msg = (content: string, id = 'msg1') => ({ id, guild_id: 'g1', channel_id: 'c1', content, author: { id: 'u1', username: 'regular' } });

test('sentinel: a malicious link is deleted with a notice; a suspicious one gets a warning reply; verdicts are cached', async () => {
  const { s, calls, checked } = bot({ verdicts: { 'drainer.xyz': 'malicious', 'odd.top': 'suspicious' } });
  await s.dispatch('GUILD_CREATE', guild);
  await s.dispatch('MESSAGE_CREATE', msg('free mint https://claim.drainer.xyz/mint'));
  const del = calls.find((c) => c.method === 'DELETE');
  assert.equal(del?.path, '/channels/c1/messages/msg1');
  const notice = calls.filter((c) => c.method === 'POST' && c.path === '/channels/c1/messages').at(-1)!;
  assert.match(String(notice.body!.content), /^Removed a message from <@u1>: the link claim\[\.\]drainer\[\.\]xyz is flagged as malicious \(listed as phishing/);
  assert.deepEqual(notice.body!.allowed_mentions, { parse: [] }, 'nobody is pinged');

  await s.dispatch('MESSAGE_CREATE', msg('again https://claim.drainer.xyz/mint', 'msg2'));
  assert.equal(checked.length, 1, 'the second time comes from the cache');

  const before = calls.length;
  await s.dispatch('MESSAGE_CREATE', msg('look https://odd.top/x', 'msg3'));
  const warn = calls.slice(before).find((c) => c.method === 'POST')!;
  assert.match(String(warn.body!.content), /^Careful: the link odd\[\.\]top looks suspicious/);
  assert.deepEqual(warn.body!.message_reference, { message_id: 'msg3', fail_if_not_exists: false });
  assert.ok(!calls.slice(before).some((c) => c.method === 'DELETE'));

  const n = calls.length;
  await s.dispatch('MESSAGE_CREATE', { ...msg('https://claim.drainer.xyz/mint', 'msg4'), author: { id: 'b', bot: true } });
  await s.dispatch('MESSAGE_CREATE', msg('clean https://fine.example.com/', 'msg5'));
  assert.equal(calls.length, n, 'bots are skipped and clean links stay quiet');
});

test('sentinel: without Manage Messages or with auto-delete off, a malicious link gets a reply instead', async () => {
  const { s, calls, ctx } = bot({ verdicts: { 'drainer.xyz': 'malicious' }, deleteStatus: 403 });
  await s.dispatch('GUILD_CREATE', guild);
  await s.dispatch('MESSAGE_CREATE', msg('https://drainer.xyz/a'));
  const post = calls.filter((c) => c.method === 'POST').at(-1)!;
  assert.match(String(post.body!.content), /^Warning: the link drainer\[\.\]xyz in this message is flagged as malicious/);
  assert.ok(post.body!.message_reference);

  const { setGuildSettings } = await import('../src/modules/discord.js');
  setGuildSettings(ctx, 'g1', { autoDelete: false, logChannel: 'log1' });
  const n = calls.length;
  await s.dispatch('MESSAGE_CREATE', msg('https://drainer.xyz/b', 'm2'));
  assert.ok(!calls.slice(n).some((c) => c.method === 'DELETE'));
  assert.ok(calls.slice(n).some((c) => c.path === '/channels/log1/messages' && /Message not deleted/.test(String(c.body!.content))), 'the log channel gets a copy');
});

test('sentinel: a member who copies a moderator name is flagged once in the system channel', async () => {
  const { s, calls } = bot();
  await s.dispatch('GUILD_CREATE', guild);
  assert.deepEqual([...s.guilds.get('g1')!.staff.keys()].sort(), ['mod1', 'owner']);
  await s.dispatch('GUILD_MEMBER_ADD', { guild_id: 'g1', user: { id: 'imp', username: 'm0d_adm1n' }, roles: [] });
  const warn = calls.filter((c) => c.path === '/channels/sys/messages');
  assert.equal(warn.length, 1);
  assert.match(String(warn[0]!.body!.content), /^Possible impersonation: <@imp> joined as "m0d_adm1n", which reads the same as moderator <@mod1>/);
  await s.dispatch('GUILD_MEMBER_UPDATE', { guild_id: 'g1', user: { id: 'imp', username: 'm0d_adm1n' }, roles: ['x'] });
  assert.equal(calls.filter((c) => c.path === '/channels/sys/messages').length, 1, 'a role change is not a new name');
  await s.dispatch('GUILD_MEMBER_UPDATE', { guild_id: 'g1', user: { id: 'u1', username: 'regular' }, nick: 'The Boss', roles: [] });
  assert.match(String(calls.filter((c) => c.path === '/channels/sys/messages').at(-1)!.body!.content), /<@u1> changed their name as "The Boss", which reads the same as owner <@owner>/);
  const n = calls.length;
  await s.dispatch('GUILD_MEMBER_ADD', { guild_id: 'g1', user: { id: 'new', username: 'friendly' }, roles: [] });
  assert.equal(calls.length, n);
});

test('slash commands: /sentinel settings needs Manage Server and is stored per server; /check answers privately', async () => {
  const { s, calls, ctx } = bot();
  await s.dispatch('READY', { user: { id: 'bot', username: 'Oculon' }, application: { id: 'app1' }, guilds: [] });
  const reg = calls.find((c) => c.method === 'PUT');
  assert.equal(reg?.path, '/applications/app1/commands');
  assert.deepEqual((reg!.body as unknown as { name: string }[]).map((c) => c.name), ['check', 'sentinel']);

  const settings = (perms: string, options: unknown[]) => s.dispatch('INTERACTION_CREATE', { id: 'i1', token: 't1', type: 2, application_id: 'app1', guild_id: 'g1', member: { permissions: perms }, data: { name: 'sentinel', options: [{ name: 'settings', type: 1, options }] } });
  await settings('0', [{ name: 'auto_delete', type: 5, value: false }]);
  assert.match(String((calls.at(-1)!.body!.data as { content: string }).content), /Only members with Manage Server/);
  assert.equal(guildSettings(ctx, 'g1').autoDelete, true);
  await settings(String(1 << 5), [{ name: 'auto_delete', type: 5, value: false }, { name: 'log_channel', type: 7, value: 'log9' }]);
  assert.deepEqual(guildSettings(ctx, 'g1'), { logChannel: 'log9', autoDelete: false });
  const saved = calls.at(-1)!;
  assert.equal(saved.path, '/interactions/i1/t1/callback');
  assert.equal((saved.body!.data as { flags: number }).flags, 64);
  assert.match(String((saved.body!.data as { content: string }).content), /^Saved\. Log channel: <#log9>\. Auto-delete of malicious links: off\./);

  await s.dispatch('INTERACTION_CREATE', { id: 'i2', token: 't2', type: 2, application_id: 'app1', guild_id: 'g1', data: { name: 'check', options: [{ name: 'input', type: 3, value: 'http://paypal-account-verify.xyz/login' }] } });
  const deferred = calls.find((c) => c.path === '/interactions/i2/t2/callback');
  assert.deepEqual(deferred?.body, { type: 5, data: { flags: 64 } });
  const edit = calls.find((c) => c.method === 'PATCH');
  assert.equal(edit?.path, '/webhooks/app1/t2/messages/@original');
  assert.match(String(edit!.body!.content), /^\*\*suspicious\*\*/);
  assert.match(String(edit!.body!.content), /Full report: https:\/\/app\.oculon\.live\/replay\/[A-Za-z0-9_-]{10,}/);
});
