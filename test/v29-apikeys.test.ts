import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { addressFromPrivateKey, personalHash, signHash } from '../src/core/evm.js';
import { Oculon, OculonClient } from '../src/index.js';
import { API_TIERS, authKey, createKey, gate, keyFromHeaders, listKeys, pathTier, revokeKey, setBalanceReader, toolTier, useQuota } from '../src/modules/apikeys.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW } from './helpers.js';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const rnd = () => (BigInt('0x' + randomBytes(32).toString('hex')) % (N - 1n)) + 1n;
const E18 = 10n ** 18n;
const WALLET = '0x' + 'ab'.repeat(20);

let now = NOW.getTime();
const fresh = () => new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => new Date(now) });

test('tiers: everyday checks are free, on-chain and deep reports need a holder key', () => {
  assert.equal(pathTier('/api/url'), 'free');
  assert.equal(pathTier('/api/scam'), 'free');
  assert.equal(pathTier('/api/contract'), 'holder');
  assert.equal(pathTier('/api/rh/launches'), 'holder');
  assert.equal(toolTier('oculon_url_check'), 'free');
  assert.equal(toolTier('oculon_robinhood_token'), 'holder');
  assert.equal(keyFromHeaders({ authorization: 'Bearer ocl_' + 'a'.repeat(43) }), 'ocl_' + 'a'.repeat(43));
  assert.equal(keyFromHeaders({ 'x-api-key': 'ocl_' + 'b'.repeat(43) }), 'ocl_' + 'b'.repeat(43));
  assert.equal(keyFromHeaders({ authorization: 'Bearer sk-nope' }), null);
});

test('keys: made once, stored hashed, tier follows the balance, revoked keys stop working', async () => {
  now = NOW.getTime();
  const o = fresh();
  let balance = 6_000_000n;
  setBalanceReader(async () => balance * E18);
  try {
    const { key, info } = await createKey(o.ctx, WALLET, 'bot');
    assert.match(key, /^ocl_[A-Za-z0-9_-]{43}$/);
    assert.equal(info.tier, 'holder');
    assert.equal(info.limit, API_TIERS.daily.holder);
    const row = o.ctx.store.db.prepare('SELECT hash FROM api_keys').get() as { hash: string };
    assert.notEqual(row.hash, key, 'only the hash is stored');
    assert.equal((await authKey(o.ctx, key))?.tier, 'holder');

    balance = 10n;
    now += (API_TIERS.recheckHours + 1) * 3_600_000;
    assert.equal((await authKey(o.ctx, key))?.tier, 'free', 'a stale balance is read again and the key drops to free');

    assert.equal(revokeKey(o.ctx, WALLET, info.id), true);
    assert.equal(await authKey(o.ctx, key), null);
    assert.equal(listKeys(o.ctx, WALLET)[0]!.revoked, true);
    for (let i = 0; i < API_TIERS.maxKeys; i++) await createKey(o.ctx, WALLET);
    await assert.rejects(createKey(o.ctx, WALLET), /active keys/);
  } finally { setBalanceReader(null); o.close(); }
});

test('gate: first-party pages pass, keyless outside calls get the free services and a small daily limit', async () => {
  now = NOW.getTime();
  const o = fresh();
  setBalanceReader(async () => 0n);
  try {
    assert.deepEqual(await gate(o.ctx, { headers: { 'sec-fetch-site': 'same-origin' } }, '1.1.1.1', '/api/contract', 'holder'), { ok: true, kind: 'first-party' });
    assert.equal((await gate(o.ctx, { headers: { referer: 'https://app.oculon.live/' } }, '1.1.1.1', '/api/contract', 'holder', 'oculon.live')).ok, true, 'an older browser on our own page');
    const held = await gate(o.ctx, { headers: {} }, '1.1.1.1', '/api/contract', 'holder');
    assert.equal(held.ok, false);
    assert.equal(held.ok === false && held.status, 401);
    const ext = await gate(o.ctx, { headers: { origin: 'chrome-extension://abc' } }, '1.1.1.1', '/api/contract', 'holder');
    assert.equal(ext.ok, true, 'the Shield extension still reads token risk without a key');
    for (let i = 0; i < API_TIERS.keylessDaily; i++) assert.equal((await gate(o.ctx, { headers: {} }, '2.2.2.2', '/api/url', 'free')).ok, true);
    const over = await gate(o.ctx, { headers: {} }, '2.2.2.2', '/api/url', 'free');
    assert.equal(over.ok === false && over.status, 429);

    const { key } = await createKey(o.ctx, WALLET);
    const free = await gate(o.ctx, { headers: { authorization: `Bearer ${key}` } }, '3.3.3.3', '/api/contract', 'holder');
    assert.equal(free.ok === false && free.status, 403, 'a free key cannot use holder services');
    assert.match(free.ok === false ? free.error : '', /5,000,000 OCULON/);
    const ok = await gate(o.ctx, { headers: { authorization: `Bearer ${key}` } }, '3.3.3.3', '/api/url', 'free');
    assert.equal(ok.ok && ok.kind, 'key');
    const priv = await gate(o.ctx, { headers: { authorization: `Bearer ${key}` } }, '3.3.3.3', '/api/cases', 'holder');
    assert.equal(priv.ok === false && priv.status, 403, 'owner data is never reachable with a key');
    const bad = await gate(o.ctx, { headers: { authorization: 'Bearer ocl_' + 'z'.repeat(43) } }, '3.3.3.3', '/api/url', 'free');
    assert.equal(bad.ok === false && bad.status, 401);
    const q = useQuota(o.ctx, 'test', '/api/url', 1);
    assert.equal(q.ok, true);
    assert.equal(useQuota(o.ctx, 'test', '/api/url', 1).ok, false);
  } finally { setBalanceReader(null); o.close(); }
});

test('console and API over HTTP: wallet sign-in, key made, key used by the SDK, holder service refused on free tier', async () => {
  now = NOW.getTime();
  setBalanceReader(async () => 100n * E18);
  const priv = rnd();
  const addr = addressFromPrivateKey(priv);
  const { server, stop } = createWebServer({ port: 0, publicMode: true, open: true, apiGate: true, rugRadar: false, burnRpcUrl: '', oculon: fresh() });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (p: string, body: unknown, cookie = '') => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  try {
    const page = await fetch(`${base}/console`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /One key\.<br><span>Every check\.<\/span>/);
    assert.deepEqual(((await (await fetch(`${base}/api/dev/me`)).json()) as { signedIn: boolean }).signedIn, false);

    const n = (await (await post('/api/dev/nonce', { address: addr })).json()) as { message: string };
    const signature = signHash(personalHash(n.message), priv, rnd());
    const login = await post('/api/dev/login', { message: n.message, signature });
    assert.equal(login.status, 200);
    const cookie = String(login.headers.get('set-cookie')).split(';')[0]!;
    assert.match(cookie, /^oculon_dev=/);
    assert.equal((await post('/api/dev/login', { message: n.message, signature })).status, 400, 'a sign-in message works once');

    const made = (await (await post('/api/dev/keys', { label: 'ci' }, cookie)).json()) as { key: string; info: { tier: string } };
    assert.equal(made.info.tier, 'free');
    const me = (await (await fetch(`${base}/api/dev/me`, { headers: { cookie } })).json()) as { keys: { label: string }[] };
    assert.equal(me.keys[0]!.label, 'ci');

    const oc = new OculonClient({ apiKey: made.key, baseUrl: base });
    const k = await oc.key();
    assert.equal(k.tier, 'free');
    assert.equal(k.limit, API_TIERS.daily.free);
    assert.equal(oc.remaining, API_TIERS.daily.free - 1);
    const held = await fetch(`${base}/api/contract?address=0x${'1'.repeat(40)}`, { headers: { authorization: `Bearer ${made.key}` } });
    assert.equal(held.status, 403);
    const keyless = await fetch(`${base}/api/contract?address=0x${'1'.repeat(40)}`);
    assert.equal(keyless.status, 401);
    const cat = (await (await fetch(`${base}/api/catalog`)).json()) as { endpoints: { path: string; tier: string }[]; tools: { name: string; tier: string }[] };
    assert.equal(cat.endpoints.find((e) => e.path === '/api/url')?.tier, 'free');
    assert.ok(cat.tools.some((t) => t.tier === 'holder'));

    const mcp = (await (await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${made.key}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'oculon_robinhood_token', arguments: { address: '0x' + '1'.repeat(40) } } }) })).json()) as { result: { isError: boolean; content: { text: string }[] } };
    assert.equal(mcp.result.isError, true);
    assert.match(mcp.result.content[0]!.text, /holder key/);
  } finally { setBalanceReader(null); await stop(); }
});
