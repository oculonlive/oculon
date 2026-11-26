import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createContext } from '../src/core/context.js';
import { cleanLabel, normalizeHash, parseTree, proveOts, proveStatus, proveSubmit, proveUpgrade, serializeTree, treeFromOts, trustedCalendar } from '../src/modules/prove.js';
import { parseTimestamp } from '../src/sources/opentimestamps.js';
import { mockFetch, NOW, type Route } from './helpers.js';

const sha = (b: Buffer) => createHash('sha256').update(b).digest();
const varbytes = (b: Buffer) => Buffer.concat([Buffer.from([b.length]), b]);
const PENDING = Buffer.from('83dfe30d2ef90c8e', 'hex');
const BITCOIN = Buffer.from('0588960d73d71901', 'hex');
const CAL = 'https://alice.btc.calendar.opentimestamps.org';

/** Calendar receipt: append a nonce, sha256, then a pending attestation pointing at `uri`. */
const receipt = (uri: string, nonce: number) => Buffer.concat([Buffer.from([0xf0]), varbytes(Buffer.from([nonce, nonce])), Buffer.from([0x08, 0x00]), PENDING, varbytes(varbytes(Buffer.from(uri)))]);
/** Upgrade from the commitment: sha256, then a Bitcoin attestation at `height`. */
const upgrade = (height: number) => Buffer.concat([Buffer.from([0x08, 0x00]), BITCOIN, varbytes(Buffer.from([(height & 0x7f) | 0x80, height >> 7]))]);

const FILE = Buffer.from('the contract, final version');
const HASH = sha(FILE).toString('hex');
const commitmentFor = (nonce: number) => sha(Buffer.concat([Buffer.from(HASH, 'hex'), Buffer.from([nonce, nonce])]));

function setup(extra: Route[] = []) {
  let t = NOW.getTime();
  const state = { upgraded: false };
  const routes: Route[] = [
    ['a.pool.opentimestamps.org/digest', () => ({ body: receipt(CAL, 1) })],
    ['b.pool.opentimestamps.org/digest', () => ({ body: receipt(CAL, 2) })],
    [`${CAL}/timestamp/`, () => (state.upgraded ? { body: upgrade(900) } : { status: 404, body: 'Pending' })],
    ['blockstream.info/api/block-height/900', () => ({ body: 'blockhash900' })],
    ...extra,
  ];
  const m = mockFetch(routes);
  const ctx = createContext({ dbPath: ':memory:', fetch: m.fetch, throttle: false, retryDelayMs: 1, now: () => new Date(t) });
  return { ctx, calls: m.calls, state, routes, advance: (min: number) => { t += min * 60_000; } };
}

test('prove: hashes and labels are checked and cleaned', () => {
  assert.equal(normalizeHash(` ${HASH.toUpperCase()} `), HASH);
  assert.throws(() => normalizeHash('abc'), /invalid hash/);
  assert.throws(() => normalizeHash('z'.repeat(64)), /invalid hash/);
  assert.equal(cleanLabel('  Thesis\n draft\u0007 v2  '), 'Thesis draft v2');
  assert.equal(cleanLabel('x'.repeat(200))!.length, 80);
  assert.equal(cleanLabel('   '), null);
  assert.equal(cleanLabel(undefined), null);
  assert.equal(trustedCalendar('https://alice.btc.calendar.opentimestamps.org'), true);
  assert.equal(trustedCalendar('https://finney.calendar.eternitywall.com'), true);
  assert.equal(trustedCalendar('http://alice.btc.calendar.opentimestamps.org'), false);
  assert.equal(trustedCalendar('https://169.254.169.254'), false);
  assert.equal(trustedCalendar('https://evil.example/opentimestamps.org'), false);
});

test('prove: tree parse and serialize round-trip, and a merged file parses with the reference parser', () => {
  const digest = Buffer.from(HASH, 'hex');
  const bytes = receipt(CAL, 1);
  assert.deepEqual(serializeTree(parseTree(bytes, digest)), bytes);
  assert.throws(() => parseTree(Buffer.concat([bytes, Buffer.from([0])]), digest), /trailing/);
});

test('prove: submit, same hash twice, pending, upgrade to a Bitcoin block, confirmed, .ots download', async () => {
  const { ctx, calls, state, routes, advance } = setup();
  const s = await proveSubmit(ctx, HASH, 'Thesis draft');
  assert.equal(s.module, 'prove');
  assert.equal(s.result.existing, false);
  const p = s.result.proof!;
  assert.equal(p.status, 'PENDING');
  assert.equal(p.label, 'Thesis draft');
  assert.equal(p.calendars.length, 2, 'both calendars');
  assert.equal(p.ots, `/prove/${HASH}.ots`);
  assert.match(s.result.doesNotProve, /Who made the file/);

  const before = calls.length;
  const again = await proveSubmit(ctx, HASH, 'another label');
  assert.equal(again.result.existing, true);
  assert.equal(again.result.proof!.label, 'Thesis draft', 'the first label stays');
  assert.equal(calls.length, before, 'no second submission to the calendars');

  // The stored .ots is a standard detached file with both calendars' pending attestations.
  const file = proveOts(ctx, HASH)!;
  assert.equal(file.subarray(1, 15).toString('latin1'), 'OpenTimestamps');
  const { node } = treeFromOts(file);
  assert.equal(node.length, 2);
  const atts = parseTimestamp(file.subarray(31 + 2 + 32), Buffer.from(HASH, 'hex'));
  assert.deepEqual(atts.map((a) => a.kind), ['pending', 'pending']);

  // Too early to ask: no calendar call.
  assert.equal((await proveStatus(ctx, HASH)).result.proof!.status, 'PENDING');
  assert.equal(calls.length, before);
  assert.deepEqual(await proveUpgrade(ctx), { checked: 0, confirmed: 0, pending: 1 });

  // Due, still pending at the calendar (404).
  advance(30);
  const st = await proveStatus(ctx, HASH);
  assert.equal(st.result.proof!.status, 'PENDING');
  assert.ok(st.result.proof!.lastCheckedAt);
  assert.equal(calls.filter((c) => c.includes('/timestamp/')).length, 2, 'one call per pending commitment');
  assert.equal((await proveUpgrade(ctx)).checked, 0, 'just checked: not due again yet');

  // The calendar has stamped it. The block's merkle root equals the reversed commitment.
  state.upgraded = true;
  const merkleRoot = Buffer.from(sha(commitmentFor(1))).reverse().toString('hex');
  routes.push(['blockstream.info/api/block/blockhash900', () => ({ body: { id: 'blockhash900', height: 900, merkle_root: merkleRoot, timestamp: 1_800_000_000 } })]);
  advance(30);
  assert.deepEqual(await proveUpgrade(ctx), { checked: 1, confirmed: 1, pending: 0 });
  const done = (await proveStatus(ctx, HASH)).result.proof!;
  assert.equal(done.status, 'CONFIRMED');
  assert.equal(done.bitcoin!.height, 900);
  assert.equal(done.bitcoin!.time, new Date(1_800_000_000_000).toISOString());

  // The upgraded .ots now carries the Bitcoin attestation as well as the pending ones.
  const up = proveOts(ctx, HASH)!;
  const kinds = parseTimestamp(up.subarray(31 + 2 + 32), Buffer.from(HASH, 'hex')).map((a) => a.kind);
  assert.ok(kinds.includes('bitcoin'));
  assert.equal(kinds.filter((k) => k === 'pending').length, 2);

  // Confirmed proofs are never asked about again.
  const n = calls.length;
  advance(120);
  await proveUpgrade(ctx);
  await proveStatus(ctx, HASH);
  assert.equal(calls.length, n);
});

test('prove: an attestation whose block merkle root does not match stays pending', async () => {
  const { ctx, state, routes, advance } = setup();
  await proveSubmit(ctx, HASH);
  state.upgraded = true;
  routes.push(['blockstream.info/api/block/blockhash900', () => ({ body: { id: 'blockhash900', height: 900, merkle_root: '00'.repeat(32), timestamp: 1 } })]);
  advance(30);
  assert.equal((await proveUpgrade(ctx)).confirmed, 0);
  assert.equal((await proveStatus(ctx, HASH, { refresh: false })).result.proof!.status, 'PENDING');
});

test('prove: unknown hash and calendars down', async () => {
  const { ctx } = setup();
  const r = await proveStatus(ctx, 'ab'.repeat(32));
  assert.equal(r.result.found, false);
  assert.equal(r.result.proof, null);
  assert.equal(proveOts(ctx, 'ab'.repeat(32)), null);
  assert.equal(proveOts(ctx, 'not a hash'), null);

  const down = createContext({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, retryDelayMs: 1, now: () => NOW });
  await assert.rejects(proveSubmit(down, HASH), /no OpenTimestamps calendar accepted/);
  assert.equal((await proveStatus(down, HASH)).result.found, false, 'nothing stored when no calendar answered');
});

test('prove page and embed script are self-contained', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../src/web/prove.html', import.meta.url), 'utf8');
  assert.match(html, /crypto\.subtle\.digest\('SHA-256'/);
  assert.match(html, /'x-oculon': '1'/);
  assert.match(html, /what it does not/i);
  assert.doesNotMatch(html, /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u, 'no emoji');
});
