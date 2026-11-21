import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { applyPath, canonicalJson, merkle } from '../src/core/merkle.js';
import { brier, momentumForecast, predict, resolve, scoreboard } from '../src/modules/raven.js';
import { stamp, verify } from '../src/modules/tortoise.js';
import { matchesMerkleRoot, parseTimestamp } from '../src/sources/opentimestamps.js';
import { testContext, type Route } from './helpers.js';

const sha = (b: Buffer) => createHash('sha256').update(b).digest();
const varbytes = (b: Buffer) => Buffer.concat([Buffer.from([b.length]), b]);
const PENDING = Buffer.from('83dfe30d2ef90c8e', 'hex');
const BITCOIN = Buffer.from('0588960d73d71901', 'hex');

/** Calendar receipt: sha256(digest) then a pending attestation pointing at `uri`. */
const pendingReceipt = (uri: string) => Buffer.concat([Buffer.from([0x08, 0x00]), PENDING, varbytes(varbytes(Buffer.from(uri)))]);
/** Upgraded timestamp: from the commitment, sha256 again, then a Bitcoin attestation at `height`. */
const bitcoinUpgrade = (height: number) => Buffer.concat([Buffer.from([0x08, 0x00]), BITCOIN, varbytes(Buffer.from([height & 0x7f | 0x80, height >> 7]))]);

test('canonical json and merkle paths', () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 3, c: 4 }] }), '{"a":[2,{"c":4,"d":3}],"b":1}');
  const leaves = ['a', 'b', 'c', 'd', 'e'].map((x) => sha(Buffer.from(x)).toString('hex'));
  const { root, paths } = merkle(leaves);
  leaves.forEach((l, i) => assert.equal(applyPath(l, paths[i]!), root));
  assert.equal(merkle([leaves[0]!]).root, leaves[0]);
});

test('ots parser follows ops to pending and bitcoin attestations', () => {
  const digest = sha(Buffer.from('root'));
  const atts = parseTimestamp(pendingReceipt('https://cal.test'), digest);
  assert.deepEqual(atts, [{ kind: 'pending', uri: 'https://cal.test', commitment: sha(digest).toString('hex') }]);
  const up = parseTimestamp(bitcoinUpgrade(900), sha(digest));
  assert.equal(up[0]?.kind, 'bitcoin');
  assert.equal((up[0] as { height: number }).height, 900);
  assert.ok(matchesMerkleRoot('0102', '0201'));
});

test('momentum rule and brier', () => {
  assert.equal(momentumForecast(0.4, 0.2), 0.45);
  assert.equal(momentumForecast(0.99, 0.5), 0.99);
  assert.ok(Math.abs(brier(0.7, 1) - 0.09) < 1e-12);
});

const market = (closed: boolean, prices: string) => ({ body: [{ id: 7, slug: 'will-x', question: 'Will X happen?', outcomes: '["Yes","No"]', outcomePrices: prices, volume24hr: 1000, oneDayPriceChange: 0.1, closed }] });

test('raven -> tortoise: forecast, stamp, pending, upgrade to bitcoin, verify, resolve, score', async () => {
  let resolved = false;
  let upgraded = false;
  const routes: Route[] = [
    ['gamma-api.polymarket.com/markets?slug=will-x', () => (resolved ? market(true, '["1","0"]') : market(false, '["0.4","0.6"]'))],
    [/pool\.opentimestamps\.org\/digest/, () => ({ body: pendingReceipt('https://cal.test').toString('latin1') })],
    ['cal.test/timestamp/', () => (upgraded ? { body: bitcoinUpgrade(900).toString('latin1') } : { status: 404, body: '' })],
    ['blockstream.info/api/block-height/900', () => ({ body: 'blockhash900' })],
  ];
  const ctx = testContext(routes);
  // Respond with raw bytes: the helper sends strings, so encode binary as latin1 and decode the same way.
  const realFetch = ctx.http as unknown as { cfg: { fetch: typeof fetch } };
  const inner = realFetch.cfg.fetch;
  realFetch.cfg.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const res = await inner(input, init);
    const url = String(input);
    if (url.includes('opentimestamps') || url.includes('cal.test')) {
      const text = await res.text();
      return new Response(Buffer.from(text, 'latin1'), { status: res.status });
    }
    return res;
  }) as typeof fetch;

  const p = (await predict(ctx, 'will-x', 0.7, 'test')).result;
  assert.equal(p.pMarket, 0.4);
  await assert.rejects(predict(ctx, 'will-x', 1.2), /between 0 and 1/);

  assert.equal((await verify(ctx, p.id)).result.status, 'NOT_STAMPED');
  const s = await stamp(ctx);
  assert.equal(s.result.batch?.size, 1);
  assert.equal(s.result.batch?.receipts.length, 2, 'both calendars');
  assert.equal((await stamp(ctx)).result.reason, 'nothing to stamp');

  assert.equal((await verify(ctx, p.id)).result.status, 'PENDING');

  // Calendar upgrades; the block's merkle root equals the (reversed) commitment.
  upgraded = true;
  const root = Buffer.from(s.result.batch!.root, 'hex');
  const commitment = sha(sha(root));
  routes.push(['blockstream.info/api/block/blockhash900', () => ({ body: { id: 'blockhash900', height: 900, merkle_root: Buffer.from(commitment).reverse().toString('hex'), timestamp: 1_800_000_000 } })]);
  const v = await verify(ctx, p.id);
  assert.equal(v.result.status, 'VERIFIED');
  assert.equal(v.result.bitcoin?.height, 900);

  // Editing the stored forecast after the fact is detected.
  ctx.store.db.prepare('UPDATE predictions SET p_model = 0.99 WHERE id = ?').run(p.id);
  assert.equal((await verify(ctx, p.id)).result.status, 'TAMPERED');
  ctx.store.db.prepare('UPDATE predictions SET p_model = 0.7 WHERE id = ?').run(p.id);

  resolved = true;
  const r = await resolve(ctx);
  assert.equal(r.result.resolved.length, 1);
  const sb = scoreboard(ctx);
  assert.equal(sb.resolved, 1);
  assert.ok(Math.abs(sb.brierModel! - 0.09) < 1e-9);
  assert.ok(Math.abs(sb.brierMarket! - 0.36) < 1e-9);
  assert.ok(sb.skill! > 0.7);
  assert.equal(sb.beatMarket, 1);
});
