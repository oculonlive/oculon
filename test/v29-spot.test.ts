import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildRound, defang, OFFICIAL, scamSigns, seeded, spotRound } from '../src/modules/spot.js';
import { testContext } from './helpers.js';

const FEED = ['18-proposal-elysium.pages.dev', '17-proposal-elysium.pages.dev', 'okx-vote13.pages.dev', 'binance-campaign.tron-network.cam', 'metamsk-claim.xyz', 'xn--uniswp-9ta.com', 'hyperlaneinbridge.com', 'near-allocation.icu', 'send-usdt-12.vercel.app', 'swiftlayerchains.xyz', 'app.uniswap.org'];
const routes = (domains: unknown, status = 200) => [
  ['scam-database/main/blacklist/domains.json', () => ({ status, body: domains })],
  ['scam-database/main/blacklist/address.json', () => ({ body: [] })],
  ['eth-phishing-detect', () => ({ body: { blacklist: [], whitelist: [] } })],
] as Parameters<typeof testContext>[0];

test('spot: defang and code-derived signs', () => {
  assert.equal(defang('https://okx-vote13.pages.dev/'), 'hxxps://okx-vote13[.]pages[.]dev/');
  assert.match(scamSigns('okx-vote13.pages.dev').signs.join(), /pages\.dev.*free site builder/);
  assert.match(scamSigns('okx-vote13.pages.dev').signs.join(), /"okx"/);
  assert.match(scamSigns('metamsk-claim.xyz').signs.join(), /look-alike of "metamask"/);
  assert.match(scamSigns('metamsk-claim.xyz').signs.join(), /bait word "claim"/);
  assert.match(scamSigns('xn--uniswp-9ta.com').signs.join(), /punycode/);
  const a = seeded('x'), b = seeded('x');
  assert.equal(a(), b());
  for (const o of OFFICIAL) assert.match(o.url, /^https:\/\/[a-z0-9.-]+\//);
});

test('spot: a round is 8 items, the same for the same date, with no official domain as a scam', () => {
  const r1 = buildRound('2026-11-27', FEED), r2 = buildRound('2026-11-27', FEED);
  assert.equal(r1.length, 8);
  assert.deepEqual(r1, r2);
  const scams = r1.filter((i) => i.answer === 'scam');
  assert.ok(scams.length >= 3 && scams.length <= 5);
  for (const s of scams) {
    assert.ok(!s.url, 'scams carry no clickable address');
    assert.ok(!/\.(?!\])/.test(s.display.replace('hxxps://', '')), `defanged: ${s.display}`);
    assert.ok(!s.display.includes('uniswap[.]org'));
    assert.match(s.signs.at(-1)!, /ScamSniffer/);
  }
  assert.equal(new Set(scams.map((s) => s.display.replace(/\d+/g, '#'))).size, scams.length, 'one per campaign');
  for (const l of r1.filter((i) => i.answer === 'legit')) assert.match(l.explanation, /^Legit: the registrable domain is/);
  assert.notDeepEqual(buildRound('2026-11-28', FEED).map((i) => i.display), r1.map((i) => i.display));
});

test('spot: the round comes from the feed, is stored for the date, and future dates are refused', async () => {
  const ctx = testContext(routes(FEED));
  const r = await spotRound(ctx, '2026-11-18');
  assert.equal(r.result.available, true);
  assert.equal(r.result.items.length, 8);
  assert.equal(r.result.share, 'Spot the Scam 2026-11-18');
  const again = await spotRound(ctx, '2026-11-18');
  assert.deepEqual(again.result.items, r.result.items);
  assert.equal(again.provenance[0]!.status, 'CACHED');
  await assert.rejects(spotRound(ctx, '2026-11-19'), /not out yet/);
  await assert.rejects(spotRound(ctx, '2026-02-30'), /YYYY-MM-DD/);
});

test('spot: no feed, no round, and nothing invented', async () => {
  const ctx = testContext(routes('down', 503));
  const r = await spotRound(ctx);
  assert.equal(r.result.available, false);
  assert.equal(r.result.items.length, 0);
  assert.match(r.result.reason!, /could not be read/);
  assert.ok(!ctx.store.cacheGet('derived:spot:round:2026-11-18'), 'a failed round is not stored');
});
