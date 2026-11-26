import assert from 'node:assert/strict';
import { test } from 'node:test';
import { recordCheck } from '../src/modules/checks.js';
import { categoriesOf, scamTrends, tldOf, trendsPostText } from '../src/modules/trends.js';
import { NOW, testContext } from './helpers.js';

type Ctx = ReturnType<typeof testContext>;

/** Stores a check as the server does: the slim module result goes through recordCheck at a chosen time. */
async function check(ctx: Ctx, daysAgo: number, kind: string, target: string, result: Record<string, unknown>) {
  const real = ctx.now;
  ctx.now = () => new Date(NOW.getTime() - daysAgo * 86_400_000);
  try { await recordCheck(ctx, kind, target, async () => ({ module: kind, input: target, generatedAt: NOW.toISOString(), result, signals: [], provenance: { sources: {} } })); }
  finally { ctx.now = real; }
}

const scam = (n: number, extra: Record<string, unknown> = {}) => ({ verdict: 'likely scam', risk: 80, reasons: [`secret message ${n} to +15550100${n}`], patterns: [{ name: 'parcel or delivery fee', evidence: `your parcel ${n} is held, pay at private-${n}.example` }], links: [{ url: `https://dhl-parcel-${n}.top/pay?id=${n}`, verdict: 'malicious', risk: 100, reasons: ['mentions "dhl" but is not on dhl\'s own domain', '.top is a top-level domain often used for abuse'] }], sender: null, phones: [`+15550100${n}`], advice: [], explanation: null, ...extra });
const url = (host: string, verdict = 'malicious') => ({ url: `https://${host}/login`, host, domain: host, verdict, risk: verdict === 'malicious' ? 100 : 0, reasons: verdict === 'malicious' ? ['listed as phishing or a wallet drainer by the ScamSniffer blocklist', 'the domain was registered 3 days ago', 'mentions "paypal" but is not on paypal\'s own domain'] : ['the domain is 9 years old'], heuristics: [] });

async function seeded() {
  const ctx = testContext([]);
  for (let i = 0; i < 12; i++) await check(ctx, 1 + (i % 5), 'scam', `Your parcel ${i} is held. Call +15550100${i}`, scam(i));
  for (let i = 0; i < 6; i++) await check(ctx, 2, 'url', `https://paypal-login-${i}.xyz/login`, url(`paypal-login-${i}.xyz`));
  for (let i = 0; i < 4; i++) await check(ctx, 3, 'url', `https://example${i}.com`, url(`example${i}.com`, 'no known threats'));
  await check(ctx, 1, 'iban', 'NL91ABNA0417164300', { valid: true, reasons: [] });
  await check(ctx, 1, 'wallet', '0x1111111111111111111111111111111111111111', { verdict: 'ok', risk: 0, reasons: [] });
  for (let i = 0; i < 5; i++) await check(ctx, 9, 'scam', `older ${i}`, scam(100 + i));
  return ctx;
}

test('trends: counts by kind, verdict split, patterns, brands and TLDs, with the week before for change', async () => {
  const t = scamTrends(await seeded());
  assert.equal(t.total, 24);
  assert.equal(t.previousTotal, 5);
  assert.equal(t.enough, true);
  assert.equal(t.note, null);
  assert.deepEqual(t.byKind.map((k) => [k.kind, k.checks]), [['scam', 12], ['url', 10]]);
  const s = t.byKind[0]!;
  assert.equal(s.label, 'Scam message');
  assert.equal(s.previous, 5);
  assert.equal(s.changePct, 140);
  assert.equal(t.otherKinds, 2, 'iban and wallet are too small to show on their own');
  assert.deepEqual(t.verdicts.map((v) => [v.tone, v.checks]), [['bad', 18], ['ok', 6]]);
  assert.equal(t.patterns[0]!.name, 'brand name on a domain the brand does not own');
  assert.equal(t.patterns[0]!.checks, 18);
  assert.ok(t.patterns.some((p) => p.name === 'parcel or delivery fee' && p.checks === 12));
  assert.ok(t.patterns.some((p) => p.name === 'on a phishing or wallet-drainer blocklist' && p.checks === 6));
  assert.deepEqual(t.brands.map((b) => [b.name, b.checks]), [['dhl', 12], ['paypal', 6]]);
  assert.deepEqual(t.tlds.map((b) => [b.name, b.checks]), [['top', 12], ['xyz', 6]]);
});

test('trends never return what was checked: no inputs, URLs, hosts, phone numbers, addresses or evidence', async () => {
  const json = JSON.stringify(scamTrends(await seeded()));
  for (const leak of ['Your parcel', '+1555', 'paypal-login', 'dhl-parcel', 'example0', 'NL91', '0x1111', 'private-', 'secret message', 'https://', '/login']) assert.ok(!json.includes(leak), leak);
});

test('trends: buckets under 3 are suppressed and a small week says so honestly', async () => {
  const ctx = testContext([]);
  await check(ctx, 1, 'scam', 'a', scam(1));
  await check(ctx, 1, 'scam', 'b', scam(2));
  await check(ctx, 1, 'qr', 'c', { verdict: 'no known risk found', risk: 0, reasons: [] });
  const t = scamTrends(ctx);
  assert.equal(t.total, 3);
  assert.equal(t.enough, false);
  assert.match(t.note!, /Only 3 checks/);
  assert.deepEqual(t.byKind, []);
  assert.equal(t.otherKinds, 3);
  assert.deepEqual(t.patterns, []);
  assert.deepEqual(t.brands, []);
  assert.equal(trendsPostText(t), null, 'no post from too little data');
  const none = scamTrends(testContext([]));
  assert.equal(none.total, 0);
  assert.match(none.note!, /No checks/);
});

test('trends: free text is matched to fixed categories only; unknown brands and odd TLDs are dropped', () => {
  const c = categoriesOf('url', { result: { host: '10.0.0.1', verdict: 'malicious', reasons: ['mentions "acmecorp" but is not on acmecorp\'s own domain', 'some new wording with a name John Smith', 'the host is a raw IP address'] } }, 'bad');
  assert.deepEqual([...c.patterns].sort(), ['brand name on a domain the brand does not own', 'raw IP address instead of a name']);
  assert.deepEqual([...c.brands], []);
  assert.deepEqual([...c.tlds], []);
  assert.equal(tldOf('https://a.b.co.uk/x'), 'uk');
  assert.equal(tldOf('192.168.1.1'), null);
  assert.equal(tldOf('localhost'), null);
  const job = categoriesOf('job', { result: { patterns: [{ name: 'asks for a fee before you start', evidence: 'pay $50 to Jane at jane@example.com' }] } }, 'bad');
  assert.deepEqual([...job.patterns], ['asks for a fee before you start']);
});

test('trends post: scam of the week, plain text, no emoji, under 600 characters', async () => {
  const p = trendsPostText(scamTrends(await seeded()))!;
  assert.ok(p.length < 600, String(p.length));
  assert.match(p, /^Scam of the week/);
  assert.match(p, /warning sign: brand name on a domain the brand does not own \(18 checks\)/);
  assert.match(p, /• Also common: parcel or delivery fee \(12\)/);
  assert.match(p, /• Most impersonated brand: dhl/);
  assert.match(p, /\+380% on last week/);
  assert.ok(p.endsWith('oculon.live/trends'));
  assert.ok(!/\p{Extended_Pictographic}/u.test(p));
});
