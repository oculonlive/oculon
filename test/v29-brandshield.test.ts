import assert from 'node:assert/strict';
import { test } from 'node:test';
import { brandShield, scoreHit } from '../src/modules/brandshield.js';
import { daysAgo, NOW, testContext, type Route } from './helpers.js';

const LIVE: Record<string, string> = { 'acmebank-login.com': '203.0.113.5', 'acmebank.xyz': '203.0.113.6', 'secure-acmebank.top': '203.0.113.7' };
const dns: Route = [/dns\.google\/resolve/, (url) => {
  const u = new URL(url);
  const name = u.searchParams.get('name')!;
  const type = u.searchParams.get('type');
  if (type === 'MX') return { body: { Status: 0, Answer: name === 'acmebank-login.com' ? [{ type: 15, data: '10 mx.acmebank-login.com.' }] : [] } };
  return { body: LIVE[name] ? { Status: 0, Answer: [{ type: 1, data: LIVE[name] }] } : { Status: 3 } };
}];
const crt = (rows: unknown[]): Route => ['crt.sh/?q=', () => ({ body: rows })];
const row = (name: string, days: number) => ({ name_value: name, not_before: daysAgo(days).replace('Z', ''), issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11' });

test('brand shield: scoring reasons', () => {
  const base = { origin: ['certificate'], resolves: true, ips: ['203.0.113.9'], mail: false, certFirstSeen: daysAgo(2), certIssuer: null, urlCheck: null };
  const a = scoreHit({ ...base, domain: 'acmebank-airdrop.xyz' }, 'acmebank', NOW.getTime());
  assert.match(a.reasons.join(' | '), /contains the brand name "acmebank" \| adds the word "airdrop".*\.xyz is a top-level domain.*certificate issued 2 days ago.*resolves in DNS/);
  assert.equal(a.score, 100);
  const quiet = scoreHit({ ...base, domain: 'acmebank.net', resolves: false, certFirstSeen: daysAgo(80) }, 'acmebank', NOW.getTime());
  assert.equal(quiet.score, 25);
  assert.ok(quiet.reasons.includes('does not resolve in DNS right now'));
  const bad = scoreHit({ ...base, domain: 'acmebank.net', certFirstSeen: null, urlCheck: { verdict: 'malicious', risk: 100, reasons: ['listed as phishing'] } }, 'acmebank', NOW.getTime());
  assert.match(bad.reasons.at(-1)!, /URL check: malicious \(listed as phishing\)/);
});

test('brand shield: lookalikes and certificate names are merged, resolved, ranked and the top live ones URL-checked', async () => {
  const ctx = testContext([
    dns,
    crt([row('acmebank-login.com', 3), row('www.acmebank.com', 1), row('mail.acmebank.com\nacmebank.com', 1), row('*.claim-acmebank.app', 5), row('acmebank-old.net', 60)]),
  ]);
  const r = await brandShield(ctx, 'https://www.acmebank.com/login');
  const d = r.result;
  assert.equal(d.domain, 'acmebank.com');
  assert.equal(d.brand, 'acmebank');
  assert.equal(d.certificates.status, 'ok');
  const names = d.hits.map((h) => h.domain);
  assert.ok(!names.includes('www.acmebank.com') && !names.includes('acmebank.com'), 'the brand\'s own names are left out');
  assert.equal(names[0], 'acmebank-login.com', 'login word, fresh certificate, resolves and has mail');
  const top = d.hits[0]!;
  assert.deepEqual(top.origin, ['lookalike: brand plus word', 'certificate']);
  assert.equal(top.mail, true);
  assert.equal(top.level, 'high');
  const claim = d.hits.find((h) => h.domain === 'claim-acmebank.app')!;
  assert.equal(claim.resolves, false, 'certificate names are resolved too');
  assert.ok(d.checkedWithUrlCheck.includes('acmebank-login.com'));
  assert.ok(d.checkedWithUrlCheck.every((h) => LIVE[h]), 'only live domains go through the URL check');
  assert.ok(top.urlCheck, 'URL check result attached');
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0]!.title, /high-risk domain/);
});

test('brand shield: crt.sh failure and slowness are reported, not hidden', async () => {
  const failing = testContext([dns, ['crt.sh/?q=', () => ({ status: 502, body: 'bad gateway' })], ['api.certspotter.com', () => ({ body: [] })]]);
  const r = await brandShield(failing, 'acmebank.com');
  assert.equal(r.result.certificates.status, 'fallback');
  assert.match(r.result.certificates.note, /crt\.sh did not answer \(HTTP 502\)/);
  assert.ok(r.result.hits.some((h) => h.domain === 'acmebank-login.com'), 'DNS results still count');

  const slow = testContext([dns, ['crt.sh/?q=', () => new Promise((res) => setTimeout(() => res({ body: [] }), 1500))]]);
  const s = await brandShield(slow, 'acmebank.com', { budgetMs: 300 });
  assert.equal(s.result.certificates.status, 'timed out');
  assert.match(s.result.certificates.note, /run Brand Shield again/);
  assert.ok(s.provenance.some((p) => p.source === 'crt.sh' && p.status === 'ERROR'));
  await assert.rejects(brandShield(slow, 'not a domain'), /not a domain/);
});
