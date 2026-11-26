import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import { extractForwarded, handleInbox, inboxAuthorized, inboxReply, inboxRoute, inboxUsage, plainAddress } from '../src/modules/inbox.js';
import { testContext } from './helpers.js';

const saved = { key: process.env.RESEND_API_KEY, secret: process.env.OCULON_INBOX_SECRET, domain: process.env.OCULON_DOMAIN };
before(() => { process.env.RESEND_API_KEY = 're_test_key_value_1234'; process.env.OCULON_DOMAIN = 'oculon.live'; delete process.env.OCULON_INBOX_SECRET; });
after(() => {
  for (const [k, v] of [['RESEND_API_KEY', saved.key], ['OCULON_INBOX_SECRET', saved.secret], ['OCULON_DOMAIN', saved.domain]] as const) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

const SCAM = [
  'From: "PayPal Security" <security@paypa1-alerts.xyz>',
  'To: victim@example.com',
  'Subject: Your account has been suspended',
  'Reply-To: help@other-domain.top',
  'Received: from mail.paypa1-alerts.xyz (mail.paypa1-alerts.xyz [203.0.113.9]) by mx.example.com; Tue, 17 Nov 2026 10:00:00 +0000',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Your account has been suspended. Verify your account within 24 hours or it will be closed: http://paypal-login-check.xyz/verify',
].join('\r\n');

const outer = (body: string, extra: string[] = []) => [
  'From: Sam <sam@example.org>',
  'To: check@oculon.live',
  'Subject: Fwd: Your account has been suspended',
  'Authentication-Results: mx.cloudflare.net; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass',
  ...extra,
  body,
].join('\r\n');

const attachedMail = () => outer([
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="b1"',
  '',
  '--b1',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Is this real?',
  '--b1',
  'Content-Type: message/rfc822',
  'Content-Disposition: attachment; filename="suspended.eml"',
  '',
  SCAM,
  '--b1--',
  '',
].join('\r\n'));

const inlineMail = () => outer([
  'MIME-Version: 1.0',
  'Content-Type: multipart/alternative; boundary="b2"',
  '',
  '--b2',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Is this real?',
  '',
  '---------- Forwarded message ---------',
  'From: PayPal Security <security@paypa1-alerts.xyz>',
  'Date: Tue, 17 Nov 2026 at 10:00',
  'Subject: Your account has been suspended',
  'To: <sam@example.org>',
  '',
  'Your account has been suspended. Verify your account within 24 hours: click here',
  '--b2',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<p>Your account has been suspended. <a href="http://paypal-login-check.xyz/verify">click here</a></p>',
  '--b2--',
  '',
].join('\r\n'));

/** A Resend stand-in that records what would be sent. */
function resend() {
  const sent: { to: string[]; subject: string; text: string; html: string }[] = [];
  const f = (async (_u: string, init?: RequestInit) => { sent.push(JSON.parse(String(init?.body))); return new Response('{"id":"em_1"}', { status: 200 }); }) as typeof fetch;
  return { sent, fetch: f };
}

test('inbox secret: compared in constant time, nothing passes without one', () => {
  assert.equal(inboxAuthorized('s3cret-value', 's3cret-value'), true);
  assert.equal(inboxAuthorized('s3cret-valuX', 's3cret-value'), false);
  assert.equal(inboxAuthorized('', 's3cret-value'), false);
  assert.equal(inboxAuthorized('anything', undefined), false);
  assert.equal(plainAddress('Sam <Sam@Example.org>'), 'sam@example.org');
  assert.equal(plainAddress('<>'), null);
});

test('inbox: an attached .eml is checked as it is; an inline forward is rebuilt from the forwarded text', () => {
  const a = extractForwarded(Buffer.from(attachedMail()));
  assert.equal(a.mode, 'attached');
  assert.match(a.message.toString(), /^From: "PayPal Security"/);
  assert.match(a.message.toString(), /Received: from mail\.paypa1-alerts\.xyz/);

  const i = extractForwarded(Buffer.from(inlineMail()));
  assert.equal(i.mode, 'inline');
  const s = i.message.toString();
  assert.match(s, /^Subject: Your account has been suspended\r\n/, 'the original subject, not "Fwd:"');
  assert.doesNotMatch(s.split('\r\n\r\n')[0]!, /^From:/m, 'no From header: the forwarder\'s headers are not the scam\'s');
  assert.match(s, /From: PayPal Security <security@paypa1-alerts\.xyz>/);
  assert.match(s, /http:\/\/paypal-login-check\.xyz\/verify/, 'links behind HTML anchors are kept');
});

test('inbox: the check is stored and the verdict goes back to the sender with the report link', async () => {
  const ctx = testContext([]);
  const mail = resend();
  const r = await handleInbox({ ctx }, attachedMail(), '<sam@example.org>', { base: 'https://app.oculon.live', fetch: mail.fetch });
  assert.equal(r.status, 'replied', r.reason);
  assert.equal(r.mode, 'attached');
  assert.ok(r.checkId);
  assert.notEqual(r.verdict, 'no known risk found', 'look-alike link, reply-to elsewhere and account-suspended wording');
  assert.equal(mail.sent.length, 1);
  const m = mail.sent[0]!;
  assert.deepEqual(m.to, ['sam@example.org']);
  assert.match(m.subject, /^Oculon check: /);
  assert.match(m.text, /^Verdict: /);
  assert.ok(m.text.includes(`https://app.oculon.live/replay/${r.checkId}`));
  assert.ok(m.html.includes(`/replay/${r.checkId}`));
  assert.doesNotMatch(m.html, /<script/i);
  const row = ctx.store.db.prepare('SELECT kind, result FROM checks WHERE id = ?').get(r.checkId!) as { kind: string; result: string };
  assert.equal(row.kind, 'eml');
  const log = ctx.store.db.prepare('SELECT * FROM inbox_log').all() as Record<string, unknown>[];
  assert.equal(log.length, 1);
  assert.ok(!JSON.stringify(log).includes('sam@example.org'), 'the sender is kept only as a hash');
  assert.ok(!JSON.stringify(log).includes('Verify your account'), 'no message text in the inbox log');
});

test('inbox: an inline forward says the headers were not available', async () => {
  const ctx = testContext([]);
  const mail = resend();
  const r = await handleInbox({ ctx }, inlineMail(), 'sam@example.org', { base: 'https://app.oculon.live', fetch: mail.fetch });
  assert.equal(r.status, 'replied', r.reason);
  assert.equal(r.mode, 'inline');
  assert.match(mail.sent[0]!.text, /forwarded inline/);
});

test('inbox: own domain, automated mail, failed authentication and daily limits get no reply', async () => {
  const ctx = testContext([]);
  const mail = resend();
  const run = (raw: string, from = 'sam@example.org', o = {}) => handleInbox({ ctx }, raw, from, { fetch: mail.fetch, ...o });
  assert.equal((await run(attachedMail(), 'alerts@oculon.live')).status, 'skipped');
  assert.equal((await run(attachedMail(), 'x@mail.oculon.live')).status, 'skipped');
  assert.equal((await run(attachedMail(), 'MAILER-DAEMON@example.org')).status, 'skipped');
  assert.equal((await run(outer('\r\nhello there friend', ['Auto-Submitted: auto-replied']))).status, 'skipped');
  assert.equal((await run(outer('\r\nhello there friend', ['List-Id: <news.example.org>']))).status, 'skipped');
  const forged = attachedMail().replace('spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass', 'spf=fail smtp.mailfrom=example.org; dkim=none; dmarc=fail');
  assert.match((await run(forged)).reason, /failed authentication/);
  assert.equal(mail.sent.length, 0);

  assert.equal((await run(attachedMail(), 'a@example.org', { perSender: 2 })).status, 'replied');
  assert.equal((await run(attachedMail(), 'a@example.org', { perSender: 2 })).status, 'replied');
  const third = await run(attachedMail(), 'a@example.org', { perSender: 2 });
  assert.equal(third.status, 'limited');
  assert.match(third.reason, /this sender/);
  assert.equal((await run(attachedMail(), 'b@example.org', { perDay: 2 })).status, 'limited', 'the inbox total counts too');
  assert.deepEqual(inboxUsage(ctx, 'a@example.org'), { sender: 2, total: 2 });
  assert.equal(mail.sent.length, 2);
});

test('inbox reply: plain text and escaped HTML', () => {
  const r = inboxReply({ subject: '<b>Win</b>', from: 'x <x@y.z>', to: null, date: null, verdict: 'likely scam', risk: 70, headers: null, body: null, attachments: [], reasons: ['message: likely scam (prize <img>)'], advice: ['Do not click.'] }, { reportUrl: null, mode: 'attached' });
  assert.match(r.subject, /^Oculon check: Likely scam - <b>Win<\/b>$/);
  assert.ok(r.html.includes('&lt;img&gt;'));
  assert.ok(!r.html.includes('<img>'));
  assert.ok(!r.text.includes('Full report'));
});

test('POST /api/inbox: only the secret header admits a request; the check runs after a 202', async () => {
  const ctx = testContext([]);
  const mail = resend();
  const logs: string[] = [];
  let done: () => void;
  const finished = new Promise<void>((r) => { done = r; });
  const server = createServer((req, res) => void inboxRoute({ ctx }, req, res, { secret: 'inbox-secret-123456', fetch: mail.fetch, base: 'https://app.oculon.live', log: (m) => { logs.push(m); done(); } }));
  const noSecret = createServer((req, res) => void inboxRoute({ ctx }, req, res, {}));
  await Promise.all([new Promise((r) => server.listen(0, '127.0.0.1', () => r(null))), new Promise((r) => noSecret.listen(0, '127.0.0.1', () => r(null)))]);
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/inbox`;
  try {
    const post = (headers: Record<string, string>, body: string = attachedMail()) => fetch(url, { method: 'POST', headers: { 'content-type': 'message/rfc822', ...headers }, body });
    assert.equal((await post({})).status, 403);
    assert.equal((await post({ 'x-oculon-inbox': 'wrong' })).status, 403);
    assert.equal((await fetch(url)).status, 405);
    assert.equal((await fetch(`http://127.0.0.1:${(noSecret.address() as AddressInfo).port}/api/inbox`, { method: 'POST', body: 'x' })).status, 404, 'off without OCULON_INBOX_SECRET');
    const ok = await post({ 'x-oculon-inbox': 'inbox-secret-123456', 'x-oculon-from': 'sam@example.org' });
    assert.equal(ok.status, 202);
    await finished;
    assert.match(logs[0]!, /^inbox: replied/);
    assert.equal(mail.sent.length, 1);
    const big = await post({ 'x-oculon-inbox': 'inbox-secret-123456', 'x-oculon-from': 'sam@example.org' }, 'x'.repeat(6 * 1024 * 1024 + 10));
    assert.equal(big.status, 413);
  } finally {
    await new Promise((r) => server.close(r));
    await new Promise((r) => noSecret.close(r));
  }
});
