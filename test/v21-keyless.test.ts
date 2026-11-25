import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkIban, mod97 } from '../src/modules/iban.js';
import { analyzeHeaders, parseHeaders } from '../src/modules/headers.js';
import { candidates } from '../src/modules/lookalike.js';
import { detectChain } from '../src/modules/address.js';
import { honeypotCheck } from '../src/modules/honeypot.js';
import { TOOLS } from '../src/mcp.js';
import { testContext } from './helpers.js';

test('IBAN: check digits, lengths, bank code and the supplier-country warning', () => {
  assert.equal(mod97('DE89370400440532013000'), 1);
  const ok = checkIban('de89 3704 0044 0532 0130 00', 'NL');
  assert.equal(ok.valid, true);
  assert.equal(ok.formatted, 'DE89 3704 0044 0532 0130 00');
  assert.deepEqual(ok.bank, { code: '37040044', kind: 'Bankleitzahl' });
  assert.match(ok.warnings[0]!, /Germany, but the supplier is in Netherlands/);
  assert.equal(checkIban('GB82 WEST 1234 5698 7654 32').sortCode, '12-34-56');
  const typo = checkIban('DE89 3704 0044 0532 0130 01');
  assert.equal(typo.valid, false);
  assert.match(typo.problems.join(' '), /check digits/);
  assert.match(checkIban('DE89 3704 0044 0532 0130').problems.join(' '), /22 characters/);
  assert.match(checkIban('hello').problems[0]!, /not an IBAN/);
  assert.match(checkIban('US12 3456 7890 1234').problems.join(' '), /does not issue IBANs/);
});

test('email headers: unfolding, auth results, origin hop and spoofing flags', () => {
  const raw = [
    'Received: from relay.example (relay.example [10.0.0.5]) by mx.google.com; Tue, 25 Nov 2026 10:00:05 +0000',
    'Received: from mail.bad.example (mail.bad.example [185.220.101.1])',
    '\tby relay.example; Tue, 25 Nov 2026 10:00:00 +0000',
    'Return-Path: <bounce@bad-mailer.example>',
    'Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bad-mailer.example; dkim=none; dmarc=fail header.from=bank.com',
    'From: "security@paypal.com" <alerts@bank.com>',
    'Reply-To: help@bank-verify.example',
    'Subject: Verify your account',
    '',
    'body text',
  ].join('\r\n');
  assert.equal(parseHeaders(raw).filter(([k]) => k === 'received').length, 2);
  const a = analyzeHeaders(raw);
  assert.equal(a.originIp, '185.220.101.1', 'oldest public hop, not the private relay');
  assert.deepEqual([a.auth.spf, a.auth.dmarc, a.auth.dkim], ['fail', 'fail', 'none']);
  assert.equal(a.verdict, 'likely spoofed');
  assert.ok(a.flags.some((f) => /replies go to help@bank-verify.example/.test(f)));
  assert.ok(a.flags.some((f) => /display name shows an address/.test(f)));
  const clean = analyzeHeaders('From: Alice <alice@example.com>\nAuthentication-Results: mx; spf=pass; dkim=pass header.d=example.com; dmarc=pass\nReceived: from a (a [8.8.8.8]) by b\n');
  assert.equal(clean.verdict, 'looks genuine');
});

test('lookalikes: candidate kinds, no duplicates, never the domain itself', () => {
  const c = candidates('paypal.com');
  const names = c.map((x) => x.domain);
  assert.equal(new Set(names).size, names.length);
  assert.ok(!names.includes('paypal.com'));
  for (const want of ['paypa1.com', 'paypal-login.com', 'paypal.net', 'payapl.com']) assert.ok(names.includes(want), want);
  assert.ok(c.length <= 160);
  assert.throws(() => candidates('localhost'), /not a domain/);
});

test('crypto addresses: chain from format', () => {
  assert.equal(detectChain('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045').chain, 'evm');
  assert.equal(detectChain('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh').chain, 'bitcoin');
  assert.equal(detectChain('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa').chain, 'bitcoin');
  assert.equal(detectChain('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t').chain, 'tron');
  assert.equal(detectChain('vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg').chain, 'solana');
  assert.equal(detectChain('hello world').chain, 'unknown');
});

test('honeypot: a failing sell becomes a honeypot verdict; unsupported chains say so', async () => {
  const ctx = testContext([[/api\.honeypot\.is/, () => ({ body: { token: { name: 'Trap', symbol: 'TRAP' }, simulationSuccess: true, honeypotResult: { isHoneypot: true, honeypotReason: 'transfer reverted' }, simulationResult: { buyTax: 0, sellTax: 100 }, holderAnalysis: { holders: '50', failed: '48', siphoned: '0', highestTax: 100 }, contractCode: { openSource: false, isProxy: false }, summary: { riskLevel: 100 } } })]]);
  const r = await honeypotCheck(ctx, '0x1111111111111111111111111111111111111111', { chain: 'bsc' });
  assert.equal(r.result.verdict, 'honeypot');
  assert.equal(r.result.chain, 'BNB Chain');
  assert.ok(r.result.reasons.some((x) => /48 of 50 recent holders could not sell/.test(x)));
  assert.equal(r.signals.length, 1);
  await assert.rejects(honeypotCheck(ctx, '0x1111111111111111111111111111111111111111', { chain: 'robinhood' }), /oculon token/);
  await assert.rejects(honeypotCheck(ctx, 'nope'), /contract address/);
});

test('MCP lists the five new keyless tools', () => {
  for (const n of ['oculon_iban_check', 'oculon_email_headers', 'oculon_lookalike_domains', 'oculon_honeypot_check', 'oculon_address_check']) assert.ok(TOOLS.some((t) => t.name === n), n);
});
