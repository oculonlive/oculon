import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findClauses, htmlToText, sentences, termsRead } from '../src/modules/terms.js';
import { testContext } from './helpers.js';

const TOS = `Terms of Service

1. Subscription. Your subscription will automatically renew at the end of each billing period, and you will be charged the then-current fee until you cancel. All fees are non-refundable.
2. Disputes. Any dispute shall be resolved by binding arbitration. You waive any right to participate in a class action or class-wide arbitration.
3. Your content. You grant us a worldwide, perpetual, irrevocable, royalty-free license to use, reproduce, modify and distribute your content.
4. Privacy. We may share your personal information with third parties and advertising partners for targeted advertising. We collect precise location data and biometric identifiers such as face geometry.
5. Changes. We may modify these Terms at any time without notice. Your continued use of the Service constitutes acceptance of the revised Terms.
6. Termination. We may suspend or terminate your account at any time, for any reason, without notice.
7. Warranty. The Service is provided "as is" and "as available". In no event shall the Company be liable for any indirect or consequential damages.
8. Law. These Terms are governed by the laws of the State of Delaware, and you submit to the exclusive jurisdiction of the courts located in Wilmington, Delaware.
9. Retention. We may retain your information even after you delete your account.
The weather is nice today and this sentence means nothing.`;

test('terms: sentences are exact substrings with offsets', () => {
  const text = 'First line here. Second one, e.g. with a dot. Third!\nFourth sentence on a new line.';
  const s = sentences(text);
  for (const x of s) assert.equal(text.slice(x.at, x.at + x.s.length), x.s);
  assert.deepEqual(s.map((x) => x.s), ['First line here.', 'Second one, e.g. with a dot.', 'Fourth sentence on a new line.']);
});

test('terms: every category is found in a typical bad contract, quotes are verbatim', () => {
  const f = findClauses(TOS);
  const cats = new Set(f.map((x) => x.category));
  for (const c of ['auto-renewal', 'cancellation', 'arbitration', 'data-sharing', 'sensitive-data', 'content-licence', 'unilateral-changes', 'termination', 'liability', 'jurisdiction', 'data-retention']) assert.ok(cats.has(c as never), `missing ${c}`);
  for (const x of f) assert.equal(TOS.slice(x.offset, x.offset + x.quote.length), x.quote, 'quote must be exact');
  assert.ok(!f.some((x) => /weather/.test(x.quote)), 'plain sentences are not flagged');
  assert.equal(f[0]!.severity, 'high', 'high findings first');
  assert.equal(f.find((x) => x.category === 'arbitration')!.severity, 'high');
  assert.deepEqual(f.map((x) => x.n), f.map((_, i) => i + 1));
});

test('terms: your own right to cancel is not a red flag; headings are skipped; "you may not cancel" is', () => {
  assert.equal(findClauses('You may cancel your subscription at any time from your account page.').length, 0);
  assert.equal(findClauses('Class action waiver and jury trial waiver').length, 0);
  assert.equal(findClauses('We may terminate your account at any time without notice.')[0]!.category, 'termination');
  assert.equal(findClauses('You may not cancel this plan during the first year.')[0]!.category, 'cancellation');
  assert.deepEqual(findClauses('Paid Subscriptions continue indefinitely until cancelled.').map((f) => f.category), ['auto-renewal']);
  assert.equal(findClauses('California law will govern these terms and all disputes.')[0]!.category, 'jurisdiction');
  assert.equal(findClauses('To the extent allowed by law, you’ll indemnify Google and its officers.')[0]!.category, 'liability');
});

test('terms: employment and rental penalties', () => {
  const f = findClauses('The Employee agrees to a non-compete covenant for 24 months after leaving. An early termination fee of two months rent applies if the Tenant leaves before the end of the lease. The Landlord may withhold the security deposit for any damage.');
  const p = f.filter((x) => x.category === 'penalties');
  assert.equal(p.length, 3);
  assert.ok(p.some((x) => /non-compete/.test(x.quote) && x.severity === 'high'));
});

test('terms: pasted text works without any LLM key and gives a rating', async () => {
  const ctx = testContext([]);
  const r = await termsRead(ctx, { text: TOS });
  assert.equal(r.result.source, 'text');
  assert.equal(r.result.rating, 'many red flags');
  assert.ok(r.result.counts.high >= 3);
  assert.equal(r.result.truncated, false);
  assert.equal(ctx.calls.length, 0, 'pasted text needs no network');
  const clean = await termsRead(ctx, { text: 'This document explains how to contact our support team by email during office hours on weekdays.' });
  assert.equal(clean.result.rating, 'nothing flagged');
  assert.match(clean.result.notes.join(' '), /not proof/);
  await assert.rejects(termsRead(ctx, {}), /paste the terms/);
  await assert.rejects(termsRead(ctx, { text: 'too short' }), /too short/);
});

test('terms: long text is cut at 60,000 characters and says so', async () => {
  const r = await termsRead(testContext([]), { text: `${'Plain words here. '.repeat(4000)}All fees are non-refundable.` });
  assert.equal(r.result.truncated, true);
  assert.equal(r.result.chars, 60_000);
  assert.match(r.result.notes.join(' '), /first 60,000/);
});

test('terms: a URL is fetched, stripped to text and checked', async () => {
  const html = `<!doctype html><html><head><title>Acme Terms</title><style>.x{}</style><script>var a = "binding arbitration";</script></head><body><nav>Home | Pricing</nav><h1>Terms</h1><p>Your plan renews automatically every month.</p><p>Disputes &amp; claims shall be resolved by binding arbitration.</p></body></html>`;
  const ctx = testContext([['acme.example.com/terms', () => ({ body: html })]]);
  const r = await termsRead(ctx, { url: 'https://acme.example.com/terms' });
  assert.equal(r.result.source, 'url');
  assert.equal(r.result.title, 'Acme Terms');
  assert.ok(r.result.findings.some((f) => f.quote === 'Disputes & claims shall be resolved by binding arbitration.'));
  assert.equal(r.result.findings.filter((f) => f.category === 'arbitration').length, 1, 'script text is not read');
  assert.equal(r.provenance[0]!.status, 'LIVE');
  await assert.rejects(termsRead(ctx, { url: 'http://localhost/terms' }), /public hosts/);
  await assert.rejects(termsRead(testContext([]), { url: 'https://acme.example.com/missing' }), /HTTP 404|did not open/);
});

test('terms: html to text decodes entities and drops scripts', () => {
  assert.equal(htmlToText('<p>A&nbsp;&amp;&#39;B&#x41;</p><script>x</script><div>C</div>'), "A &'BA\nC");
});
