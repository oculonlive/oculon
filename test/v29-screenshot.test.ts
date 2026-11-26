import assert from 'node:assert/strict';
import { test } from 'node:test';
import { defang, imageMime, parseReading, screenshotCheck } from '../src/modules/screenshot.js';
import { testContext } from './helpers.js';

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(64)]);
const JPG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(64)]);
const WEBP = Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WEBP'), Buffer.alloc(64)]);
const GIF = Buffer.concat([Buffer.from('GIF89a'), Buffer.alloc(64)]);

const gemini = (reading: unknown, extra: Record<string, unknown> = {}) => ({ body: { candidates: [{ content: { parts: [{ text: typeof reading === 'string' ? reading : JSON.stringify(reading) }] }, finishReason: 'STOP', ...extra }] } });

function withKey<T>(fn: () => Promise<T>): Promise<T> {
  const old = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = 'test-gemini-key-000000';
  return fn().finally(() => { if (old === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = old; });
}

test('screenshot: image types are sniffed from bytes, links are defanged', () => {
  assert.equal(imageMime(PNG), 'image/png');
  assert.equal(imageMime(JPG), 'image/jpeg');
  assert.equal(imageMime(WEBP), 'image/webp');
  assert.equal(imageMime(GIF), null);
  assert.equal(defang('https://paypal-verify.top/login'), 'hxxps://paypal-verify[.]top/login');
  assert.equal(defang('usps-redeliver.com'), 'usps-redeliver[.]com');
});

test('screenshot: the reader answer keeps only known fields, a verdict from the model is dropped', () => {
  const r = parseReading(JSON.stringify({ screen: 'SMS', text: 'hello', verdict: 'scam', links: ['a.com', 'a.com', 3] }))!;
  assert.equal(r.screen, 'sms');
  assert.deepEqual(r.links, ['a.com']);
  assert.equal((r as unknown as Record<string, unknown>).verdict, undefined);
  assert.equal(parseReading('not json'), null);
  assert.equal(parseReading('```json\n{"screen":"weird","text":"x"}\n```')!.screen, 'other');
});

test('screenshot: rejects other formats and big files before calling anything', async () => {
  const ctx = testContext([]);
  await assert.rejects(screenshotCheck(ctx, GIF, 'a.gif'), /PNG, JPEG and WebP/);
  await assert.rejects(screenshotCheck(ctx, Buffer.concat([PNG, Buffer.alloc(8 * 1024 * 1024)]), 'big.png'), /limit is 8 MB/);
  assert.equal(ctx.calls.length, 0);
});

test('screenshot: a missing Gemini key fails with a clear message', async () => {
  const old = process.env.GEMINI_API_KEY;
  delete process.env.GEMINI_API_KEY;
  try {
    await assert.rejects(screenshotCheck(testContext([]), PNG), /GEMINI_API_KEY/);
  } finally {
    if (old !== undefined) process.env.GEMINI_API_KEY = old;
  }
});

test('screenshot: a parcel SMS is transcribed by the reader and judged by the scam check', async () => {
  const sms = 'USPS: Your package is on hold due to an unpaid delivery fee of $1.99. Pay within 24 hours or it will be returned: usps-redeliver.top/pay';
  const ctx = testContext([
    ['generativelanguage.googleapis.com', () => gemini({ screen: 'sms', sender: '+1 (415) 555-0134', text: sms, links: ['usps-redeliver.top/pay'], handles: [], phones: ['+1 (415) 555-0134'], emails: [], amounts: ['$1.99'], brands: ['USPS'] })],
  ]);
  const r = await withKey(() => screenshotCheck(ctx, PNG, 'sms.png'));
  const d = r.result;
  assert.equal(d.read, true);
  assert.equal(d.screen, 'sms');
  assert.equal(d.text, sms);
  assert.ok(d.verdict === 'likely scam' || d.verdict === 'suspicious', `verdict ${d.verdict}`);
  assert.ok(d.reasons.some((x) => /parcel or delivery fee/.test(x)));
  assert.deepEqual(d.items.links.map((l) => l.defanged), ['usps-redeliver[.]top/pay']);
  assert.deepEqual(d.items.amounts, ['$1.99']);
  assert.deepEqual(d.items.phones, ['+1 (415) 555-0134'], 'one number, written as on screen');
  const g = r.provenance.find((p) => p.source === 'gemini-vision')!;
  assert.equal(g.status, 'LIVE');
  assert.ok(!g.url.includes('test-gemini-key'), 'the key is never in provenance');
  assert.ok(ctx.calls.some((u) => u.includes(':generateContent')));
});

test('screenshot: when the reader fails the result says so and gives no verdict', async () => {
  const ctx = testContext([['generativelanguage.googleapis.com', () => ({ status: 503, body: { error: { message: 'overloaded' } } })]]);
  const r = await withKey(() => screenshotCheck(ctx, JPG, 'chat.jpg'));
  assert.equal(r.result.read, false);
  assert.equal(r.result.verdict, null);
  assert.equal(r.result.text, '');
  assert.equal(r.provenance[0]!.status, 'ERROR');
  assert.match(r.result.notes.join(' '), /did not answer/);
});

test('screenshot: a model out of free quota falls back to the next one; a bad key stops', async () => {
  const ctx = testContext([
    ['models/gemini-2.5-flash:', () => ({ status: 429, body: { error: { message: 'quota' } } })],
    ['models/gemini-3.5-flash:', () => gemini({ screen: 'chat', text: 'see you at 6 tomorrow then, bring the tickets' })],
  ]);
  const r = await withKey(() => screenshotCheck(ctx, PNG));
  assert.equal(r.result.read, true);
  assert.equal(r.result.screen, 'chat');
  assert.deepEqual(r.provenance.filter((p) => p.source === 'gemini-vision').map((p) => p.status), ['ERROR', 'LIVE']);
  assert.match(r.provenance[1]!.note ?? '', /gemini-3\.5-flash/);
  const bad = testContext([['generativelanguage.googleapis.com', () => ({ status: 400, body: { error: { message: 'API key not valid' } } })]]);
  const b = await withKey(() => screenshotCheck(bad, PNG));
  assert.equal(b.result.read, false);
  assert.equal(bad.calls.length, 1, 'a 400 is not retried on other models');
});

test('screenshot: a blocked or empty answer is reported, an image with no text is not checked', async () => {
  const blocked = testContext([['generativelanguage.googleapis.com', () => ({ body: { promptFeedback: { blockReason: 'SAFETY' } } })]]);
  const b = await withKey(() => screenshotCheck(blocked, PNG));
  assert.equal(b.result.read, false);
  assert.match(b.provenance[0]!.note ?? '', /blocked: SAFETY/);
  const empty = testContext([['generativelanguage.googleapis.com', () => gemini({ screen: 'other', text: '' })]]);
  const e = await withKey(() => screenshotCheck(empty, WEBP));
  assert.equal(e.result.read, true);
  assert.equal(e.result.verdict, null);
  assert.match(e.result.notes.join(' '), /No readable text/);
});
