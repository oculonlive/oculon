import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cdnOf, exposure } from '../src/modules/exposure.js';
import { findMentions, fmtTime, podcast, transcribe } from '../src/modules/listen.js';
import { testContext } from './helpers.js';

test('mentions merge nearby sentences and carry timestamps', () => {
  const s = [
    { text: 'Welcome back.', start: 0 },
    { text: 'Today we cover Example Corp results.', start: 5 },
    { text: 'Revenue grew.', start: 9 },
    { text: 'Example Corp also hired a CEO.', start: 12 },
    { text: 'Weather now.', start: 100 },
    { text: 'Back to Example Corp later.', start: 200 },
  ];
  const m = findMentions(s, 'Example Corp');
  assert.deepEqual(m.map((x) => x.start), [0, 100]);
  assert.match(m[0]!.text, /Welcome back\. Today we cover Example Corp results\. Revenue grew\./);
  assert.equal(fmtTime(503), '08:23');
  assert.equal(fmtTime(3725), '1:02:05');
});

test('transcribe calls Deepgram once, caches a slim copy, drops English-only summary for other languages', async () => {
  process.env.DEEPGRAM_API_KEY = 'dg-test-0000000000000000';
  try {
    let calls = 0;
    const body = (lang: string) => ({
      metadata: { duration: 61.2 },
      results: {
        channels: [{ detected_language: lang, alternatives: [{ transcript: 'Example Corp grew fast.', words: [{ word: 'x' }], paragraphs: { paragraphs: [{ sentences: [{ text: 'Example Corp grew fast.', start: 3.2, end: 5 }] }] } }] }],
        summary: { short: lang === 'en' ? 'A short summary.' : 'The v2 summarization feature is currently only available in English.' },
        topics: { segments: [{ topics: [{ topic: 'Growth' }] }] },
      },
    });
    const ctx = testContext([['api.deepgram.com', () => (calls++, { body: body(calls === 1 ? 'en' : 'zh') })]]);
    const a = await transcribe(ctx, 'https://cdn.test/ep1.mp3', 'Example Corp', 'Show: Ep 1');
    assert.equal(a.result!.summary, 'A short summary.');
    assert.equal(a.result!.durationSec, 61);
    assert.deepEqual(a.result!.topics, ['Growth']);
    assert.equal(a.result!.mentions[0]!.start, 3.2);
    const again = await transcribe(ctx, 'https://cdn.test/ep1.mp3', 'Example Corp');
    assert.equal(calls, 1, 'second read comes from the stored transcript');
    assert.equal(again.provenance[0]!.status, 'CACHED');
    assert.ok(!ctx.store.cacheGet('derived:deepgram:https://cdn.test/ep1.mp3')!.body.includes('"words"'), 'word timings are not stored');
    const zh = await transcribe(ctx, 'https://cdn.test/ep2.mp3', 'Example Corp');
    assert.equal(zh.result!.summary, null);
    await assert.rejects(transcribe(ctx, 'ftp://x', ''), /http/);
  } finally {
    delete process.env.DEEPGRAM_API_KEY;
  }
});

test('podcast pick skips episodes that announce another language', async () => {
  process.env.DEEPGRAM_API_KEY = 'dg-test-0000000000000000';
  try {
    const transcribed: string[] = [];
    const ctx = testContext([
      [
        'itunes.apple.com',
        () => ({
          body: {
            results: [
              { collectionName: 'Daily Brief - CN', trackName: 'Example Corp results', releaseDate: '2026-11-18T10:00:00Z', episodeUrl: 'https://cdn.test/cn.mp3' },
              { collectionName: 'Daily Brief - EN', trackName: 'Example Corp results', releaseDate: '2026-11-18T09:00:00Z', episodeUrl: 'https://cdn.test/en.mp3' },
              { collectionName: 'Old Show', trackName: 'Older', releaseDate: '2026-11-01T00:00:00Z', episodeUrl: 'https://cdn.test/old.mp3' },
            ],
          },
        }),
      ],
      ['api.deepgram.com', () => (transcribed.push('x'), { body: { metadata: { duration: 10 }, results: { channels: [{ detected_language: 'en', alternatives: [{ transcript: 'hi', paragraphs: { paragraphs: [] } }] }] } } })],
    ]);
    const r = await podcast(ctx, 'Example Corp');
    assert.equal(r.result.picked!.audioUrl, 'https://cdn.test/en.mp3');
    assert.equal(r.result.episodes.length, 3);
    assert.equal(transcribed.length, 1);
    const p = await podcast(ctx, 'Example Corp', 0);
    assert.equal(p.result.picked!.audioUrl, 'https://cdn.test/cn.mp3', 'explicit pick wins');
  } finally {
    delete process.env.DEEPGRAM_API_KEY;
  }
});

test('exposure: CDN edges are marked, direct machines with CVEs and risky ports become a signal', async () => {
  assert.equal(cdnOf(['cpe:/a:cloudflare:cloudflare'], []), 'Cloudflare');
  assert.equal(cdnOf([], ['x.cloudfront.net']), 'Amazon CloudFront');
  assert.equal(cdnOf(['cpe:/a:nginx:nginx'], ['host.example.test']), null);
  const ctx = testContext([
    [/dns\.google\/resolve\?name=example\.test&/, () => ({ body: { Answer: [{ type: 1, data: '104.16.0.1' }] } })],
    [/dns\.google\/resolve\?name=dev\.example\.test&/, () => ({ body: { Answer: [{ type: 5, data: 'alias.' }, { type: 1, data: '203.0.113.7' }] } })],
    [/dns\.google/, () => ({ body: { Status: 3 } })],
    ['internetdb.shodan.io/104.16.0.1', () => ({ body: { ports: [443, 80, 8443], vulns: ['CVE-2099-0001'], cpes: ['cpe:/a:cloudflare:cloudflare'], hostnames: [] } })],
    ['internetdb.shodan.io/203.0.113.7', () => ({ body: { ports: [22, 443, 6379], vulns: ['CVE-2023-1234', 'CVE-2024-5678'], cpes: ['cpe:/a:redis:redis'], hostnames: ['dev.example.test', 'other.test'] } })],
  ]);
  const r = await exposure(ctx, 'https://Example.test/path');
  assert.equal(r.result.domain, 'example.test');
  assert.equal(r.result.resolved, 2);
  assert.equal(r.result.vulns, 2, 'CVEs on CDN edges are not counted');
  assert.deepEqual(r.result.unusualPorts.map((p) => p.port), [22, 6379]);
  assert.equal(r.result.ips[0]!.ip, '203.0.113.7');
  assert.deepEqual(r.result.ips[0]!.otherHostnames, ['other.test']);
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0]!.title, /example\.test: 2 known vulnerabilities, exposed SSH, Redis/);
});
