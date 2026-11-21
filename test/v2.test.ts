import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { newFindings, normalizeReport } from '../src/cases.js';
import { Oculon } from '../src/index.js';
import { addFence, checkFences, validBox } from '../src/modules/fence.js';
import { deployerVerdict } from '../src/modules/heron.js';
import { launches } from '../src/modules/launches.js';
import { bestMatch, searchTerm, shortlist } from '../src/modules/lynx.js';
import { subjectOf } from '../src/modules/scoop.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW, testContext } from './helpers.js';

test('case report: citations must come from tool results; confidence is earned', () => {
  const allowed = new Set(['https://a.test/1', 'https://b.test/2']);
  const r = normalizeReport(
    {
      answer: 'Yes.',
      confidence: 'high',
      summary: 's',
      findings: [
        { claim: 'Two sources agree', confidence: 'high', sources: ['https://a.test/1', 'https://b.test/2'] },
        { claim: 'One source only', confidence: 'high', sources: ['https://a.test/1'] },
        { claim: 'Invented citation', confidence: 'high', sources: ['https://made-up.test/x'] },
      ],
      timeline: [{ date: '2026-11-12', event: 'e', source: 'https://made-up.test/x' }, { date: 'bad', event: 'x' }],
      entities: [{ name: 'Nvidia', kind: 'company' }],
      open_questions: ['who next?'],
    },
    allowed,
  );
  assert.deepEqual(r.findings.map((f) => f.confidence), ['high', 'medium', 'low']);
  assert.deepEqual(r.findings[2]!.sources, []);
  assert.equal(r.timeline.length, 1);
  assert.equal(r.timeline[0]!.source, undefined, 'made-up timeline source dropped');
  assert.equal(newFindings(r.findings, [{ claim: 'Two sources agree today', confidence: 'high', sources: [] }, { claim: 'Something entirely different happened', confidence: 'medium', sources: [] }]).length, 1);
});

test('deployer verdict', () => {
  const t = (dead: boolean) => ({ address: '0x', symbol: 'X', createdAt: '', reserveUsd: dead ? 0 : 50_000, dead });
  assert.equal(deployerVerdict([t(true), t(true), t(true), t(false)]).verdict, 'DANGER');
  assert.equal(deployerVerdict([t(true), t(true), t(false), t(false)]).verdict, 'CAUTION');
  assert.equal(deployerVerdict([t(false), t(true)]).verdict, 'OK');
  assert.equal(deployerVerdict([]).verdict, 'UNKNOWN');
});

test('lynx helpers', () => {
  assert.equal(searchTerm("Will Tim Walz win the 2028 Democratic presidential nomination?"), 'Tim Walz 2028 Democratic');
  const cands = [{ question: 'Will Tim Walz be the next DNC chair?' }, { question: 'Will Tim Walz win the 2028 Democratic nomination?' }, { question: 'Will it rain?' }];
  assert.equal(shortlist('Will Tim Walz win the 2028 Democratic presidential nomination?', cands, 2)[0]!.question, cands[1]!.question);
  assert.equal(bestMatch('Will it snow in Paris tomorrow?', cands), null);
});

test('scoop subject strips module boilerplate', () => {
  const s = (title: string) => subjectOf({ id: 'x', module: 'owl', title, score: 70, evidence: [], createdAt: NOW.toISOString() });
  assert.equal(s('Jensen Huang'), 'Jensen Huang');
  assert.equal(s('Watch company Nvidia: new court case: X'), 'Nvidia');
  assert.equal(s('Tropical Cyclone Xavier: 130 kt winds'), 'Tropical Cyclone Xavier');
});

test('fences: validation, baseline, then only new things inside the box', async () => {
  assert.ok(validBox(25, 54, 27, 57));
  assert.ok(!validBox(27, 54, 25, 57));
  assert.ok(!validBox(0, 0, 40, 40), 'too large');
  let ac = [{ hex: 'ae0001', t: 'K35R', flight: 'TANK1', lat: 26, lon: 56, alt_baro: 30000, dbFlags: 1 }];
  const ctx = testContext([
    ['api.adsb.lol/v2/point', () => ({ body: { ac } })],
    ['earthquake.usgs.gov', () => ({ body: { features: [] } })],
    ['eonet', () => ({ body: { events: [] } })],
  ]);
  addFence(ctx, 'hormuz', [25, 54, 27.8, 57.7], ['air', 'quake', 'events']);
  const first = await checkFences(ctx);
  assert.equal(first.checks[0]!.baseline, true);
  assert.equal(first.signals.length, 0);
  ac = [...ac, { hex: 'ae0002', t: 'R135', flight: 'SNOOP', lat: 26.5, lon: 56.2, alt_baro: 32000, dbFlags: 1 }, { hex: 'abc123', t: 'A320', flight: 'CIV1', lat: 26.1, lon: 56.1, alt_baro: 35000, dbFlags: 0 }];
  ctx.store.db.prepare('DELETE FROM cache').run();
  const second = await checkFences(ctx);
  assert.deepEqual(second.checks[0]!.changes, ['military aircraft entered: R135 (ISR) SNOOP']);
  assert.equal(second.signals.length, 1);
  assert.ok(second.signals[0]!.score >= 65);
});

test('launch radar: new launches first, routine app updates last', async () => {
  const ctx = testContext([
    ['huggingface.co/api/models', () => ({ body: [{ id: 'acme/new-model', createdAt: '2026-11-15T00:00:00Z' }] })],
    ['huggingface.co/api/datasets', () => ({ body: [] })],
    ['huggingface.co/api/spaces', () => ({ body: [] })],
    ['itunes.apple.com', () => ({ body: { results: [{ trackName: 'Acme', artistName: 'Acme Inc', releaseDate: '2024-01-01T00:00:00Z', currentVersionReleaseDate: '2026-11-17T00:00:00Z', version: '2.0', trackViewUrl: 'https://apps.test/acme' }] } })],
    ['registry.npmjs.org/-/v1/search', () => ({ body: { objects: [] } })],
  ]);
  const r = await launches(ctx, 'Acme', { org: 'acme' });
  assert.deepEqual(r.result.items.map((i) => i.kind), ['model', 'app-update']);
});

test('dashboard write endpoints refuse cross-site requests', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const { server, stop } = createWebServer({ port: 0, oculon });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const body = JSON.stringify({ name: 'x', box: [25, 54, 27, 57] });
  try {
    assert.equal((await fetch(base + '/api/fences', { method: 'POST', headers: { 'content-type': 'application/json' }, body })).status, 403, 'no custom header');
    assert.equal((await fetch(base + '/api/fences', { method: 'POST', headers: { 'content-type': 'text/plain', 'x-oculon': '1' }, body })).status, 403, 'not JSON');
    assert.equal((await fetch(base + '/api/fences', { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1', origin: 'https://evil.test' }, body })).status, 403, 'foreign origin');
    const ok = await fetch(base + '/api/fences', { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1' }, body });
    assert.equal(ok.status, 200);
    assert.equal(((await ok.json()) as { name: string }).name, 'x');
    assert.equal((await fetch(base + '/api/fences', { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1' }, body: JSON.stringify({ name: 'y', box: [0, 0, 50, 50] }) })).status, 400);
  } finally {
    await stop();
    oculon.close();
  }
});
