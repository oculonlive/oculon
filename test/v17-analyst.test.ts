import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { createWebServer } from '../src/web/server.js';
import { ANALYST_MODELS, isAnalystModel, toolLabel } from '../src/analyst.js';
import { mockFetch, NOW } from './helpers.js';

test('analyst: page, request guards and model names (no model is called)', async () => {
  const oculon = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const { server, stop } = createWebServer({ port: 0, oculon });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (path: string, body: unknown, headers: Record<string, string> = { 'content-type': 'application/json', 'x-oculon': '1' }) => fetch(base + path, { method: 'POST', headers, body: JSON.stringify(body) });
  try {
    const page = await (await fetch(base + '/ask')).text();
    assert.match(page, /<title>Oculon Analyst<\/title>/);
    assert.match(page, /data-m="opus"/);
    assert.equal((await post('/api/analyst', { q: 'Is nginx safe?' }, { 'content-type': 'application/json' })).status, 403, 'needs the page header');
    assert.equal((await post('/api/analyst', { q: 'hi' })).status, 400, 'too short');
    assert.equal((await fetch(base + '/api/analyst')).status, 405);
    const review = await post('/api/analyst/review', { id: 'nope' });
    assert.equal(review.status, 400);
    assert.match(((await review.json()) as { error: string }).error, /expired/);
  } finally {
    await stop();
    oculon.close();
  }
  assert.ok(isAnalystModel('opus') && !isAnalystModel('gpt-4'));
  assert.equal(ANALYST_MODELS.haiku.id, 'anthropic/claude-haiku-5.5');
  assert.equal(toolLabel('oculon_url_check'), 'URL check');
});
