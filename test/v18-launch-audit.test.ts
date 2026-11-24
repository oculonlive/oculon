import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { checkArgs, McpServer } from '../src/mcp.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW } from './helpers.js';

const offline = () => new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });

test('api: bad input is a 400 and a missing record a 404, never a 500', async () => {
  const { server, stop } = createWebServer({ port: 0, oculon: offline() });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const status = async (p: string) => (await fetch(base + p)).status;
    assert.equal(await status('/api/cve?id=nope'), 400);
    assert.equal(await status('/api/rewind?date=yesterday'), 400);
    assert.equal(await status('/api/proof?id=does-not-exist'), 404);
    assert.equal(await status('/api/verify?id=does-not-exist'), 404);
    assert.equal(await status('/api/case?id=abc'), 400);
    assert.equal(await status('/api/case?id=999'), 404);
    assert.equal(await status('/api/scam'), 400);
  } finally {
    await stop();
  }
});

test('mcp: arguments are checked against the schema before a tool runs', async () => {
  const schema = { type: 'object', properties: { message: { type: 'string' }, days: { type: 'number' }, chain: { type: 'string', enum: ['eth', 'base'] } }, required: ['message'], additionalProperties: false };
  assert.match(checkArgs(schema, { text: 'hi' }) ?? '', /unknown argument "text"; this tool takes "message", "days", "chain"/);
  assert.match(checkArgs(schema, {}) ?? '', /missing required argument "message"/);
  assert.match(checkArgs(schema, { message: '  ' }) ?? '', /missing required/);
  assert.match(checkArgs(schema, { message: 'x', days: 'soon' }) ?? '', /"days" must be a number/);
  assert.match(checkArgs(schema, { message: 'x', chain: 'sol' }) ?? '', /must be one of eth, base/);
  const ok = { message: 'x', days: '7' };
  assert.equal(checkArgs(schema, ok), null);
  assert.equal(ok.days, 7, 'numeric strings become numbers');

  // The scam check used to answer "no strong signs" when called with the wrong argument name.
  const s = new McpServer(offline);
  const r = (await s.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'oculon_scam_check', arguments: { text: 'Pay the $1.99 fee within 24 hours' } } })) as { result: { isError: boolean; content: { text: string }[] } };
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0]!.text, /unknown argument "text"; this tool takes "message"/);
  const arr = (await s.handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'oculon_scam_check', arguments: ['x'] } })) as { result: { isError: boolean } };
  assert.equal(arr.result.isError, true);
  s.close();
});
