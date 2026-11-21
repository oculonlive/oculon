import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { activeTools, McpServer, TOOLS } from '../src/mcp.js';
import { mockFetch, NOW } from './helpers.js';

const offline = () => new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });

test('initialize negotiates protocol version and advertises tools', async () => {
  const s = new McpServer(offline);
  const init = (await s.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' } } })) as { result: { protocolVersion: string; capabilities: { tools: object } } };
  assert.equal(init.result.protocolVersion, '2024-11-05');
  assert.ok(init.result.capabilities.tools);
  const unknownVersion = (await s.handle({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '1999-01-01' } })) as { result: { protocolVersion: string } };
  assert.equal(unknownVersion.result.protocolVersion, '2025-06-18');
  assert.equal(await s.handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
  s.close();
});

test('tools/list exposes valid schemas; tools/call works and reports errors as tool errors', async () => {
  const s = new McpServer(offline);
  const list = (await s.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list' })) as { result: { tools: { name: string; inputSchema: { type: string; required: string[]; properties: object } }[] } };
  assert.equal(list.result.tools.length, activeTools().length);
  assert.ok(activeTools().length < TOOLS.length, "on-chain tools are left out by default");
  assert.ok(!list.result.tools.some((t: { name: string }) => /robinhood|wallet|^oculon_token$/.test(t.name)));
  for (const t of list.result.tools) {
    assert.match(t.name, /^oculon_[a-z_]+$/);
    assert.equal(t.inputSchema.type, 'object');
    for (const r of t.inputSchema.required) assert.ok(r in t.inputSchema.properties, `${t.name}.${r}`);
  }

  const sb = (await s.handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'oculon_scoreboard', arguments: {} } })) as { result: { content: { text: string }[]; isError?: boolean } };
  assert.equal(JSON.parse(sb.result.content[0]!.text).total, 0);

  // Offline fetch -> market lookup fails -> surfaced as a tool error, not a protocol error.
  const bad = (await s.handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'oculon_forecast', arguments: { market_slug: 'nope', probability: 0.5 } } })) as { result: { isError: boolean; content: { text: string }[] } };
  assert.equal(bad.result.isError, true);
  assert.match(bad.result.content[0]!.text, /market not found/);

  const unknown = (await s.handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'nope' } })) as { error: { code: number } };
  assert.equal(unknown.error.code, -32602);
  const nomethod = (await s.handle({ jsonrpc: '2.0', id: 5, method: 'resources/list' })) as { error: { code: number } };
  assert.equal(nomethod.error.code, -32601);
  s.close();
});

test('stdio server speaks line-delimited JSON-RPC as a real child process', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oculon-mcp-'));
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'mcp'], {
    env: { ...process.env, OCULON_DB: join(dir, 'test.db'), OCULON_PLUGINS: dir },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const responses: Record<string, unknown>[] = [];
  let buf = '';
  const done = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout waiting for MCP responses')), 20_000);
    child.stdout.on('data', (d: Buffer) => {
      buf += d.toString();
      let i: number;
      while ((i = buf.indexOf('\n')) >= 0) {
        responses.push(JSON.parse(buf.slice(0, i)));
        buf = buf.slice(i + 1);
        if (responses.length === 3) {
          clearTimeout(timer);
          resolve();
        }
      }
    });
  });
  const send = (m: object) => child.stdin.write(`${JSON.stringify(m)}\n`);
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } } });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'oculon_signals', arguments: { limit: 5 } } });
  await done;
  child.stdin.end();
  await new Promise((r) => child.on('close', r));
  rmSync(dir, { recursive: true, force: true });

  const byId = Object.fromEntries(responses.map((r) => [String(r.id), r])) as Record<string, { result: Record<string, unknown> }>;
  assert.equal((byId['1']!.result.serverInfo as { name: string }).name, 'oculon');
  assert.equal((byId['2']!.result.tools as unknown[]).length, activeTools().length);
  assert.deepEqual(JSON.parse((byId['3']!.result.content as { text: string }[])[0]!.text), []);
});
