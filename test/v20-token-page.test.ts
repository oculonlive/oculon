import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { createWebServer, tokenBlock } from '../src/web/server.js';
import { mockFetch, NOW } from './helpers.js';

test('token block: nothing official without an address, escaped values with one', () => {
  assert.match(tokenBlock({}), /No official token address has been posted yet/);
  assert.match(tokenBlock({ ca: '   ' }), /No official token address/);
  const b = tokenBlock({ ca: '0xabc<script>', chain: 'Base', ticker: '$OCU', explorer: 'javascript:alert(1)' });
  assert.ok(b.includes('0xabc&lt;script&gt;') && !b.includes('<script>'));
  assert.ok(b.includes('$OCU') && !b.includes('$$OCU'));
  assert.ok(!b.includes('javascript:'), 'only https explorer links');
  assert.match(tokenBlock({ ca: '0xabc', explorer: 'https://basescan.org/token/0xabc' }), /href="https:\/\/basescan\.org\/token\/0xabc"/);
  const lp = tokenBlock({ ca: '0xabc', explorer: 'https://basescan.org/token/0xabc', launchpad: 'https://ponsfamily.com/launchpad/0xabc' });
  assert.match(lp, /<b>Launchpad<\/b><span><a href="https:\/\/ponsfamily\.com\/launchpad\/0xabc"[^>]*>ponsfamily\.com<\/a>/);
});

const official = JSON.parse(readFileSync(new URL('../src/web/token.json', import.meta.url), 'utf8')) as { ca: string };

test('README and token.json name the same address', () => {
  if (!official.ca) return;
  assert.ok(readFileSync(new URL('../README.md', import.meta.url), 'utf8').includes(official.ca));
});

test('/thetoken is served, in public mode too', async () => {
  const { server, stop } = createWebServer({ port: 0, publicMode: true, oculon: new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW }) });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    for (const p of ['/thetoken', '/thetoken/']) {
      const r = await fetch(base + p);
      assert.equal(r.status, 200, p);
      const html = await r.text();
      assert.match(html, /One address\.<br><span>Three places\./);
      assert.ok(!html.includes('{{TOKEN_BLOCK}}'));
      if (official.ca) assert.ok(html.includes(official.ca), 'page shows the address from token.json');
    }
  } finally {
    await stop();
  }
});
