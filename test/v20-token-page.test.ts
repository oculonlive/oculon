import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { burnBlock, createWebServer, tokenBlock, tokenFooter } from '../src/web/server.js';
import { readBurns } from '../src/web/burns.js';
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

test('home page footer names the official contract', () => {
  assert.equal(tokenFooter({}), '');
  assert.equal(tokenFooter({ ca: '0xabc<script>' }), '');
  if (!official.ca) return;
  const f = tokenFooter(official);
  assert.ok(f.includes(official.ca) && f.includes('href="/thetoken"'));
  assert.ok(readFileSync(new URL('../src/web/landing.html', import.meta.url), 'utf8').includes('{{TOKEN_CA}}'));
});

test('burns: read from transfer logs, newest first, total from the dead balance plus zero-address burns', async () => {
  const E18 = 10n ** 18n;
  const hex = (n: bigint) => `0x${n.toString(16)}`;
  const rpc = async <T>(method: string, params: unknown[]): Promise<T> => {
    const p = params as [{ data?: string; topics?: string[] }, ...unknown[]];
    if (method === 'eth_call') {
      const d = p[0].data!;
      return (d === '0x313ce567' ? hex(18n) : d === '0x18160ddd' ? hex(999_000_000n * E18) : hex(10_000_000n * E18)) as T;
    }
    if (method === 'eth_getLogs') {
      const toZero = p[0].topics![2]!.endsWith('0'.repeat(40));
      return (toZero
        ? [{ transactionHash: '0xzz', blockNumber: '0x10', data: hex(1_000_000n * E18), logIndex: '0x0' }]
        : [{ transactionHash: '0xaa', blockNumber: '0x5', data: hex(4_000_000n * E18), logIndex: '0x0' }, { transactionHash: '0xbb', blockNumber: '0x20', data: hex(6_000_000n * E18 + 5n * 10n ** 16n), logIndex: '0x1' }]) as T;
    }
    if (method === 'eth_getBlockByNumber') return { timestamp: hex(1_800_000_000n + BigInt(params[0] as string)) } as T;
    throw new Error(method);
  };
  const b = await readBurns(rpc, '0x12a3f1a05d827007f17a43a250cce44868c4a263', 1);
  assert.deepEqual(b.burns.map((x) => x.tx), ['0xbb', '0xzz', '0xaa']);
  assert.equal(b.burns[0]!.amount, '6,000,000.05');
  assert.equal(b.total, '11,000,000');
  assert.equal(b.percent, '1.10%');
  assert.equal(b.supply, '989000000', 'launch supply minus everything burned, plain number');
  const html = burnBlock(b, { txBase: 'https://robin.etherscan.io' });
  assert.match(html, /href="https:\/\/robin\.etherscan\.io\/tx\/0xbb"/);
  assert.match(html, /11,000,000<\/span><em>1\.10% of supply/);
  assert.equal(burnBlock(null, {}), '');
});

test('/thetoken is served, in public mode too', async () => {
  const { server, stop } = createWebServer({ port: 0, publicMode: true, burnRpcUrl: '', oculon: new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW }) });
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

test('token page: trade and chart links, DEX cell after migration, details from token.json', async () => {
  const { tokenDetails } = await import('../src/web/server.js');
  const t = { ca: '0xabc', chain: 'Robinhood Chain', ticker: 'OCULON', launchpad: 'https://ponsfamily.com/launchpad/0xabc', uniswap: 'https://app.uniswap.org/explore/tokens/robinhood/0xabc', dexscreener: 'javascript:alert(1)', pool: { dex: 'Uniswap v4', pair: 'OCULON / ETH', id: '0x' + 'a'.repeat(64), url: 'https://app.uniswap.org/explore/pools/robinhood/0xaa' }, supply: '1,000,000,000', launched: '2026-11-25T14:38:27Z', migrated: '2026-11-25T21:22:31Z', deployBlock: 123115234 };
  const b = tokenBlock(t);
  assert.match(b, /<b>DEX<\/b><span>Uniswap v4<\/span>/);
  assert.match(b, /<a href="https:\/\/app\.uniswap\.org\/explore\/tokens\/robinhood\/0xabc"[^>]*><b>Trade<\/b><span>Uniswap<\/span>/);
  assert.match(b, /<b>Launchpad<\/b><span>Pons<\/span>/);
  assert.doesNotMatch(b, /javascript:/, 'non-https links are dropped');
  const d = tokenDetails(t);
  assert.match(d, /1,000,000,000 OCULON/);
  assert.match(d, /2026-11-25 21:22 UTC: the bonding curve completed and trading moved to Uniswap v4/);
  assert.match(d, /block 123,115,234/);
  assert.equal(tokenDetails({}), '');
});
