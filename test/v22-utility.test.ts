import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { addressFromPrivateKey, keccak256, personalHash, recoverPersonalSigner, signHash, toHex } from '../src/core/evm.js';
import { Oculon } from '../src/index.js';
import { badgeSvg, createNonce, holderFor, setUtilityRpc, startInvestigation, targetKind, tokenConfig, utilityMessage, verifyBurn, verifyHolder, UTILITY } from '../src/modules/utility.js';
import { mockFetch, NOW } from './helpers.js';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const rnd = () => (BigInt('0x' + randomBytes(32).toString('hex')) % (N - 1n)) + 1n;
const personalSign = (msg: string, priv: bigint) => signHash(personalHash(msg), priv, rnd());

test('keccak256 and secp256k1: known vectors and signature round trips', () => {
  assert.equal(toHex(keccak256('')), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(toHex(keccak256('abc')), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  assert.equal(addressFromPrivateKey(1n), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf', 'private key 1 has a well-known address');
  for (let i = 0; i < 5; i++) {
    const priv = rnd();
    const msg = `hello ${i}`;
    assert.equal(recoverPersonalSigner(msg, personalSign(msg, priv)), addressFromPrivateKey(priv));
  }
  assert.equal(recoverPersonalSigner('x', '0x1234'), null);
});

const E18 = 10n ** 18n;
const pad = (a: string) => '0x' + a.slice(2).padStart(64, '0');
const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function chain(opts: { from: string; amount: bigint; time: number; balance?: bigint }) {
  const ca = tokenConfig()!.ca;
  return async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getTransactionReceipt') {
      if (params[0] === '0x' + 'f'.repeat(64)) return null as T;
      return { status: '0x1', from: opts.from, blockNumber: '0x10', logs: [{ address: ca, topics: [TRANSFER, pad(opts.from), pad('0x000000000000000000000000000000000000dead')], data: '0x' + (opts.amount * E18).toString(16) }] } as T;
    }
    if (method === 'eth_getBlockByNumber') return { timestamp: '0x' + Math.floor(opts.time / 1000).toString(16) } as T;
    if (method === 'eth_call') return ('0x' + ((opts.balance ?? 0n) * E18).toString(16)) as T;
    throw new Error(method);
  };
}

test('burns: amount, burn address, cutoff date, one use per burn, only the burner can spend it', async () => {
  if (!tokenConfig()) return;
  const priv = rnd(), from = addressFromPrivateKey(priv);
  const o = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => new Date('2026-12-01T00:00:00Z') });
  const tx = '0x' + 'a'.repeat(64);
  try {
    setUtilityRpc(chain({ from, amount: 1_000_000n, time: Date.parse('2026-11-30T00:00:00Z') }));
    await assert.rejects(verifyBurn(o.ctx, tx, UTILITY.investigate), /needs at least 1,500,000/);
    setUtilityRpc(chain({ from, amount: 2_000_000n, time: Date.parse('2026-11-20T00:00:00Z') }));
    await assert.rejects(verifyBurn(o.ctx, tx, UTILITY.investigate), /before the utility went live/);
    await assert.rejects(verifyBurn(o.ctx, '0x' + 'f'.repeat(64), 1n), /not found yet/);
    setUtilityRpc(chain({ from, amount: 1_600_000n, time: Date.parse('2026-11-30T00:00:00Z') }));
    const stranger = rnd();
    await assert.rejects(startInvestigation(o, tx, 'example.com', personalSign(utilityMessage('investigate', 'example.com', tx), stranger)), /not from the wallet that made this burn/);
    const ok = await startInvestigation(o, tx, 'example.com', personalSign(utilityMessage('investigate', 'example.com', tx), priv));
    assert.match(ok.id, /^[0-9a-f]{12}$/);
    assert.equal(ok.burn.amount, '1,600,000');
    await assert.rejects(startInvestigation(o, tx, 'example.com', personalSign(utilityMessage('investigate', 'example.com', tx), priv)), /already used/);
  } finally {
    setUtilityRpc(null);
    await new Promise((r) => setTimeout(r, 50));
  }
});

test('holder tier: signature over a fresh nonce, then the on-chain balance decides', async () => {
  if (!tokenConfig()) return;
  const priv = rnd(), addr = addressFromPrivateKey(priv);
  const o = new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  try {
    setUtilityRpc(chain({ from: addr, amount: 0n, time: 0, balance: 1_000_000n }));
    let n = createNonce('oculon.live', addr);
    const low = await verifyHolder(o.ctx, 'web:a', n.message, personalSign(n.message, priv));
    assert.equal(low.holder, false);
    assert.equal(low.balance, '1,000,000');
    await assert.rejects(verifyHolder(o.ctx, 'web:a', n.message, personalSign(n.message, priv)), /expired/, 'a nonce works once');
    setUtilityRpc(chain({ from: addr, amount: 0n, time: 0, balance: 4_000_000n }));
    n = createNonce('oculon.live', addr);
    await assert.rejects(verifyHolder(o.ctx, 'web:a', n.message, personalSign(n.message, rnd())), /does not match/);
    n = createNonce('oculon.live', addr);
    const hi = await verifyHolder(o.ctx, 'web:a', n.message, personalSign(n.message, priv));
    assert.equal(hi.holder, true);
    assert.equal(holderFor(o.ctx, 'web:a')?.address, addr);
    assert.equal(holderFor(o.ctx, 'web:b'), null);
  } finally { setUtilityRpc(null); }
});

test('targets and badges', () => {
  assert.equal(targetKind('0x12a3f1a05d827007f17a43a250cce44868c4a263'), 'evm');
  assert.equal(targetKind('example.com'), 'domain');
  assert.equal(targetKind('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'), 'crypto');
  assert.equal(targetKind('Acme Trading Ltd'), 'name');
  const svg = badgeSvg({ token: '0x1', active: true, expiresAt: null, verdict: 'DANGER', reasons: [], name: null, symbol: null, lastCheck: null, history: [] });
  assert.match(svg, /DANGER/);
  assert.match(svg, /#d23b4a/);
  assert.match(badgeSvg({ token: '0x1', active: false, expiresAt: null, verdict: null, reasons: [], name: null, symbol: null, lastCheck: null, history: [] }), /NOT MONITORED/);
});
