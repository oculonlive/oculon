/**
 * Minimal EVM cryptography with no dependencies: keccak256 and secp256k1 public-key recovery, enough to
 * check an Ethereum "personal_sign" signature (Sign-In with Ethereum) and turn it into the signer's address.
 * Plain BigInt arithmetic: slow next to native code, but a sign-in needs one recovery.
 */

const M64 = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// Rotation offsets r[x][y] of the Keccak specification.
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
const rotl = (v: bigint, n: number) => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & M64);

function keccakF(A: bigint[]): void {
  const C = new Array<bigint>(5), B = new Array<bigint>(25);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) C[x] = A[x]! ^ A[x + 5]! ^ A[x + 10]! ^ A[x + 15]! ^ A[x + 20]!;
    for (let x = 0; x < 5; x++) {
      const d = C[(x + 4) % 5]! ^ rotl(C[(x + 1) % 5]!, 1);
      for (let y = 0; y < 25; y += 5) A[x + y] = A[x + y]! ^ d;
    }
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y]!, ROT[x]![y]!);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 25; y += 5) A[x + y] = (B[x + y]! ^ (~B[((x + 1) % 5) + y]! & M64 & B[((x + 2) % 5) + y]!)) & M64;
    A[0] = A[0]! ^ RC[round]!;
  }
}

/** Keccak-256 as used by Ethereum (original Keccak padding, not NIST SHA3-256). */
export function keccak256(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] = padded[bytes.length]! ^ 0x01;
  padded[padded.length - 1] = padded[padded.length - 1]! ^ 0x80;
  const A = new Array<bigint>(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]!);
      A[i] = A[i]! ^ lane;
    }
    keccakF(A);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let b = 0; b < 8; b++) out[i * 8 + b] = Number((A[i]! >> BigInt(8 * b)) & 0xffn);
  return out;
}

export const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
export const fromHex = (h: string) => { const s = h.replace(/^0x/, ''); if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error('not hex'); return Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16)); };

// secp256k1
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
type Pt = [bigint, bigint] | null;

const mod = (a: bigint, m: bigint) => { const r = a % m; return r < 0n ? r + m : r; };
function pow(b: bigint, e: bigint, m: bigint): bigint { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
const inv = (a: bigint, m: bigint) => pow(a, m - 2n, m);

function add(p: Pt, q: Pt): Pt {
  if (!p) return q; if (!q) return p;
  if (p[0] === q[0] && mod(p[1] + q[1], P) === 0n) return null;
  const l = p[0] === q[0] && p[1] === q[1] ? mod(3n * p[0] * p[0] * inv(2n * p[1], P), P) : mod((q[1] - p[1]) * inv(mod(q[0] - p[0], P), P), P);
  const x = mod(l * l - p[0] - q[0], P);
  return [x, mod(l * (p[0] - x) - p[1], P)];
}
function mul(p: Pt, k: bigint): Pt { let r: Pt = null, q = p; k = mod(k, N); while (k > 0n) { if (k & 1n) r = add(r, q); q = add(q, q); k >>= 1n; } return r; }

/** Recover the uncompressed public key (64 bytes, x||y) from a message hash and an (r, s, recovery id) signature. */
export function recoverPublicKey(hash: Uint8Array, r: bigint, s: bigint, recId: number): Uint8Array | null {
  if (r <= 0n || r >= N || s <= 0n || s >= N || recId < 0 || recId > 3) return null;
  const x = recId >= 2 ? r + N : r;
  if (x >= P) return null;
  const y2 = mod(x * x * x + 7n, P);
  let y = pow(y2, (P + 1n) / 4n, P);
  if (mod(y * y, P) !== y2) return null;
  if ((y & 1n) !== BigInt(recId & 1)) y = P - y;
  const e = BigInt('0x' + toHex(hash)) % N;
  const rInv = inv(r, N);
  const Q = add(mul([x, y], mod(s * rInv, N)), mul([GX, GY], mod(-e * rInv, N)));
  if (!Q) return null;
  const out = new Uint8Array(64);
  out.set(fromHex(Q[0].toString(16).padStart(64, '0')), 0);
  out.set(fromHex(Q[1].toString(16).padStart(64, '0')), 32);
  return out;
}

export const addressOf = (pub64: Uint8Array) => '0x' + toHex(keccak256(pub64).slice(12));

/** The address of a private key (used by tests to build signatures). */
export function addressFromPrivateKey(priv: bigint): string {
  const Q = mul([GX, GY], priv)!;
  const pub = new Uint8Array(64);
  pub.set(fromHex(Q[0].toString(16).padStart(64, '0')), 0);
  pub.set(fromHex(Q[1].toString(16).padStart(64, '0')), 32);
  return addressOf(pub);
}

/** A 65-byte Ethereum signature (r, s, v) over a 32-byte hash, low-s. `k` must be a fresh random nonce. Tests use it; Oculon never holds keys. */
export function signHash(hash: Uint8Array, priv: bigint, k: bigint): string {
  const R = mul([GX, GY], k)!;
  const r = mod(R[0], N);
  const e = BigInt('0x' + toHex(hash)) % N;
  let s = mod(inv(k, N) * (e + r * priv), N);
  let recId = Number(R[1] & 1n) | (R[0] >= N ? 2 : 0);
  if (s > N / 2n) { s = N - s; recId ^= 1; }
  return '0x' + r.toString(16).padStart(64, '0') + s.toString(16).padStart(64, '0') + (27 + recId).toString(16).padStart(2, '0');
}

/** The hash Ethereum wallets sign for personal_sign: keccak256("\x19Ethereum Signed Message:\n" + length + message). */
export function personalHash(message: string): Uint8Array {
  const msg = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msg.length}`);
  const all = new Uint8Array(prefix.length + msg.length); all.set(prefix); all.set(msg, prefix.length);
  return keccak256(all);
}

/** The lower-case address that signed a personal_sign message, or null if the signature is malformed. */
export function recoverPersonalSigner(message: string, signature: string): string | null {
  let sig: Uint8Array;
  try { sig = fromHex(signature); } catch { return null; }
  if (sig.length !== 65) return null;
  const r = BigInt('0x' + toHex(sig.slice(0, 32))), s = BigInt('0x' + toHex(sig.slice(32, 64)));
  let v = sig[64]!; if (v >= 27) v -= 27;
  if (s > N / 2n) return null; // wallets produce low-s signatures; reject malleated ones
  const pub = recoverPublicKey(personalHash(message), r, s, v);
  return pub ? addressOf(pub) : null;
}
