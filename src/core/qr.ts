/**
 * QR code reader without dependencies: finds the three finder patterns in a grayscale image, locates the
 * alignment pattern, samples the module grid through a perspective transform, reads format information,
 * removes the mask, de-interleaves the blocks, corrects errors with Reed-Solomon and decodes numeric,
 * alphanumeric and byte segments (UTF-8). Supports versions 1 to 15 (up to about 400 characters), which covers
 * links, payment and wallet codes, Wi-Fi codes and contact cards in practice.
 */
import type { Gray } from './raster.js';

/* ---------- Galois field and Reed-Solomon (generator base 0, as QR uses) ---------- */

const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
}
const mul = (a: number, b: number) => (a && b ? EXP[LOG[a]! + LOG[b]!]! : 0);
const div = (a: number, b: number) => (a ? EXP[(LOG[a]! + 255 - LOG[b]!) % 255]! : 0);
const pow = (x: number, p: number) => EXP[(((LOG[x]! * p) % 255) + 255) % 255]!;
const inv = (x: number) => EXP[255 - LOG[x]!]!;
const pEval = (p: number[], x: number) => { let y = p[0]!; for (let i = 1; i < p.length; i++) y = mul(y, x) ^ p[i]!; return y; };
const pScale = (p: number[], x: number) => p.map((c) => mul(c, x));
const pAdd = (p: number[], q: number[]) => { const r = new Array(Math.max(p.length, q.length)).fill(0) as number[]; p.forEach((c, i) => { r[i + r.length - p.length] = c; }); q.forEach((c, i) => { r[i + r.length - q.length]! ^= c; }); return r; };
const pMul = (p: number[], q: number[]) => { const r = new Array(p.length + q.length - 1).fill(0) as number[]; for (let j = 0; j < q.length; j++) for (let i = 0; i < p.length; i++) r[i + j]! ^= mul(p[i]!, q[j]!); return r; };
function pDivRem(a: number[], d: number[]): number[] {
  const out = [...a];
  for (let i = 0; i < a.length - (d.length - 1); i++) { const c = out[i]!; if (c) for (let j = 1; j < d.length; j++) if (d[j]) out[i + j]! ^= mul(d[j]!, c); }
  return out.slice(-(d.length - 1));
}

/** Corrects a block in place (data then EC codewords). Returns false when there are too many errors. */
export function rsCorrect(msg: number[], nsym: number): boolean {
  const synd = [0, ...Array.from({ length: nsym }, (_, i) => pEval(msg, pow(2, i)))];
  if (synd.every((s) => s === 0)) return true;
  // Berlekamp-Massey.
  let loc = [1], old = [1];
  for (let i = 0; i < nsym; i++) {
    const K = i + 1;
    let delta = synd[K]!;
    for (let j = 1; j < loc.length; j++) delta ^= mul(loc[loc.length - 1 - j]!, synd[K - j]!);
    old = [...old, 0];
    if (delta) {
      if (old.length > loc.length) { const nl = pScale(old, delta); old = pScale(loc, inv(delta)); loc = nl; }
      loc = pAdd(loc, pScale(old, delta));
    }
  }
  while (loc.length && loc[0] === 0) loc.shift();
  const errs = loc.length - 1;
  if (errs * 2 > nsym) return false;
  // Chien search.
  const rev = [...loc].reverse();
  const pos: number[] = [];
  for (let i = 0; i < msg.length; i++) if (pEval(rev, pow(2, i)) === 0) pos.push(msg.length - 1 - i);
  if (pos.length !== errs) return false;
  // Forney.
  const coef = pos.map((p) => msg.length - 1 - p);
  let eLoc = [1];
  for (const c of coef) eLoc = pMul(eLoc, pAdd([1], [pow(2, c), 0]));
  const sr = [...synd].reverse();
  const eEval = pDivRem(pMul(sr, eLoc), [1, ...new Array(eLoc.length).fill(0)]).reverse();
  const X = coef.map((c) => pow(2, c));
  for (let i = 0; i < X.length; i++) {
    const xi = inv(X[i]!);
    let prime = 1;
    for (let j = 0; j < X.length; j++) if (j !== i) prime = mul(prime, 1 ^ mul(xi, X[j]!));
    if (!prime) return false;
    const y = mul(X[i]!, pEval([...eEval].reverse(), xi));
    msg[pos[i]!]! ^= div(y, prime);
  }
  return Array.from({ length: nsym }, (_, i) => pEval(msg, pow(2, i))).every((s) => s === 0);
}

/* ---------- version tables (1-15) ---------- */

type Ec = [number, [number, number][]];
/** Per version: EC codewords per block and (block count, data codewords) groups, for L, M, Q, H. */
export const EC: Record<number, [Ec, Ec, Ec, Ec]> = {
  1: [[7, [[1, 19]]], [10, [[1, 16]]], [13, [[1, 13]]], [17, [[1, 9]]]],
  2: [[10, [[1, 34]]], [16, [[1, 28]]], [22, [[1, 22]]], [28, [[1, 16]]]],
  3: [[15, [[1, 55]]], [26, [[1, 44]]], [18, [[2, 17]]], [22, [[2, 13]]]],
  4: [[20, [[1, 80]]], [18, [[2, 32]]], [26, [[2, 24]]], [16, [[4, 9]]]],
  5: [[26, [[1, 108]]], [24, [[2, 43]]], [18, [[2, 15], [2, 16]]], [22, [[2, 11], [2, 12]]]],
  6: [[18, [[2, 68]]], [16, [[4, 27]]], [24, [[4, 19]]], [28, [[4, 15]]]],
  7: [[20, [[2, 78]]], [18, [[4, 31]]], [18, [[2, 14], [4, 15]]], [26, [[4, 13], [1, 14]]]],
  8: [[24, [[2, 97]]], [22, [[2, 38], [2, 39]]], [22, [[4, 18], [2, 19]]], [26, [[4, 14], [2, 15]]]],
  9: [[30, [[2, 116]]], [22, [[3, 36], [2, 37]]], [20, [[4, 16], [4, 17]]], [24, [[4, 12], [4, 13]]]],
  10: [[18, [[2, 68], [2, 69]]], [26, [[4, 43], [1, 44]]], [24, [[6, 19], [2, 20]]], [28, [[6, 15], [2, 16]]]],
  11: [[20, [[4, 81]]], [30, [[1, 50], [4, 51]]], [28, [[4, 22], [4, 23]]], [24, [[3, 12], [8, 13]]]],
  12: [[24, [[2, 92], [2, 93]]], [22, [[6, 36], [2, 37]]], [26, [[4, 20], [6, 21]]], [28, [[7, 14], [4, 15]]]],
  13: [[26, [[4, 107]]], [22, [[8, 37], [1, 38]]], [24, [[8, 20], [4, 21]]], [22, [[12, 11], [4, 12]]]],
  14: [[30, [[3, 115], [1, 116]]], [24, [[4, 40], [5, 41]]], [20, [[11, 16], [5, 17]]], [24, [[11, 12], [5, 13]]]],
  15: [[22, [[5, 87], [1, 88]]], [24, [[5, 41], [5, 42]]], [30, [[5, 24], [7, 25]]], [24, [[11, 12], [7, 13]]]],
};
export const ALIGN: Record<number, number[]> = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50], 11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66], 15: [6, 26, 48, 70] };

/** Modules that hold function patterns (not data) for a version. */
export function functionMask(version: number): Uint8Array {
  const n = 17 + 4 * version, f = new Uint8Array(n * n);
  const set = (x: number, y: number, w: number, h: number) => { for (let j = y; j < y + h; j++) for (let i = x; i < x + w; i++) if (i >= 0 && j >= 0 && i < n && j < n) f[j * n + i] = 1; };
  set(0, 0, 9, 9); set(n - 8, 0, 8, 9); set(0, n - 8, 9, 8);
  set(6, 0, 1, n); set(0, 6, n, 1);
  const a = ALIGN[version]!;
  for (const ay of a) for (const ax of a) {
    if ((ax === 6 && ay === 6) || (ax === 6 && ay === a[a.length - 1]) || (ay === 6 && ax === a[a.length - 1])) continue;
    set(ax - 2, ay - 2, 5, 5);
  }
  if (version >= 7) { set(n - 11, 0, 3, 6); set(0, n - 11, 6, 3); }
  return f;
}

const FORMAT: number[] = (() => {
  const out: number[] = [];
  for (let d = 0; d < 32; d++) {
    let r = d << 10;
    for (let i = 14; i >= 10; i--) if (r & (1 << i)) r ^= 0x537 << (i - 10);
    out.push(((d << 10) | r) ^ 0x5412);
  }
  return out;
})();

const MASKS: ((i: number, j: number) => boolean)[] = [
  (i, j) => (i + j) % 2 === 0, (i) => i % 2 === 0, (_i, j) => j % 3 === 0, (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0, (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0, (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
];

/** Decodes a sampled module grid (1 = dark), row-major. */
export function decodeGrid(grid: Uint8Array, n: number): string | null {
  const version = (n - 17) / 4;
  if (!EC[version]) return null;
  const g = (x: number, y: number) => grid[y * n + x]!;
  let a = 0, b = 0;
  for (let i = 0; i <= 5; i++) a = (a << 1) | g(i, 8);
  a = (a << 1) | g(7, 8); a = (a << 1) | g(8, 8); a = (a << 1) | g(8, 7);
  for (let j = 5; j >= 0; j--) a = (a << 1) | g(8, j);
  for (let j = n - 1; j >= n - 7; j--) b = (b << 1) | g(8, j);
  for (let i = n - 8; i < n; i++) b = (b << 1) | g(i, 8);
  let best = -1, bestD = 99;
  for (let d = 0; d < 32; d++) for (const v of [a, b]) {
    let x = v ^ FORMAT[d]!, c = 0;
    while (x) { c += x & 1; x >>= 1; }
    if (c < bestD) { bestD = c; best = d; }
  }
  if (bestD > 3) return null;
  const ecl = [1, 0, 3, 2][best >> 3]!; // bits: 01 L, 00 M, 11 Q, 10 H -> index L0 M1 Q2 H3
  const mask = MASKS[best & 7]!;
  const fm = functionMask(version);
  // Read codewords in the zigzag order.
  const bits: number[] = [];
  let up = true;
  for (let x = n - 1; x > 0; x -= 2) {
    if (x === 6) x--;
    for (let k = 0; k < n; k++) {
      const y = up ? n - 1 - k : k;
      for (const xx of [x, x - 1]) {
        if (fm[y * n + xx]) continue;
        bits.push(g(xx, y) ^ (mask(y, xx) ? 1 : 0));
      }
    }
    up = !up;
  }
  const words: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) words.push(bits.slice(i, i + 8).reduce((s, v) => (s << 1) | v, 0));
  const [ecPer, groups] = EC[version]![ecl]!;
  const blocks: { data: number; words: number[] }[] = [];
  for (const [count, data] of groups) for (let k = 0; k < count; k++) blocks.push({ data, words: [] });
  const maxData = Math.max(...blocks.map((x) => x.data));
  let p = 0;
  for (let i = 0; i < maxData; i++) for (const bl of blocks) if (i < bl.data) bl.words.push(words[p++] ?? 0);
  for (let i = 0; i < ecPer; i++) for (const bl of blocks) bl.words.push(words[p++] ?? 0);
  const data: number[] = [];
  for (const bl of blocks) {
    if (!rsCorrect(bl.words, ecPer)) return null;
    data.push(...bl.words.slice(0, bl.data));
  }
  return segments(data, version);
}

const ALNUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
function segments(data: number[], version: number): string | null {
  let bit = 0;
  const read = (n: number) => { let v = 0; for (let k = 0; k < n; k++) { const byte = data[(bit >> 3)] ?? 0; v = (v << 1) | ((byte >> (7 - (bit & 7))) & 1); bit++; } return v; };
  const total = data.length * 8;
  const big = version >= 10;
  let out = '';
  const bytes: number[] = [];
  const flush = () => { if (bytes.length) { const buf = Buffer.from(bytes); const u = buf.toString('utf8'); out += u.includes('�') ? buf.toString('latin1') : u; bytes.length = 0; } };
  while (bit + 4 <= total) {
    const mode = read(4);
    if (mode === 0) break;
    if (mode === 1) { flush(); let c = read(big ? 12 : 10); while (c >= 3) { out += String(read(10)).padStart(3, '0'); c -= 3; } if (c === 2) out += String(read(7)).padStart(2, '0'); else if (c === 1) out += String(read(4)); }
    else if (mode === 2) { flush(); let c = read(big ? 11 : 9); while (c >= 2) { const v = read(11); out += ALNUM[Math.floor(v / 45)]! + ALNUM[v % 45]!; c -= 2; } if (c) out += ALNUM[read(6)]!; }
    else if (mode === 4) { const c = read(big ? 16 : 8); for (let k = 0; k < c; k++) bytes.push(read(8)); }
    else if (mode === 7) { const f = read(8); if (f & 0x80) read((f & 0x40) ? 16 : 8); }
    else if (mode === 8) { flush(); const c = read(big ? 10 : 8); bit += c * 13; out += '?'.repeat(c); }
    else if (mode === 3) read(16);
    else if (mode === 5) { /* FNC1, first position: no data */ }
    else if (mode === 9) read(8);
    else return out || null;
    if (bit > total) break;
  }
  flush();
  return out;
}

/* ---------- locating the code in an image ---------- */

interface Pt { x: number; y: number }
interface Finder extends Pt { size: number; count: number }

/** Dark/light per pixel: local mean thresholding over an integral image. */
export function binarize(img: Gray, invert = false): Uint8Array {
  const { width: w, height: h, data } = img;
  const integ = new Float64Array((w + 1) * (h + 1));
  for (let y = 0; y < h; y++) { let row = 0; for (let x = 0; x < w; x++) { row += data[y * w + x]!; integ[(y + 1) * (w + 1) + x + 1] = integ[y * (w + 1) + x + 1]! + row; } }
  const r = Math.max(8, Math.round(Math.min(w, h) / 16));
  const out = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) {
    const y0 = Math.max(0, y - r), y1 = Math.min(h, y + r + 1);
    for (let x = 0; x < w; x++) {
      const x0 = Math.max(0, x - r), x1 = Math.min(w, x + r + 1);
      const sum = integ[y1 * (w + 1) + x1]! - integ[y0 * (w + 1) + x1]! - integ[y1 * (w + 1) + x0]! + integ[y0 * (w + 1) + x0]!;
      const mean = sum / ((x1 - x0) * (y1 - y0));
      const v = data[y * w + x]!;
      const dark = v < mean - 4 || (v < 60 && mean < 70);
      out[y * w + x] = (dark ? 1 : 0) ^ (invert ? 1 : 0);
    }
  }
  return out;
}

const ratioOk = (s: number[]) => {
  const t = s.reduce((a, b) => a + b, 0);
  if (t < 7) return false;
  const m = t / 7, v = m / 1.6;
  return Math.abs(m - s[0]!) < v && Math.abs(m - s[1]!) < v && Math.abs(3 * m - s[2]!) < 3 * v && Math.abs(m - s[3]!) < v && Math.abs(m - s[4]!) < v;
};

function crossCheck(bin: Uint8Array, w: number, h: number, cx: number, cy: number, vertical: boolean, maxCount: number): number | null {
  const at = (k: number) => (vertical ? (k >= 0 && k < h ? bin[k * w + cx]! : -1) : (k >= 0 && k < w ? bin[cy * w + k]! : -1));
  const c = vertical ? cy : cx;
  const s = [0, 0, 0, 0, 0];
  let k = c;
  while (at(k) === 1) { s[2]!++; k--; }
  if (at(k) === -1) return null;
  while (at(k) === 0 && s[1]! <= maxCount) { s[1]!++; k--; }
  if (at(k) === -1 || s[1]! > maxCount) return null;
  while (at(k) === 1 && s[0]! <= maxCount) { s[0]!++; k--; }
  if (s[0]! > maxCount) return null;
  k = c + 1;
  while (at(k) === 1) { s[2]!++; k++; }
  if (at(k) === -1) return null;
  while (at(k) === 0 && s[3]! < maxCount) { s[3]!++; k++; }
  if (at(k) === -1 || s[3]! >= maxCount) return null;
  while (at(k) === 1 && s[4]! < maxCount) { s[4]!++; k++; }
  if (s[4]! >= maxCount || !ratioOk(s)) return null;
  return k - s[4]! - s[3]! - s[2]! / 2;
}

function findFinders(bin: Uint8Array, w: number, h: number): Finder[] {
  const found: Finder[] = [];
  const step = Math.max(1, Math.floor(h / 400));
  for (let y = 0; y < h; y += step) {
    const s = [0, 0, 0, 0, 0];
    let state = 0;
    for (let x = 0; x <= w; x++) {
      const v = x < w ? bin[y * w + x]! : 0;
      if (v === 1) { if (state & 1) state++; s[state]!++; }
      else {
        if (!(state & 1)) { if (state === 4) {
          if (ratioOk(s)) {
            const total = s.reduce((a, b) => a + b, 0);
            const cx = Math.floor(x - s[4]! - s[3]! - s[2]! / 2);
            const cy = crossCheck(bin, w, h, cx, y, true, s[2]!);
            if (cy !== null) {
              const cx2 = crossCheck(bin, w, h, cx, Math.floor(cy), false, s[2]!);
              if (cx2 !== null) {
                const size = total / 7;
                const near = found.find((f) => Math.abs(f.x - cx2) <= size * 2 && Math.abs(f.y - cy) <= size * 2 && Math.abs(f.size - size) <= Math.max(1, f.size * 0.5));
                if (near) { near.x = (near.x * near.count + cx2) / (near.count + 1); near.y = (near.y * near.count + cy) / (near.count + 1); near.size = (near.size * near.count + size) / (near.count + 1); near.count++; }
                else found.push({ x: cx2, y: cy, size, count: 1 });
              }
            }
            s[0] = s[2]!; s[1] = s[3]!; s[2] = s[4]!; s[3] = 1; s[4] = 0; state = 3; continue;
          }
          s[0] = s[2]!; s[1] = s[3]!; s[2] = s[4]!; s[3] = 1; s[4] = 0; state = 3;
        } else { state++; s[state]!++; } }
        else s[state]!++;
      }
    }
  }
  return found;
}

const dist = (a: Pt, b: Pt) => Math.hypot(a.x - b.x, a.y - b.y);

/** Best three finders: similar size, arranged as a right isosceles triangle. Returned as TL, TR, BL. */
function pickThree(fs: Finder[]): [Finder, Finder, Finder][] {
  const c = fs.filter((f) => f.count >= 1).sort((a, b) => b.count - a.count).slice(0, 12);
  const out: { s: number; t: [Finder, Finder, Finder] }[] = [];
  for (let i = 0; i < c.length; i++) for (let j = i + 1; j < c.length; j++) for (let k = j + 1; k < c.length; k++) {
    const p = [c[i]!, c[j]!, c[k]!];
    const sizes = p.map((f) => f.size);
    if (Math.max(...sizes) > Math.min(...sizes) * 1.6) continue;
    const d = [[dist(p[0]!, p[1]!), 2], [dist(p[1]!, p[2]!), 0], [dist(p[0]!, p[2]!), 1]] as [number, number][];
    d.sort((a, b) => b[0] - a[0]);
    const tl = p[d[0]![1]]!;
    const others = p.filter((x) => x !== tl);
    const [a, b] = [dist(tl, others[0]!), dist(tl, others[1]!)];
    const hyp = d[0]![0];
    const err = Math.abs(a - b) / Math.max(a, b) + Math.abs(hyp - Math.hypot(a, b)) / hyp;
    if (err > 0.5 || Math.min(a, b) < tl.size * 6) continue;
    let tr = others[0]!, bl = others[1]!;
    const cross = (tr.x - tl.x) * (bl.y - tl.y) - (tr.y - tl.y) * (bl.x - tl.x);
    if (cross < 0) [tr, bl] = [bl, tr];
    out.push({ s: err - (tl.count + tr.count + bl.count) * 0.01, t: [tl, tr, bl] });
  }
  return out.sort((a, b) => a.s - b.s).slice(0, 3).map((x) => x.t);
}

/** Homography from four point pairs (solved directly), mapping grid coordinates to image pixels. */
function quadToQuad(from: Pt[], to: Pt[]): (x: number, y: number) => Pt {
  const A: number[][] = [];
  for (let i = 0; i < 4; i++) {
    const { x, y } = from[i]!, { x: u, y: v } = to[i]!;
    A.push([x, y, 1, 0, 0, 0, -u * x, -u * y, u]);
    A.push([0, 0, 0, x, y, 1, -v * x, -v * y, v]);
  }
  for (let c = 0; c < 8; c++) {
    let p = c;
    for (let r = c + 1; r < 8; r++) if (Math.abs(A[r]![c]!) > Math.abs(A[p]![c]!)) p = r;
    [A[c], A[p]] = [A[p]!, A[c]!];
    const d = A[c]![c]! || 1e-12;
    for (let k = c; k < 9; k++) A[c]![k]! /= d;
    for (let r = 0; r < 8; r++) if (r !== c) { const m = A[r]![c]!; if (m) for (let k = c; k < 9; k++) A[r]![k]! -= m * A[c]![k]!; }
  }
  const h = A.map((r) => r[8]!);
  return (x, y) => { const den = h[6]! * x + h[7]! * y + 1; return { x: (h[0]! * x + h[1]! * y + h[2]!) / den, y: (h[3]! * x + h[4]! * y + h[5]!) / den }; };
}

function findAlignment(bin: Uint8Array, w: number, h: number, est: Pt, module: number): Pt | null {
  const r = Math.round(module * 5);
  let best: Pt | null = null, bestScore = 0;
  const at = (x: number, y: number) => { const xi = Math.round(x), yi = Math.round(y); return xi >= 0 && yi >= 0 && xi < w && yi < h ? bin[yi * w + xi]! : 0; };
  for (let y = Math.round(est.y - r); y <= est.y + r; y++) for (let x = Math.round(est.x - r); x <= est.x + r; x++) {
    if (!at(x, y)) continue;
    let s = 0;
    for (let k = 0; k < 8; k++) {
      const a = (k * Math.PI) / 4, cx = Math.cos(a), cy = Math.sin(a);
      const sq = Math.max(Math.abs(cx), Math.abs(cy));
      if (!at(x + (cx / sq) * module, y + (cy / sq) * module)) s++;
      if (at(x + (cx / sq) * module * 2, y + (cy / sq) * module * 2)) s++;
    }
    const score = s - dist({ x, y }, est) / (module * 10);
    if (score > bestScore) { bestScore = score; best = { x, y }; }
  }
  return bestScore >= 14 ? best : null;
}

function sample(bin: Uint8Array, w: number, h: number, tl: Pt, tr: Pt, bl: Pt, br: Pt, n: number, brOffset: number): Uint8Array {
  const map = quadToQuad([{ x: 3.5, y: 3.5 }, { x: n - 3.5, y: 3.5 }, { x: n - brOffset, y: n - brOffset }, { x: 3.5, y: n - 3.5 }], [tl, tr, br, bl]);
  const grid = new Uint8Array(n * n);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
    const p = map(x + 0.5, y + 0.5);
    const xi = Math.round(p.x - 0.5), yi = Math.round(p.y - 0.5);
    grid[y * n + x] = xi >= 0 && yi >= 0 && xi < w && yi < h ? bin[yi * w + xi]! : 0;
  }
  return grid;
}

/** Finds and decodes QR codes in an image. Returns the decoded texts (usually one). */
export function readQr(img: Gray): string[] {
  const results = new Set<string>();
  for (const invert of [false, true]) {
    const bin = binarize(img, invert);
    const { width: w, height: h } = img;
    for (const [tl, tr, bl] of pickThree(findFinders(bin, w, h))) {
      // Finder sizes come from horizontal runs, which a rotated code stretches by 1/cos(angle).
      const ang = Math.atan2(tr.y - tl.y, tr.x - tl.x);
      const module = ((tl.size + tr.size + bl.size) / 3) * Math.max(Math.abs(Math.cos(ang)), Math.abs(Math.sin(ang)));
      const est = Math.round(((dist(tl, tr) + dist(tl, bl)) / 2) / module) + 7;
      for (const n of [...new Set([0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5, -6, 6].map((d) => est + d))].filter((d) => d >= 21 && (d - 17) % 4 === 0 && EC[(d - 17) / 4])) {
        const version = (n - 17) / 4;
        const brEst = { x: tr.x - tl.x + bl.x, y: tr.y - tl.y + bl.y };
        const tries: [Pt, number][] = [];
        if (version >= 2) {
          const k = 1 - 3 / (n - 7);
          const ae = { x: tl.x + k * (brEst.x - tl.x), y: tl.y + k * (brEst.y - tl.y) };
          const al = findAlignment(bin, w, h, ae, module);
          if (al) tries.push([al, 6.5]);
          tries.push([ae, 6.5]);
        }
        tries.push([brEst, 3.5]);
        for (const [br, off] of tries) {
          const text = decodeGrid(sample(bin, w, h, tl, tr, bl, br, n, off), n);
          if (text !== null) { results.add(text); break; }
        }
        if (results.size) break;
      }
      if (results.size) break;
    }
    if (results.size) break;
  }
  return [...results];
}
