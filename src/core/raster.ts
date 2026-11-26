/**
 * Image decoding to a grayscale raster, without dependencies: PNG (all color types, bit depths 1-16,
 * no interlacing) and baseline JPEG (Huffman, any sampling; only the luminance channel is reconstructed,
 * which is all a QR reader needs). Progressive JPEG and interlaced PNG are rejected with a plain message.
 */
import { inflateSync } from 'node:zlib';

export interface Gray { width: number; height: number; data: Uint8Array }

const MAX_PIXELS = 25_000_000;

export function decodeGray(b: Buffer): Gray {
  if (b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return png(b);
  if (b[0] === 0xff && b[1] === 0xd8) return jpeg(b);
  throw new Error('not a PNG or JPEG image');
}

/* ---------- PNG ---------- */

function png(b: Buffer): Gray {
  let i = 8, w = 0, h = 0, depth = 8, ct = 0, interlace = 0;
  let palette: Buffer | null = null, trns: Buffer | null = null;
  const idat: Buffer[] = [];
  while (i + 12 <= b.length) {
    const len = b.readUInt32BE(i), t = b.toString('latin1', i + 4, i + 8), d = b.subarray(i + 8, i + 8 + len);
    if (t === 'IHDR') { w = d.readUInt32BE(0); h = d.readUInt32BE(4); depth = d[8]!; ct = d[9]!; interlace = d[12]!; }
    else if (t === 'PLTE') palette = d;
    else if (t === 'tRNS') trns = d;
    else if (t === 'IDAT') idat.push(d);
    else if (t === 'IEND') break;
    i += 12 + len;
  }
  if (!w || !h || w * h > MAX_PIXELS) throw new Error('the image is empty or too large');
  if (interlace) throw new Error('interlaced PNG is not supported; save it again without interlacing or take a screenshot');
  const ch = ({ 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 } as Record<number, number>)[ct];
  if (!ch) throw new Error('unsupported PNG color type');
  const raw = inflateSync(Buffer.concat(idat));
  const bpp = Math.max(1, (ch * depth) >> 3);
  const stride = Math.ceil((w * ch * depth) / 8);
  const cur = Buffer.alloc(stride), prev = Buffer.alloc(stride);
  const out = new Uint8Array(w * h);
  let p = 0;
  for (let y = 0; y < h; y++) {
    const f = raw[p++]!;
    raw.copy(cur, 0, p, p + stride); p += stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? cur[x - bpp]! : 0, up = prev[x]!, c = x >= bpp ? prev[x - bpp]! : 0;
      let v = cur[x]!;
      if (f === 1) v += a; else if (f === 2) v += up; else if (f === 3) v += (a + up) >> 1;
      else if (f === 4) { const pa = Math.abs(up - c), pb = Math.abs(a - c), pc = Math.abs(a + up - 2 * c); v += pa <= pb && pa <= pc ? a : pb <= pc ? up : c; }
      cur[x] = v & 255;
    }
    const sample = (k: number): number => {
      if (depth === 8) return cur[k]!;
      if (depth === 16) return cur[k * 2]!;
      const per = 8 / depth, byte = cur[Math.floor(k / per)]!, shift = 8 - depth * ((k % per) + 1);
      return (byte >> shift) & ((1 << depth) - 1);
    };
    const scale = depth < 8 && ct !== 3 ? 255 / ((1 << depth) - 1) : 1;
    for (let x = 0; x < w; x++) {
      let g: number, alpha = 255;
      if (ct === 0) g = sample(x) * scale;
      else if (ct === 2) { const r = sample(x * 3), gg = sample(x * 3 + 1), bl = sample(x * 3 + 2); g = 0.299 * r + 0.587 * gg + 0.114 * bl; }
      else if (ct === 3) { const k = sample(x) * 3; g = palette ? 0.299 * palette[k]! + 0.587 * palette[k + 1]! + 0.114 * palette[k + 2]! : 0; if (trns && sample(x) < trns.length) alpha = trns[sample(x)]!; }
      else if (ct === 4) { g = sample(x * 2); alpha = sample(x * 2 + 1); }
      else { const r = sample(x * 4), gg = sample(x * 4 + 1), bl = sample(x * 4 + 2); g = 0.299 * r + 0.587 * gg + 0.114 * bl; alpha = sample(x * 4 + 3); }
      // Transparent parts sit on white, as a viewer shows them.
      out[y * w + x] = Math.round((g * alpha + 255 * (255 - alpha)) / 255);
    }
    cur.copy(prev);
  }
  return { width: w, height: h, data: out };
}

/* ---------- baseline JPEG ---------- */

const ZZ = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63];
const COS: number[][] = Array.from({ length: 8 }, (_, x) => Array.from({ length: 8 }, (_, u) => (u === 0 ? Math.SQRT1_2 : 1) * Math.cos(((2 * x + 1) * u * Math.PI) / 16)));

interface Huff { lookup: Map<number, number>[] }
function buildHuff(counts: number[], syms: number[]): Huff {
  const lookup: Map<number, number>[] = Array.from({ length: 17 }, () => new Map());
  let code = 0, k = 0;
  for (let len = 1; len <= 16; len++) {
    for (let i = 0; i < counts[len - 1]!; i++) lookup[len]!.set(code++, syms[k++]!);
    code <<= 1;
  }
  return { lookup };
}

function idct(block: Float32Array, out: Uint8Array, ow: number, ox: number, oy: number, oh: number) {
  const tmp = new Float32Array(64);
  for (let y = 0; y < 8; y++) for (let u = 0; u < 8; u++) { let s = 0; for (let v = 0; v < 8; v++) s += COS[y]![v]! * block[v * 8 + u]!; tmp[y * 8 + u] = s; }
  for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) {
    let s = 0;
    for (let u = 0; u < 8; u++) s += COS[x]![u]! * tmp[y * 8 + u]!;
    const px = ox + x, py = oy + y;
    if (px < ow && py < oh) out[py * ow + px] = Math.max(0, Math.min(255, Math.round(s / 4 + 128)));
  }
}

function jpeg(b: Buffer): Gray {
  const qt: Int32Array[] = [];
  const dcT: Huff[] = [], acT: Huff[] = [];
  let w = 0, h = 0, restart = 0;
  let comps: { id: number; h: number; v: number; tq: number; td: number; ta: number; pred: number }[] = [];
  let i = 2;
  while (i < b.length) {
    if (b[i] !== 0xff) { i++; continue; }
    const m = b[i + 1]!;
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7) || m === 0xff) { i += m === 0xff ? 1 : 2; continue; }
    if (m === 0xd9) break;
    const len = b.readUInt16BE(i + 2), seg = b.subarray(i + 4, i + 2 + len);
    if (m === 0xdb) {
      let p = 0;
      while (p < seg.length) {
        const pq = seg[p]! >> 4, tq = seg[p]! & 15; p++;
        const t = new Int32Array(64);
        for (let k = 0; k < 64; k++) { t[ZZ[k]!] = pq ? seg.readUInt16BE(p + k * 2) : seg[p + k]!; }
        p += pq ? 128 : 64;
        qt[tq] = t;
      }
    } else if (m === 0xc4) {
      let p = 0;
      while (p < seg.length) {
        const tc = seg[p]! >> 4, th = seg[p]! & 15;
        const counts = [...seg.subarray(p + 1, p + 17)];
        const n = counts.reduce((s, x) => s + x, 0);
        const t = buildHuff(counts, [...seg.subarray(p + 17, p + 17 + n)]);
        if (tc === 0) dcT[th] = t; else acT[th] = t;
        p += 17 + n;
      }
    } else if (m === 0xc0 || m === 0xc1) {
      h = seg.readUInt16BE(1); w = seg.readUInt16BE(3);
      const n = seg[5]!;
      comps = Array.from({ length: n }, (_, k) => ({ id: seg[6 + k * 3]!, h: seg[7 + k * 3]! >> 4, v: seg[7 + k * 3]! & 15, tq: seg[8 + k * 3]!, td: 0, ta: 0, pred: 0 }));
    } else if (m === 0xc2 || m === 0xc3 || (m >= 0xc5 && m <= 0xcf && m !== 0xc8 && m !== 0xcc)) {
      throw new Error('progressive or lossless JPEG is not supported; take a screenshot (PNG) of the QR code instead');
    } else if (m === 0xdd) restart = seg.readUInt16BE(0);
    else if (m === 0xda) {
      if (!w || !h || w * h > MAX_PIXELS) throw new Error('the image is empty or too large');
      const ns = seg[0]!;
      const scan = Array.from({ length: ns }, (_, k) => { const c = comps.find((x) => x.id === seg[1 + k * 2])!; c.td = seg[2 + k * 2]! >> 4; c.ta = seg[2 + k * 2]! & 15; return c; });
      return scanData(b, i + 2 + len, w, h, comps, scan, qt, dcT, acT, restart);
    }
    i += 2 + len;
  }
  throw new Error('no image data in the JPEG');
}

function scanData(b: Buffer, start: number, w: number, h: number, comps: { id: number; h: number; v: number; tq: number; td: number; ta: number; pred: number }[], scan: typeof comps, qt: Int32Array[], dcT: Huff[], acT: Huff[], restart: number): Gray {
  const hmax = Math.max(...comps.map((c) => c.h)), vmax = Math.max(...comps.map((c) => c.v));
  const y0 = comps[0]!;
  // Luminance plane at its own resolution; scaled to full size at the end when subsampled.
  const lw = Math.ceil((w * y0.h) / hmax), lh = Math.ceil((h * y0.v) / vmax);
  const plane = new Uint8Array(lw * lh);
  let pos = start, bitBuf = 0, bitCnt = 0;
  const readBit = (): number => {
    if (bitCnt === 0) {
      let byte = b[pos++] ?? 0;
      if (byte === 0xff) { const nx = b[pos]; if (nx === 0) pos++; else if (nx !== undefined && nx >= 0xd0 && nx <= 0xd7) { /* marker: handled by restart */ } }
      bitBuf = byte; bitCnt = 8;
      if (byte === undefined) byte = 0;
    }
    bitCnt--;
    return (bitBuf >> bitCnt) & 1;
  };
  const receive = (n: number) => { let v = 0; for (let k = 0; k < n; k++) v = (v << 1) | readBit(); return v; };
  const extend = (v: number, n: number) => (n && v < 1 << (n - 1) ? v - (1 << n) + 1 : v);
  const decode = (t: Huff) => { let code = 0; for (let len = 1; len <= 16; len++) { code = (code << 1) | readBit(); const s = t.lookup[len]!.get(code); if (s !== undefined) return s; } throw new Error('bad Huffman code in JPEG'); };
  const block = new Float32Array(64);
  const mcuX = Math.ceil(w / (8 * hmax)), mcuY = Math.ceil(h / (8 * vmax));
  const single = scan.length === 1;
  const blocksX = single ? Math.ceil(lw / 8) : mcuX, blocksY = single ? Math.ceil(lh / 8) : mcuY;
  let mcus = 0;
  const doBlock = (c: (typeof comps)[number], bx: number, by: number) => {
    block.fill(0);
    const s = decode(dcT[c.td]!);
    c.pred += s ? extend(receive(s), s) : 0;
    const q = qt[c.tq]!;
    block[0] = c.pred * q[0]!;
    for (let k = 1; k < 64;) {
      const rs = decode(acT[c.ta]!), r = rs >> 4, sz = rs & 15;
      if (!sz) { if (r === 15) { k += 16; continue; } break; }
      k += r;
      if (k > 63) break;
      block[ZZ[k]!] = extend(receive(sz), sz) * q[ZZ[k]!]!;
      k++;
    }
    if (c === y0) idct(block, plane, lw, bx * 8, by * 8, lh);
  };
  for (let my = 0; my < blocksY; my++) for (let mx = 0; mx < blocksX; mx++) {
    if (restart && mcus && mcus % restart === 0) {
      bitCnt = 0;
      while (pos < b.length && !(b[pos] === 0xff && b[pos + 1]! >= 0xd0 && b[pos + 1]! <= 0xd7)) pos++;
      pos += 2;
      for (const c of comps) c.pred = 0;
    }
    if (single) doBlock(scan[0]!, mx, my);
    else for (const c of scan) for (let v = 0; v < c.v; v++) for (let u = 0; u < c.h; u++) doBlock(c, mx * c.h + u, my * c.v + v);
    mcus++;
  }
  if (lw === w && lh === h) return { width: w, height: h, data: plane };
  const out = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) out[y * w + x] = plane[Math.min(lh - 1, Math.floor((y * lh) / h)) * lw + Math.min(lw - 1, Math.floor((x * lw) / w))]!;
  return { width: w, height: h, data: out };
}
