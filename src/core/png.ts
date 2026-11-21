import { inflateSync } from 'node:zlib';

export interface Image {
  width: number;
  height: number;
  /** RGBA, 4 bytes per pixel. */
  rgba: Uint8Array;
}

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CHANNELS: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/** Minimal PNG decoder: 8-bit, non-interlaced, all color types. Enough for map tiles and WMS images. */
export function decodePng(buf: Buffer): Image {
  if (!buf.subarray(0, 8).equals(SIG)) throw new Error('png: bad signature');
  let pos = 8;
  let width = 0;
  let height = 0;
  let depth = 0;
  let colorType = 0;
  let interlace = 0;
  let palette: Buffer | null = null;
  let trns: Buffer | null = null;
  const idat: Buffer[] = [];
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString('latin1', pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + len);
    pos += 12 + len;
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      depth = data[8]!;
      colorType = data[9]!;
      interlace = data[12]!;
    } else if (type === 'PLTE') palette = data;
    else if (type === 'tRNS') trns = data;
    else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
  }
  if (depth !== 8 || interlace !== 0) throw new Error(`png: unsupported depth ${depth} / interlace ${interlace}`);
  const ch = CHANNELS[colorType];
  if (!ch) throw new Error(`png: unsupported color type ${colorType}`);

  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * ch;
  const px = new Uint8Array(height * stride);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)]!;
    const src = y * (stride + 1) + 1;
    const dst = y * stride;
    for (let x = 0; x < stride; x++) {
      const v = raw[src + x]!;
      const a = x >= ch ? px[dst + x - ch]! : 0;
      const b = y > 0 ? px[dst - stride + x]! : 0;
      const c = x >= ch && y > 0 ? px[dst - stride + x - ch]! : 0;
      px[dst + x] =
        (filter === 0 ? v : filter === 1 ? v + a : filter === 2 ? v + b : filter === 3 ? v + ((a + b) >> 1) : v + paeth(a, b, c)) & 0xff;
    }
  }

  const rgba = new Uint8Array(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    const o = i * 4;
    const s = i * ch;
    if (colorType === 6) rgba.set(px.subarray(s, s + 4), o);
    else if (colorType === 2) rgba.set([px[s]!, px[s + 1]!, px[s + 2]!, 255], o);
    else if (colorType === 0) rgba.set([px[s]!, px[s]!, px[s]!, 255], o);
    else if (colorType === 4) rgba.set([px[s]!, px[s]!, px[s]!, px[s + 1]!], o);
    else {
      const idx = px[s]!;
      rgba.set([palette?.[idx * 3] ?? 0, palette?.[idx * 3 + 1] ?? 0, palette?.[idx * 3 + 2] ?? 0, trns && idx < trns.length ? trns[idx]! : 255], o);
    }
  }
  return { width, height, rgba };
}

export interface Brightness {
  /** Mean luminance (0-255) over pixels that have data. */
  mean: number;
  /** Share of pixels with data (alpha > 0). */
  coverage: number;
  /** Share of pixels brighter than 64, a rough "lit area" measure. */
  litShare: number;
}

export function brightness(img: Image): Brightness {
  let sum = 0;
  let n = 0;
  let lit = 0;
  const total = img.width * img.height;
  for (let i = 0; i < total; i++) {
    const o = i * 4;
    if (img.rgba[o + 3] === 0) continue;
    const l = 0.2126 * img.rgba[o]! + 0.7152 * img.rgba[o + 1]! + 0.0722 * img.rgba[o + 2]!;
    sum += l;
    n++;
    if (l > 64) lit++;
  }
  return { mean: n ? sum / n : 0, coverage: total ? n / total : 0, litShare: n ? lit / n : 0 };
}
