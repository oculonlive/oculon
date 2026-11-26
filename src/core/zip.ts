/**
 * Minimal ZIP reader (central directory, stored and deflated entries) for Office files, which are ZIP packages.
 * Entries are read lazily; sizes are capped so a zip bomb cannot exhaust memory.
 */
import { inflateRawSync } from 'node:zlib';

export interface ZipEntry { name: string; method: number; size: number; csize: number; offset: number }

const MAX_ENTRY = 40 * 1024 * 1024;

export function zipEntries(b: Buffer): ZipEntry[] {
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 66_000); i--) if (b.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('not a valid ZIP package');
  const n = b.readUInt16LE(eocd + 10);
  let p = b.readUInt32LE(eocd + 16);
  const out: ZipEntry[] = [];
  for (let k = 0; k < n && p + 46 <= b.length; k++) {
    if (b.readUInt32LE(p) !== 0x02014b50) break;
    const method = b.readUInt16LE(p + 10), csize = b.readUInt32LE(p + 20), size = b.readUInt32LE(p + 24);
    const nl = b.readUInt16LE(p + 28), el = b.readUInt16LE(p + 30), cl = b.readUInt16LE(p + 32);
    const offset = b.readUInt32LE(p + 42);
    out.push({ name: b.toString('utf8', p + 46, p + 46 + nl), method, size, csize, offset });
    p += 46 + nl + el + cl;
  }
  return out;
}

export function zipRead(b: Buffer, e: ZipEntry): Buffer | null {
  if (e.size > MAX_ENTRY || e.offset + 30 > b.length) return null;
  const nl = b.readUInt16LE(e.offset + 26), el = b.readUInt16LE(e.offset + 28);
  const start = e.offset + 30 + nl + el;
  const data = b.subarray(start, start + e.csize);
  try {
    if (e.method === 0) return data;
    if (e.method === 8) return inflateRawSync(data, { maxOutputLength: MAX_ENTRY });
  } catch { return null; }
  return null;
}
