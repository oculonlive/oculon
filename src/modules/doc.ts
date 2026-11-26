/**
 * Document check: was this invoice, bank statement or payment proof edited?
 * Reads the file itself, no upload to anyone else:
 *   - PDF: producer and creator programs, creation vs modification dates, how many times it was saved
 *     (incremental updates), edit history in XMP, fonts embedded twice (text added by a second program),
 *     white boxes drawn over the page, annotations, signatures, and dangerous parts (JavaScript, launch actions,
 *     embedded files). The text layer is extracted and every IBAN in it is checked.
 *   - JPEG / PNG (screenshots, photos): editor software in EXIF, XMP and PNG text chunks. When a free AI key
 *     (Gemini or Mistral) is set, the text in the image is transcribed so IBANs in it are checked too.
 * A clean result is not proof that a document is genuine: it only means none of these traces were found.
 */
import { createHash } from 'node:crypto';
import { inflateSync, constants as zc } from 'node:zlib';
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { checkIban } from './iban.js';
import { zipEntries, zipRead } from '../core/zip.js';

export interface DocIban {
  iban: string;
  valid: boolean;
  country: string | null;
  problems: string[];
}

export interface DocResult {
  name: string;
  type: 'pdf' | 'jpeg' | 'png' | 'docx' | 'xlsx' | 'pptx' | 'office (legacy)';
  bytes: number;
  sha256: string;
  verdict: 'dangerous file' | 'likely edited' | 'signs of editing' | 'no signs of editing found';
  risk: number;
  flags: string[];
  notes: string[];
  metadata: Record<string, string>;
  /** PDF: times the file was saved (1 = never changed after it was made). */
  revisions: number | null;
  signed: boolean;
  fonts: string[];
  text: { chars: number; excerpt: string; from: 'text layer' | 'ocr' | 'none' };
  /** Office files: macros, external links, embedded objects and hidden sheets found in the package. */
  office?: { macros: boolean; external: string[]; embedded: string[]; hiddenSheets: string[] };
  ibans: DocIban[];
  domains: string[];
  advice: string[];
}

export const DOC_MAX_BYTES = 10 * 1024 * 1024;

/* ---------- small PDF reader ---------- */

interface PdfObj {
  num: number;
  dict: string;
  stream: Buffer | null;
  /** Raw stream bytes as stored (for images). */
  raw: Buffer | null;
}

export function inflate(b: Buffer): Buffer | null {
  try {
    return inflateSync(b, { finishFlush: zc.Z_SYNC_FLUSH });
  } catch {
    return null;
  }
}

/** Objects of a PDF, including those packed in object streams. Streams are decoded when they use FlateDecode. */
export function pdfObjects(buf: Buffer): PdfObj[] {
  const raw = buf.toString('latin1');
  const out: PdfObj[] = [];
  const re = /(\d+)\s+\d+\s+obj\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const start = m.index + m[0].length;
    const end = raw.indexOf('endobj', start);
    if (end < 0) break;
    const body = raw.slice(start, end);
    const si = body.search(/\bstream\r?\n/);
    let dict = body, stream: Buffer | null = null, rawStream: Buffer | null = null;
    if (si >= 0) {
      dict = body.slice(0, si);
      const ds = start + si + (/\bstream\r\n/.test(body.slice(si, si + 8)) ? 8 : 7);
      const len = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
      let de = len ? ds + Number(len[1]) : raw.indexOf('endstream', ds);
      if (de < ds || de > end) de = raw.indexOf('endstream', ds);
      rawStream = buf.subarray(ds, de > ds ? de : ds);
      stream = /\/FlateDecode/.test(dict) ? inflate(rawStream) : /\/Filter/.test(dict) ? null : rawStream;
    }
    out.push({ num: Number(m[1]), dict, stream, raw: rawStream });
    re.lastIndex = end;
  }
  // Object streams (PDF 1.5+) hold more objects, often including the metadata.
  for (const o of [...out]) {
    if (!/\/Type\s*\/ObjStm/.test(o.dict) || !o.stream) continue;
    const s = o.stream.toString('latin1');
    const n = Number(/\/N\s+(\d+)/.exec(o.dict)?.[1] ?? 0);
    const first = Number(/\/First\s+(\d+)/.exec(o.dict)?.[1] ?? 0);
    const nums = s.slice(0, first).trim().split(/\s+/).map(Number);
    for (let i = 0; i < n && i * 2 + 1 < nums.length; i++) {
      const a = first + nums[i * 2 + 1]!;
      const b = i + 1 < n && i * 2 + 3 < nums.length ? first + nums[i * 2 + 3]! : s.length;
      out.push({ num: nums[i * 2]!, dict: s.slice(a, b), stream: null, raw: null });
    }
  }
  return out;
}

/** A PDF string value: (literal) with escapes, or <hex>, UTF-16 when it starts with a byte order mark. */
export function pdfString(src: string): string {
  let bytes: number[] = [];
  if (src.startsWith('<')) {
    const hex = src.slice(1, src.indexOf('>') < 0 ? undefined : src.indexOf('>')).replace(/\s+/g, '');
    for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2).padEnd(2, '0'), 16));
  } else {
    let depth = 0;
    for (let i = 1; i < src.length; i++) {
      const c = src[i]!;
      if (c === '\\') {
        const n = src[++i]!;
        const map: Record<string, number> = { n: 10, r: 13, t: 9, b: 8, f: 12, '(': 40, ')': 41, '\\': 92 };
        if (n in map) bytes.push(map[n]!);
        else if (/[0-7]/.test(n)) {
          let o = n;
          while (o.length < 3 && /[0-7]/.test(src[i + 1] ?? '')) o += src[++i];
          bytes.push(parseInt(o, 8) & 255);
        } else if (n === '\r' || n === '\n') {
          if (n === '\r' && src[i + 1] === '\n') i++;
        } else bytes.push(n.charCodeAt(0));
        continue;
      }
      if (c === '(') depth++;
      if (c === ')') { if (depth === 0) break; depth--; }
      bytes.push(c.charCodeAt(0) & 255);
    }
  }
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    bytes = bytes.slice(2);
    let s = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
    return s;
  }
  return Buffer.from(bytes).toString('latin1');
}

/** Value of `/Key (string)` or `/Key <hex>` in a dictionary. */
function dictString(dict: string, k: string): string | null {
  const m = new RegExp(`/${k}\\s*(\\((?:\\\\.|[^\\\\])*?\\)|<[0-9A-Fa-f\\s]*>)`).exec(dict);
  if (!m) return null;
  // Literal strings may contain balanced parentheses; read from the match to the real end.
  const at = m.index + m[0].indexOf(m[1]!);
  return pdfString(m[1]!.startsWith('<') ? m[1]! : dict.slice(at)).trim() || null;
}

/** D:YYYYMMDDHHmmSS+hh'mm' to epoch milliseconds. */
export function pdfDate(s: string | null): number | null {
  if (!s) return null;
  const m = /(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?/.exec(s);
  if (!m) return null;
  const [y, mo = '01', d = '01', h = '00', mi = '00', se = '00'] = m.slice(1, 7) as string[];
  let t = Date.UTC(+y!, +mo - 1, +d, +h, +mi, +se);
  const tz = m[7];
  if (tz && tz !== 'Z') {
    const sign = tz[0] === '-' ? -1 : 1;
    const [hh, mm] = [Number(tz.slice(1, 3)), Number(tz.replace(/'/g, '').slice(3, 5) || 0)];
    t -= sign * (hh * 60 + mm) * 60_000;
  }
  return Number.isFinite(t) ? t : null;
}

/** ToUnicode CMap: character code (hex) to text. */
function parseCMap(s: string): { map: Map<string, string>; bytes: number } {
  const map = new Map<string, string>();
  const hexText = (h: string) => {
    let t = '';
    for (let i = 0; i + 3 < h.length + 1; i += 4) t += String.fromCharCode(parseInt(h.slice(i, i + 4).padEnd(4, '0'), 16));
    return t;
  };
  let bytes = 1;
  const cs = /begincodespacerange\s*<([0-9A-Fa-f]+)>/.exec(s);
  if (cs) bytes = cs[1]!.length / 2;
  for (const block of s.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const p of block[1]!.matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) map.set(p[1]!.toUpperCase(), hexText(p[2]!));
  }
  for (const block of s.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    for (const p of block[1]!.matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]+>|\[[^\]]*\])/g)) {
      const lo = parseInt(p[1]!, 16), hi = parseInt(p[2]!, 16), w = p[1]!.length;
      if (hi - lo > 5000) continue;
      if (p[3]!.startsWith('[')) {
        const items = [...p[3]!.matchAll(/<([0-9A-Fa-f]+)>/g)].map((x) => hexText(x[1]!));
        items.forEach((t, i) => map.set((lo + i).toString(16).toUpperCase().padStart(w, '0'), t));
      } else {
        const base = parseInt(p[3]!.slice(1, -1), 16);
        for (let c = lo; c <= hi; c++) map.set(c.toString(16).toUpperCase().padStart(w, '0'), String.fromCharCode(base + (c - lo)));
      }
    }
  }
  return { map, bytes };
}

interface PdfFont { name: string; cmap: { map: Map<string, string>; bytes: number } | null; twoByte: boolean }

/** Text of the pages, in drawing order. Good enough to find account numbers, not a layout-perfect extraction. */
function pdfText(objs: PdfObj[]): { text: string; whiteBoxes: number } {
  const byNum = new Map<number, PdfObj>();
  for (const o of objs) if (!byNum.has(o.num) || o.dict.length > byNum.get(o.num)!.dict.length) byNum.set(o.num, o);
  const deref = (s: string): string => {
    const r = /^\s*(\d+)\s+\d+\s+R/.exec(s);
    return r ? byNum.get(Number(r[1]))?.dict ?? '' : s;
  };
  const sub = (dict: string, k: string): string => {
    const i = dict.search(new RegExp(`/${k}\\b`));
    if (i < 0) return '';
    let rest = dict.slice(i + k.length + 1).trimStart();
    if (/^\d+\s+\d+\s+R/.test(rest)) return deref(rest);
    if (!rest.startsWith('<<')) return '';
    let depth = 0;
    for (let j = 0; j < rest.length - 1; j++) {
      if (rest.startsWith('<<', j)) { depth++; j++; } else if (rest.startsWith('>>', j)) { depth--; j++; if (depth === 0) return rest.slice(0, j + 1); }
    }
    return rest;
  };
  const fontCache = new Map<number, PdfFont>();
  const font = (num: number): PdfFont => {
    const hit = fontCache.get(num);
    if (hit) return hit;
    const d = byNum.get(num)?.dict ?? '';
    const tu = /\/ToUnicode\s+(\d+)\s+\d+\s+R/.exec(d);
    const cm = tu ? byNum.get(Number(tu[1]))?.stream : null;
    const f: PdfFont = { name: /\/BaseFont\s*\/([^\s/<>\[\]]+)/.exec(d)?.[1] ?? '?', cmap: cm ? parseCMap(cm.toString('latin1')) : null, twoByte: /\/Type0|Identity-H/.test(d) };
    fontCache.set(num, f);
    return f;
  };
  let text = '';
  let whiteBoxes = 0;
  for (const page of objs.filter((o) => /\/Type\s*\/Page\b(?!s)/.test(o.dict))) {
    const fonts = new Map<string, PdfFont>();
    const res = sub(page.dict, 'Resources');
    const fdict = sub(res, 'Font');
    for (const m of fdict.matchAll(/\/([^\s/<>\[\]]+)\s+(\d+)\s+\d+\s+R/g)) fonts.set(m[1]!, font(Number(m[2])));
    const contents = /\/Contents\s*(\[[^\]]*\]|\d+\s+\d+\s+R)/.exec(page.dict)?.[1] ?? '';
    const streams = [...contents.matchAll(/(\d+)\s+\d+\s+R/g)].map((m) => byNum.get(Number(m[1]))?.stream).filter((s): s is Buffer => Boolean(s));
    const c = streams.map((s) => s.toString('latin1')).join('\n');
    const r = contentText(c, fonts);
    text += r.text + '\n';
    whiteBoxes += r.whiteBoxes;
  }
  return { text, whiteBoxes };
}

function decodeShow(s: string, f: PdfFont | undefined): string {
  const isHex = s.startsWith('<');
  const raw = isHex ? s.slice(1, -1).replace(/\s+/g, '') : Buffer.from(pdfString(s), 'latin1').toString('hex');
  if (f?.cmap && f.cmap.map.size) {
    const step = (f.twoByte ? 2 : f.cmap.bytes) * 2;
    let out = '';
    for (let i = 0; i < raw.length; i += step) out += f.cmap.map.get(raw.slice(i, i + step).toUpperCase()) ?? '';
    return out;
  }
  if (f?.twoByte) return '';
  return Buffer.from(raw, 'hex').toString('latin1');
}

/** Text shown by a content stream, plus white filled boxes that are not page backgrounds. */
export function contentText(c: string, fonts: Map<string, PdfFont>): { text: string; whiteBoxes: number } {
  let out = '', cur: PdfFont | undefined, white = false, whiteBoxes = 0, lastShow = '';
  const nums: number[] = [];
  let rects: number[][] = [];
  const tok = /\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>|\[|\]|\/[^\s/<>\[\]()]+|-?\d*\.?\d+|[A-Za-z'"*]+/g;
  let arr: string[] | null = null;
  let lastName = '';
  let m: RegExpExecArray | null;
  while ((m = tok.exec(c))) {
    const t = m[0];
    if (t === '[') { arr = []; continue; }
    if (t === ']') continue;
    if (t.startsWith('(') || (t.startsWith('<') && !t.startsWith('<<'))) { if (arr) arr.push(t); else lastShow = t; continue; }
    if (t.startsWith('/')) { lastName = t.slice(1); continue; }
    if (/^-?\d*\.?\d+$/.test(t)) {
      if (arr) { if (Number(t) < -200) arr.push(' '); } else nums.push(Number(t));
      continue;
    }
    switch (t) {
      case 'Tf': cur = fonts.get(lastName); break;
      case 'Tj': case "'": case '"': out += decodeShow(lastShow, cur); if (t !== 'Tj') out += '\n'; break;
      case 'TJ': if (arr) out += arr.map((x) => (x === ' ' ? ' ' : decodeShow(x, cur))).join(''); arr = null; break;
      case 'Td': case 'TD': { const ty = nums[nums.length - 1]; out += ty && Math.abs(ty) > 1 ? '\n' : ' '; break; }
      case 'T*': case 'Tm': case 'ET': out += '\n'; break;
      case 'rg': { const [r, g, b] = nums.slice(-3); white = r === 1 && g === 1 && b === 1; break; }
      case 'g': white = nums[nums.length - 1] === 1; break;
      case 'k': { const k = nums.slice(-4); white = k.length === 4 && k.every((x) => x === 0); break; }
      case 're': rects.push(nums.slice(-4)); break;
      case 'f': case 'F': case 'f*': case 'B': case 'b':
        if (white) for (const [, , w, h] of rects) if (w !== undefined && h !== undefined && Math.abs(w) < 500 && Math.abs(h) > 4 && Math.abs(h) < 60 && Math.abs(w) > 10) whiteBoxes++;
        rects = [];
        break;
      case 'n': case 'S': case 's': rects = []; break;
    }
    if (!/^-?\d/.test(t)) nums.length = 0;
  }
  return { text: out.replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n'), whiteBoxes };
}

/* ---------- image metadata ---------- */

function exifSoftware(app1: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  if (app1.subarray(0, 6).toString('latin1') !== 'Exif\0\0') return out;
  const t = app1.subarray(6);
  const le = t.subarray(0, 2).toString('latin1') === 'II';
  const u16 = (o: number) => (le ? t.readUInt16LE(o) : t.readUInt16BE(o));
  const u32 = (o: number) => (le ? t.readUInt32LE(o) : t.readUInt32BE(o));
  try {
    const ifd = u32(4);
    const n = u16(ifd);
    const names: Record<number, string> = { 0x010f: 'make', 0x0110: 'model', 0x0131: 'software', 0x0132: 'modified', 0x013b: 'artist' };
    for (let i = 0; i < n; i++) {
      const e = ifd + 2 + i * 12;
      const tag = u16(e), type = u16(e + 2), count = u32(e + 4);
      if (!names[tag] || type !== 2) continue;
      const off = count > 4 ? u32(e + 8) : e + 8;
      out[names[tag]!] = t.subarray(off, off + count).toString('latin1').replace(/\0+$/, '').trim();
    }
  } catch {}
  return out;
}

function xmpFields(x: string): Record<string, string> {
  const out: Record<string, string> = {};
  const get = (k: string) => new RegExp(`${k}(?:="([^"]*)"|>([^<]*)<)`).exec(x);
  for (const [k, name] of [['xmp:CreatorTool', 'creator tool'], ['pdf:Producer', 'producer (xmp)'], ['xmp:CreateDate', 'created (xmp)'], ['xmp:ModifyDate', 'modified (xmp)'], ['photoshop:History', 'photoshop history']] as const) {
    const m = get(k);
    const v = (m?.[1] ?? m?.[2] ?? '').trim();
    if (v) out[name] = v;
  }
  const agents = [...x.matchAll(/stEvt:softwareAgent(?:="([^"]*)"|>([^<]*)<)/g)].map((m) => (m[1] ?? m[2] ?? '').trim()).filter(Boolean);
  const saves = [...x.matchAll(/stEvt:action(?:="(saved|converted|derived|edited)"|>(saved|converted|derived|edited)<)/g)].length;
  if (agents.length) out['edit history'] = [...new Set(agents)].join('; ');
  if (saves) out['saves in history'] = String(saves);
  return out;
}

export function jpegMeta(b: Buffer): { meta: Record<string, string> } {
  const meta: Record<string, string> = {};
  let i = 2;
  while (i + 4 < b.length && b[i] === 0xff) {
    const marker = b[i + 1]!;
    if (marker === 0xda || marker === 0xd9) break;
    const len = b.readUInt16BE(i + 2);
    const seg = b.subarray(i + 4, i + 2 + len);
    if (marker === 0xe1) {
      if (seg.subarray(0, 4).toString('latin1') === 'Exif') Object.assign(meta, exifSoftware(seg));
      else if (seg.toString('latin1', 0, 40).includes('ns.adobe.com/xap')) Object.assign(meta, xmpFields(seg.toString('utf8')));
    }
    if (marker === 0xed && seg.toString('latin1', 0, 14).startsWith('Photoshop')) meta['photoshop block'] = 'present';
    i += 2 + len;
  }
  return { meta };
}

export function pngMeta(b: Buffer): { meta: Record<string, string> } {
  const meta: Record<string, string> = {};
  let i = 8;
  while (i + 12 <= b.length) {
    const len = b.readUInt32BE(i);
    const type = b.toString('latin1', i + 4, i + 8);
    const data = b.subarray(i + 8, i + 8 + len);
    if (type === 'tEXt' || type === 'iTXt' || type === 'zTXt') {
      const z = data.indexOf(0);
      const k = data.toString('latin1', 0, z);
      let v = '';
      if (type === 'tEXt') v = data.toString('latin1', z + 1);
      else if (type === 'zTXt') v = inflate(data.subarray(z + 2))?.toString('latin1') ?? '';
      else {
        const rest = data.subarray(z + 1);
        const compressed = rest[0] === 1;
        let p = 2;
        p = rest.indexOf(0, p) + 1; // language tag
        p = rest.indexOf(0, p) + 1; // translated keyword
        v = compressed ? inflate(rest.subarray(p))?.toString('utf8') ?? '' : rest.subarray(p).toString('utf8');
      }
      if (k === 'XML:com.adobe.xmp') Object.assign(meta, xmpFields(v));
      else if (/^(Software|Creation Time|Author|Comment|Title|Source)$/i.test(k)) meta[k.toLowerCase()] = v.slice(0, 200).trim();
    }
    if (type === 'IEND') break;
    i += 12 + len;
  }
  return { meta };
}

/* ---------- what the traces mean ---------- */

const ONLINE_EDITORS = /ilovepdf|smallpdf|sejda|pdfescape|pdf ?candy|pdffiller|docfly|pdf2go|soda ?pdf|xodo|pdf24|hipdf|pdfzorro|online2pdf|lightpdf|pdfsimpli/i;
const DESKTOP_EDITORS = /pdf-xchange editor|foxit (pdf )?editor|phantompdf|nitro|pdfelement|wondershare|master pdf editor|pdf studio|inkscape|libreoffice draw|qoppa|able2extract|acrobat (pro|dc)|adobe acrobat(?! distiller)/i;
export const IMAGE_EDITORS = /photoshop|gimp|canva|illustrator|picsart|snapseed|lightroom|pixlr|paint\.net|fotor|affinity|photopea|corel/i;
const WORD_PROCESSORS = /microsoft.{0,10}word|microsoft.{0,10}excel|google docs|libreoffice writer|openoffice|pages|wps (writer|office)/i;

function editorFlag(label: string, v: string, flags: [string, number][]) {
  if (ONLINE_EDITORS.test(v)) flags.push([`${label} is an online PDF editor (${v}): the file went through an editing site`, 35]);
  else if (IMAGE_EDITORS.test(v)) flags.push([`${label} is an image editor (${v})`, 35]);
  else if (DESKTOP_EDITORS.test(v)) flags.push([`${label} is a PDF editor (${v}): the file was opened and saved in an editor`, 25]);
  else if (WORD_PROCESSORS.test(v)) flags.push([`${label} is a word processor (${v}): normal for a small business invoice, unusual for a bank statement or bank receipt`, 12]);
}

function textFindings(text: string): { ibans: DocIban[]; domains: string[] } {
  const ibans = new Map<string, DocIban>();
  for (const m of text.toUpperCase().matchAll(/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g)) {
    const c = checkIban(m[0]);
    if (!c.iban || ibans.has(c.iban)) continue;
    // Strings that only look like IBANs (no known country length) are left out.
    if (!c.valid && !c.countryName) continue;
    ibans.set(c.iban, { iban: c.formatted ?? c.iban, valid: c.valid, country: c.countryName, problems: c.problems });
  }
  const domains = new Set<string>();
  for (const m of text.toLowerCase().matchAll(/\b(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|uk|de|fr|nl|es|it|eu|info|biz|top|xyz|online|site|app|me|us|ca|au|in|id|sg|my|ph|ch|be|at|pl|ru|br|mx|live|shop|store|bank))\b/g)) domains.add(m[1]!);
  for (const m of text.toLowerCase().matchAll(/[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)/g)) domains.add(m[1]!);
  return { ibans: [...ibans.values()].slice(0, 20), domains: [...domains].slice(0, 20) };
}

/** Transcribe the text in an image with a free AI key. Returns null when no key is set or the call fails. */
async function ocr(ctx: Ctx, img: Buffer, mime: string, provenance: Provenance[]): Promise<string | null> {
  // Free vision models, fastest first. (Mistral's vision models need a paid plan.)
  const providers = [
    { name: 'openrouter', env: 'OPENROUTER_API_KEY', url: 'https://openrouter.ai/api/v1/chat/completions', model: process.env.OCULON_OCR_OPENROUTER_MODEL || 'nvidia/nemotron-3.5-super-vl:free' },
    { name: 'gemini', env: 'GEMINI_API_KEY', url: 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', model: process.env.OCULON_OCR_GEMINI_MODEL || 'gemini-flash-latest' },
  ];
  for (const p of providers) {
    const k = key(p.env);
    if (!k) continue;
    const body = JSON.stringify({
      model: p.model,
      temperature: 0,
      max_tokens: 3000,
      messages: [{ role: 'user', content: [
        { type: 'text', text: 'Transcribe all text in this image exactly as written, line by line. Output only the text, nothing else. If there is no text, output nothing.' },
        { type: 'image_url', image_url: { url: `data:${mime};base64,${img.toString('base64')}` } },
      ] }],
    });
    const r = await ctx.http.postBytes(p.url, Buffer.from(body), { source: `ocr-${p.name}`, headers: { authorization: `Bearer ${k}`, 'content-type': 'application/json' }, timeoutMs: 45_000, retries: 0 });
    provenance.push({ ...r.prov, note: `${r.data ? 'text read from the image' : 'could not read the text'} (${p.model})${r.prov.note ? `: ${r.prov.note}` : ''}` });
    if (!r.data) continue;
    try {
      const j = JSON.parse(r.data.toString('utf8')) as { choices?: { message?: { content?: string } }[] };
      const t = j.choices?.[0]?.message?.content?.trim();
      if (t !== undefined) return t;
    } catch {}
  }
  return null;
}

/** Check one document. `name` is only used for display. */
/* ---------- Office files ---------- */

function officeType(b: Buffer): DocResult['type'] | null {
  if (b.readUInt32BE(0) === 0xd0cf11e0) return 'office (legacy)';
  if (b.readUInt32LE(0) !== 0x04034b50) return null;
  try {
    const names = zipEntries(b).map((e) => e.name);
    if (!names.includes('[Content_Types].xml')) return null;
    return names.some((n) => n.startsWith('word/')) ? 'docx' : names.some((n) => n.startsWith('xl/')) ? 'xlsx' : names.some((n) => n.startsWith('ppt/')) ? 'pptx' : null;
  } catch { return null; }
}

const xmlText = (x: string, tag: string) => [...x.matchAll(new RegExp(`<${tag}(?: [^>]*)?>([^<]*)</${tag}>`, 'g'))].map((m) => m[1]!).join(' ');
const xmlUnescape = (s: string) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

export function officeScan(b: Buffer, type: DocResult['type'], nowMs: number): { flags: [string, number][]; notes: string[]; metadata: Record<string, string>; danger: boolean; text: string; office: NonNullable<DocResult['office']> } {
  const flags: [string, number][] = [], notes: string[] = [], metadata: Record<string, string> = {};
  const office = { macros: false, external: [] as string[], embedded: [] as string[], hiddenSheets: [] as string[] };
  let danger = false;
  if (type === 'office (legacy)') {
    const s = b.toString('latin1');
    office.macros = /_VBA_PROJECT|VBA\0|Attribute VB_Name/.test(s);
    if (office.macros) { danger = true; flags.push(['contains VBA macros: code that runs when you enable content', 70]); }
    if (/DDEAUTO|\bDDE\b\s/.test(s)) { danger = true; flags.push(['contains a DDE field that can start programs', 60]); }
    if (/Excel 4\.0|\bEXEC\(|\bCALL\(/.test(s) && /Macro/.test(s)) { danger = true; flags.push(['contains Excel 4.0 macros', 60]); }
    notes.push('Old binary Office format (.doc / .xls): only macros and DDE are checked. Ask for a PDF instead.');
    return { flags, notes, metadata, danger, text: '', office };
  }
  const entries = zipEntries(b);
  const read = (n: string) => { const e = entries.find((x) => x.name === n); return e ? zipRead(b, e)?.toString('utf8') ?? '' : ''; };
  const names = entries.map((e) => e.name);
  if (names.some((n) => /vbaProject\.bin$/i.test(n)) || /macroEnabled/i.test(read('[Content_Types].xml'))) { office.macros = true; danger = true; flags.push(['contains VBA macros: code that runs when you enable content. Invoices and statements never need macros', 70]); }
  if (names.some((n) => n.startsWith('xl/macrosheets/'))) { danger = true; flags.push(['contains Excel 4.0 macro sheets, a common malware trick', 70]); }
  if (names.some((n) => /\/activeX\//.test(n))) flags.push(['contains ActiveX controls', 25]);
  for (const n of names.filter((x) => /\/embeddings\//.test(x)).slice(0, 8)) office.embedded.push(n.split('/').pop()!);
  if (office.embedded.length) flags.push([`embeds ${office.embedded.length} object${office.embedded.length > 1 ? 's' : ''} (${office.embedded.slice(0, 3).join(', ')}): a file or program hidden inside the document`, office.embedded.some((e) => /\.(exe|bin|scr|js|vbs|ps1|bat|hta)$/i.test(e)) ? 40 : 15]);
  for (const n of names.filter((x) => x.endsWith('.rels'))) {
    for (const m of read(n).matchAll(/<Relationship\b([^>]*)\/?>/g)) {
      const attrs = m[1]!;
      if (!/TargetMode="External"/.test(attrs)) continue;
      const target = xmlUnescape(/Target="([^"]*)"/.exec(attrs)?.[1] ?? '');
      const rel = /Type="[^"]*\/([^"/]+)"/.exec(attrs)?.[1] ?? '';
      if (/attachedTemplate|oleObject|frame|subDocument/i.test(rel)) { danger = true; flags.push([`loads ${rel} from outside the file (${target.slice(0, 80)}): remote template injection, used to run code`, 65]); }
      if (office.external.length < 12) office.external.push(`${rel}: ${target.slice(0, 120)}`);
    }
  }
  const main = type === 'docx' ? read('word/document.xml') : '';
  if (/DDEAUTO|instr="\s*DDE\b|<w:instrText[^>]*>\s*DDE/i.test(main)) { danger = true; flags.push(['contains a DDE field that can start programs', 60]); }
  if (/<w:instrText[^>]*>\s*(INCLUDEPICTURE|INCLUDETEXT|LINK)\b[^<]*https?:/i.test(main)) flags.push(['fields load content from the internet when opened (can reveal that you opened it)', 15]);
  if (type === 'xlsx') {
    for (const m of read('xl/workbook.xml').matchAll(/<sheet\b[^>]*name="([^"]*)"[^>]*state="(hidden|veryHidden)"/g)) office.hiddenSheets.push(`${xmlUnescape(m[1]!)} (${m[2]})`);
    if (office.hiddenSheets.length) flags.push([`${office.hiddenSheets.length} hidden sheet${office.hiddenSheets.length > 1 ? 's' : ''}: ${office.hiddenSheets.slice(0, 3).join(', ')}`, office.hiddenSheets.some((h) => /veryHidden/.test(h)) ? 30 : 10]);
  }
  // Metadata.
  const core = read('docProps/core.xml'), app = read('docProps/app.xml');
  for (const [tag, label] of [['dc:creator', 'author'], ['cp:lastModifiedBy', 'last saved by'], ['dcterms:created', 'created'], ['dcterms:modified', 'modified'], ['cp:revision', 'revision'], ['dc:title', 'title']] as const) { const v = xmlText(core, tag).trim(); if (v) metadata[label] = xmlUnescape(v).slice(0, 120); }
  for (const [tag, label] of [['Application', 'application'], ['AppVersion', 'app version'], ['Company', 'company'], ['TotalTime', 'editing minutes']] as const) { const v = xmlText(app, tag).trim(); if (v) metadata[label] = xmlUnescape(v).slice(0, 120); }
  if (metadata.author && metadata['last saved by'] && metadata.author !== metadata['last saved by']) flags.push([`written by "${metadata.author}" and last saved by "${metadata['last saved by']}"`, 8]);
  const c = Date.parse(metadata.created ?? ''), mo = Date.parse(metadata.modified ?? '');
  if (c && mo && mo - c > 86_400_000) flags.push([`modified ${Math.round((mo - c) / 86_400_000)} days after it was created`, 10]);
  if (c && c > nowMs + 86_400_000) flags.push(['the creation date is in the future', 15]);
  if (Number(metadata.revision) >= 10) notes.push(`Saved ${metadata.revision} times.`);
  notes.push('Word and Excel files are easy to change and leave little trace. For payments, ask for a PDF from the issuer and confirm bank details by phone.');
  // Text.
  const text = type === 'docx' ? xmlText(main, 'w:t') : type === 'xlsx' ? xmlText(read('xl/sharedStrings.xml'), 't') : names.filter((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n)).slice(0, 40).map((n) => xmlText(read(n), 'a:t')).join('\n');
  return { flags, notes, metadata, danger, text: xmlUnescape(text), office };
}

export async function docCheck(ctx: Ctx, file: Buffer, name = 'document'): Promise<ModuleResult<DocResult>> {
  if (!file.length) throw new Error('the file is empty');
  if (file.length > DOC_MAX_BYTES) throw new Error(`the file is larger than ${DOC_MAX_BYTES / 1024 / 1024} MB`);
  const now = ctx.now();
  const head = file.subarray(0, 1024).toString('latin1');
  const type: DocResult['type'] | null = head.includes('%PDF-') ? 'pdf' : file[0] === 0xff && file[1] === 0xd8 ? 'jpeg' : file.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) ? 'png' : officeType(file);
  if (!type) throw new Error('not a PDF, Word, Excel, PowerPoint, JPEG or PNG file (expected a document, a screenshot or a photo of one)');
  const flags: [string, number][] = [];
  const notes: string[] = [];
  const metadata: Record<string, string> = {};
  const provenance: Provenance[] = [{ source: 'oculon-doc', url: 'local', status: 'LIVE', fetchedAt: now.toISOString(), note: 'read from the file itself, not uploaded anywhere else' }];
  let revisions: number | null = null, signed = false, fonts: string[] = [], text = '', from: DocResult['text']['from'] = 'none';
  let danger = false;
  let office: DocResult['office'];

  if (type === 'docx' || type === 'xlsx' || type === 'pptx' || type === 'office (legacy)') {
    const o = officeScan(file, type, now.getTime());
    flags.push(...o.flags); notes.push(...o.notes); Object.assign(metadata, o.metadata);
    danger = o.danger; text = o.text; if (text) from = 'text layer';
    office = o.office;
  } else if (type === 'pdf') {
    const raw = file.toString('latin1');
    const objs = pdfObjects(file);
    const all = objs.map((o) => o.dict).join('\n');
    // Metadata: the Info dictionary and XMP.
    // After an incremental update the newest Info dictionary (named by the last trailer) is the one that counts.
    const infos = objs.filter((o) => /\/(Producer|CreationDate|Creator)\s*[(<]/.test(o.dict));
    const infoRef = [...raw.matchAll(/\/Info\s+(\d+)\s+\d+\s+R/g)].pop()?.[1];
    const info = (infoRef ? infos.filter((o) => o.num === Number(infoRef)).pop() : undefined)?.dict ?? infos[infos.length - 1]?.dict ?? '';
    const producers = [...new Set(infos.map((o) => dictString(o.dict, 'Producer')).filter((p): p is string => Boolean(p)))];
    if (producers.length > 1) flags.push([`made by one program and saved again by another (${producers.slice(0, 3).join(' -> ')})`, 20]);
    for (const [k, label] of [['Producer', 'producer'], ['Creator', 'creator'], ['CreationDate', 'created'], ['ModDate', 'modified'], ['Author', 'author'], ['Title', 'title']] as const) {
      const v = dictString(info, k);
      if (v) metadata[label] = v.slice(0, 200);
    }
    const xmp = objs.map((o) => o.stream?.toString('utf8') ?? '').find((s) => s.includes('<x:xmpmeta') || s.includes('ns.adobe.com/xap'));
    if (xmp) Object.assign(metadata, xmpFields(xmp));
    for (const k of ['producer', 'creator', 'creator tool', 'producer (xmp)'] as const) if (metadata[k]) editorFlag(k[0]!.toUpperCase() + k.slice(1), metadata[k]!, flags);
    if (metadata['edit history']) {
      const agents = metadata['edit history']!.split('; ');
      if (agents.length > 1) flags.push([`the edit history lists ${agents.length} programs: ${agents.join(', ')}`, 15]);
    }
    const c = pdfDate(metadata.created ?? null), mo = pdfDate(metadata.modified ?? null);
    const fmt = (t: number) => `${new Date(t).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
    if (c) metadata.created = fmt(c);
    if (mo) metadata.modified = fmt(mo);
    if (c && mo && mo - c > 120_000) {
      const days = (mo - c) / 86_400_000;
      flags.push([`modified ${days >= 1 ? `${Math.round(days)} day${Math.round(days) === 1 ? '' : 's'}` : `${Math.round((mo - c) / 60_000)} minutes`} after it was created`, days >= 1 ? 20 : 12]);
    }
    if (c && c > now.getTime() + 86_400_000) flags.push(['the creation date is in the future', 20]);
    if (!Object.keys(metadata).length) notes.push('The file has no metadata. Some generators leave it out; editors and scrubbing tools also remove it.');
    // Saves: each incremental update adds a %%EOF. Signatures add one per signature.
    signed = /\/Type\s*\/Sig\b|\/ByteRange\s*\[/.test(all);
    revisions = Math.max(1, (raw.match(/%%EOF/g) ?? []).length);
    if (revisions > 1) {
      if (signed) notes.push(`Saved ${revisions} times; the file is digitally signed, and signing adds a save. Check the signature in a PDF reader.`);
      else flags.push([`saved ${revisions} times: content was added or changed after the first version`, revisions > 2 ? 25 : 18]);
    }
    if (signed) notes.push('The file carries a digital signature. A valid signature from the issuer is the strongest proof it was not changed; open it in a PDF reader to see whether the signature is valid.');
    // Fonts: the same font embedded twice under different subset tags usually means a second program added text.
    const baseFonts = [...new Set([...all.matchAll(/\/BaseFont\s*\/([^\s/<>\[\]()]+)/g)].map((m) => m[1]!))];
    fonts = [...new Set(baseFonts.map((f) => f.replace(/^[A-Z]{6}\+/, '')))].slice(0, 30);
    const subsets = new Map<string, Set<string>>();
    for (const f of baseFonts) {
      const m = /^([A-Z]{6})\+(.+)$/.exec(f);
      const nameOnly = m ? m[2]! : f;
      const s = subsets.get(nameOnly) ?? new Set<string>();
      s.add(m ? m[1]! : '(full)');
      subsets.set(nameOnly, s);
    }
    const twice = [...subsets].filter(([, s]) => s.size > 1).map(([n]) => n);
    if (twice.length) flags.push([`font${twice.length > 1 ? 's' : ''} embedded more than once (${twice.slice(0, 3).join(', ')}): typical when a second program adds or replaces text`, 25]);
    const families = new Set(fonts.map((f) => f.split(/[-,]/)[0]!.replace(/(MT|PS|Std)$/, '').toLowerCase()));
    const pages = objs.filter((o) => /\/Type\s*\/Page\b(?!s)/.test(o.dict)).length;
    if (pages && pages <= 2 && families.size >= 6) flags.push([`${families.size} different font families on ${pages} page${pages > 1 ? 's' : ''}`, 10]);
    // Annotations drawn on top of the page.
    const ann = (all.match(/\/Subtype\s*\/(FreeText|Stamp|Square|Ink|Redact)\b/g) ?? []).length;
    if (ann) flags.push([`${ann} annotation${ann > 1 ? 's' : ''} (text boxes, stamps or shapes) placed on top of the page`, 20]);
    // Dangerous parts.
    const bad: string[] = [];
    if (/\/JavaScript\b|\/JS\s*[(<\d]/.test(all)) bad.push('JavaScript');
    if (/\/Launch\b/.test(all)) bad.push('a launch action that can start a program');
    if (/\/EmbeddedFile\b/.test(all)) bad.push('embedded files');
    if (/\/XFA\b/.test(all)) bad.push('an XFA form');
    if (/\/RichMedia\b/.test(all)) bad.push('rich media');
    if (bad.length) {
      danger = bad.some((b) => b !== 'an XFA form');
      flags.push([`contains ${bad.join(', ')}: invoices and statements do not need this. Do not open it with JavaScript enabled`, danger ? 60 : 10]);
    }
    // Text layer and white boxes.
    const t = pdfText(objs);
    text = t.text.trim();
    if (text) from = 'text layer';
    if (t.whiteBoxes >= 1) flags.push([`${t.whiteBoxes} white box${t.whiteBoxes > 1 ? 'es' : ''} drawn on the page: sometimes used to cover the original text before typing over it`, t.whiteBoxes >= 3 ? 15 : 8]);
    // A scanned PDF has no text layer: read its largest image instead.
    if (!text) {
      const img = objs.filter((o) => /\/Subtype\s*\/Image/.test(o.dict) && /\/DCTDecode/.test(o.dict) && o.raw).sort((a, b) => b.raw!.length - a.raw!.length)[0];
      if (img?.raw && img.raw.length < 4_000_000) {
        const o = await ocr(ctx, img.raw, 'image/jpeg', provenance);
        if (o) { text = o; from = 'ocr'; }
      }
      if (!text) notes.push('No text layer: this looks like a scan or a picture inside a PDF. The numbers in it were not checked.');
    }
  } else {
    const { meta } = type === 'jpeg' ? jpegMeta(file) : pngMeta(file);
    Object.assign(metadata, meta);
    for (const k of ['software', 'creator tool'] as const) if (metadata[k]) editorFlag(k === 'software' ? 'Software' : 'Creator tool', metadata[k]!, flags);
    if (metadata['photoshop block']) flags.push(['the image carries a Photoshop data block', 20]);
    if (metadata['edit history']) flags.push([`the edit history lists: ${metadata['edit history']}`, 15]);
    if (!Object.keys(metadata).length) notes.push(type === 'png' ? 'No metadata: normal for a screenshot. A screenshot can be edited without leaving traces, so check the numbers in it with the sender through a channel you already trust.' : 'No metadata: it was removed, or the app that made the image does not write any.');
    if (file.length < 4_000_000) {
      const o = await ocr(ctx, file, type === 'jpeg' ? 'image/jpeg' : 'image/png', provenance);
      if (o) { text = o; from = 'ocr'; }
      else if (!provenance.some((p) => p.source.startsWith('ocr-'))) notes.push('Text in the image was not read: set OPENROUTER_API_KEY or GEMINI_API_KEY (both have free tiers) to check account numbers in screenshots.');
    }
  }

  // Say plainly when the picture left this machine to be read.
  const sent = provenance.filter((p) => p.source.startsWith('ocr-')).map((p) => p.source.slice(4));
  if (sent.length) provenance[0]!.note = `file read here; the image was sent to ${[...new Set(sent)].join(' and ')} only to read its text`;

  const found = textFindings(text);
  for (const ib of found.ibans) if (!ib.valid) flags.push([`IBAN ${ib.iban} in the document is not valid (${ib.problems[0] ?? 'checksum fails'}): a typo, or a number that was changed`, 35]);
  if (found.ibans.some((i) => i.valid)) notes.push('Valid IBANs only mean the number is well formed. Confirm the account with the company on a phone number you already have, never one from this document.');

  const risk = Math.min(100, flags.reduce((s, [, w]) => s + w, 0));
  const verdict: DocResult['verdict'] = danger ? 'dangerous file' : risk >= 50 ? 'likely edited' : risk >= 20 ? 'signs of editing' : 'no signs of editing found';
  if (verdict === 'no signs of editing found') notes.push('No traces of editing were found. That is not proof the document is genuine: a careful forger, or a document made from scratch, leaves none.');
  const advice = verdict === 'dangerous file'
    ? ['Do not open this file in a PDF reader with JavaScript on.', 'Delete it unless you expected exactly this file from someone you know.']
    : verdict === 'no signs of editing found'
      ? ['Before paying, confirm the bank details with the sender on a number or address you already had.']
      : ['Do not pay or act on this document yet.', 'Ask the issuer for the original, or confirm the details with them on a phone number you already had.', 'Banks can confirm whether a statement or a transfer is real; ask yours.'];

  const result: DocResult = {
    name: name.slice(0, 120),
    type,
    bytes: file.length,
    sha256: createHash('sha256').update(file).digest('hex'),
    verdict,
    risk,
    flags: flags.sort((a, b) => b[1] - a[1]).map(([f]) => f),
    notes,
    metadata,
    revisions,
    signed,
    fonts,
    text: { chars: text.length, excerpt: text.slice(0, 600), from },
    ibans: found.ibans,
    domains: found.domains,
    advice,
    ...(office ? { office } : {}),
  };
  const signals: Signal[] = risk >= 50 || danger
    ? [{ id: signalId('doc', result.sha256), module: 'doc', title: `Document ${result.name}: ${verdict}`, score: risk, entity: `doc:${result.sha256.slice(0, 16)}`, evidence: result.flags.slice(0, 4).map((t) => ({ source: 'oculon-doc', text: t })), createdAt: now.toISOString() }]
    : [];
  return { module: 'doc', input: result.name, generatedAt: now.toISOString(), result, signals, provenance };
}
