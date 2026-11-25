/**
 * A small PDF writer for reports, no dependencies: A4 pages, the standard Helvetica and Courier fonts
 * (WinAnsi), headings, paragraphs with word wrap, bullet lists, key-value rows, coloured verdict bars and links.
 * Characters outside WinAnsi are replaced, so any input gives a valid file.
 */

type RGB = [number, number, number];

export type Block =
  | { t: 'title'; text: string }
  | { t: 'h'; text: string }
  | { t: 'p'; text: string; size?: number; color?: RGB }
  | { t: 'mono'; text: string }
  | { t: 'bullets'; items: string[]; color?: RGB }
  | { t: 'kv'; rows: [string, string][] }
  | { t: 'bar'; label: string; text: string; color: RGB }
  | { t: 'link'; text: string; url: string }
  | { t: 'table'; head: string[]; rows: string[][]; widths: number[] }
  | { t: 'gap'; h?: number };

const W = 595, H = 842, M = 50, CW = W - 2 * M;
const INK: RGB = [0.08, 0.1, 0.11], MUTE: RGB = [0.42, 0.47, 0.49], ACCENT: RGB = [0, 0.48, 0.53];

// Helvetica widths (per 1000 em) for ASCII 32-126; other characters use 556.
const HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];
const BOLD_EXTRA = 1.06;

type Font = 'F1' | 'F2' | 'F3';
function width(s: string, size: number, font: Font): number {
  if (font === 'F3') return s.length * 600 * size / 1000;
  let w = 0;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    w += c >= 32 && c <= 126 ? HELV[c - 32]! : 556;
  }
  return (w * size / 1000) * (font === 'F2' ? BOLD_EXTRA : 1);
}

/** WinAnsi-safe text: common punctuation mapped, anything else outside Latin-1 becomes '?'. */
export function ansi(s: string): string {
  return s
    .replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, '-').replace(/…/g, '...').replace(/→/g, '->').replace(/•/g, '-')
    .replace(/[\r\t]/g, ' ')
    .replace(/[^\n\x20-\x7e\xa0-\xff]/g, '?');
}

const esc = (s: string) => s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');

function wrap(text: string, size: number, font: Font, max: number): string[] {
  const out: string[] = [];
  for (const para of ansi(text).split('\n')) {
    let line = '';
    for (const word of para.split(/ +/)) {
      const tryLine = line ? `${line} ${word}` : word;
      if (width(tryLine, size, font) <= max) { line = tryLine; continue; }
      if (line) out.push(line);
      // A single word wider than the line (a hash, a URL) is cut into pieces.
      let w = word;
      while (width(w, size, font) > max) {
        let n = w.length;
        while (n > 1 && width(w.slice(0, n), size, font) > max) n--;
        out.push(w.slice(0, n));
        w = w.slice(n);
      }
      line = w;
    }
    out.push(line);
  }
  return out;
}

class Doc {
  pages: string[][] = [];
  links: { page: number; rect: [number, number, number, number]; url: string }[][] = [];
  y = 0;
  constructor(private readonly footer: string) { this.page(); }
  get ops() { return this.pages[this.pages.length - 1]!; }
  page() {
    this.pages.push([]);
    this.links.push([]);
    this.y = H - M;
  }
  need(h: number) { if (this.y - h < M + 24) this.page(); }
  text(x: number, y: number, s: string, size: number, font: Font, color: RGB = INK) {
    this.ops.push(`BT /${font} ${size} Tf ${color.map((c) => c.toFixed(3)).join(' ')} rg ${x.toFixed(1)} ${y.toFixed(1)} Td (${esc(s)}) Tj ET`);
  }
  rect(x: number, y: number, w: number, h: number, color: RGB) {
    this.ops.push(`${color.map((c) => c.toFixed(3)).join(' ')} rg ${x.toFixed(1)} ${y.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re f`);
  }
  line(y: number, color: RGB = [0.85, 0.87, 0.88]) {
    this.ops.push(`${color.map((c) => c.toFixed(3)).join(' ')} RG 0.8 w ${M} ${y.toFixed(1)} m ${W - M} ${y.toFixed(1)} l S`);
  }
  para(s: string, size: number, font: Font, color: RGB = INK, indent = 0, lead = 1.45) {
    for (const l of wrap(s, size, font, CW - indent)) {
      this.need(size * lead);
      this.y -= size * lead;
      this.text(M + indent, this.y, l, size, font, color);
    }
  }
  build(): Buffer {
    const objs: string[] = [];
    const add = (s: string) => { objs.push(s); return objs.length; };
    add('<< /Type /Catalog /Pages 2 0 R >>');
    add('PAGES');
    const f1 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
    const f2 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
    const f3 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');
    const kids: number[] = [];
    this.pages.forEach((ops, i) => {
      const foot = `BT /F1 8 Tf ${MUTE.join(' ')} rg ${M} 28 Td (${esc(ansi(this.footer))}) Tj ET BT /F1 8 Tf ${MUTE.join(' ')} rg ${W - M - 40} 28 Td (Page ${i + 1} of ${this.pages.length}) Tj ET`;
      const content = [...ops, foot].join('\n');
      const c = add(`<< /Length ${Buffer.byteLength(content, 'latin1')} >>\nstream\n${content}\nendstream`);
      const annots = this.links[i]!.map((l) => add(`<< /Type /Annot /Subtype /Link /Rect [${l.rect.map((n) => n.toFixed(1)).join(' ')}] /Border [0 0 0] /A << /S /URI /URI (${esc(ansi(l.url))}) >> >>`));
      kids.push(add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R /F3 ${f3} 0 R >> >> /Contents ${c} 0 R${annots.length ? ` /Annots [${annots.map((a) => `${a} 0 R`).join(' ')}]` : ''} >>`));
    });
    objs[1] = `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`;
    add('<< /Producer (Oculon) /Title (Oculon report) >>');
    return Buffer.from(rebuild(objs), 'latin1');
  }
}

function rebuild(objs: string[]): string {
  let out = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n';
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(Buffer.byteLength(out, 'latin1'));
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info ${objs.length} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return out;
}

/** Render blocks to a PDF file. `footer` is printed on every page. */
export function renderPdf(blocks: Block[], footer: string): Buffer {
  const d = new Doc(footer);
  for (const b of blocks) {
    switch (b.t) {
      case 'title':
        d.text(M, d.y - 10, 'OCULON', 9, 'F2', ACCENT);
        d.y -= 22;
        d.para(b.text, 20, 'F2', INK, 0, 1.25);
        d.y -= 8;
        d.line(d.y);
        d.y -= 6;
        break;
      case 'h':
        d.need(40);
        d.y -= 14;
        d.para(b.text.toUpperCase(), 9.5, 'F2', ACCENT, 0, 1.6);
        d.y -= 2;
        break;
      case 'p':
        d.para(b.text, b.size ?? 10.5, 'F1', b.color ?? INK);
        break;
      case 'mono':
        d.para(b.text, 8.5, 'F3', INK, 0, 1.4);
        break;
      case 'bullets':
        for (const it of b.items) {
          const lines = wrap(it, 10.5, 'F1', CW - 14);
          lines.forEach((l, i) => {
            d.need(15);
            d.y -= 15;
            if (i === 0) d.text(M, d.y, '-', 10.5, 'F2', b.color ?? ACCENT);
            d.text(M + 14, d.y, l, 10.5, 'F1');
          });
        }
        break;
      case 'kv':
        for (const [k, v] of b.rows) {
          const lines = wrap(v, 10, 'F1', CW - 150);
          lines.forEach((l, i) => {
            d.need(15);
            d.y -= 15;
            if (i === 0) d.text(M, d.y, ansi(k), 9, 'F2', MUTE);
            d.text(M + 150, d.y, l, 10, 'F1');
          });
          d.y -= 3;
        }
        break;
      case 'bar': {
        d.need(48);
        d.y -= 42;
        d.rect(M, d.y, CW, 36, b.color);
        d.text(M + 14, d.y + 22, ansi(b.label), 8, 'F2', [1, 1, 1]);
        d.text(M + 14, d.y + 8, ansi(b.text).slice(0, 70), 14, 'F2', [1, 1, 1]);
        d.y -= 4;
        break;
      }
      case 'link': {
        d.need(15);
        d.y -= 15;
        const s = ansi(b.text);
        d.text(M, d.y, s, 10, 'F1', ACCENT);
        d.links[d.pages.length - 1]!.push({ page: d.pages.length - 1, rect: [M, d.y - 2, M + width(s, 10, 'F1'), d.y + 10], url: b.url });
        break;
      }
      case 'table': {
        const xs = b.widths.reduce<number[]>((a, w, i) => [...a, (a[i - 1] ?? M) + (i ? b.widths[i - 1]! : 0)], []).map((x, i) => (i === 0 ? M : x));
        const row = (cells: string[], font: Font, color: RGB) => {
          const wrapped = cells.map((c, i) => wrap(c, 8.5, font, b.widths[i]! - 6));
          const h = Math.max(...wrapped.map((w) => w.length)) * 11 + 4;
          d.need(h);
          wrapped.forEach((ls, i) => ls.forEach((l, j) => d.text(xs[i]!, d.y - 11 - j * 11, l, 8.5, font, color)));
          d.y -= h;
          d.line(d.y + 1);
        };
        row(b.head, 'F2', MUTE);
        for (const r of b.rows) row(r, 'F1', INK);
        break;
      }
      case 'gap':
        d.y -= b.h ?? 8;
        break;
    }
  }
  return d.build();
}

export const TONE_RGB: Record<string, RGB> = { bad: [0.78, 0.18, 0.24], warn: [0.79, 0.52, 0.06], ok: [0.1, 0.55, 0.35], info: [0.25, 0.32, 0.36] };
