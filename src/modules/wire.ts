/**
 * Oculon Wire: the day in one card. Picks the strongest stored signals of the last 24 hours across a few fixed
 * desks (internet, air and sea, hazards, cyber, markets, space), at most six, and writes each as one line from the
 * signal's own title, its source names and its time. Nothing is generated: every line is a stored signal.
 *   wireToday():    the digest (JSON for /api/wire and the /today page)
 *   wirePostText(): the digest as one X post (no emoji, bullets, under 600 characters)
 *   wireCardPng():  the digest as a 1200x675 PNG card, drawn here without dependencies
 */
import { deflateSync } from 'node:zlib';
import type { Ctx } from '../core/context.js';
import { isOnchainEntity, ONCHAIN_MODULES, onchainEnabled } from '../core/features.js';
import type { Evidence } from '../core/types.js';

export type WireDesk = 'internet' | 'transport' | 'hazards' | 'cyber' | 'markets' | 'space';

export const DESK_LABEL: Record<WireDesk, string> = {
  internet: 'Internet',
  transport: 'Air and sea',
  hazards: 'Hazards',
  cyber: 'Cyber',
  markets: 'Markets',
  space: 'Space',
};

export interface WireItem {
  desk: WireDesk;
  label: string;
  headline: string;
  score: number;
  module: string;
  sources: string[];
  at: string;
  url: string | null;
  signalId: string;
}

export interface WireDigest {
  /** UTC day the window ends on, YYYY-MM-DD. */
  day: string;
  from: string;
  to: string;
  generatedAt: string;
  items: WireItem[];
  /** Signals in the window that belong to a desk (the pool the items were picked from). */
  considered: number;
  byDesk: Partial<Record<WireDesk, number>>;
  note: string | null;
}

const MAX_ITEMS = 6;
const SPACE_SRC = /swpc|donki|celestrak|space-track|satnogs/i;
const SPACE_TITLE = /\b(solar flare|geomagnetic|cme|kp \d|radio blackout|re-?entry|satellite|aurora)\b/i;
const HAZARD_SRC = /usgs|eonet|gdacs|firms|nws|emsc|tsunami/i;
const HAZARD_TITLE = /\b(earthquake|wildfire|fire activity|volcan|storm|cyclone|hurricane|typhoon|flood|tsunami|drought)\b/i;
const MARKET_SRC = /polymarket|kalshi|manifold|coingecko|finnhub|defillama|sec-edgar/i;

/** Which desk a stored signal belongs to, or null when it is not wire material (checks, watchlist, social). */
export function deskOf(module: string, title: string, evidence: Evidence[]): WireDesk | null {
  const srcs = evidence.map((e) => e.source).join(' ');
  switch (module) {
    case 'bgp': case 'blackout': case 'cloud': return 'internet';
    case 'falcon': case 'squawk': case 'darkships': case 'ships': case 'sky': return 'transport';
    case 'hazards': case 'fires': case 'impact': case 'quakes': return 'hazards';
    case 'vulns': case 'ransomware': return 'cyber';
    case 'raven': case 'lynx': case 'defi': case 'filings': case 'health': return 'markets';
    case 'satellites': return 'space';
    case 'condor':
      if (SPACE_SRC.test(srcs) || SPACE_TITLE.test(title)) return 'space';
      if (HAZARD_SRC.test(srcs) || HAZARD_TITLE.test(title)) return 'hazards';
      return null;
    case 'owl': {
      // Owl fuses attention spikes from many places; it joins a desk only when its lead source is that desk's source.
      const lead = evidence[0]?.source ?? '';
      if (MARKET_SRC.test(lead)) return 'markets';
      if (SPACE_SRC.test(lead) || SPACE_TITLE.test(title)) return 'space';
      if (HAZARD_SRC.test(lead) || HAZARD_TITLE.test(title)) return 'hazards';
      return null;
    }
    default: return null;
  }
}

/** One clean line: no line breaks, no doubled spaces, cut at a word near `max`. */
export function oneLine(s: string, max = 140): string {
  const t = s.replace(/\s+/g, ' ').trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max - 3);
  const sp = cut.lastIndexOf(' ');
  return `${(sp > max * 0.6 ? cut.slice(0, sp) : cut).replace(/[\s,;:(-]+$/, '')}...`;
}

const norm = (t: string) => t.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 60);

interface Row { id: string; module: string; entity_id: string | null; title: string; score: number; evidence: string; created_at: number }

function windowOf(now: Date, date?: string): { from: number; to: number } {
  if (date !== undefined && date !== '') {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(`${date}T00:00:00Z`))) throw new Error('date must be YYYY-MM-DD');
    const end = Math.min(now.getTime(), Date.parse(`${date}T00:00:00Z`) + 86_400_000);
    return { from: end - 86_400_000, to: end };
  }
  return { from: now.getTime() - 86_400_000, to: now.getTime() };
}

const ctxOf = (x: Ctx | { ctx: Ctx }): Ctx => ('ctx' in x ? x.ctx : x);

/** The digest for the 24 hours ending now (or at the end of `date`, a UTC day). */
export function wireToday(source: Ctx | { ctx: Ctx }, date?: string): WireDigest {
  const ctx = ctxOf(source);
  const now = ctx.now();
  const { from, to } = windowOf(now, date);
  const rows = ctx.store.db.prepare('SELECT id, module, entity_id, title, score, evidence, created_at FROM signals WHERE created_at >= ? AND created_at < ? ORDER BY score DESC, created_at DESC LIMIT 3000').all(from, to) as unknown as Row[];
  const on = onchainEnabled();
  const pool: (WireItem & { key: string })[] = [];
  const byDesk: Partial<Record<WireDesk, number>> = {};
  for (const r of rows) {
    if (!on && (ONCHAIN_MODULES.has(r.module) || (r.entity_id && isOnchainEntity(r.entity_id)))) continue;
    let ev: Evidence[] = [];
    try { ev = JSON.parse(r.evidence) as Evidence[]; } catch { /* keep empty */ }
    if (!Array.isArray(ev)) ev = [];
    const desk = deskOf(r.module, r.title, ev);
    if (!desk) continue;
    byDesk[desk] = (byDesk[desk] ?? 0) + 1;
    const url = ev.map((e) => e.url).find((u): u is string => typeof u === 'string' && /^https:\/\//i.test(u)) ?? null;
    pool.push({
      desk,
      label: DESK_LABEL[desk],
      headline: oneLine(r.title),
      score: Math.round(r.score),
      module: r.module,
      sources: [...new Set(ev.map((e) => String(e.source ?? '').trim()).filter(Boolean))].slice(0, 4),
      at: new Date(r.created_at).toISOString(),
      url,
      signalId: r.id,
      key: norm(r.title),
    });
  }
  // Strongest of each desk first, so one busy desk cannot fill the wire; then the next strongest, two per desk at most.
  const picked: typeof pool = [];
  const seen = new Set<string>();
  const perDesk = new Map<WireDesk, number>();
  const take = (it: (typeof pool)[number]) => { picked.push(it); seen.add(it.key); perDesk.set(it.desk, (perDesk.get(it.desk) ?? 0) + 1); };
  for (const it of pool) if (picked.length < MAX_ITEMS && !perDesk.has(it.desk) && !seen.has(it.key)) take(it);
  for (const it of pool) if (picked.length < MAX_ITEMS && !seen.has(it.key) && (perDesk.get(it.desk) ?? 0) < 2) take(it);
  picked.sort((a, b) => b.score - a.score || Date.parse(b.at) - Date.parse(a.at));
  const items = picked.map(({ key: _k, ...it }) => it);
  return {
    day: new Date(to - 1).toISOString().slice(0, 10),
    from: new Date(from).toISOString(),
    to: new Date(to).toISOString(),
    generatedAt: now.toISOString(),
    items,
    considered: pool.length,
    byDesk,
    note: items.length ? (items.length < 3 ? `Only ${items.length} signal${items.length === 1 ? '' : 's'} in this window belong to a desk.` : null) : 'No stored signals in this window belong to a desk (internet, air and sea, hazards, cyber, markets, space).',
  };
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const dayLabel = (day: string) => { const [y, m, d] = day.split('-'); return `${Number(d)} ${MONTHS[Number(m) - 1]} ${y}`; };

/** The digest as one X post: plain text, "•" bullets, under 600 characters, ending with the page link. */
export function wirePostText(d: WireDigest, link = 'oculon.live/today'): string {
  const head = `Oculon Wire, ${dayLabel(d.day)}`;
  if (!d.items.length) return `${head}\n\nA quiet day: no signals on the wire desks in the last 24 hours.\n\n${link}`;
  const build = (items: WireItem[], max: number) => `${head}\n\n${items.map((i) => `• ${i.label}: ${oneLine(i.headline, max)}`).join('\n')}\n\n${link}`;
  let items = d.items.slice();
  for (;;) {
    for (let max = 120; max >= 50; max -= 10) {
      const t = build(items, max);
      if (t.length < 600) return t;
    }
    if (items.length <= 1) return build(items, 50).slice(0, 599);
    items = items.slice(0, -1);
  }
}

/* ---------------- PNG card ---------------- */

// 5x7 bitmap font (columns, least significant bit on top; bit 7 is the descender row), ASCII 32-126.
const FONT = '0000000000' + '00005f0000' + '0007000700' + '147f147f14' + '242a7f2a12' + '2313086462' + '3649562050' + '0008070300' + '001c224100' + '0041221c00' + '2a1c7f1c2a' + '08083e0808' + '0080703000' + '0808080808' + '0000606000' + '2010080402'
  + '3e5149453e' + '00427f4000' + '7249494946' + '2141494d33' + '1814127f10' + '2745454539' + '3c4a494931' + '4121110907' + '3649494936' + '464949291e' + '0000140000' + '0040340000' + '0008142241' + '1414141414' + '0041221408' + '0201590906'
  + '3e415d594e' + '7c1211127c' + '7f49494936' + '3e41414122' + '7f4141413e' + '7f49494941' + '7f09090901' + '3e41415173' + '7f0808087f' + '00417f4100' + '2040413f01' + '7f08142241' + '7f40404040' + '7f021c027f' + '7f0408107f' + '3e4141413e'
  + '7f09090906' + '3e4151215e' + '7f09192946' + '2649494932' + '03017f0103' + '3f4040403f' + '1f2040201f' + '3f4038403f' + '6314081463' + '0304780403' + '6159494d43' + '007f414141' + '0204081020' + '004141417f' + '0402010204' + '4040404040'
  + '0003070800' + '2054547840' + '7f28444438' + '3844444428' + '384444287f' + '3854545418' + '00087e0902' + '18a4a49c78' + '7f08040478' + '00447d4000' + '2040403d00' + '7f10284400' + '00417f4000' + '7c0478047c' + '7c08040478' + '3844444438'
  + 'fc18242418' + '18242418fc' + '7c08040408' + '4854545424' + '04043f4424' + '3c4040207c' + '1c2040201c' + '3c4030403c' + '4428102844' + '4c9090907c' + '4464544c44' + '0008364100' + '0000770000' + '0041360800' + '0201020402';

/** Plain ASCII for the bitmap font: accents dropped, typographic quotes and dashes replaced. */
export function asciiOnly(s: string): string {
  return s
    .replace(/[\u2018\u2019\u201a\u2032]/g, "'").replace(/[\u201c\u201d\u201e\u2033]/g, '"').replace(/[\u2013\u2014\u2212]/g, '-').replace(/\u2026/g, '...').replace(/\u00b7|\u2022/g, '-').replace(/\u00b0/g, ' deg')
    .normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^\x20-\x7e]/g, '?');
}

class Canvas {
  readonly px: Uint8Array;
  constructor(readonly w: number, readonly h: number, bg: number) {
    this.px = new Uint8Array(w * h * 3);
    for (let i = 0; i < w * h; i++) { this.px[i * 3] = bg >> 16; this.px[i * 3 + 1] = (bg >> 8) & 255; this.px[i * 3 + 2] = bg & 255; }
  }
  rect(x: number, y: number, w: number, h: number, c: number): void {
    const x0 = Math.max(0, Math.round(x)), y0 = Math.max(0, Math.round(y)), x1 = Math.min(this.w, Math.round(x + w)), y1 = Math.min(this.h, Math.round(y + h));
    for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) { const o = (yy * this.w + xx) * 3; this.px[o] = c >> 16; this.px[o + 1] = (c >> 8) & 255; this.px[o + 2] = c & 255; }
  }
  /** Text in the bitmap font at `scale`; `track` adds space between letters. Returns the width drawn. */
  text(s: string, x: number, y: number, scale: number, c: number, track = 0): number {
    let cx = x;
    for (const ch of asciiOnly(s)) {
      const k = ch.charCodeAt(0) - 32;
      for (let col = 0; col < 5; col++) {
        const bits = parseInt(FONT.slice(k * 10 + col * 2, k * 10 + col * 2 + 2), 16);
        for (let row = 0; row < 8; row++) if (bits & (1 << row)) this.rect(cx + col * scale, y + row * scale, scale, scale, c);
      }
      cx += 6 * scale + track;
    }
    return cx - x;
  }
  png(): Buffer {
    const raw = Buffer.alloc((this.w * 3 + 1) * this.h);
    for (let y = 0; y < this.h; y++) { raw[y * (this.w * 3 + 1)] = 0; Buffer.from(this.px.buffer, this.px.byteOffset + y * this.w * 3, this.w * 3).copy(raw, y * (this.w * 3 + 1) + 1); }
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(this.w, 0); ihdr.writeUInt32BE(this.h, 4); ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
    return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
  }
}

const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(b: Buffer): number { let c = 0xffffffff; for (const x of b) c = CRC_TABLE[(c ^ x) & 255]! ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function chunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

const CYAN = 0x00f0ff, WHITE = 0xf2f6f7, MUTED = 0x8a9a9e, DIM = 0x0c1618, LINE = 0x1b2a2e;
const fit = (s: string, chars: number) => { const t = asciiOnly(s); return t.length <= chars ? t : `${t.slice(0, chars - 3).replace(/\s+\S*$/, '') || t.slice(0, chars - 3)}...`; };

/** The digest as a 1200x675 PNG card: black, cyan accents, one row per item. */
export function wireCardPng(d: WireDigest, link = 'oculon.live/today'): Buffer {
  const W = 1200, H = 675, L = 60, R = W - 60;
  const c = new Canvas(W, H, 0x000000);
  for (let y = 15; y < H; y += 30) for (let x = 15; x < W; x += 30) c.rect(x, y, 2, 2, DIM);
  c.rect(0, 0, W, 6, CYAN);
  const wOc = c.text('OCULON', L, 44, 5, CYAN, 6);
  c.text('WIRE', L + wOc + 24, 44, 5, WHITE, 6);
  const date = dayLabel(d.day).toUpperCase();
  c.text(date, R - date.length * 18, 52, 3, MUTED);
  c.rect(L, 112, R - L, 2, LINE);
  c.rect(L, 112, 120, 2, CYAN);
  if (!d.items.length) {
    c.text('A quiet day on the wire.', L, 250, 4, WHITE);
    c.text('No stored signals on any desk in these 24 hours.', L, 320, 3, MUTED);
  } else {
    const n = d.items.length, rowH = Math.min(78, Math.floor(470 / n)), headScale = rowH >= 70 ? 3 : 2;
    d.items.forEach((it, i) => {
      const y = 138 + i * rowH;
      c.rect(L, y + 2, 6, rowH - 22, CYAN);
      const lbl = it.label.toUpperCase();
      const lw = c.text(lbl, L + 24, y, 2, CYAN, 2);
      const meta = `${it.at.slice(11, 16)} UTC  ${it.sources.slice(0, 2).join(', ')}`;
      c.text(fit(meta, Math.floor((R - (L + 24 + lw + 24)) / 12) - 6), L + 24 + lw + 24, y, 2, MUTED);
      const sc = String(it.score);
      c.text(sc, R - sc.length * 12, y, 2, it.score >= 75 ? CYAN : MUTED);
      c.text(fit(it.headline, Math.floor((R - (L + 24)) / (6 * headScale - 2))), L + 24, y + 22, headScale, WHITE, -2);
    });
  }
  c.rect(L, H - 72, R - L, 2, LINE);
  c.text(link, L, H - 50, 3, CYAN);
  const right = `${d.considered} desk signal${d.considered === 1 ? '' : 's'} in 24h, top ${d.items.length} shown`;
  c.text(right, R - asciiOnly(right).length * 12, H - 46, 2, MUTED);
  return c.png();
}
