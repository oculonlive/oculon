/**
 * Email file check: one .eml file (Gmail "Download message", Outlook "Save as", Apple Mail) checked in full.
 *   Headers: SPF, DKIM, DMARC, the delivery path and spoofing signs (the email header check).
 *   Body: the text and HTML parts go through the scam check (every link, the sender, known scam patterns).
 *   Attachments: PDF and Office files through the document check, images through the QR reader (QR codes in
 *     emails are a common way past link filters) and the image check, everything else hashed and looked up as
 *     known malware. Risky types (programs, scripts, disk images, HTML attachments) are flagged by name.
 * MIME is parsed here: multipart, base64, quoted-printable and encoded-word headers.
 */
import { createHash } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { verdictOf, type Tone } from '../core/verdict.js';
import { headerCheck } from './headers.js';
import { scamCheck } from './scam.js';
import { docCheck } from './doc.js';
import { qrCheck } from './qrcheck.js';
import { imageCheck } from './image.js';
import { hashCheck } from './hashcheck.js';

export interface EmlPart { name: string; type: string; bytes: number; sha256: string; check: string; verdict: string | null; tone: Tone; points: string[] }

export interface EmlReport {
  subject: string | null;
  from: string | null;
  to: string | null;
  date: string | null;
  verdict: 'dangerous email' | 'likely scam' | 'suspicious' | 'no known risk found';
  risk: number;
  headers: { verdict: string | null; tone: Tone; points: string[] } | null;
  body: { verdict: string | null; tone: Tone; points: string[]; links: number } | null;
  attachments: EmlPart[];
  reasons: string[];
  advice: string[];
}

interface Part { headers: Record<string, string>; body: Buffer }

const RISKY = /\.(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|lnk|iso|img|vhd|jar|apk|html?|svg|xll|one|reg|cpl|chm)$/i;

function decodeWords(s: string): string {
  return s.replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=/g, (_m, cs: string, enc: string, txt: string) => {
    try {
      const buf = enc.toUpperCase() === 'B' ? Buffer.from(txt, 'base64') : Buffer.from(txt.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (_x, h: string) => String.fromCharCode(parseInt(h, 16))), 'latin1');
      return /utf-?8/i.test(cs) ? buf.toString('utf8') : buf.toString('latin1');
    } catch { return txt; }
  });
}

function parseHead(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of raw.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0) { const k = line.slice(0, i).trim().toLowerCase(); if (!(k in out)) out[k] = line.slice(i + 1).trim(); }
  }
  return out;
}

function decodeBody(body: Buffer, enc: string | undefined): Buffer {
  const e = (enc ?? '').toLowerCase();
  if (e === 'base64') return Buffer.from(body.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  if (e === 'quoted-printable') return Buffer.from(body.toString('latin1').replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16))), 'latin1');
  return body;
}

/** Leaf parts of a MIME message, depth-first. */
export function mimeParts(raw: Buffer, depth = 0): { head: Record<string, string>; parts: Part[] } {
  const s = raw.toString('latin1');
  const sep = /\r?\n\r?\n/.exec(s);
  const headRaw = sep ? s.slice(0, sep.index) : s;
  const bodyStart = sep ? sep.index + sep[0].length : s.length;
  const head = parseHead(headRaw);
  const ct = head['content-type'] ?? 'text/plain';
  const boundary = /boundary="?([^";]+)"?/i.exec(ct)?.[1];
  if (/^multipart\//i.test(ct) && boundary && depth < 6) {
    const body = s.slice(bodyStart);
    const pieces = body.split(new RegExp(`\\r?\\n?--${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:--)?[ \\t]*\\r?\\n?`)).slice(1, -1).filter((p) => p.trim());
    const parts = pieces.flatMap((p) => mimeParts(Buffer.from(p, 'latin1'), depth + 1).parts);
    return { head, parts };
  }
  return { head, parts: [{ headers: head, body: decodeBody(Buffer.from(s.slice(bodyStart), 'latin1'), head['content-transfer-encoding']) }] };
}

const textOf = (p: Part) => { const cs = /charset="?([\w-]+)/i.exec(p.headers['content-type'] ?? '')?.[1] ?? 'utf-8'; return /utf-?8|us-ascii/i.test(cs) ? p.body.toString('utf8') : p.body.toString('latin1'); };
const htmlToText = (h: string) => h.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<a\b[^>]*href=["']([^"']+)["'][^>]*>/gi, ' $1 ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ');

export async function emlCheck(ctx: Ctx, file: Buffer, name = 'email.eml'): Promise<ModuleResult<EmlReport>> {
  if (!file.length) throw new Error('the file is empty');
  if (file.length > 25 * 1024 * 1024) throw new Error('the email is larger than 25 MB');
  const { head, parts } = mimeParts(file);
  if (!head.from && !head.received && !head.subject) throw new Error('not an email file (.eml): no From, Subject or Received headers');
  const provenance: Provenance[] = [{ source: 'oculon-eml', url: 'local', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: `${parts.length} MIME parts read here` }];
  const signals: Signal[] = [];
  const reasons: [string, number][] = [];
  const subject = head.subject ? decodeWords(head.subject).slice(0, 200) : null;

  // Headers.
  const rawHead = file.toString('latin1').split(/\r?\n\r?\n/)[0]!;
  let headers: EmlReport['headers'] = null;
  try {
    const h = await headerCheck(ctx, rawHead);
    provenance.push(...h.provenance.slice(0, 3));
    const v = verdictOf(h);
    headers = { verdict: v.verdict, tone: v.tone, points: v.points.slice(0, 5) };
    if (v.tone === 'bad') reasons.push([`headers: ${v.verdict}${v.points[0] ? ` (${v.points[0]})` : ''}`, 40]);
    else if (v.tone === 'warn') reasons.push([`headers: ${v.verdict}${v.points[0] ? ` (${v.points[0]})` : ''}`, 15]);
  } catch {}

  // Body text: the plain part, or the HTML part as text with its links kept.
  const texts = parts.filter((p) => /^text\/(plain|html)/i.test(p.headers['content-type'] ?? 'text/plain') && !/attachment/i.test(p.headers['content-disposition'] ?? ''));
  const plain = texts.find((p) => /text\/plain/i.test(p.headers['content-type'] ?? 'text/plain'));
  const html = texts.find((p) => /text\/html/i.test(p.headers['content-type'] ?? ''));
  const bodyText = `${head.from ? `From: ${decodeWords(head.from)}\n` : ''}${subject ? `Subject: ${subject}\n\n` : ''}${(plain ? textOf(plain) : '') + (html ? `\n${htmlToText(textOf(html))}` : '')}`.slice(0, 20_000);
  let body: EmlReport['body'] = null;
  if (bodyText.trim()) {
    try {
      const s = await scamCheck(ctx, bodyText);
      provenance.push(...s.provenance.slice(0, 6));
      signals.push(...s.signals);
      const v = verdictOf(s);
      const links = ((s.result as { links?: unknown[] }).links ?? []).length;
      body = { verdict: v.verdict, tone: v.tone, points: v.points.slice(0, 6), links };
      if (v.tone === 'bad') reasons.push([`message: ${v.verdict}${v.points[0] ? ` (${v.points[0]})` : ''}`, 55]);
      else if (v.tone === 'warn') reasons.push([`message: ${v.verdict}${v.points[0] ? ` (${v.points[0]})` : ''}`, 20]);
    } catch {}
  }

  // Attachments.
  const attachments: EmlPart[] = [];
  const files = parts.filter((p) => p !== plain && p !== html && (/attachment|inline/i.test(p.headers['content-disposition'] ?? '') || /name=/i.test(p.headers['content-type'] ?? '') || !/^text\//i.test(p.headers['content-type'] ?? 'text/plain')));
  for (const p of files.slice(0, 10)) {
    const fname = decodeWords(/filename\*?="?([^";]+)"?/i.exec(p.headers['content-disposition'] ?? '')?.[1] ?? /name="?([^";]+)"?/i.exec(p.headers['content-type'] ?? '')?.[1] ?? 'attachment');
    const type = (p.headers['content-type'] ?? 'application/octet-stream').split(';')[0]!.trim().toLowerCase();
    const sha256 = createHash('sha256').update(p.body).digest('hex');
    let check = 'hash', verdict: string | null = null, tone: Tone = 'info', points: string[] = [];
    const head4 = p.body.subarray(0, 8);
    try {
      let r: ModuleResult<unknown> | null = null;
      if (head4.toString('latin1', 0, 5) === '%PDF-' || head4.readUInt32LE(0) === 0x04034b50 && /\.(docx|docm|xlsx|xlsm|pptx)$/i.test(fname) || head4.readUInt32BE(0) === 0xd0cf11e0) { check = 'document'; r = await docCheck(ctx, p.body, fname); }
      else if (/^image\//.test(type) || /\.(png|jpe?g|webp)$/i.test(fname)) {
        check = 'qr code';
        const q = await qrCheck(ctx, p.body, fname).catch(() => null);
        if (q?.result.found) r = q;
        else { check = 'image'; r = await imageCheck(ctx, p.body, fname).catch(() => null); }
      } else { r = await hashCheck(ctx, sha256); }
      if (r) {
        provenance.push(...r.provenance.slice(0, 2));
        const v = verdictOf(r);
        verdict = v.verdict; tone = v.tone; points = v.points.slice(0, 4);
      }
    } catch (e) { points = [`not checked: ${(e as Error).message.slice(0, 80)}`]; }
    if (RISKY.test(fname)) { tone = 'bad'; points.unshift(`${fname.split('.').pop()!.toUpperCase()} attachment: a type that can run code or open a fake login page`); }
    if (tone === 'bad') reasons.push([`attachment ${fname}: ${verdict ?? 'risky type'}${points[0] ? ` (${points[0]})` : ''}`, RISKY.test(fname) ? 60 : 50]);
    else if (tone === 'warn') reasons.push([`attachment ${fname}: ${verdict}`, 20]);
    attachments.push({ name: fname.slice(0, 120), type, bytes: p.body.length, sha256, check, verdict, tone, points });
  }

  const risk = Math.min(100, reasons.reduce((s, [, w]) => s + w, 0));
  const danger = attachments.some((a) => a.tone === 'bad');
  const verdict: EmlReport['verdict'] = danger && risk >= 50 ? 'dangerous email' : risk >= 50 ? 'likely scam' : risk >= 20 ? 'suspicious' : 'no known risk found';
  const advice = verdict === 'dangerous email'
    ? ['Do not open the attachments. Delete the email, or report it as phishing in your mail app.']
    : verdict === 'likely scam' ? ['Do not click the links or reply. Contact the sender through a website or number you already know.'] : verdict === 'suspicious' ? ['Check with the sender through another channel before you act on it.'] : ['Nothing alarming found. Still type addresses yourself instead of clicking links for logins and payments.'];
  return {
    module: 'eml', input: name.slice(0, 120), generatedAt: ctx.now().toISOString(), signals, provenance,
    result: { subject, from: head.from ? decodeWords(head.from).slice(0, 200) : null, to: head.to ? decodeWords(head.to).slice(0, 200) : null, date: head.date ?? null, verdict, risk, headers, body, attachments, reasons: reasons.sort((a, b) => b[1] - a[1]).map(([r]) => r), advice },
  };
}
