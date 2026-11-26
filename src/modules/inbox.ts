/**
 * Scam Inbox: people forward a suspicious email to check@<domain> and get the verdict back by email.
 *   Mail arrives through a Cloudflare Email Worker (edge/inbox), which posts the raw message here with a shared
 *   secret (OCULON_INBOX_SECRET) and the envelope sender.
 *   A forwarded message attached as .eml or message/rfc822 is checked in full (headers, body, attachments). A
 *   message forwarded inline is rebuilt from the forwarded text: its original headers are gone, so SPF, DKIM and
 *   DMARC cannot be read and only the text, links and attachments are checked.
 *   The check is the email file check (emlCheck), stored like every other check, so the reply links to its page.
 *   Kept: the check record (as for any check, 90 days) and, per message, a one-way hash of the sender address, the
 *   verdict and the check id for the daily limits (30 days). The raw email is not stored.
 *   Limits: 10 replies per sender per day and 300 per day in total; mail from the inbox's own domain is never
 *   answered, nor mail whose sending domain failed authentication at the receiving server.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { DatabaseSync } from 'node:sqlite';
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { sendEmail, type MailResult } from '../sources/resend.js';
import { recordCheck } from './checks.js';
import { emlCheck, mimeParts, type EmlReport } from './eml.js';
import { analyzeHeaders } from './headers.js';

export const INBOX_LIMITS = { perSender: 10, perDay: 300, maxBytes: 6 * 1024 * 1024, keepDays: 30 } as const;

export interface InboxOptions {
  /** Base URL for report links (e.g. https://app.oculon.live). */
  base?: string;
  /** The domain whose own addresses are never answered (default OCULON_DOMAIN or oculon.live). */
  domain?: string;
  /** Fetch used for the reply (tests). */
  fetch?: typeof fetch;
  perSender?: number;
  perDay?: number;
}

export type InboxStatus = 'replied' | 'skipped' | 'limited' | 'failed';

export interface InboxResult {
  status: InboxStatus;
  reason: string;
  verdict?: EmlReport['verdict'];
  checkId?: string;
  /** How the checked message was found: an attached .eml, or the forwarded text. */
  mode?: 'attached' | 'inline';
}

const ready = new WeakSet<DatabaseSync>();
function db(ctx: Ctx): DatabaseSync {
  const d = ctx.store.db;
  if (!ready.has(d)) {
    d.exec(`CREATE TABLE IF NOT EXISTS inbox_log (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, day TEXT NOT NULL, at INTEGER NOT NULL, status TEXT NOT NULL, verdict TEXT, check_id TEXT);
      CREATE INDEX IF NOT EXISTS inbox_log_day ON inbox_log (day, sender);`);
    ready.add(d);
  }
  return d;
}

/** Constant-time comparison of the header the Worker sends with OCULON_INBOX_SECRET. */
export function inboxAuthorized(given: string | undefined, secret: string | undefined = key('OCULON_INBOX_SECRET')): boolean {
  if (!secret || !given) return false;
  const a = createHash('sha256').update(given).digest();
  const b = createHash('sha256').update(secret).digest();
  return timingSafeEqual(a, b);
}

const senderHash = (addr: string) => createHash('sha256').update(`inbox\n${addr.trim().toLowerCase()}`).digest('hex').slice(0, 32);
const dayOf = (d: Date) => d.toISOString().slice(0, 10);

/** The plain address from an envelope sender or a From header ("Name <a@b.c>" -> a@b.c), or null. */
export function plainAddress(s: string | null | undefined): string | null {
  const v = String(s ?? '').trim();
  const m = /<([^<>\s]+@[^<>\s]+)>/.exec(v)?.[1] ?? /[^\s<>"]+@[^\s<>"]+/.exec(v)?.[0];
  if (!m) return null;
  const a = m.toLowerCase().replace(/[>.,;]+$/, '');
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(a) && a.length <= 254 ? a : null;
}

const htmlToText = (h: string) => h.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<br\s*\/?>|<\/(p|div|tr|li)>/gi, '\n').replace(/<a\b[^>]*href=["']([^"']+)["'][^>]*>/gi, ' $1 ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/[ \t]+/g, ' ');

const partText = (p: { headers: Record<string, string>; body: Buffer }) => {
  const cs = /charset="?([\w-]+)/i.exec(p.headers['content-type'] ?? '')?.[1] ?? 'utf-8';
  return /utf-?8|us-ascii/i.test(cs) ? p.body.toString('utf8') : p.body.toString('latin1');
};

/**
 * The message to check inside a forwarded email: an attached .eml or message/rfc822 when there is one, otherwise
 * a message rebuilt from the forwarded text (the original From and Subject lines when the mail app wrote them).
 */
export function extractForwarded(raw: Buffer): { message: Buffer; mode: 'attached' | 'inline' } {
  const { head, parts } = mimeParts(raw);
  const attached = parts.find((p) => {
    const ct = (p.headers['content-type'] ?? '').toLowerCase();
    const name = /filename\*?="?([^";]+)"?/i.exec(p.headers['content-disposition'] ?? '')?.[1] ?? /name="?([^";]+)"?/i.exec(p.headers['content-type'] ?? '')?.[1] ?? '';
    return (ct.startsWith('message/rfc822') || /\.eml$/i.test(name)) && p.body.length > 20;
  });
  if (attached) return { message: attached.body, mode: 'attached' };

  const plain = parts.find((p) => /^text\/plain/i.test(p.headers['content-type'] ?? 'text/plain') && !/attachment/i.test(p.headers['content-disposition'] ?? ''));
  const html = parts.find((p) => /^text\/html/i.test(p.headers['content-type'] ?? '') && !/attachment/i.test(p.headers['content-disposition'] ?? ''));
  let text = plain ? partText(plain) : html ? htmlToText(partText(html)) : '';
  // Links behind HTML anchors are often missing from the plain part: keep them.
  if (html) {
    const extra = [...partText(html).matchAll(/href=["'](https?:\/\/[^"']+)["']/gi)].map((m) => m[1]!.replace(/&amp;/g, '&')).filter((u) => !text.includes(u));
    if (extra.length) text += `\n\nLinks in the message:\n${[...new Set(extra)].slice(0, 30).join('\n')}`;
  }
  text = text.replace(/\r\n/g, '\n');
  // Gmail, Outlook and Apple Mail start an inline forward with a block of the original headers.
  const marker = /^[ \t>]*(-{2,}\s*(forwarded message|original message)\s*-{2,}|begin forwarded message:)[ \t]*$/im.exec(text);
  let origFrom: string | null = null, origSubject: string | null = null;
  if (marker) {
    const after = text.slice(marker.index + marker[0].length);
    const block = after.split(/\n[ \t>]*\n/)[0] ?? '';
    origFrom = /^[ \t>]*from:\s*(.+)$/im.exec(block)?.[1]?.trim() ?? null;
    origSubject = /^[ \t>]*subject:\s*(.+)$/im.exec(block)?.[1]?.trim() ?? null;
  }
  const outerSubject = (head.subject ?? '').replace(/^\s*((fwd?|fw)\s*:\s*)+/i, '').trim();
  const subject = (origSubject ?? outerSubject) || 'Forwarded message';
  // No From header on purpose: the forwarder's own headers are not the scam's, so the header check is skipped.
  const body = `${origFrom ? `From: ${origFrom}\n` : ''}${text}`.slice(0, 200_000);
  const msg = `Subject: ${subject.replace(/[\r\n]+/g, ' ').slice(0, 300)}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${body}`;
  return { message: Buffer.from(msg, 'utf8'), mode: 'inline' };
}

const esc = (t: string) => t.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** The reply: verdict, top reasons, advice and the link to the full report. */
export function inboxReply(r: EmlReport, opts: { reportUrl: string | null; mode: 'attached' | 'inline' }): { subject: string; text: string; html: string } {
  const reasons = r.reasons.slice(0, 4);
  const label = r.verdict.charAt(0).toUpperCase() + r.verdict.slice(1);
  const subject = `Oculon check: ${label}${r.subject ? ` - ${r.subject.replace(/[\r\n]+/g, ' ').slice(0, 80)}` : ''}`;
  const note = opts.mode === 'inline'
    ? 'This email was forwarded inline, so its original headers (SPF, DKIM, DMARC, delivery path) were not available and only its text, links and attachments were checked. Forward it as an attachment for a full check.'
    : null;
  const color = r.verdict === 'no known risk found' ? '#1a7f4b' : r.verdict === 'suspicious' ? '#a15c00' : '#b3261e';
  const text = [
    `Verdict: ${label} (risk ${r.risk}/100)`,
    r.subject ? `Checked: "${r.subject}"${r.from ? ` from ${r.from}` : ''}` : null,
    '',
    reasons.length ? 'Why:' : 'No warning signs were found by the sources checked.',
    ...reasons.map((x) => `- ${x}`),
    '',
    ...r.advice,
    opts.reportUrl ? `\nFull report: ${opts.reportUrl}` : null,
    note ? `\n${note}` : null,
    '\nA verdict is what the sources found at this moment, not a guarantee. Oculon never asks for passwords or payments by email.',
  ].filter((l): l is string => l !== null).join('\n');
  const html = `<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:15px;line-height:1.55;color:#111;max-width:560px">
<p style="margin:0 0 6px;font:600 11px monospace;letter-spacing:.2em;color:#555">OCULON SCAM INBOX</p>
<h2 style="margin:0 0 6px;color:${color};font-weight:600">${esc(label)} <span style="color:#666;font-weight:400;font-size:15px">risk ${r.risk}/100</span></h2>
${r.subject ? `<p style="margin:0 0 14px;color:#444">Checked: "${esc(r.subject)}"${r.from ? ` from ${esc(r.from)}` : ''}</p>` : ''}
${reasons.length ? `<p style="margin:0 0 4px"><b>Why</b></p><ul style="margin:0 0 14px;padding-left:20px">${reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p>No warning signs were found by the sources checked.</p>'}
${r.advice.map((a) => `<p style="margin:0 0 10px">${esc(a)}</p>`).join('')}
${opts.reportUrl ? `<p style="margin:16px 0"><a href="${esc(opts.reportUrl)}" style="color:#0a58ca">Open the full report</a></p>` : ''}
${note ? `<p style="margin:0 0 10px;color:#555;font-size:13px">${esc(note)}</p>` : ''}
<p style="margin:14px 0 0;color:#777;font-size:12px">A verdict is what the sources found at this moment, not a guarantee. Oculon never asks for passwords or payments by email.</p>
</div>`;
  return { subject, text, html };
}

function log(ctx: Ctx, sender: string, status: InboxStatus, verdict: string | null, checkId: string | null) {
  const d = db(ctx);
  const now = ctx.now();
  d.prepare('INSERT INTO inbox_log (sender, day, at, status, verdict, check_id) VALUES (?, ?, ?, ?, ?, ?)').run(sender, dayOf(now), now.getTime(), status, verdict, checkId);
  if (Math.random() < 0.05) d.prepare('DELETE FROM inbox_log WHERE at < ?').run(now.getTime() - INBOX_LIMITS.keepDays * 86_400_000);
}

/** Replies sent today: to this sender and in total. */
export function inboxUsage(ctx: Ctx, from: string): { sender: number; total: number } {
  const d = db(ctx);
  const day = dayOf(ctx.now());
  const one = (sql: string, ...a: string[]) => Number(Object.values(d.prepare(sql).get(...a) as Record<string, number>)[0] ?? 0);
  return {
    sender: one("SELECT count(*) FROM inbox_log WHERE day = ? AND sender = ? AND status = 'replied'", day, senderHash(from)),
    total: one("SELECT count(*) FROM inbox_log WHERE day = ? AND status = 'replied'", day),
  };
}

/**
 * One forwarded email: find the message in it, run the email check, store the check and answer the sender.
 * `oculon` is anything with a context (the Oculon instance).
 */
export async function handleInbox(oculon: { ctx: Ctx }, raw: Buffer | string, from: string, opts: InboxOptions = {}): Promise<InboxResult> {
  const ctx = oculon.ctx;
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'utf8');
  const sender = plainAddress(from);
  const domain = (opts.domain ?? process.env.OCULON_DOMAIN ?? 'oculon.live').trim().toLowerCase() || 'oculon.live';
  if (!sender) return { status: 'skipped', reason: 'no valid sender address' };
  const sDomain = sender.split('@')[1]!;
  if (sDomain === domain || sDomain.endsWith(`.${domain}`)) return { status: 'skipped', reason: `mail from ${domain} itself is never answered` };
  if (/^(mailer-daemon|postmaster|no-?reply|do-?not-?reply|bounce[s]?)([+@.-]|$)/i.test(sender)) return { status: 'skipped', reason: 'automated sender' };
  if (!buf.length) return { status: 'skipped', reason: 'empty message' };
  if (buf.length > INBOX_LIMITS.maxBytes) return { status: 'skipped', reason: 'message over the size limit' };

  // The forwarding message itself: automated mail is not answered, and a sender that failed authentication at the
  // receiving server may be forged (answering it would send mail to someone who did not ask).
  const outer = mimeParts(buf.subarray(0, 300_000)).head;
  if ((outer['auto-submitted'] && !/^no\b/i.test(outer['auto-submitted'])) || /^(bulk|list|junk|auto_reply)$/i.test(outer.precedence ?? '') || outer['list-id']) {
    return { status: 'skipped', reason: 'automated or list mail' };
  }
  const headRaw = buf.subarray(0, 300_000).toString('latin1').split(/\r?\n\r?\n/)[0] ?? '';
  const auth = analyzeHeaders(headRaw).auth;
  const failed = (v: string | null) => v === 'fail' || v === 'softfail' || v === 'permerror';
  if (auth.dmarc === 'fail' || (failed(auth.spf) && auth.dkim !== 'pass')) return { status: 'skipped', reason: 'the sending domain failed authentication' };

  const usage = inboxUsage(ctx, sender);
  const hash = senderHash(sender);
  // OCULON_INBOX_PER_DAY lowers the total to fit the mail plan (Resend's free plan has its own daily cap).
  const perDay = opts.perDay ?? (Number(process.env.OCULON_INBOX_PER_DAY) > 0 ? Math.min(INBOX_LIMITS.perDay, Number(process.env.OCULON_INBOX_PER_DAY)) : INBOX_LIMITS.perDay);
  if (usage.sender >= (opts.perSender ?? INBOX_LIMITS.perSender) || usage.total >= perDay) {
    log(ctx, hash, 'limited', null, null);
    return { status: 'limited', reason: usage.sender >= (opts.perSender ?? INBOX_LIMITS.perSender) ? 'daily limit for this sender reached' : 'daily limit for the inbox reached' };
  }

  const { message, mode } = extractForwarded(buf);
  let verdict: EmlReport | null = null, checkId: string | null = null;
  try {
    const fileHash = createHash('sha256').update(message).digest('hex');
    const r = await recordCheck(ctx, 'eml', fileHash, () => emlCheck(ctx, message, 'forwarded.eml'), { label: `forwarded email: ${(mimeParts(message.subarray(0, 100_000)).head.subject ?? 'no subject').replace(/\s+/g, ' ').slice(0, 70)}` });
    verdict = r.value.result;
    checkId = r.check.id;
  } catch (e) {
    log(ctx, hash, 'failed', null, null);
    return { status: 'failed', reason: `the email could not be checked: ${(e as Error).message.slice(0, 120)}`, mode };
  }

  const base = (opts.base ?? (process.env.OCULON_DOMAIN?.trim() ? `https://app.${process.env.OCULON_DOMAIN.trim()}` : '')).replace(/\/+$/, '');
  const reply = inboxReply(verdict, { reportUrl: base ? `${base}/replay/${checkId}` : null, mode });
  const sent: MailResult = await sendEmail({ to: sender, subject: reply.subject, text: reply.text, html: reply.html }, opts.fetch);
  log(ctx, hash, sent.ok ? 'replied' : 'failed', verdict.verdict, checkId);
  return sent.ok
    ? { status: 'replied', reason: 'verdict sent', verdict: verdict.verdict, checkId, mode }
    : { status: 'failed', reason: `the reply could not be sent: ${sent.error ?? 'unknown error'}`, verdict: verdict.verdict, checkId, mode };
}

/**
 * POST /api/inbox from the Email Worker: raw MIME in the body, x-oculon-inbox (the secret) and x-oculon-from (the
 * envelope sender) in headers. Answers 202 at once and checks in the background, so the Worker is not held.
 * Not browser-facing: no cookies, no CORS; only the secret header admits a request.
 */
export async function inboxRoute(oculon: { ctx: Ctx }, req: IncomingMessage, res: ServerResponse, opts: InboxOptions & { log?: (m: string) => void; secret?: string } = {}): Promise<void> {
  const reply = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
  if (req.method !== 'POST') return reply(405, { error: 'method not allowed' });
  const secret = opts.secret ?? key('OCULON_INBOX_SECRET');
  if (!secret) return reply(404, { error: 'not found' });
  if (!inboxAuthorized(String(req.headers['x-oculon-inbox'] ?? ''), secret)) return reply(403, { error: 'forbidden' });
  const from = String(req.headers['x-oculon-from'] ?? '');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > INBOX_LIMITS.maxBytes) { req.resume(); return reply(413, { error: 'message too large' }); }
    chunks.push(c as Buffer);
  }
  reply(202, { accepted: true });
  const logLine = opts.log ?? (() => {});
  void handleInbox(oculon, Buffer.concat(chunks), from, opts)
    .then((r) => logLine(`inbox: ${r.status} (${r.reason}${r.verdict ? `, ${r.verdict}` : ''}${r.mode ? `, ${r.mode}` : ''})`))
    .catch((e) => logLine(`inbox failed: ${(e as Error).message}`));
}
