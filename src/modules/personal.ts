/**
 * Personal monitors: each visitor (web) or chat (Telegram) keeps its own monitors, separate from the
 * install's shared watchlist. Owners are "web:<random id>" or "tg:<chat id>"; there are no accounts.
 * Monitors are written in plain language (see monitor.ts), re-checked about hourly, and changes are kept as
 * alerts for the owner, emailed to a confirmed address, or sent to the Telegram chat.
 */
import { randomBytes } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import { observe, type WatchItem, type WatchKind } from './meerkat.js';
import { parseMonitor, type MonitorRule } from './monitor.js';
import { mailEnabled, sendEmail } from '../sources/resend.js';

export const MAX_PER_OWNER = 10;
const HOUR = 3_600_000;

export interface PersonalMonitor { id: number; kind: WatchKind; target: string; description: string; createdAt: string; lastRun: string | null; lastChange: string | null }
export interface PersonalAlert { id: number; monitorId: number; text: string; createdAt: string }
export interface Delivery { owner: string; monitor: PersonalMonitor; changes: string[] }

const SCHEMA = `
CREATE TABLE IF NOT EXISTS personal_monitors (
  id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, description TEXT NOT NULL,
  created_at INTEGER NOT NULL, last_run INTEGER, last_state TEXT, last_change INTEGER, UNIQUE (owner, kind, target)
);
CREATE INDEX IF NOT EXISTS personal_monitors_owner ON personal_monitors (owner);
CREATE TABLE IF NOT EXISTS personal_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, monitor_id INTEGER NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS personal_alerts_owner ON personal_alerts (owner, created_at);
CREATE TABLE IF NOT EXISTS personal_emails (owner TEXT PRIMARY KEY, email TEXT NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0, token TEXT NOT NULL, sent_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS personal_emails_token ON personal_emails (token);
`;

const db = (ctx: Ctx) => { ctx.store.db.exec(SCHEMA); return ctx.store.db; };

interface Row { id: number; owner: string; kind: WatchKind; target: string; description: string; created_at: number; last_run: number | null; last_state: string | null; last_change: number | null }
const toMonitor = (r: Row): PersonalMonitor => ({ id: r.id, kind: r.kind, target: r.target, description: r.description, createdAt: new Date(r.created_at).toISOString(), lastRun: r.last_run ? new Date(r.last_run).toISOString() : null, lastChange: r.last_change ? new Date(r.last_change).toISOString() : null });

export const isOwner = (o: string) => /^(web|tg):[A-Za-z0-9_-]{1,64}$/.test(o);

export function listPersonal(ctx: Ctx, owner: string): PersonalMonitor[] {
  return (db(ctx).prepare('SELECT * FROM personal_monitors WHERE owner = ? ORDER BY id').all(owner) as unknown as Row[]).map(toMonitor);
}

/** Reads the request into a rule and saves it for this owner (at most MAX_PER_OWNER). */
export async function addPersonal(ctx: Ctx, owner: string, text: string, max = MAX_PER_OWNER): Promise<{ monitor: PersonalMonitor; rule: MonitorRule; method: string }> {
  if (!isOwner(owner)) throw new Error('invalid owner');
  const d = db(ctx);
  const n = (d.prepare('SELECT COUNT(*) n FROM personal_monitors WHERE owner = ?').get(owner) as { n: number }).n;
  if (n >= max) throw new Error(`you can keep up to ${max} monitors; remove one first${max === MAX_PER_OWNER ? ' (OCULON holders can keep more)' : ''}`);
  const r = await parseMonitor(text);
  d.prepare('INSERT INTO personal_monitors (owner, kind, target, description, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(owner, kind, target) DO NOTHING').run(owner, r.kind, r.target, r.description, ctx.now().getTime());
  const row = d.prepare('SELECT * FROM personal_monitors WHERE owner = ? AND kind = ? AND target = ?').get(owner, r.kind, r.target) as unknown as Row;
  return { monitor: toMonitor(row), rule: { kind: r.kind, target: r.target, description: r.description }, method: r.method };
}

export function removePersonal(ctx: Ctx, owner: string, id: number): boolean {
  const d = db(ctx);
  const ok = d.prepare('DELETE FROM personal_monitors WHERE owner = ? AND id = ?').run(owner, id).changes > 0;
  if (ok) d.prepare('DELETE FROM personal_alerts WHERE owner = ? AND monitor_id = ?').run(owner, id);
  return ok;
}

export function personalAlerts(ctx: Ctx, owner: string, limit = 50): PersonalAlert[] {
  return (db(ctx).prepare('SELECT id, monitor_id, text, created_at FROM personal_alerts WHERE owner = ? ORDER BY created_at DESC, id DESC LIMIT ?').all(owner, limit) as { id: number; monitor_id: number; text: string; created_at: number }[]).map((r) => ({ id: r.id, monitorId: r.monitor_id, text: r.text, createdAt: new Date(r.created_at).toISOString() }));
}

/** Checks monitors not run in the last ~hour (oldest first, at most `max` per call) and records what changed. */
export async function runPersonal(ctx: Ctx, opts: { max?: number; everyMs?: number } = {}): Promise<Delivery[]> {
  const d = db(ctx);
  const now = ctx.now().getTime();
  // Monitors of OCULON holders (a signed-in wallet with enough tokens) are checked every ~15 minutes instead of hourly.
  let holderSql = '';
  try { d.prepare('SELECT 1 FROM holder_sessions LIMIT 1').get(); holderSql = ' OR (last_run <= ? AND owner IN (SELECT owner FROM holder_sessions WHERE expires_at > ?))'; } catch { /* no holder table yet */ }
  const args: number[] = [now - (opts.everyMs ?? 55 * 60_000)];
  if (holderSql) args.push(now - 14 * 60_000, now);
  const rows = d.prepare(`SELECT * FROM personal_monitors WHERE last_run IS NULL OR last_run <= ?${holderSql} ORDER BY COALESCE(last_run, 0) LIMIT ?`).all(...args, opts.max ?? 60) as unknown as Row[];
  const out: Delivery[] = [];
  for (const r of rows) {
    const item: WatchItem = { id: r.id, kind: r.kind, target: r.target, label: r.description, createdAt: new Date(r.created_at).toISOString(), lastRun: r.last_run ? new Date(r.last_run).toISOString() : null };
    const prev = r.last_state ? (JSON.parse(r.last_state) as Record<string, unknown>) : null;
    try {
      const { state, changes } = await observe(ctx, item, prev);
      d.prepare('UPDATE personal_monitors SET last_run = ?, last_state = ?, last_change = COALESCE(?, last_change) WHERE id = ?').run(now, JSON.stringify(state), changes.length ? now : null, r.id);
      if (changes.length) {
        const ins = d.prepare('INSERT INTO personal_alerts (owner, monitor_id, text, created_at) VALUES (?, ?, ?, ?)');
        for (const c of changes) ins.run(r.owner, r.id, c, now);
        out.push({ owner: r.owner, monitor: toMonitor({ ...r, last_run: now }), changes });
      }
    } catch {
      d.prepare('UPDATE personal_monitors SET last_run = ? WHERE id = ?').run(now, r.id);
    }
  }
  // Keep each owner's alert history short.
  d.prepare('DELETE FROM personal_alerts WHERE created_at < ?').run(now - 30 * 24 * HOUR);
  return out;
}

// ---- email

export interface EmailStatus { email: string | null; confirmed: boolean }

export function emailStatus(ctx: Ctx, owner: string): EmailStatus {
  const r = db(ctx).prepare('SELECT email, confirmed FROM personal_emails WHERE owner = ?').get(owner) as { email: string; confirmed: number } | undefined;
  return { email: r?.email ?? null, confirmed: Boolean(r?.confirmed) };
}

const EMAIL_RE = /^[^\s@<>"']{1,64}@[a-z0-9.-]+\.[a-z]{2,}$/i;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function shell(title: string, body: string, footer: string): string {
  return `<!doctype html><html><body style="margin:0;background:#f4f6f6;padding:24px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#111"><div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e3e7e7;padding:28px"><div style="font:600 12px monospace;letter-spacing:.18em;color:#00838f">OCULON</div><h1 style="font-size:20px;font-weight:600;margin:14px 0 16px">${title}</h1>${body}<p style="font-size:12px;color:#777;margin-top:28px;border-top:1px solid #eee;padding-top:14px">${footer}</p></div></body></html>`;
}

/** Saves the address and sends a confirmation link. Limited to one email per owner every 10 minutes. */
export async function requestEmail(ctx: Ctx, owner: string, email: string, baseUrl: string): Promise<{ sent: boolean; error?: string }> {
  if (!isOwner(owner)) throw new Error('invalid owner');
  const addr = email.trim().toLowerCase();
  if (!EMAIL_RE.test(addr)) throw new Error('that does not look like an email address');
  if (!mailEnabled()) throw new Error('email alerts are not set up on this install');
  const d = db(ctx);
  const prev = d.prepare('SELECT sent_at FROM personal_emails WHERE owner = ?').get(owner) as { sent_at: number } | undefined;
  if (prev && Date.now() - prev.sent_at < 10 * 60_000) throw new Error('a confirmation email was sent a moment ago; check your inbox (and spam)');
  const recent = (d.prepare('SELECT COUNT(*) n FROM personal_emails WHERE email = ? AND sent_at > ?').get(addr, Date.now() - 24 * HOUR) as { n: number }).n;
  if (recent >= 3) throw new Error('too many confirmation requests for this address today');
  const token = randomBytes(18).toString('base64url');
  d.prepare('INSERT INTO personal_emails (owner, email, confirmed, token, sent_at) VALUES (?, ?, 0, ?, ?) ON CONFLICT(owner) DO UPDATE SET email = excluded.email, confirmed = 0, token = excluded.token, sent_at = excluded.sent_at').run(owner, addr, token, Date.now());
  const link = `${baseUrl}/mail/confirm?t=${token}`;
  const r = await sendEmail({
    to: addr,
    subject: 'Confirm Oculon monitor alerts',
    text: `Confirm that you want Oculon monitor alerts at this address:\n${link}\n\nIf you did not ask for this, ignore this email and nothing will be sent.`,
    html: shell('Confirm your alerts', `<p style="font-size:15px;line-height:1.55">Click below to get an email when one of your Oculon monitors finds a change.</p><p><a href="${esc(link)}" style="display:inline-block;background:#00838f;color:#fff;padding:11px 18px;text-decoration:none;font-weight:600">Confirm alerts</a></p>`, 'If you did not ask for this, ignore this email and nothing will be sent.'),
  });
  return r.ok ? { sent: true } : { sent: false, error: r.error };
}

export function confirmEmail(ctx: Ctx, token: string): boolean {
  if (!/^[A-Za-z0-9_-]{20,40}$/.test(token)) return false;
  return db(ctx).prepare('UPDATE personal_emails SET confirmed = 1 WHERE token = ?').run(token).changes > 0;
}

export function unsubscribeEmail(ctx: Ctx, token: string): boolean {
  if (!/^[A-Za-z0-9_-]{20,40}$/.test(token)) return false;
  return db(ctx).prepare('DELETE FROM personal_emails WHERE token = ?').run(token).changes > 0;
}

export function removeEmail(ctx: Ctx, owner: string): boolean {
  return db(ctx).prepare('DELETE FROM personal_emails WHERE owner = ?').run(owner).changes > 0;
}

/** Emails each web owner with a confirmed address one message listing every change from this run. */
export async function emailDeliveries(ctx: Ctx, deliveries: Delivery[], baseUrl: string, appUrl: string): Promise<number> {
  if (!mailEnabled()) return 0;
  const byOwner = new Map<string, Delivery[]>();
  for (const x of deliveries) if (x.owner.startsWith('web:')) byOwner.set(x.owner, [...(byOwner.get(x.owner) ?? []), x]);
  let sent = 0;
  for (const [owner, list] of byOwner) {
    const r = db(ctx).prepare('SELECT email, token FROM personal_emails WHERE owner = ? AND confirmed = 1').get(owner) as { email: string; token: string } | undefined;
    if (!r) continue;
    const unsub = `${baseUrl}/mail/unsubscribe?t=${r.token}`;
    const n = list.reduce((a, x) => a + x.changes.length, 0);
    const subject = list.length === 1 ? `Oculon: ${list[0]!.monitor.description}` : `Oculon: ${n} changes in ${list.length} monitors`;
    const linkify = (s: string) => esc(s).replace(/https?:\/\/[^\s<]+/g, (u) => `<a href="${u}" style="color:#00838f">${u.length > 60 ? `${u.slice(0, 60)}…` : u}</a>`);
    const html = shell(esc(subject.replace(/^Oculon: /, '')), list.map((x) => `<p style="font:600 13px monospace;color:#555;margin:18px 0 6px">${esc(x.monitor.description)}</p><ul style="padding-left:18px;margin:0">${x.changes.map((c) => `<li style="margin:6px 0;font-size:14px;line-height:1.5">${linkify(c)}</li>`).join('')}</ul>`).join('') + `<p style="margin-top:22px"><a href="${esc(appUrl)}" style="color:#00838f">Open your monitors</a></p>`, `You get this because you confirmed Oculon monitor alerts. <a href="${esc(unsub)}" style="color:#777">Unsubscribe</a>.`);
    const text = list.map((x) => `${x.monitor.description}\n${x.changes.map((c) => `- ${c}`).join('\n')}`).join('\n\n') + `\n\nUnsubscribe: ${unsub}`;
    const res = await sendEmail({ to: r.email, subject, html, text, unsubscribeUrl: unsub });
    if (res.ok) sent++;
  }
  return sent;
}
