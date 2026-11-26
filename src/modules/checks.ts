/**
 * Check history: every check (scam, link, IBAN, document, token...) is stored with its verdict and the source calls
 * it made. That gives three features:
 *   - seen before: checking the same thing again says what changed since last time;
 *   - replay log: /replay/<id> shows every source called, when, how long it took and what it answered;
 *   - PDF report: /report/<id>.pdf is one investigation as a file to send on.
 * Ids are random (96 bits) so a replay link is only known to whoever ran the check. Kept for 90 days.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import { withCallLog, type CallEntry } from '../core/calls.js';
import { verdictChanges, verdictOf, type Verdict } from '../core/verdict.js';

export interface SeenBefore {
  id: string;
  at: string;
  verdict: string | null;
  /** Plain-word changes since that check; empty when nothing changed. */
  changes: string[];
}

export interface CheckMeta {
  id: string;
  kind: string;
  seenBefore: SeenBefore | null;
  replay: string;
  report: string;
}

export interface CheckRecord {
  id: string;
  kind: string;
  label: string;
  createdAt: string;
  durationMs: number;
  verdict: Verdict;
  calls: CallEntry[];
  seenBefore: SeenBefore | null;
  /** The full result as returned, or null when it was too large to keep. */
  result: unknown;
}

const KEEP_DAYS = 90;
const MAX_RESULT = 300_000;

const ensured = new WeakSet<object>();
function db(ctx: Ctx) {
  const d = ctx.store.db;
  if (!ensured.has(d)) {
    d.exec(`CREATE TABLE IF NOT EXISTS checks (id TEXT PRIMARY KEY, kind TEXT NOT NULL, target_key TEXT NOT NULL, label TEXT NOT NULL, created_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL, verdict TEXT NOT NULL, calls TEXT NOT NULL, seen_before TEXT, result TEXT);
      CREATE INDEX IF NOT EXISTS checks_target ON checks (target_key, created_at);`);
    ensured.add(d);
  }
  return d;
}

export const targetKey = (kind: string, target: string) => createHash('sha256').update(`${kind}\n${target.trim().toLowerCase().replace(/\s+/g, ' ')}`).digest('hex').slice(0, 32);

/** Long inputs (a pasted message, raw headers) are shown by their start only. */
export function labelFor(target: string): string {
  const t = target.replace(/\s+/g, ' ').trim();
  return t.length > 90 ? `${t.slice(0, 87)}...` : t;
}

/**
 * Run a check, keep its verdict and source calls, and compare it with the last check of the same target.
 * `target` identifies what was checked (it is hashed for matching); `label` is what pages show.
 */
export async function recordCheck<T>(ctx: Ctx, kind: string, target: string, run: () => Promise<T>, opts: { label?: string } = {}): Promise<{ value: T; check: CheckMeta }> {
  const t0 = Date.now();
  const { value, calls } = await withCallLog(run);
  const durationMs = Date.now() - t0;
  const d = db(ctx);
  const key = targetKey(kind, target);
  const label = opts.label ?? labelFor(target);
  const verdict = verdictOf(value, label);
  const nowMs = ctx.now().getTime();
  const prev = d.prepare('SELECT id, created_at, verdict FROM checks WHERE target_key = ? ORDER BY created_at DESC LIMIT 1').get(key) as { id: string; created_at: number; verdict: string } | undefined;
  let seenBefore: SeenBefore | null = null;
  if (prev) {
    const was = JSON.parse(prev.verdict) as Verdict;
    seenBefore = { id: prev.id, at: new Date(prev.created_at).toISOString(), verdict: was.verdict, changes: verdictChanges(was, verdict) };
  }
  const id = randomBytes(12).toString('base64url');
  let result: string | null = JSON.stringify(value);
  if (result.length > MAX_RESULT) result = null;
  d.prepare('INSERT INTO checks (id, kind, target_key, label, created_at, duration_ms, verdict, calls, seen_before, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, kind, key, label, nowMs, durationMs, JSON.stringify(verdict), JSON.stringify(calls), seenBefore ? JSON.stringify(seenBefore) : null, result);
  if (Math.random() < 0.02) d.prepare('DELETE FROM checks WHERE created_at < ?').run(nowMs - KEEP_DAYS * 86_400_000);
  return { value, check: { id, kind, seenBefore, replay: `/replay/${id}`, report: `/report/${id}.pdf` } };
}

export function getCheck(ctx: Ctx, id: string): CheckRecord | null {
  if (!/^[A-Za-z0-9_-]{10,40}$/.test(id)) return null;
  const r = db(ctx).prepare('SELECT * FROM checks WHERE id = ?').get(id) as Record<string, string | number | null> | undefined;
  if (!r) return null;
  return {
    id: String(r.id),
    kind: String(r.kind),
    label: String(r.label),
    createdAt: new Date(Number(r.created_at)).toISOString(),
    durationMs: Number(r.duration_ms),
    verdict: JSON.parse(String(r.verdict)) as Verdict,
    calls: JSON.parse(String(r.calls)) as CallEntry[],
    seenBefore: r.seen_before ? (JSON.parse(String(r.seen_before)) as SeenBefore) : null,
    result: r.result ? JSON.parse(String(r.result)) : null,
  };
}

/** Earlier checks of the same target, newest first (for "history" on the replay page). */
export function checkHistory(ctx: Ctx, id: string, limit = 10): { id: string; at: string; verdict: string | null; risk: number | null }[] {
  const d = db(ctx);
  const row = d.prepare('SELECT target_key FROM checks WHERE id = ?').get(id) as { target_key: string } | undefined;
  if (!row) return [];
  const rows = d.prepare('SELECT id, created_at, verdict FROM checks WHERE target_key = ? ORDER BY created_at DESC LIMIT ?').all(row.target_key, limit) as { id: string; created_at: number; verdict: string }[];
  return rows.map((r) => {
    const v = JSON.parse(r.verdict) as Verdict;
    return { id: r.id, at: new Date(r.created_at).toISOString(), verdict: v.verdict, risk: v.risk };
  });
}

/** Checks Oculon records, by web route and by MCP tool, with how to read the target from the input. */
export const CHECK_ROUTES: Record<string, { kind: string; param: string }> = {
  '/api/scam': { kind: 'scam', param: 'message' },
  '/api/url': { kind: 'url', param: 'url' },
  '/api/iban': { kind: 'iban', param: 'iban' },
  '/api/lookalike': { kind: 'lookalike', param: 'domain' },
  '/api/honeypot': { kind: 'honeypot', param: 'address' },
  '/api/address': { kind: 'address', param: 'address' },
  '/api/phone': { kind: 'phone', param: 'number' },
  '/api/ip': { kind: 'ip', param: 'ip' },
  '/api/hash': { kind: 'hash', param: 'hash' },
  '/api/emailsec': { kind: 'emailsec', param: 'domain' },
  '/api/company': { kind: 'company', param: 'q' },
  '/api/token': { kind: 'token', param: 'address' },
  '/api/rhtoken': { kind: 'rhtoken', param: 'address' },
  '/api/wallet': { kind: 'wallet', param: 'address' },
  '/api/sanctions': { kind: 'sanctions', param: 'q' },
  '/api/factcheck': { kind: 'factcheck', param: 'claim' },
  '/api/recall': { kind: 'recall', param: 'q' },
  '/api/travel': { kind: 'travel', param: 'place' },
  '/api/cve': { kind: 'cve', param: 'id' },
  '/api/exposure': { kind: 'exposure', param: 'domain' },
  '/api/approvals': { kind: 'approvals', param: 'address' },
  '/api/contract': { kind: 'contract', param: 'address' },
  '/api/poisoning': { kind: 'poisoning', param: 'address' },
  '/api/trace': { kind: 'trace', param: 'address' },
  '/api/repo': { kind: 'repo', param: 'repo' },
  '/api/report/domain': { kind: 'domainreport', param: 'domain' },
  '/api/report/wallet': { kind: 'walletreport', param: 'address' },
  '/api/site': { kind: 'site', param: 'url' },
  '/api/tx': { kind: 'tx', param: 'hash' },
  '/api/creator': { kind: 'creator', param: 'address' },
  '/api/archive': { kind: 'archive', param: 'url' },
  '/api/invite': { kind: 'invite', param: 'link' },
  '/api/stocktoken': { kind: 'stocktoken', param: 'q' },
};

export const CHECK_TOOLS: Record<string, { kind: string; arg: string }> = {
  oculon_scam_check: { kind: 'scam', arg: 'message' },
  oculon_url_check: { kind: 'url', arg: 'url' },
  oculon_iban_check: { kind: 'iban', arg: 'iban' },
  oculon_email_headers: { kind: 'headers', arg: 'headers' },
  oculon_lookalike_domains: { kind: 'lookalike', arg: 'domain' },
  oculon_honeypot_check: { kind: 'honeypot', arg: 'address' },
  oculon_address_check: { kind: 'address', arg: 'address' },
  oculon_phone_check: { kind: 'phone', arg: 'number' },
  oculon_ip_check: { kind: 'ip', arg: 'ip' },
  oculon_hash_check: { kind: 'hash', arg: 'hash' },
  oculon_email_security: { kind: 'emailsec', arg: 'domain' },
  oculon_company_lookup: { kind: 'company', arg: 'query' },
  oculon_token: { kind: 'token', arg: 'address' },
  oculon_robinhood_token: { kind: 'rhtoken', arg: 'address' },
  oculon_wallet: { kind: 'wallet', arg: 'address' },
  oculon_sanctions: { kind: 'sanctions', arg: 'query' },
  oculon_fact_check: { kind: 'factcheck', arg: 'claim' },
  oculon_recall: { kind: 'recall', arg: 'query' },
  oculon_travel: { kind: 'travel', arg: 'place' },
  oculon_cve: { kind: 'cve', arg: 'id' },
  oculon_exposure: { kind: 'exposure', arg: 'domain' },
  oculon_doc_check: { kind: 'doc', arg: 'name' },
  oculon_approvals: { kind: 'approvals', arg: 'address' },
  oculon_contract_risk: { kind: 'contract', arg: 'address' },
  oculon_signature_check: { kind: 'signature', arg: 'request' },
  oculon_address_poisoning: { kind: 'poisoning', arg: 'address' },
  oculon_trace_funds: { kind: 'trace', arg: 'address' },
  oculon_image_check: { kind: 'image', arg: 'name' },
  oculon_qr_check: { kind: 'qr', arg: 'name' },
  oculon_repo_check: { kind: 'repo', arg: 'repo' },
  oculon_domain_report: { kind: 'domainreport', arg: 'domain' },
  oculon_wallet_report: { kind: 'walletreport', arg: 'address' },
  oculon_site_check: { kind: 'site', arg: 'url' },
  oculon_tx_explain: { kind: 'tx', arg: 'hash' },
  oculon_token_creator: { kind: 'creator', arg: 'address' },
  oculon_email_file: { kind: 'eml', arg: 'name' },
  oculon_apk_check: { kind: 'apk', arg: 'name' },
  oculon_job_check: { kind: 'job', arg: 'message' },
  oculon_photo_location: { kind: 'where', arg: 'name' },
  oculon_archive: { kind: 'archive', arg: 'url' },
  oculon_invite_check: { kind: 'invite', arg: 'link' },
  oculon_stock_token: { kind: 'stocktoken', arg: 'query' },
};
