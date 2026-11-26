/**
 * Oculon API keys. One key works for the REST API, the SDK, the CLI and the remote MCP server.
 *
 *   Free key    any wallet that signs in: the everyday checks and public feeds, 200 calls a day.
 *   Holder key  a wallet holding 5,000,000 OCULON: every service, 5,000 calls a day.
 *
 * A key is made in the console after a wallet signature (no email, no payment, nothing leaves the wallet).
 * It is shown once and stored only as a SHA-256 hash. The tier follows the wallet's live balance: it is read
 * again every few hours, and a wallet that drops below the line keeps a working key on the free tier.
 * Calls without a key from outside Oculon's own pages stay possible, on the free services, with a small daily limit.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { Ctx } from '../core/context.js';
import { balanceOf } from './utility.js';

export type Tier = 'free' | 'holder';

export const API_TIERS = {
  holderMin: 5_000_000n,
  daily: { free: 200, holder: 5000 } as Record<Tier, number>,
  /** Keyless calls from outside Oculon's own pages, per client address per day. */
  keylessDaily: 50,
  /** Keyless calls from a browser extension (Oculon Shield), per client address per day. */
  extensionDaily: 500,
  maxKeys: 5,
  recheckHours: 6,
  sessionDays: 7,
} as const;

const E18 = 10n ** 18n;

/** Endpoints a free key (and a keyless caller) may use: everyday checks and public feeds. */
export const FREE_PATHS = new Set([
  '/api/meta', '/api/status', '/api/check', '/api/readme', '/api/signals', '/api/stream', '/api/bgp', '/api/vulns', '/api/hazards',
  '/api/squawks', '/api/quakes', '/api/events', '/api/space', '/api/cloud', '/api/blackout', '/api/calendar', '/api/forecasts',
  '/api/verify', '/api/proof', '/api/url', '/api/scam', '/api/emailsec', '/api/ip', '/api/hash', '/api/ransomware', '/api/pwned',
  '/api/breaches', '/api/phone', '/api/iban', '/api/recall', '/api/travel', '/api/country', '/api/airport', '/api/satellites',
  '/api/share', '/api/lookalike', '/api/site', '/api/invite', '/api/key', '/api/catalog',
  '/api/screenshot', '/api/rescue', '/api/checkup', '/api/spot', '/api/down', '/api/charity', '/api/prove', '/api/wire', '/api/trends',
]);

/** Never reachable with a key: the install owner's own data and the console itself. */
export const PRIVATE_PATHS = /^\/api\/(cases?|fences|watch|my|utility|dev|analyst|feedback|inbox|personal)(\/|$)/;

/** Remote MCP tools a free key (and a keyless caller) may use. Every other listed tool needs a holder key. */
export const FREE_TOOLS = new Set([
  'oculon_radar', 'oculon_url_check', 'oculon_scam_check', 'oculon_recall', 'oculon_travel', 'oculon_email_security', 'oculon_ip_check',
  'oculon_hash_check', 'oculon_ransomware', 'oculon_breaches', 'oculon_phone_check', 'oculon_iban_check', 'oculon_email_headers',
  'oculon_lookalike_domains', 'oculon_site_check', 'oculon_invite_check', 'oculon_status', 'oculon_satellites', 'oculon_country',
  'oculon_airport', 'oculon_signals', 'oculon_hazards', 'oculon_calendar', 'oculon_blackout', 'oculon_cloud_outages', 'oculon_bgp',
  'oculon_vulns', 'oculon_cve', 'oculon_fires', 'oculon_space_weather', 'oculon_air_quality', 'oculon_natural_events', 'oculon_squawks',
  'oculon_verify_proof', 'oculon_scoreboard', 'oculon_replay', 'oculon_qr_check', 'oculon_image_check', 'oculon_health',
  'oculon_screenshot_check', 'oculon_rescue', 'oculon_checkup', 'oculon_spot_the_scam', 'oculon_is_it_down', 'oculon_charity_check',
  'oculon_prove', 'oculon_prove_status', 'oculon_wire', 'oculon_scam_trends',
]);

/** The Oculon Shield extension also reads these without a key, for the risk pill on token pages. */
const EXTENSION_PATHS = new Set(['/api/contract', '/api/address']);

export const pathTier = (path: string): Tier => (FREE_PATHS.has(path) ? 'free' : 'holder');
export const toolTier = (name: string): Tier => (FREE_TOOLS.has(name) ? 'free' : 'holder');
export const tierAllows = (tier: Tier, needed: Tier) => tier === 'holder' || needed === 'free';

const ready = new WeakSet<DatabaseSync>();
function db(ctx: Ctx): DatabaseSync {
  const d = ctx.store.db;
  if (ready.has(d)) return d;
  d.exec(`CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, address TEXT NOT NULL, label TEXT NOT NULL, tier TEXT NOT NULL, balance TEXT NOT NULL, checked_at INTEGER NOT NULL, created_at INTEGER NOT NULL, last_used INTEGER, revoked_at INTEGER);
    CREATE INDEX IF NOT EXISTS api_keys_address ON api_keys(address);
    CREATE TABLE IF NOT EXISTS api_usage (subject TEXT NOT NULL, day TEXT NOT NULL, path TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (subject, day, path));
    CREATE TABLE IF NOT EXISTS dev_sessions (hash TEXT PRIMARY KEY, address TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);`);
  ready.add(d);
  return d;
}

const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export function tierForBalance(raw: bigint): Tier {
  return raw >= API_TIERS.holderMin * E18 ? 'holder' : 'free';
}

let balanceReader: (address: string) => Promise<bigint> = balanceOf;
/** Tests replace the chain read. */
export function setBalanceReader(fn: ((address: string) => Promise<bigint>) | null) { balanceReader = fn ?? balanceOf; }

const whole = (raw: bigint) => (raw / E18).toString();

/* ---------------- console sessions ---------------- */

export function createDevSession(ctx: Ctx, address: string): { token: string; expiresAt: string } {
  const token = randomBytes(24).toString('base64url');
  const now = ctx.now().getTime();
  const exp = now + API_TIERS.sessionDays * 86_400_000;
  const d = db(ctx);
  d.prepare('DELETE FROM dev_sessions WHERE expires_at < ?').run(now);
  d.prepare('INSERT INTO dev_sessions (hash, address, expires_at, created_at) VALUES (?, ?, ?, ?)').run(sha(token), address.toLowerCase(), exp, now);
  return { token, expiresAt: new Date(exp).toISOString() };
}

export function devSession(ctx: Ctx, token: string | null | undefined): string | null {
  if (!token || token.length < 20 || token.length > 64) return null;
  const r = db(ctx).prepare('SELECT address, expires_at FROM dev_sessions WHERE hash = ?').get(sha(token)) as { address: string; expires_at: number } | undefined;
  return r && r.expires_at > ctx.now().getTime() ? r.address : null;
}

export function endDevSession(ctx: Ctx, token: string | null | undefined): void {
  if (token) db(ctx).prepare('DELETE FROM dev_sessions WHERE hash = ?').run(sha(token));
}

/* ---------------- keys ---------------- */

export interface KeyInfo { id: string; label: string; tier: Tier; createdAt: string; lastUsed: string | null; revoked: boolean; usedToday: number; limit: number }

/** The wallet's current tier and whole-token balance, read live. */
export async function walletTier(address: string): Promise<{ tier: Tier; balance: string }> {
  const raw = await balanceReader(address.toLowerCase());
  return { tier: tierForBalance(raw), balance: whole(raw) };
}

export async function createKey(ctx: Ctx, address: string, labelInput = ''): Promise<{ key: string; info: KeyInfo }> {
  const a = address.toLowerCase();
  const d = db(ctx);
  const active = (d.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE address = ? AND revoked_at IS NULL').get(a) as { n: number }).n;
  if (active >= API_TIERS.maxKeys) throw new Error(`a wallet can have ${API_TIERS.maxKeys} active keys; revoke one first`);
  const { tier, balance } = await walletTier(a);
  const secret = randomBytes(32).toString('base64url');
  const key = `ocl_${secret}`;
  const id = secret.slice(0, 8);
  const label = labelInput.replace(/[^\w .,:@/+-]/g, '').trim().slice(0, 40) || `key ${active + 1}`;
  const now = ctx.now().getTime();
  d.prepare('INSERT INTO api_keys (id, hash, address, label, tier, balance, checked_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, sha(key), a, label, tier, balance, now, now);
  return { key, info: keyInfo(ctx, id)! };
}

export function revokeKey(ctx: Ctx, address: string, id: string): boolean {
  return Number(db(ctx).prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND address = ? AND revoked_at IS NULL').run(ctx.now().getTime(), id, address.toLowerCase()).changes) > 0;
}

function usedToday(ctx: Ctx, subject: string): number {
  const r = db(ctx).prepare('SELECT COALESCE(SUM(n), 0) AS n FROM api_usage WHERE subject = ? AND day = ?').get(subject, day(ctx.now().getTime())) as { n: number };
  return Number(r.n);
}

function keyInfo(ctx: Ctx, id: string): KeyInfo | null {
  const r = db(ctx).prepare('SELECT * FROM api_keys WHERE id = ?').get(id) as { id: string; label: string; tier: Tier; created_at: number; last_used: number | null; revoked_at: number | null } | undefined;
  if (!r) return null;
  return { id: r.id, label: r.label, tier: r.tier, createdAt: new Date(r.created_at).toISOString(), lastUsed: r.last_used ? new Date(r.last_used).toISOString() : null, revoked: r.revoked_at != null, usedToday: usedToday(ctx, `key:${r.id}`), limit: API_TIERS.daily[r.tier] };
}

export function listKeys(ctx: Ctx, address: string): KeyInfo[] {
  const ids = db(ctx).prepare('SELECT id FROM api_keys WHERE address = ? ORDER BY revoked_at IS NOT NULL, created_at DESC LIMIT 20').all(address.toLowerCase()) as { id: string }[];
  return ids.map((r) => keyInfo(ctx, r.id)!).filter(Boolean);
}

/** Re-reads the wallet balance and moves all its keys to the matching tier. */
export async function refreshWallet(ctx: Ctx, address: string): Promise<{ tier: Tier; balance: string }> {
  const t = await walletTier(address);
  db(ctx).prepare('UPDATE api_keys SET tier = ?, balance = ?, checked_at = ? WHERE address = ?').run(t.tier, t.balance, ctx.now().getTime(), address.toLowerCase());
  return t;
}

export interface KeyAuth { id: string; address: string; tier: Tier; limit: number }

/** Reads a key from `authorization: Bearer ocl_...` or `x-api-key`. */
export function keyFromHeaders(h: Record<string, string | string[] | undefined>): string | null {
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() ?? '';
  const bearer = /^Bearer\s+(ocl_[A-Za-z0-9_-]{20,80})$/i.exec(one(h.authorization))?.[1];
  const x = /^ocl_[A-Za-z0-9_-]{20,80}$/.exec(one(h['x-api-key']))?.[0];
  return bearer ?? x ?? null;
}

/** Looks a key up. Returns null for an unknown or revoked key. Re-reads the balance when it is stale (a failed read keeps the last tier). */
export async function authKey(ctx: Ctx, key: string): Promise<KeyAuth | null> {
  const d = db(ctx);
  const r = d.prepare('SELECT id, address, tier, checked_at, revoked_at FROM api_keys WHERE hash = ?').get(sha(key)) as { id: string; address: string; tier: Tier; checked_at: number; revoked_at: number | null } | undefined;
  if (!r || r.revoked_at != null) return null;
  let tier = r.tier;
  if (ctx.now().getTime() - r.checked_at > API_TIERS.recheckHours * 3_600_000) {
    try { tier = (await refreshWallet(ctx, r.address)).tier; } catch { d.prepare('UPDATE api_keys SET checked_at = ? WHERE address = ?').run(ctx.now().getTime() - (API_TIERS.recheckHours - 1) * 3_600_000, r.address); }
  }
  return { id: r.id, address: r.address, tier, limit: API_TIERS.daily[tier] };
}

/** Counts one call against `subject` (a key id or a client address) and says whether it is within `limit` for today. */
export function useQuota(ctx: Ctx, subject: string, path: string, limit: number): { ok: boolean; used: number; limit: number; remaining: number } {
  const d = db(ctx);
  const now = ctx.now().getTime();
  const used = usedToday(ctx, subject);
  if (used >= limit) return { ok: false, used, limit, remaining: 0 };
  d.prepare('INSERT INTO api_usage (subject, day, path, n) VALUES (?, ?, ?, 1) ON CONFLICT(subject, day, path) DO UPDATE SET n = n + 1').run(subject, day(now), path.slice(0, 80));
  if (subject.startsWith('key:')) d.prepare('UPDATE api_keys SET last_used = ? WHERE id = ?').run(now, subject.slice(4));
  return { ok: true, used: used + 1, limit, remaining: limit - used - 1 };
}

/** Calls per day for the wallet's keys over the last `days` days, plus the endpoints used most. */
export function usageFor(ctx: Ctx, address: string, days = 14): { days: { day: string; n: number }[]; top: { path: string; n: number }[] } {
  const d = db(ctx);
  const ids = (d.prepare('SELECT id FROM api_keys WHERE address = ?').all(address.toLowerCase()) as { id: string }[]).map((r) => `key:${r.id}`);
  const out: { day: string; n: number }[] = [];
  const now = ctx.now().getTime();
  const from = day(now - (days - 1) * 86_400_000);
  const rows = ids.length ? d.prepare(`SELECT day, SUM(n) AS n FROM api_usage WHERE subject IN (${ids.map(() => '?').join(',')}) AND day >= ? GROUP BY day`).all(...ids, from) as { day: string; n: number }[] : [];
  const by = new Map(rows.map((r) => [r.day, Number(r.n)]));
  for (let i = days - 1; i >= 0; i--) { const k = day(now - i * 86_400_000); out.push({ day: k, n: by.get(k) ?? 0 }); }
  const top = ids.length ? (d.prepare(`SELECT path, SUM(n) AS n FROM api_usage WHERE subject IN (${ids.map(() => '?').join(',')}) AND day >= ? GROUP BY path ORDER BY n DESC LIMIT 8`).all(...ids, from) as { path: string; n: number }[]).map((r) => ({ path: r.path, n: Number(r.n) })) : [];
  return { days: out, top };
}

/* ---------------- the gate ---------------- */

export type GateResult =
  | { ok: true; kind: 'first-party' }
  | { ok: true; kind: 'key' | 'keyless'; tier: Tier; limit: number; remaining: number; keyId?: string }
  | { ok: false; status: number; error: string };

/**
 * Decides whether an API call (or a remote MCP tool call) may go ahead.
 * `resource` is a path like /api/url or an MCP tool name; `needed` is the tier it requires.
 * Oculon's own pages (the browser says same-origin or same-site) pass as before.
 */
export async function gate(ctx: Ctx, req: { headers: Record<string, string | string[] | undefined> }, ip: string, resource: string, needed: Tier, site?: string | null): Promise<GateResult> {
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim().toLowerCase() ?? '';
  const key = keyFromHeaders(req.headers);
  if (key) {
    const a = await authKey(ctx, key);
    if (!a) return { ok: false, status: 401, error: 'this API key is not valid or was revoked; make a new one at https://console.oculon.live' };
    if (PRIVATE_PATHS.test(resource)) return { ok: false, status: 403, error: 'this endpoint is not part of the API' };
    if (!tierAllows(a.tier, needed)) return { ok: false, status: 403, error: `this service needs a holder key: hold ${API_TIERS.holderMin.toLocaleString('en-US')} OCULON in the wallet that owns the key (free keys cover the everyday checks)` };
    const q = useQuota(ctx, `key:${a.id}`, resource, a.limit);
    if (!q.ok) return { ok: false, status: 429, error: `this key used its ${a.limit} calls for today (UTC); it resets at midnight UTC${a.tier === 'free' ? `, and a holder key gets ${API_TIERS.daily.holder}` : ''}` };
    return { ok: true, kind: 'key', tier: a.tier, limit: q.limit, remaining: q.remaining, keyId: a.id };
  }
  const fetchSite = one(req.headers['sec-fetch-site']);
  if (fetchSite === 'same-origin' || fetchSite === 'same-site') return { ok: true, kind: 'first-party' };
  // Older browsers send no Sec-Fetch-Site; the page's own Origin or Referer then says it is one of ours.
  if (!fetchSite && site) {
    const from = one(req.headers.origin) || one(req.headers.referer);
    const h = (() => { try { return new URL(from).hostname; } catch { return ''; } })();
    if (h && (h === site || h.endsWith(`.${site}`))) return { ok: true, kind: 'first-party' };
  }
  if (PRIVATE_PATHS.test(resource)) return { ok: true, kind: 'first-party' }; // left to the server's own checks
  const origin = one(req.headers.origin);
  const ext = /^(chrome|moz|safari-web)-extension:\/\//.test(origin);
  if (needed !== 'free' && !(ext && EXTENSION_PATHS.has(resource))) return { ok: false, status: 401, error: 'this service needs an Oculon API key (holder tier); get one at https://console.oculon.live' };
  const limit = ext ? API_TIERS.extensionDaily : API_TIERS.keylessDaily;
  const q = useQuota(ctx, `${ext ? 'ext' : 'ip'}:${ip}`, resource, limit);
  if (!q.ok) return { ok: false, status: 429, error: `${limit} calls a day without a key are used up for this address; a free key from https://console.oculon.live gives ${API_TIERS.daily.free}` };
  return { ok: true, kind: 'keyless', tier: 'free', limit, remaining: q.remaining };
}
