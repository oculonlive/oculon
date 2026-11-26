/**
 * $OCULON utility, read straight from Robinhood Chain: nothing is custodied, nothing is paid to anyone.
 * Holding is the main way in; burning is optional for people who would rather not hold.
 *   A. Deep investigation of one domain, wallet, token or company, published as a public page.
 *      Hold 1,500,000 OCULON: one investigation per wallet every 30 days. Or burn 1,500,000 for one.
 *   B. Live safety badge on one Robinhood Chain token. Hold 2,000,000: the badge stays live while the
 *      wallet keeps that balance (checked daily; one badge per wallet). Or burn 1,000,000 for 30 days.
 *      Paying, either way, buys monitoring, never a better verdict.
 *   C. Holder tier: a wallet holding 3,500,000 signs in once and gets up to 30 personal monitors, checked
 *      every 15 minutes instead of every hour.
 * Holding is proven by a signature over a one-time nonce plus a live balance read. A burn is a transfer to the
 * dead or zero address, confirmed on chain; each burn counts once and only the burning wallet can use it.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Ctx } from '../core/context.js';
import { recoverPersonalSigner } from '../core/evm.js';
import type { Oculon } from '../index.js';
import { formatUnits, rpcClient, type Rpc } from '../web/burns.js';

export const UTILITY = { investigate: 1_500_000n, safety: 1_000_000n, holdInvestigate: 1_500_000n, holdSafety: 2_000_000n, holder: 3_500_000n, safetyDays: 30, holdInvestigateDays: 30, holderMonitors: 30, sessionDays: 7 } as const;

/** What a holder signs to spend their holding on an action. The nonce comes from createNonce and works once. */
export function holdMessage(kind: 'investigate' | 'safety', target: string, address: string, nonce: string): string {
  return `Oculon ${kind === 'investigate' ? 'investigation' : 'safety badge'}\nTarget: ${target.trim()}\nWallet: ${address.trim().toLowerCase()}\nPaid by: holding OCULON\nNonce: ${nonce}`;
}
/** Burns before the utility went live (buyback burns, for example) do not count. */
export const UTILITY_START = Date.parse('2026-11-25T19:45:00Z');

/** What the burning wallet signs, so only the wallet that burned can spend its burn. */
export function utilityMessage(kind: 'investigate' | 'safety', target: string, tx: string): string {
  return `Oculon ${kind === 'investigate' ? 'investigation' : 'safety badge'}\nTarget: ${target.trim()}\nBurn: ${tx.trim().toLowerCase()}`;
}

function checkSigner(kind: 'investigate' | 'safety', target: string, burn: Burn, signature: string) {
  const signer = recoverPersonalSigner(utilityMessage(kind, target, burn.tx), signature);
  if (!signer) throw new Error('sign the request with the wallet that made the burn');
  if (signer !== burn.from) throw new Error('the signature is not from the wallet that made this burn');
}
const E18 = 10n ** 18n;
const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const BURN_TO = new Set(['0x000000000000000000000000000000000000dead', '0x0000000000000000000000000000000000000000']);
const DEFAULT_RPC = 'https://rpc.mainnet.chain.robinhood.com';

export interface TokenConfig { ca: string; txBase: string | null }
export function tokenConfig(): TokenConfig | null {
  try {
    const t = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'web', 'token.json'), 'utf8')) as { ca?: string; txBase?: string };
    return t.ca && /^0x[0-9a-fA-F]{40}$/.test(t.ca) ? { ca: t.ca.toLowerCase(), txBase: t.txBase ?? null } : null;
  } catch { return null; }
}

let rpcOverride: Rpc | null = null;
/** Tests replace the chain with a stub. */
export function setUtilityRpc(r: Rpc | null) { rpcOverride = r; }
const rpc = (): Rpc => rpcOverride ?? rpcClient(process.env.ROBINHOOD_PUBLIC_RPC_URL?.trim() || DEFAULT_RPC);

function db(ctx: Ctx) {
  const d = ctx.store.db;
  d.exec(`CREATE TABLE IF NOT EXISTS utility_burns (tx TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL, from_addr TEXT NOT NULL, amount TEXT NOT NULL, block INTEGER, burned_at TEXT, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, tx TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, result TEXT, created_at INTEGER NOT NULL, finished_at INTEGER);
    CREATE TABLE IF NOT EXISTS safety_monitors (token TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, last_check INTEGER, verdict TEXT, reasons TEXT, name TEXT, symbol TEXT);
    CREATE TABLE IF NOT EXISTS safety_checks (token TEXT NOT NULL, at INTEGER NOT NULL, verdict TEXT NOT NULL, reasons TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS holder_sessions (key TEXT PRIMARY KEY, owner TEXT NOT NULL, address TEXT NOT NULL, balance TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS hold_uses (address TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, balance TEXT NOT NULL, at INTEGER NOT NULL);`);
  for (const col of ['holder TEXT', 'holder_check INTEGER']) { try { d.exec(`ALTER TABLE safety_monitors ADD COLUMN ${col}`); } catch { /* already there */ } }
  return d;
}

export interface Burn { tx: string; from: string; amount: string; raw: string; block: number; time: string }

/** Confirms that `tx` burned at least `min` whole OCULON and has not been used before. Throws a readable error otherwise. */
export async function verifyBurn(ctx: Ctx, txInput: string, min: bigint): Promise<Burn> {
  const tx = txInput.trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(tx)) throw new Error('give the burn transaction hash: 0x followed by 64 hex characters');
  const cfg = tokenConfig();
  if (!cfg) throw new Error('the official token address is not configured on this install');
  const used = db(ctx).prepare('SELECT kind FROM utility_burns WHERE tx = ?').get(tx) as { kind: string } | undefined;
  if (used) throw new Error(`this burn was already used for ${used.kind === 'investigate' ? 'an investigation' : used.kind === 'safety' ? 'a safety badge' : used.kind}`);
  const r = rpc();
  const receipt = await r<{ status: string; from: string; blockNumber: string; logs: { address: string; topics: string[]; data: string }[] } | null>('eth_getTransactionReceipt', [tx]);
  if (!receipt) throw new Error('transaction not found yet: wait until it is confirmed, then try again');
  if (receipt.status !== '0x1') throw new Error('this transaction failed on chain, so nothing was burned');
  let raw = 0n; let from = receipt.from.toLowerCase();
  for (const l of receipt.logs) {
    if (l.address.toLowerCase() !== cfg.ca || l.topics[0] !== TRANSFER || l.topics.length < 3) continue;
    const to = `0x${l.topics[2]!.slice(26)}`.toLowerCase();
    if (!BURN_TO.has(to)) continue;
    raw += BigInt(l.data);
    from = `0x${l.topics[1]!.slice(26)}`.toLowerCase();
  }
  if (raw === 0n) throw new Error('no OCULON was sent to the burn address in this transaction');
  if (raw < min * E18) throw new Error(`this burn is ${formatUnits(raw, 18)} OCULON; it needs at least ${min.toLocaleString('en-US')}`);
  const blk = await r<{ timestamp: string }>('eth_getBlockByNumber', [receipt.blockNumber, false]);
  if (Number(BigInt(blk.timestamp)) * 1000 < UTILITY_START) throw new Error('this burn happened before the utility went live, so it cannot be used');
  return { tx, from, amount: formatUnits(raw, 18), raw: raw.toString(), block: Number(BigInt(receipt.blockNumber)), time: new Date(Number(BigInt(blk.timestamp)) * 1000).toISOString() };
}

function recordBurn(ctx: Ctx, kind: string, target: string, b: Burn) {
  db(ctx).prepare('INSERT INTO utility_burns (tx, kind, target, from_addr, amount, block, burned_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(b.tx, kind, target, b.from, b.amount, b.block, b.time, ctx.now().getTime());
}

// ---------- A. Burn-to-Investigate ----------

export interface InvestigationPart { title: string; ok: boolean; verdict: string | null; lines: string[]; error?: string; sources: string[] }
export interface Investigation { id: string; target: string; kind: string; status: 'running' | 'done'; burn: Burn | null; heldBy: { address: string; balance: string } | null; parts: InvestigationPart[]; createdAt: string; finishedAt: string | null }

export function targetKind(t: string): 'evm' | 'crypto' | 'domain' | 'name' {
  if (/^0x[0-9a-fA-F]{40}$/.test(t)) return 'evm';
  if (/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(t) || /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(t) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(t)) return 'crypto';
  if (/^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i.test(t)) return 'domain';
  return 'name';
}

/** A few readable lines out of any module result: its verdict, then its reasons, warnings or flags. */
export function summarize(title: string, r: { result: unknown; provenance: { source: string; status: string }[] }): InvestigationPart {
  const x = r.result as Record<string, unknown>;
  const verdict = ['verdict', 'risk'].map((k) => x?.[k]).find((v) => typeof v === 'string' || typeof v === 'number');
  const lines: string[] = [];
  for (const k of ['reasons', 'warnings', 'flags', 'problems', 'fixes']) { const v = x?.[k]; if (Array.isArray(v)) lines.push(...v.filter((s) => typeof s === 'string').slice(0, 8) as string[]); }
  if (Array.isArray(x?.live)) lines.push(...(x.live as { domain: string; kind: string }[]).slice(0, 12).map((l) => `lookalike live: ${l.domain} (${l.kind})`));
  if (Array.isArray(x?.breaches)) lines.push(...(x.breaches as { title: string; accounts: number; breachDate: string }[]).slice(0, 6).map((b) => `breach: ${b.title}, ${b.accounts.toLocaleString('en-US')} accounts, ${b.breachDate}`));
  if (Array.isArray(x?.victims)) lines.push(...(x.victims as { victim: string; group: string; discovered: string | null }[]).slice(0, 6).map((v) => `ransomware claim: ${v.group} lists ${v.victim}${v.discovered ? ` (${v.discovered.slice(0, 10)})` : ''}`));
  if (typeof x?.score === 'number' && !verdict) lines.unshift(`score ${x.score}`);
  return { title, ok: true, verdict: verdict === undefined ? null : String(verdict), lines: lines.slice(0, 16), sources: r.provenance.map((p) => `${p.source} ${p.status.toLowerCase()}`) };
}

async function part(title: string, f: () => Promise<{ result: unknown; provenance: { source: string; status: string }[] }>): Promise<InvestigationPart> {
  try { return summarize(title, await f()); } catch (e) { return { title, ok: false, verdict: null, lines: [], error: (e as Error).message.slice(0, 200), sources: [] }; }
}

export async function runInvestigation(o: Oculon, target: string): Promise<InvestigationPart[]> {
  const kind = targetKind(target);
  if (kind === 'evm') {
    return Promise.all([
      part('Robinhood Chain token', () => o.robinhoodToken(target)),
      part('Deployer history', () => o.robinhoodDeployer(target)),
      part('Address on Robinhood Chain', () => o.addressCheck(target, { network: 'robinhood' })),
      part('Address on Ethereum', () => o.addressCheck(target)),
    ]);
  }
  if (kind === 'crypto') return Promise.all([part('Address', () => o.addressCheck(target))]);
  if (kind === 'domain') {
    const d = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
    return Promise.all([
      part('Link safety', () => o.urlCheck(`https://${d}`)),
      part('Lookalike domains', () => o.lookalikes(d)),
      part('Email spoofing protection', () => o.emailSecurity(d)),
      part('Data breaches', () => o.breaches(d)),
      part('Ransomware claims', () => o.ransomware(d.split('.')[0]!.length >= 3 ? d.split('.')[0]! : d)),
    ]);
  }
  return Promise.all([
    part('Company registers', () => o.companyCheck(target)),
    part('Ransomware claims', () => o.ransomware(target)),
    part('Scam patterns in the name', () => o.scamCheck(target)),
  ]);
}

export async function startInvestigation(o: Oculon, tx: string, targetInput: string, signature: string): Promise<{ id: string; burn: Burn }> {
  const target = targetInput.trim().slice(0, 200);
  if (target.length < 3) throw new Error('give what to investigate: a domain, a wallet or token address, or a company name');
  const burn = await verifyBurn(o.ctx, tx, UTILITY.investigate);
  checkSigner('investigate', target, burn, signature);
  const id = randomBytes(6).toString('hex');
  const d = db(o.ctx);
  recordBurn(o.ctx, 'investigate', target, burn);
  d.prepare('INSERT INTO investigations (id, tx, target, status, created_at) VALUES (?, ?, ?, ?, ?)').run(id, burn.tx, target, 'running', o.ctx.now().getTime());
  void runInvestigation(o, target).then((parts) => {
    d.prepare('UPDATE investigations SET status = ?, result = ?, finished_at = ? WHERE id = ?').run('done', JSON.stringify(parts), Date.now(), id);
  }).catch((e) => {
    d.prepare('UPDATE investigations SET status = ?, result = ?, finished_at = ? WHERE id = ?').run('done', JSON.stringify([{ title: 'Investigation', ok: false, verdict: null, lines: [], error: String((e as Error).message), sources: [] }]), Date.now(), id);
  });
  return { id, burn };
}

/** Proves a wallet signed this action over a fresh nonce and returns its live OCULON balance. */
async function proveHolding(kind: 'investigate' | 'safety', target: string, address: string, nonce: string, signature: string): Promise<{ address: string; raw: bigint }> {
  const a = address.trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(a)) throw new Error('connect the wallet that holds OCULON');
  consumeNonce(nonce, a);
  const signer = recoverPersonalSigner(holdMessage(kind, target, a, nonce), signature);
  if (signer !== a) throw new Error('the signature does not match the wallet address');
  return { address: a, raw: await balanceOf(a) };
}

export async function startInvestigationHold(o: Oculon, targetInput: string, address: string, nonce: string, signature: string): Promise<{ id: string; nextFree: string }> {
  const target = targetInput.trim().slice(0, 200);
  if (target.length < 3) throw new Error('give what to investigate: a domain, a wallet or token address, or a company name');
  const h = await proveHolding('investigate', target, address, nonce, signature);
  if (h.raw < UTILITY.holdInvestigate * E18) throw new Error(`this wallet holds ${formatUnits(h.raw, 18)} OCULON; holding needs at least ${UTILITY.holdInvestigate.toLocaleString('en-US')} (or burn ${UTILITY.investigate.toLocaleString('en-US')} instead)`);
  const d = db(o.ctx);
  const now = o.ctx.now().getTime();
  const last = d.prepare("SELECT at FROM hold_uses WHERE address = ? AND kind = 'investigate' ORDER BY at DESC LIMIT 1").get(h.address) as { at: number } | undefined;
  const period = UTILITY.holdInvestigateDays * 86_400_000;
  if (last && now - last.at < period) throw new Error(`this wallet used its investigation for this period; the next one is free from ${new Date(last.at + period).toISOString().slice(0, 10)}`);
  d.prepare('INSERT INTO hold_uses (address, kind, target, balance, at) VALUES (?, ?, ?, ?, ?)').run(h.address, 'investigate', target, h.raw.toString(), now);
  const id = randomBytes(6).toString('hex');
  d.prepare('INSERT INTO investigations (id, tx, target, status, created_at) VALUES (?, ?, ?, ?, ?)').run(id, `hold:${h.address}:${formatUnits(h.raw, 18)}`, target, 'running', now);
  void runInvestigation(o, target).then((parts) => {
    d.prepare('UPDATE investigations SET status = ?, result = ?, finished_at = ? WHERE id = ?').run('done', JSON.stringify(parts), Date.now(), id);
  }).catch((e) => {
    d.prepare('UPDATE investigations SET status = ?, result = ?, finished_at = ? WHERE id = ?').run('done', JSON.stringify([{ title: 'Investigation', ok: false, verdict: null, lines: [], error: String((e as Error).message), sources: [] }]), Date.now(), id);
  });
  return { id, nextFree: new Date(now + period).toISOString() };
}

export function getInvestigation(ctx: Ctx, id: string): Investigation | null {
  if (!/^[0-9a-f]{12}$/.test(id)) return null;
  const row = db(ctx).prepare('SELECT i.*, b.from_addr, b.amount, b.raw, b.block, b.burned_at FROM investigations i LEFT JOIN (SELECT tx, from_addr, amount, amount AS raw, block, burned_at FROM utility_burns) b ON b.tx = i.tx WHERE i.id = ?').get(id) as Record<string, unknown> | undefined;
  if (!row) return null;
  return {
    id, target: String(row.target), kind: targetKind(String(row.target)), status: row.status as Investigation['status'],
    burn: row.from_addr ? { tx: String(row.tx), from: String(row.from_addr), amount: String(row.amount), raw: '', block: Number(row.block), time: String(row.burned_at) } : null,
    heldBy: String(row.tx).startsWith('hold:') ? { address: String(row.tx).split(':')[1]!, balance: String(row.tx).split(':')[2] ?? '' } : null,
    parts: row.result ? (JSON.parse(String(row.result)) as InvestigationPart[]) : [],
    createdAt: new Date(Number(row.created_at)).toISOString(), finishedAt: row.finished_at ? new Date(Number(row.finished_at)).toISOString() : null,
  };
}

export function listInvestigations(ctx: Ctx, limit = 20): { id: string; target: string; status: string; createdAt: string }[] {
  return (db(ctx).prepare('SELECT id, target, status, created_at FROM investigations ORDER BY created_at DESC LIMIT ?').all(limit) as { id: string; target: string; status: string; created_at: number }[]).map((r) => ({ id: r.id, target: r.target, status: r.status, createdAt: new Date(r.created_at).toISOString() }));
}

// ---------- B. Live Safety Badge ----------

export interface SafetyState { token: string; active: boolean; expiresAt: string | null; heldBy: string | null; verdict: string | null; reasons: string[]; name: string | null; symbol: string | null; lastCheck: string | null; history: { at: string; verdict: string }[] }

export async function checkSafety(o: Oculon, token: string): Promise<SafetyState> {
  const t = token.toLowerCase();
  const r = await o.robinhoodToken(t);
  const now = o.ctx.now().getTime();
  const d = db(o.ctx);
  d.prepare('UPDATE safety_monitors SET last_check = ?, verdict = ?, reasons = ?, name = ?, symbol = ? WHERE token = ?').run(now, r.result.verdict, JSON.stringify(r.result.reasons), r.result.name, r.result.symbol, t);
  const last = d.prepare('SELECT verdict FROM safety_checks WHERE token = ? ORDER BY at DESC LIMIT 1').get(t) as { verdict: string } | undefined;
  if (!last || last.verdict !== r.result.verdict) d.prepare('INSERT INTO safety_checks (token, at, verdict, reasons) VALUES (?, ?, ?, ?)').run(t, now, r.result.verdict, JSON.stringify(r.result.reasons));
  return safetyState(o.ctx, t);
}

export async function startSafety(o: Oculon, tx: string, tokenInput: string, signature: string): Promise<{ state: SafetyState; burn: Burn }> {
  const token = tokenInput.trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(token)) throw new Error('give the Robinhood Chain token address to monitor: 0x followed by 40 hex characters');
  const burn = await verifyBurn(o.ctx, tx, UTILITY.safety);
  checkSigner('safety', token, burn, signature);
  const d = db(o.ctx);
  const now = o.ctx.now().getTime();
  const cur = d.prepare('SELECT expires_at FROM safety_monitors WHERE token = ?').get(token) as { expires_at: number } | undefined;
  const start = cur && cur.expires_at > now ? cur.expires_at : now;
  const expires = start + UTILITY.safetyDays * 86_400_000;
  recordBurn(o.ctx, 'safety', token, burn);
  d.prepare('INSERT INTO safety_monitors (token, expires_at, created_at) VALUES (?, ?, ?) ON CONFLICT(token) DO UPDATE SET expires_at = excluded.expires_at').run(token, expires, now);
  const state = await checkSafety(o, token).catch(() => safetyState(o.ctx, token));
  return { state, burn };
}

/** Hold-backed badge: live while the wallet keeps the balance, re-checked daily. One badge per wallet. */
export async function startSafetyHold(o: Oculon, tokenInput: string, address: string, nonce: string, signature: string): Promise<{ state: SafetyState }> {
  const token = tokenInput.trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(token)) throw new Error('give the Robinhood Chain token address to monitor: 0x followed by 40 hex characters');
  const h = await proveHolding('safety', token, address, nonce, signature);
  if (h.raw < UTILITY.holdSafety * E18) throw new Error(`this wallet holds ${formatUnits(h.raw, 18)} OCULON; holding needs at least ${UTILITY.holdSafety.toLocaleString('en-US')} (or burn ${UTILITY.safety.toLocaleString('en-US')} for 30 days)`);
  const d = db(o.ctx);
  const now = o.ctx.now().getTime();
  const other = d.prepare('SELECT token FROM safety_monitors WHERE holder = ? AND token != ? AND expires_at > ?').get(h.address, token, now) as { token: string } | undefined;
  if (other) throw new Error(`this wallet already backs the badge of ${other.token}; one badge per wallet`);
  const until = now + 2 * 86_400_000;
  d.prepare('INSERT INTO safety_monitors (token, expires_at, created_at, holder, holder_check) VALUES (?, ?, ?, ?, ?) ON CONFLICT(token) DO UPDATE SET holder = excluded.holder, holder_check = excluded.holder_check, expires_at = MAX(safety_monitors.expires_at, excluded.expires_at)').run(token, until, now, h.address, now);
  d.prepare('INSERT INTO hold_uses (address, kind, target, balance, at) VALUES (?, ?, ?, ?, ?)').run(h.address, 'safety', token, h.raw.toString(), now);
  const state = await checkSafety(o, token).catch(() => safetyState(o.ctx, token));
  return { state };
}

/** Daily: a hold-backed badge stays live two more days while the wallet still holds enough; otherwise it lapses. */
export async function refreshHolders(ctx: Ctx): Promise<{ token: string; holder: string; ok: boolean }[]> {
  const d = db(ctx);
  const now = ctx.now().getTime();
  const rows = d.prepare('SELECT token, holder FROM safety_monitors WHERE holder IS NOT NULL AND (holder_check IS NULL OR holder_check <= ?)').all(now - 23 * 3_600_000) as { token: string; holder: string }[];
  const out: { token: string; holder: string; ok: boolean }[] = [];
  for (const r of rows) {
    try {
      const ok = (await balanceOf(r.holder)) >= UTILITY.holdSafety * E18;
      if (ok) d.prepare('UPDATE safety_monitors SET holder_check = ?, expires_at = MAX(expires_at, ?) WHERE token = ?').run(now, now + 2 * 86_400_000, r.token);
      else d.prepare('UPDATE safety_monitors SET holder_check = ?, holder = NULL WHERE token = ?').run(now, r.token);
      out.push({ ...r, ok });
    } catch { /* try again next round */ }
  }
  return out;
}

export function safetyState(ctx: Ctx, token: string): SafetyState {
  const t = token.toLowerCase();
  const d = db(ctx);
  const m = d.prepare('SELECT * FROM safety_monitors WHERE token = ?').get(t) as { expires_at: number; last_check: number | null; verdict: string | null; reasons: string | null; name: string | null; symbol: string | null; holder: string | null } | undefined;
  const hist = (d.prepare('SELECT at, verdict FROM safety_checks WHERE token = ? ORDER BY at DESC LIMIT 30').all(t) as { at: number; verdict: string }[]).map((h) => ({ at: new Date(h.at).toISOString(), verdict: h.verdict }));
  return { token: t, active: !!m && m.expires_at > ctx.now().getTime(), expiresAt: m ? new Date(m.expires_at).toISOString() : null, heldBy: m?.holder ?? null, verdict: m?.verdict ?? null, reasons: m?.reasons ? (JSON.parse(m.reasons) as string[]) : [], name: m?.name ?? null, symbol: m?.symbol ?? null, lastCheck: m?.last_check ? new Date(m.last_check).toISOString() : null, history: hist };
}

/** Re-checks every active monitor not checked in the last `everyMs` (default 14 minutes). Returns verdict changes. */
export async function runSafety(o: Oculon, everyMs = 14 * 60_000): Promise<{ token: string; from: string | null; to: string }[]> {
  await refreshHolders(o.ctx).catch(() => []);
  const now = o.ctx.now().getTime();
  const rows = db(o.ctx).prepare('SELECT token, verdict FROM safety_monitors WHERE expires_at > ? AND (last_check IS NULL OR last_check <= ?)').all(now, now - everyMs) as { token: string; verdict: string | null }[];
  const changes: { token: string; from: string | null; to: string }[] = [];
  for (const r of rows) {
    try { const s = await checkSafety(o, r.token); if (s.verdict && s.verdict !== r.verdict) changes.push({ token: r.token, from: r.verdict, to: s.verdict }); } catch { /* next round */ }
  }
  return changes;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
/** A shields-style SVG badge with the live verdict, or "not monitored". */
export function badgeSvg(s: SafetyState): string {
  const v = s.active ? s.verdict ?? 'CHECKING' : 'NOT MONITORED';
  const color = !s.active ? '#5d676b' : v === 'OK' ? '#2ea36b' : v === 'CAUTION' ? '#c98a12' : v === 'DANGER' ? '#d23b4a' : '#5d676b';
  const left = 'Oculon safety', lw = 96, rw = Math.max(64, Math.ceil(v.length * 8.2 + 22));
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${lw + rw}" height="22" role="img" aria-label="${left}: ${esc(v)}"><title>${left}: ${esc(v)}</title><rect width="${lw}" height="22" fill="#0b1013"/><rect x="${lw}" width="${rw}" height="22" fill="${color}"/><g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11"><text x="9" y="15" fill="#00f0ff">${left}</text><text x="${lw + 9}" y="15" font-weight="bold">${esc(v)}</text></g></svg>`;
}

// ---------- C. Holder tier ----------

const nonces = new Map<string, { address: string; exp: number }>();

export function holderMessage(domain: string, address: string, nonce: string, issuedAt: string): string {
  return `${domain} wants you to sign in with your wallet:\n${address}\n\nSign in to Oculon to check your OCULON holder tier. This does not send a transaction or cost anything.\n\nNonce: ${nonce}\nIssued At: ${issuedAt}`;
}

export function createNonce(domain: string, addressInput: string, now = Date.now()): { message: string; nonce: string } {
  const address = addressInput.trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) throw new Error('give the wallet address you will sign with');
  for (const [k, v] of nonces) if (v.exp < now) nonces.delete(k);
  if (nonces.size > 5000) throw new Error('too many sign-in attempts right now, try again in a minute');
  const nonce = randomBytes(12).toString('hex');
  nonces.set(nonce, { address, exp: now + 10 * 60_000 });
  return { nonce, message: holderMessage(domain, address, nonce, new Date(now).toISOString()) };
}

/** A nonce works once, for the wallet it was issued to, within ten minutes. */
export function consumeNonce(nonce: string, address: string): void {
  const e = nonces.get(nonce);
  if (!e || e.exp < Date.now() || e.address !== address.toLowerCase()) throw new Error('this request expired; start again');
  nonces.delete(nonce);
}

export async function balanceOf(address: string): Promise<bigint> {
  const cfg = tokenConfig();
  if (!cfg) throw new Error('the official token address is not configured on this install');
  const hex = await rpc()<string>('eth_call', [{ to: cfg.ca, data: `0x70a08231${address.slice(2).toLowerCase().padStart(64, '0')}` }, 'latest']);
  return BigInt(hex);
}

/** Checks a sign-in message from createNonce and its signature, uses the nonce up, and returns the signing wallet. */
export function signInWallet(message: string, signature: string): string {
  const nonce = /Nonce: ([0-9a-f]{24})/.exec(message)?.[1];
  const entry = nonce ? nonces.get(nonce) : undefined;
  if (!nonce || !entry || entry.exp < Date.now()) throw new Error('this sign-in request expired; start again');
  if (!/^[^\n]+ wants you to sign in with your wallet:\n/.test(message)) throw new Error('not a sign-in message');
  const signer = recoverPersonalSigner(message, signature);
  if (!signer || signer !== entry.address || !message.includes(entry.address)) throw new Error('the signature does not match the wallet address');
  nonces.delete(nonce);
  return signer;
}

export interface HolderSession { key: string | null; address: string; balance: string; holder: boolean; expiresAt: string | null; needs: string }

export async function verifyHolder(ctx: Ctx, owner: string, message: string, signature: string): Promise<HolderSession> {
  const nonce = /Nonce: ([0-9a-f]{24})/.exec(message)?.[1];
  const entry = nonce ? nonces.get(nonce) : undefined;
  if (!nonce || !entry || entry.exp < Date.now()) throw new Error('this sign-in request expired; start again');
  if (!message.startsWith(`${message.split(' wants you')[0]} wants you to sign in`)) throw new Error('not a sign-in message');
  const signer = recoverPersonalSigner(message, signature);
  if (!signer || signer !== entry.address || !message.includes(entry.address)) throw new Error('the signature does not match the wallet address');
  nonces.delete(nonce);
  const raw = await balanceOf(signer);
  const balance = formatUnits(raw, 18);
  const needs = `${UTILITY.holder.toLocaleString('en-US')} OCULON`;
  if (raw < UTILITY.holder * E18) return { key: null, address: signer, balance, holder: false, expiresAt: null, needs };
  const key = randomBytes(24).toString('hex');
  const exp = ctx.now().getTime() + UTILITY.sessionDays * 86_400_000;
  db(ctx).prepare('INSERT INTO holder_sessions (key, owner, address, balance, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(key, owner, signer, raw.toString(), exp, ctx.now().getTime());
  return { key, address: signer, balance, holder: true, expiresAt: new Date(exp).toISOString(), needs };
}

/** The holder session behind an owner (web visitor), if any is still valid. */
export function holderFor(ctx: Ctx, owner: string): { address: string; expiresAt: string } | null {
  const r = db(ctx).prepare('SELECT address, expires_at FROM holder_sessions WHERE owner = ? AND expires_at > ? ORDER BY expires_at DESC LIMIT 1').get(owner, ctx.now().getTime()) as { address: string; expires_at: number } | undefined;
  return r ? { address: r.address, expiresAt: new Date(r.expires_at).toISOString() } : null;
}

export function holderOwners(ctx: Ctx): Set<string> {
  return new Set((db(ctx).prepare('SELECT DISTINCT owner FROM holder_sessions WHERE expires_at > ?').all(ctx.now().getTime()) as { owner: string }[]).map((r) => r.owner));
}

export function signOutHolder(ctx: Ctx, owner: string): void {
  db(ctx).prepare('DELETE FROM holder_sessions WHERE owner = ?').run(owner);
}
