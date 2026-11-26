/**
 * Rug Radar: every new token on Robinhood Chain, checked as it launches and followed afterwards.
 *   Discovery: GeckoTerminal's newest Robinhood Chain pools (Uniswap v2/v4, Pons), a few pages each pass.
 *   Quick read (every token): pool-only flags from Heron (thin liquidity, buys without sells, a crash in the
 *     last hour, valuation far above liquidity).
 *   Full check (tokens that draw liquidity first): Heron's token check: verified source, top-10 holder share,
 *     every pool, and the deployer's record (how many of its earlier tokens are dead).
 *   Follow-up: liquidity is re-read for a day after launch. A pool that had real liquidity and lost most of it
 *     is marked RUGGED; one that never drew any and sits empty after a day is marked DEAD.
 * Alerts for dangerous tokens with real money in them, and for rugs, can be posted to a Telegram channel.
 * A verdict is a reading of public data at one moment, not proof of intent.
 */
import type { Ctx } from '../core/context.js';
import type { DatabaseSync } from 'node:sqlite';
import { poolFlags, rhTokenCheck } from './heron.js';
import { toPool, tokensMarket, type Pool } from '../sources/robinhood.js';

const GT = 'https://api.geckoterminal.com/api/v2/networks/robinhood';
/** Quote tokens: a pool's other side, never the launch itself. */
const QUOTES = new Set(['0x0000000000000000000000000000000000000000']);
const QUOTE_SYMBOLS = /^(W?ETH|USDG|USDC|USDT)$/i;

export type RadarVerdict = 'DANGER' | 'CAUTION' | 'OK' | 'UNKNOWN' | 'RUGGED' | 'DEAD';

export interface Launch {
  token: string;
  symbol: string;
  name: string;
  pool: string;
  dex: string;
  poolUrl: string;
  createdAt: string;
  firstSeen: number;
  liquidityUsd: number;
  peakLiquidityUsd: number;
  volume24h: number;
  buyers24h: number;
  sellers24h: number;
  change1h: number | null;
  fdvUsd: number | null;
  verdict: RadarVerdict;
  checked: 'quick' | 'full';
  reasons: string[];
  holders: number | null;
  top10Share: number | null;
  verified: boolean | null;
  deployer: string | null;
  deployerTokens: number | null;
  deployerDead: number | null;
  ruggedAt: number | null;
  updatedAt: number;
}

export interface RadarStats {
  windowHours: number;
  launches: number;
  danger: number;
  caution: number;
  ok: number;
  rugged: number;
  dead: number;
  fullyChecked: number;
  lostUsd: number;
}

export interface RadarAlert {
  kind: 'danger' | 'rug';
  launch: Launch;
}

const PER_PAGE_PAGES = 2;
const FULL_PER_PASS = 2;
/** A pool that once held this much and lost most of it counts as a rug; under it, a dead launch. */
const RUG_PEAK_USD = 3_000;
const RUG_LEFT = 0.2;
const FOLLOW_HOURS = 48;
const KEEP_DAYS = 7;

const ready = new WeakSet<DatabaseSync>();
function db(ctx: Ctx): DatabaseSync {
  const d = ctx.store.db;
  if (!ready.has(d)) {
    d.exec(`CREATE TABLE IF NOT EXISTS rug_radar (token TEXT PRIMARY KEY, symbol TEXT NOT NULL DEFAULT '', first_seen INTEGER NOT NULL, created_at TEXT NOT NULL, verdict TEXT NOT NULL, checked TEXT NOT NULL, liquidity REAL NOT NULL, peak REAL NOT NULL, rugged_at INTEGER, alerted TEXT, data TEXT NOT NULL, updated_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS rug_radar_seen ON rug_radar (first_seen);
      CREATE INDEX IF NOT EXISTS rug_radar_symbol ON rug_radar (symbol);`);
    ready.add(d);
  }
  return d;
}

interface Row { data: string; alerted: string | null }
const load = (ctx: Ctx, token: string): (Launch & { alerted: string | null }) | null => {
  const r = db(ctx).prepare('SELECT data, alerted FROM rug_radar WHERE token = ?').get(token) as Row | undefined;
  return r ? { ...(JSON.parse(r.data) as Launch), alerted: r.alerted } : null;
};
const save = (ctx: Ctx, l: Launch, alerted?: string | null) => {
  db(ctx)
    .prepare(
      `INSERT INTO rug_radar (token, symbol, first_seen, created_at, verdict, checked, liquidity, peak, rugged_at, alerted, data, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(token) DO UPDATE SET verdict = excluded.verdict, checked = excluded.checked, liquidity = excluded.liquidity, peak = excluded.peak, rugged_at = excluded.rugged_at, alerted = COALESCE(excluded.alerted, rug_radar.alerted), data = excluded.data, updated_at = excluded.updated_at`,
    )
    .run(l.token, l.symbol.toLowerCase(), l.firstSeen, l.createdAt, l.verdict, l.checked, l.liquidityUsd, l.peakLiquidityUsd, l.ruggedAt, alerted ?? null, JSON.stringify(l), l.updatedAt);
};

interface GtPoolRaw {
  attributes: { name: string; address: string; pool_created_at: string };
  relationships?: { base_token?: { data?: { id?: string } }; quote_token?: { data?: { id?: string } }; dex?: { data?: { id?: string } } };
}

/** The launched token's side of a pool name like "KURO / WETH 0.3%". */
export function launchSymbol(poolName: string): string {
  return (poolName.split(' / ')[0] ?? poolName).trim();
}

const DEX_NAMES: Record<string, string> = { 'pons-v2': 'Pons', 'uniswap-v4-robinhood': 'Uniswap v4', 'uniswap-v2-robinhood': 'Uniswap v2', 'uniswap-v3-robinhood': 'Uniswap v3' };
export const dexName = (id: string) => DEX_NAMES[id] ?? id.replace(/-robinhood$/, '').replace(/-/g, ' ');

/** Verdict from the pool alone, before any explorer call. */
export function quickVerdict(p: Pool, nowMs: number): { verdict: RadarVerdict; reasons: string[] } {
  const f = poolFlags(p, nowMs);
  const strong = f.flags.filter((x) => /honeypot|rug/.test(x));
  if (strong.length) return { verdict: 'DANGER', reasons: f.flags };
  // Thin liquidity is how nearly every launch starts (a Pons curve opens near $3,000): a note, not a warning.
  const warn = f.flags.filter((x) => !/^thin liquidity/.test(x));
  return { verdict: warn.length ? 'CAUTION' : 'UNKNOWN', reasons: [...f.flags, 'not fully checked yet: the full check runs once it draws liquidity'] };
}

/** The note on a token that reuses an earlier launch's ticker. */
export const copyReason = (symbol: string, original: string) => `copycat ticker: another ${symbol} (${original.slice(0, 8)}…${original.slice(-4)}) launched earlier; check you have the right address`;

/** Where a launch stands after its liquidity moved. Rugs and dead launches stay that way. */
export function followUp(l: Launch, liquidityUsd: number, nowMs: number): Launch {
  const peak = Math.max(l.peakLiquidityUsd, liquidityUsd);
  const next: Launch = { ...l, liquidityUsd, peakLiquidityUsd: peak, updatedAt: nowMs };
  if (l.verdict === 'RUGGED') return next;
  if (peak >= RUG_PEAK_USD && liquidityUsd < peak * RUG_LEFT) {
    const lost = Math.round(peak - liquidityUsd);
    return { ...next, verdict: 'RUGGED', ruggedAt: nowMs, reasons: [`liquidity fell from $${Math.round(peak).toLocaleString('en-US')} to $${Math.round(liquidityUsd).toLocaleString('en-US')} (about $${lost.toLocaleString('en-US')} pulled or sold out)`, ...l.reasons.filter((r) => !/^liquidity fell/.test(r))] };
  }
  const ageH = (nowMs - Date.parse(l.createdAt)) / 3_600_000;
  if (ageH >= 24 && peak < RUG_PEAK_USD && liquidityUsd < 100) return { ...next, verdict: 'DEAD', reasons: ['never drew real liquidity; empty a day after launch'] };
  return next;
}

async function newPoolsPages(ctx: Ctx): Promise<{ pool: Pool; dex: string; quote: string }[]> {
  const out: { pool: Pool; dex: string; quote: string }[] = [];
  for (let page = 1; page <= PER_PAGE_PAGES; page++) {
    const r = await ctx.http.get<{ data?: GtPoolRaw[] }>(`${GT}/new_pools?page=${page}`, { source: 'geckoterminal', ttlSec: 60 });
    const list = r.data?.data ?? [];
    for (const raw of list) {
      const pool = toPool(raw as Parameters<typeof toPool>[0]);
      out.push({ pool, dex: raw.relationships?.dex?.data?.id ?? '', quote: (raw.relationships?.quote_token?.data?.id ?? '').replace(/^robinhood_/, '') });
    }
    if (list.length < 20) break;
  }
  return out;
}

/** One pass: discover new launches, fully check the ones with money in them, follow up on the last two days. */
export async function radarScan(ctx: Ctx, opts: { marketTtlSec?: number } = {}): Promise<{ added: number; checked: number; followed: number; alerts: RadarAlert[] }> {
  const nowMs = ctx.now().getTime();
  const alerts: RadarAlert[] = [];
  let added = 0;
  const pools = await newPoolsPages(ctx);
  pools.sort((a, b) => Date.parse(a.pool.createdAt) - Date.parse(b.pool.createdAt));
  for (const { pool, dex } of pools) {
    const token = pool.token.toLowerCase();
    const symbol = launchSymbol(pool.name);
    if (!/^0x[0-9a-f]{40}$/.test(token) || QUOTES.has(token) || QUOTE_SYMBOLS.test(symbol)) continue;
    const have = load(ctx, token);
    if (have) {
      // A second pool for a token we know: keep the deeper one.
      if (pool.liquidityUsd > have.liquidityUsd && have.verdict !== 'RUGGED') save(ctx, { ...have, pool: pool.address, dex: dexName(dex), poolUrl: pool.url, liquidityUsd: pool.liquidityUsd, peakLiquidityUsd: Math.max(have.peakLiquidityUsd, pool.liquidityUsd), volume24h: pool.volume24h, buyers24h: pool.buyers24h, sellers24h: pool.sellers24h, change1h: pool.change1h, fdvUsd: pool.fdvUsd, updatedAt: nowMs });
      continue;
    }
    const q = quickVerdict(pool, nowMs);
    // Same ticker as a token launched earlier: copies ride the original's attention.
    const original = db(ctx).prepare('SELECT token, created_at FROM rug_radar WHERE symbol = ? AND token != ? AND created_at < ? ORDER BY peak DESC LIMIT 1').get(symbol.toLowerCase(), token, pool.createdAt) as { token: string; created_at: string } | undefined;
    if (original) {
      q.reasons = [copyReason(symbol, original.token), ...q.reasons.filter((r) => !/^not fully checked/.test(r))];
      if (q.verdict === 'UNKNOWN') q.verdict = 'CAUTION';
    }
    save(ctx, {
      token, symbol, name: symbol, pool: pool.address, dex: dexName(dex), poolUrl: pool.url, createdAt: pool.createdAt, firstSeen: nowMs,
      liquidityUsd: pool.liquidityUsd, peakLiquidityUsd: pool.liquidityUsd, volume24h: pool.volume24h, buyers24h: pool.buyers24h, sellers24h: pool.sellers24h, change1h: pool.change1h, fdvUsd: pool.fdvUsd,
      verdict: q.verdict, checked: 'quick', reasons: q.reasons, holders: null, top10Share: null, verified: null, deployer: null, deployerTokens: null, deployerDead: null, ruggedAt: null, updatedAt: nowMs,
    });
    added++;
  }

  // Full checks: the launches holding the most liquidity that have not had one yet.
  const since = nowMs - FOLLOW_HOURS * 3_600_000;
  const due = db(ctx).prepare("SELECT token FROM rug_radar WHERE checked = 'quick' AND first_seen >= ? AND liquidity >= 1000 AND verdict NOT IN ('RUGGED','DEAD') ORDER BY liquidity DESC LIMIT ?").all(since, FULL_PER_PASS) as { token: string }[];
  let checked = 0;
  for (const { token } of due) {
    const l = load(ctx, token);
    if (!l) continue;
    try {
      const r = (await rhTokenCheck(ctx, token)).result;
      const full: Launch = {
        ...l,
        symbol: r.symbol || l.symbol,
        name: r.name || l.name,
        checked: 'full',
        verdict: r.verdict,
        reasons: [...l.reasons.filter((x) => x.startsWith('copycat ticker')), ...(r.reasons.length ? r.reasons : ['no risk flags in contract, holders, pools or deployer record'])],
        ...(l.reasons.some((x) => x.startsWith('copycat ticker')) && r.verdict === 'OK' ? { verdict: 'CAUTION' as const } : {}),
        holders: r.holders,
        top10Share: r.top10Share,
        verified: r.verified,
        deployer: r.deployer.address,
        deployerTokens: r.deployer.otherTokens,
        deployerDead: r.deployer.dead,
        updatedAt: nowMs,
      };
      let alerted = l.alerted;
      if (full.verdict === 'DANGER' && full.liquidityUsd >= 5_000 && !alerted) {
        alerts.push({ kind: 'danger', launch: full });
        alerted = 'danger';
      }
      save(ctx, full, alerted);
      checked++;
    } catch {
      // explorer down or rate limited: the next pass tries again
    }
  }

  // Follow-up: liquidity of launches from the last two days, oldest reading first, 30 per GeckoTerminal call.
  const follow = db(ctx).prepare("SELECT token FROM rug_radar WHERE first_seen >= ? AND verdict NOT IN ('RUGGED','DEAD') ORDER BY updated_at ASC LIMIT 30").all(since) as { token: string }[];
  let followed = 0;
  for (let i = 0; i < follow.length; i += 30) {
    const batch = follow.slice(i, i + 30).map((x) => x.token);
    const m = await tokensMarket(ctx, batch, opts.marketTtlSec ?? 150);
    if (!m.data) break;
    for (const token of batch) {
      const l = load(ctx, token);
      if (!l) continue;
      const mk = m.data.get(token);
      // Absent from the market list means no pool left with any reserve.
      const next = followUp(l, mk ? mk.reserveUsd : 0, nowMs);
      if (mk) next.volume24h = mk.volume24h;
      let alerted = l.alerted;
      if (next.verdict === 'RUGGED' && l.verdict !== 'RUGGED' && next.peakLiquidityUsd >= 5_000 && alerted !== 'rug') {
        alerts.push({ kind: 'rug', launch: next });
        alerted = 'rug';
      }
      save(ctx, next, alerted);
      followed++;
    }
  }
  db(ctx).prepare('DELETE FROM rug_radar WHERE first_seen < ?').run(nowMs - KEEP_DAYS * 86_400_000);
  return { added, checked, followed, alerts };
}

/** Launches for the page: newest first, optionally one verdict only. */
export function radarList(ctx: Ctx, opts: { limit?: number; verdict?: string; hours?: number } = {}): Launch[] {
  const nowMs = ctx.now().getTime();
  const since = nowMs - (opts.hours ?? 24) * 3_600_000;
  const limit = Math.min(300, opts.limit ?? 100);
  const v = (opts.verdict ?? '').toUpperCase();
  const rows = (v && /^(DANGER|CAUTION|OK|UNKNOWN|RUGGED|DEAD)$/.test(v)
    ? db(ctx).prepare('SELECT data FROM rug_radar WHERE first_seen >= ? AND verdict = ? ORDER BY created_at DESC LIMIT ?').all(since, v, limit)
    : db(ctx).prepare('SELECT data FROM rug_radar WHERE first_seen >= ? ORDER BY created_at DESC LIMIT ?').all(since, limit)) as { data: string }[];
  return rows.map((r) => JSON.parse(r.data) as Launch);
}

export function radarStats(ctx: Ctx, hours = 24): RadarStats {
  const since = ctx.now().getTime() - hours * 3_600_000;
  const rows = db(ctx).prepare('SELECT verdict, checked, peak, liquidity FROM rug_radar WHERE first_seen >= ?').all(since) as { verdict: RadarVerdict; checked: string; peak: number; liquidity: number }[];
  const n = (v: RadarVerdict) => rows.filter((r) => r.verdict === v).length;
  return {
    windowHours: hours,
    launches: rows.length,
    danger: n('DANGER'),
    caution: n('CAUTION'),
    ok: n('OK'),
    rugged: n('RUGGED'),
    dead: n('DEAD'),
    fullyChecked: rows.filter((r) => r.checked === 'full').length,
    lostUsd: Math.round(rows.filter((r) => r.verdict === 'RUGGED').reduce((a, r) => a + Math.max(0, r.peak - r.liquidity), 0)),
  };
}

/** A Telegram message for one alert (HTML parse mode). */
export function alertText(a: RadarAlert, base = 'https://oculon.live'): string {
  const l = a.launch;
  const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);
  const usd = (n: number) => `$${Math.round(n).toLocaleString('en-US')}`;
  const head = a.kind === 'rug' ? `RUG on Robinhood Chain: ${esc(l.symbol)}` : `DANGER on Robinhood Chain: ${esc(l.symbol)}`;
  const lines = [
    `<b>${head}</b>`,
    `<code>${l.token}</code>`,
    a.kind === 'rug' ? `Liquidity ${usd(l.peakLiquidityUsd)} → ${usd(l.liquidityUsd)}` : `Liquidity ${usd(l.liquidityUsd)} on ${esc(l.dex)}`,
    ...l.reasons.slice(0, 4).map((r) => `• ${esc(r)}`),
    `<a href="${l.poolUrl}">Pool</a> · <a href="${base}/rugradar">Rug Radar</a>`,
  ];
  return lines.join('\n');
}

/** Post alerts to a Telegram channel (TELEGRAM_BOT_TOKEN and OCULON_RADAR_CHAT). At most `max` per call. */
export async function postAlerts(alerts: RadarAlert[], opts: { token?: string; chat?: string; base?: string; fetch?: typeof fetch; max?: number } = {}): Promise<number> {
  const token = opts.token ?? process.env.TELEGRAM_BOT_TOKEN?.trim();
  const chat = opts.chat ?? process.env.OCULON_RADAR_CHAT?.trim();
  if (!token || !chat || !alerts.length) return 0;
  const f = opts.fetch ?? fetch;
  let sent = 0;
  for (const a of alerts.slice(0, opts.max ?? 5)) {
    try {
      const r = await f(`https://api.telegram.org/bot${token}/sendMessage`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chat_id: chat, text: alertText(a, opts.base), parse_mode: 'HTML', disable_web_page_preview: true }) });
      if (r.ok) sent++;
    } catch {
      // Telegram unreachable: the alert is dropped, the page still shows it
    }
  }
  return sent;
}
