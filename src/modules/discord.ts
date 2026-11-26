/**
 * Discord Sentinel: a small Discord bot that guards a server against scam links and impersonators.
 *   Links: every link in a message goes through the URL check (results cached per URL). Malicious: the message is
 *     deleted (when auto-delete is on and the bot has Manage Messages) and a short notice with the reasons is
 *     posted. Suspicious: a reply warns about the link.
 *   Impersonation: when a member joins or changes their name, the display name is normalized (lowercase, look-alike
 *     letters such as 0/o, 1/l/i, rn/m and Cyrillic or Greek copies folded, spaces and punctuation removed) and
 *     compared with the owner and members whose roles can moderate. A match with someone else is posted to the
 *     log channel (or the server's system channel).
 *   Slash commands: /check <link or text> and /sentinel settings (log channel, auto-delete), stored per server.
 * Runs over the Gateway (v10) with heartbeat, resume and reconnect with backoff; REST calls retry on 429.
 * Needs DISCORD_BOT_TOKEN, and the Server Members and Message Content intents enabled for the bot.
 * A link verdict is what the sources found at that moment; "no known threats" is not a promise.
 */
import type { DatabaseSync } from 'node:sqlite';
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { verdictOf } from '../core/verdict.js';
import { recordCheck } from './checks.js';
import { scamCheck } from './scam.js';
import { apexOf, normalizeUrl, urlCheck, type UrlVerdict } from './urlcheck.js';

export const DISCORD_API = 'https://discord.com/api/v10';
export const GATEWAY_URL = 'wss://gateway.discord.gg';

/** GUILDS, GUILD_MEMBERS, GUILD_MESSAGES, MESSAGE_CONTENT. */
export const INTENTS = (1 << 0) | (1 << 1) | (1 << 9) | (1 << 15);

/** View Channels, Send Messages, Manage Messages, Read Message History (76800). */
export const BOT_PERMISSIONS = String((1 << 10) + (1 << 11) + (1 << 13) + (1 << 16));

const P = { KICK: 1n << 1n, BAN: 1n << 2n, ADMIN: 1n << 3n, MANAGE_GUILD: 1n << 5n, MANAGE_MESSAGES: 1n << 13n, MANAGE_ROLES: 1n << 28n, MODERATE: 1n << 40n };
const STAFF_MASK = P.KICK | P.BAN | P.ADMIN | P.MANAGE_GUILD | P.MANAGE_MESSAGES | P.MANAGE_ROLES | P.MODERATE;

/** What the /discord page needs: whether the bot runs here and the invite link (null without DISCORD_CLIENT_ID). */
export function discordInfo(clientId: string | undefined = key('DISCORD_CLIENT_ID')): { enabled: boolean; clientId: string | null; permissions: string; invite: string | null } {
  const id = clientId && /^\d{15,25}$/.test(clientId) ? clientId : null;
  return {
    enabled: Boolean(key('DISCORD_BOT_TOKEN')),
    clientId: id,
    permissions: BOT_PERMISSIONS,
    invite: id ? `https://discord.com/oauth2/authorize?client_id=${id}&permissions=${BOT_PERMISSIONS}&scope=bot%20applications.commands` : null,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Names

const CONFUSABLE: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'з': '3', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ь': 'b', 'п': 'n', 'г': 'r',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'μ': 'u',
  // Latin extensions and symbols
  'ı': 'i', 'ł': 'l', 'ɡ': 'g', 'ɑ': 'a', 'ø': 'o', 'ð': 'd', 'þ': 'p', 'ß': 'ss', 'æ': 'ae', 'œ': 'oe',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a', '|': 'l', '!': 'i', '€': 'e',
};

/** Capitals that look like a different Latin letter than their lower case does (Greek Mu is M, its lower case u). */
const CONFUSABLE_UPPER: Record<string, string> = {
  'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h', 'Ι': 'i', 'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o', 'Ρ': 'p', 'Τ': 't', 'Υ': 'y', 'Χ': 'x',
  'А': 'a', 'В': 'b', 'Е': 'e', 'К': 'k', 'М': 'm', 'Н': 'h', 'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't', 'Х': 'x', 'І': 'i', 'Ј': 'j', 'Ѕ': 's',
};

/** A name folded so look-alikes compare equal: "Μ0D_Aԁmin" and "mod admin" both become "modadmln". */
export function normalizeName(s: string): string {
  const upper = [...s.normalize('NFKD')].map((c) => CONFUSABLE_UPPER[c] ?? c).join('');
  const folded = [...upper.toLowerCase().replace(/[̀-ͯ]/g, '')].map((c) => CONFUSABLE[c] ?? c).join('');
  return folded
    .replace(/[^a-z]/g, '')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd')
    .replace(/[il]/g, 'l');
}

interface UserLike { id: string; username?: string; global_name?: string | null; bot?: boolean }
interface MemberLike { user?: UserLike; nick?: string | null; roles?: string[] }

export const displayName = (m: MemberLike): string => m.nick || m.user?.global_name || m.user?.username || '';
const memberNames = (m: MemberLike) => [...new Set([m.nick, m.user?.global_name, m.user?.username].filter((x): x is string => Boolean(x)).map(normalizeName).filter((n) => n.length >= 3))];

export interface Protected { id: string; label: string; role: string; names: string[] }

/** The protected member (owner or staff, not `selfId`) whose normalized name equals one of this member's. */
export function findImpersonation(member: MemberLike, staff: Iterable<Protected>): Protected | null {
  const mine = memberNames(member);
  if (!mine.length || !member.user) return null;
  for (const p of staff) {
    if (p.id === member.user.id) continue;
    if (p.names.some((n) => mine.includes(n))) return p;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Links

/** Big platforms whose links are not worth a check each time (exact registrable domain only). */
const SKIP_APEX = new Set(['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'tenor.com', 'giphy.com', 'youtube.com', 'youtu.be', 'google.com', 'github.com', 'wikipedia.org', 'x.com', 'twitter.com', 'reddit.com', 'twitch.tv', 'spotify.com', 'imgur.com', 'oculon.live']);

/** Links in a message, deduplicated, at most `max`; links to skipped platforms are left out. */
export function extractLinks(text: string, max = 5): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/https?:\/\/[^\s<>"'`)\]|]+/gi)) {
    const raw = m[0].replace(/[.,;:!?]+$/, '');
    try {
      const u = normalizeUrl(raw);
      if (SKIP_APEX.has(apexOf(u.hostname))) continue;
      if (!out.includes(u.href)) out.push(u.href);
    } catch { /* not a URL */ }
    if (out.length >= max) break;
  }
  return out;
}

/** "evil.com" -> "evil[.]com", so a notice never carries a clickable copy of a bad link. */
export const defang = (host: string) => host.replace(/\./g, '[.]');

// ---------------------------------------------------------------------------------------------------------------
// Settings

export interface GuildSettings { logChannel: string | null; autoDelete: boolean }

const ready = new WeakSet<DatabaseSync>();
function db(ctx: Ctx): DatabaseSync {
  const d = ctx.store.db;
  if (!ready.has(d)) {
    d.exec('CREATE TABLE IF NOT EXISTS discord_guilds (guild_id TEXT PRIMARY KEY, log_channel TEXT, auto_delete INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL)');
    ready.add(d);
  }
  return d;
}

export function guildSettings(ctx: Ctx, guildId: string): GuildSettings {
  const r = db(ctx).prepare('SELECT log_channel, auto_delete FROM discord_guilds WHERE guild_id = ?').get(guildId) as { log_channel: string | null; auto_delete: number } | undefined;
  return { logChannel: r?.log_channel ?? null, autoDelete: r ? Boolean(r.auto_delete) : true };
}

export function setGuildSettings(ctx: Ctx, guildId: string, patch: Partial<GuildSettings>): GuildSettings {
  const next = { ...guildSettings(ctx, guildId), ...patch };
  db(ctx)
    .prepare('INSERT INTO discord_guilds (guild_id, log_channel, auto_delete, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(guild_id) DO UPDATE SET log_channel = excluded.log_channel, auto_delete = excluded.auto_delete, updated_at = excluded.updated_at')
    .run(guildId, next.logChannel, next.autoDelete ? 1 : 0, ctx.now().getTime());
  return next;
}

// ---------------------------------------------------------------------------------------------------------------
// REST

export interface RestResult<T> { ok: boolean; status: number; data: T | null }

/** Discord REST with the bot token; a 429 waits retry_after and tries again (three times). */
export class DiscordRest {
  constructor(
    private readonly token: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  ) {}

  async call<T = unknown>(method: string, path: string, body?: unknown): Promise<RestResult<T>> {
    for (let attempt = 0; attempt < 4; attempt++) {
      let res: Response;
      try {
        res = await this.fetchImpl(`${DISCORD_API}${path}`, {
          method,
          headers: { authorization: `Bot ${this.token}`, 'user-agent': 'DiscordBot (https://oculon.live, 1)', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          signal: AbortSignal.timeout(15_000),
        });
      } catch {
        return { ok: false, status: 0, data: null };
      }
      if (res.status === 429 && attempt < 3) {
        const j = (await res.json().catch(() => ({}))) as { retry_after?: number };
        const wait = Number(j.retry_after ?? res.headers.get('retry-after') ?? 1) || 1;
        await this.sleep(Math.min(30_000, wait * 1000) + 50);
        continue;
      }
      const data = res.status === 204 ? null : ((await res.json().catch(() => null)) as T | null);
      return { ok: res.ok, status: res.status, data };
    }
    return { ok: false, status: 429, data: null };
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Gateway

type WsCtor = new (url: string) => WebSocket;
interface Payload { op: number; d?: unknown; s?: number | null; t?: string | null }

/** Close codes after which reconnecting cannot help (bad token, intents not enabled, bad shard). */
const FATAL = new Set([4004, 4010, 4011, 4012, 4013, 4014]);

export interface GatewayOptions {
  token: string;
  url?: string;
  WebSocket?: WsCtor;
  onDispatch: (t: string, d: unknown) => void;
  log?: (m: string) => void;
  /** First reconnect delay in ms (doubles each try, at most a minute). */
  backoffMs?: number;
  random?: () => number;
}

/** One Gateway connection: identify or resume, heartbeat with zombie detection, reconnect with backoff. */
export class DiscordGateway {
  ws: WebSocket | null = null;
  seq: number | null = null;
  sessionId: string | null = null;
  resumeUrl: string | null = null;
  private hb: NodeJS.Timeout | null = null;
  private retry: NodeJS.Timeout | null = null;
  private acked = true;
  private backoff: number;
  stopped = false;

  constructor(private readonly o: GatewayOptions) { this.backoff = o.backoffMs ?? 1000; }

  start(): void { this.connect(); }

  private log(m: string) { this.o.log?.(`discord: ${m}`); }

  private connect(): void {
    if (this.stopped) return;
    const base = (this.sessionId && this.resumeUrl) || this.o.url || GATEWAY_URL;
    const Ws = this.o.WebSocket ?? (globalThis.WebSocket as unknown as WsCtor);
    let ws: WebSocket;
    try { ws = new Ws(`${base.replace(/\/+$/, '')}/?v=10&encoding=json`); } catch (e) { this.log(`connect failed: ${(e as Error).message}`); return this.schedule(); }
    this.ws = ws;
    ws.onmessage = (ev: MessageEvent) => { let p: Payload; try { p = JSON.parse(String(ev.data)) as Payload; } catch { return; } this.onPayload(p); };
    ws.onclose = (ev: CloseEvent) => { if (this.ws === ws) this.onClose(ev.code ?? 1006); };
    ws.onerror = () => { /* followed by close */ };
  }

  send(p: Payload): void { if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(p)); }

  private beat(): void {
    if (!this.acked) { this.log('no heartbeat answer; reconnecting'); this.ws?.close(4000, 'zombie'); return; }
    this.acked = false;
    this.send({ op: 1, d: this.seq });
  }

  onPayload(p: Payload): void {
    if (typeof p.s === 'number') this.seq = p.s;
    switch (p.op) {
      case 10: {
        const every = Number((p.d as { heartbeat_interval?: number })?.heartbeat_interval ?? 41_250);
        this.acked = true;
        if (this.hb) clearInterval(this.hb);
        const first = setTimeout(() => { this.beat(); this.hb = setInterval(() => this.beat(), every); this.hb.unref?.(); }, Math.floor(every * (this.o.random ?? Math.random)()));
        first.unref?.();
        this.hb = first as unknown as NodeJS.Timeout;
        if (this.sessionId && this.seq !== null) this.send({ op: 6, d: { token: this.o.token, session_id: this.sessionId, seq: this.seq } });
        else this.send({ op: 2, d: { token: this.o.token, intents: INTENTS, properties: { os: process.platform, browser: 'oculon', device: 'oculon' } } });
        return;
      }
      case 11: this.acked = true; return;
      case 1: this.send({ op: 1, d: this.seq }); return;
      case 7: this.log('asked to reconnect'); this.ws?.close(4000, 'reconnect'); return;
      case 9:
        if (!p.d) { this.sessionId = null; this.seq = null; this.resumeUrl = null; }
        this.ws?.close(4000, 'invalid session');
        return;
      case 0: {
        if (p.t === 'READY') {
          const d = p.d as { session_id?: string; resume_gateway_url?: string };
          this.sessionId = d.session_id ?? null;
          this.resumeUrl = d.resume_gateway_url ?? null;
          this.backoff = this.o.backoffMs ?? 1000;
        } else if (p.t === 'RESUMED') this.backoff = this.o.backoffMs ?? 1000;
        if (p.t) { try { this.o.onDispatch(p.t, p.d); } catch (e) { this.log(`${p.t} handler failed: ${(e as Error).message}`); } }
        return;
      }
    }
  }

  private onClose(code: number): void {
    if (this.hb) { clearInterval(this.hb); clearTimeout(this.hb); this.hb = null; }
    this.ws = null;
    if (this.stopped) return;
    if (FATAL.has(code)) {
      this.stopped = true;
      this.log(code === 4014 ? 'closed 4014: enable the Server Members and Message Content intents for the bot in the Discord developer portal' : code === 4004 ? 'closed 4004: DISCORD_BOT_TOKEN is not valid' : `closed ${code}; not reconnecting`);
      return;
    }
    // Invalid sequence or a timed-out session cannot be resumed.
    if (code === 4007 || code === 4009) { this.sessionId = null; this.seq = null; this.resumeUrl = null; }
    this.schedule();
  }

  private schedule(): void {
    if (this.stopped) return;
    const wait = this.backoff + Math.floor((this.o.random ?? Math.random)() * Math.min(1000, this.backoff));
    this.backoff = Math.min(60_000, this.backoff * 2);
    this.retry = setTimeout(() => this.connect(), wait);
    this.retry.unref?.();
  }

  stop(): void {
    this.stopped = true;
    if (this.hb) { clearInterval(this.hb); clearTimeout(this.hb); }
    if (this.retry) clearTimeout(this.retry);
    try { this.ws?.close(1000, 'stop'); } catch { /* already closed */ }
    this.ws = null;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The bot

export interface SentinelOptions {
  /** Default DISCORD_BOT_TOKEN. */
  token?: string;
  /** Base URL for report links (e.g. https://app.oculon.live). */
  base?: string;
  fetch?: typeof fetch;
  WebSocket?: WsCtor;
  gatewayUrl?: string;
  log?: (m: string) => void;
  /** Register the slash commands on READY (default true). */
  registerCommands?: boolean;
  /** New links checked per server per hour (default 120). */
  linksPerHour?: number;
  /** The URL check (tests). */
  checkUrl?: (url: string) => Promise<{ verdict: UrlVerdict; reasons: string[] }>;
  sleep?: (ms: number) => Promise<void>;
  backoffMs?: number;
}

interface Guild { id: string; ownerId: string; systemChannel: string | null; roles: Map<string, bigint>; staff: Map<string, Protected> }
interface LinkVerdict { verdict: UrlVerdict; reasons: string[]; at: number }

export const COMMANDS = [
  { name: 'check', type: 1, description: 'Check a link or a message for scams', contexts: [0, 1, 2], integration_types: [0], options: [{ type: 3, name: 'input', description: 'A link, or the text of a message you received', required: true, max_length: 2000 }] },
  {
    name: 'sentinel', type: 1, description: 'Oculon Sentinel settings for this server', contexts: [0], integration_types: [0], default_member_permissions: String(P.MANAGE_GUILD),
    options: [{ type: 1, name: 'settings', description: 'Show or change the log channel and auto-delete', options: [
      { type: 7, name: 'log_channel', description: 'Channel for impersonation and removal notices', required: false, channel_types: [0, 5] },
      { type: 5, name: 'auto_delete', description: 'Delete messages with malicious links', required: false },
    ] }],
  },
];

const NO_PINGS = { parse: [] as string[] };
const CACHE_MS = 6 * 3600_000;
const short = (s: string, n = 180) => (s.length > n ? `${s.slice(0, n - 3)}...` : s);

export class Sentinel {
  readonly rest: DiscordRest;
  readonly guilds = new Map<string, Guild>();
  private readonly cache = new Map<string, LinkVerdict>();
  private readonly inflight = new Map<string, Promise<LinkVerdict | null>>();
  private readonly budget = new Map<string, { hour: number; n: number }>();
  private readonly seenNames = new Map<string, string>();
  private readonly warned = new Map<string, number>();
  userId: string | null = null;
  appId: string | null = null;
  private registered = false;
  gateway: DiscordGateway | null = null;

  constructor(private readonly ctx: Ctx, private readonly opts: SentinelOptions & { token: string }) {
    this.rest = new DiscordRest(opts.token, opts.fetch ?? fetch, opts.sleep);
  }

  private log(m: string) { this.opts.log?.(`discord: ${m}`); }
  private now() { return this.ctx.now().getTime(); }

  start(): void {
    this.gateway = new DiscordGateway({ token: this.opts.token, ...(this.opts.gatewayUrl ? { url: this.opts.gatewayUrl } : {}), ...(this.opts.WebSocket ? { WebSocket: this.opts.WebSocket } : {}), ...(this.opts.backoffMs ? { backoffMs: this.opts.backoffMs } : {}), onDispatch: (t, d) => void this.dispatch(t, d).catch((e) => this.log(`${t}: ${(e as Error).message}`)), log: this.opts.log });
    this.gateway.start();
  }

  stop(): void { this.gateway?.stop(); }

  /** One Gateway event. Exposed for tests. */
  async dispatch(t: string, d: unknown): Promise<void> {
    const x = d as Record<string, unknown>;
    switch (t) {
      case 'READY': {
        this.userId = (x.user as UserLike | undefined)?.id ?? null;
        this.appId = (x.application as { id?: string } | undefined)?.id ?? null;
        this.log(`ready as ${(x.user as UserLike | undefined)?.username ?? 'bot'} in ${(x.guilds as unknown[] | undefined)?.length ?? 0} server(s)`);
        if (this.appId && !this.registered && this.opts.registerCommands !== false) {
          this.registered = true;
          const r = await this.rest.call('PUT', `/applications/${this.appId}/commands`, COMMANDS);
          if (!r.ok) this.log(`slash commands not registered (HTTP ${r.status})`);
        }
        return;
      }
      case 'GUILD_CREATE': case 'GUILD_UPDATE': return this.onGuild(x);
      case 'GUILD_DELETE': if (!x.unavailable) this.guilds.delete(String(x.id)); return;
      case 'GUILD_ROLE_CREATE': case 'GUILD_ROLE_UPDATE': {
        const g = this.guilds.get(String(x.guild_id));
        const role = x.role as { id: string; permissions: string } | undefined;
        if (g && role) { g.roles.set(role.id, BigInt(role.permissions)); if ((BigInt(role.permissions) & STAFF_MASK) !== 0n) void this.loadStaff(g); }
        return;
      }
      case 'GUILD_ROLE_DELETE': { const g = this.guilds.get(String(x.guild_id)); g?.roles.delete(String(x.role_id)); return; }
      case 'GUILD_MEMBER_ADD': return this.onMember(String(x.guild_id), x as MemberLike, 'joined');
      case 'GUILD_MEMBER_UPDATE': return this.onMember(String(x.guild_id), x as MemberLike, 'changed their name');
      case 'MESSAGE_CREATE': return this.onMessage(x);
      case 'INTERACTION_CREATE': return this.onInteraction(x);
    }
  }

  private async onGuild(x: Record<string, unknown>): Promise<void> {
    const id = String(x.id);
    const prev = this.guilds.get(id);
    const roles = new Map<string, bigint>();
    for (const r of (x.roles as { id: string; permissions: string }[] | undefined) ?? []) roles.set(r.id, BigInt(r.permissions));
    const g: Guild = { id, ownerId: String(x.owner_id ?? prev?.ownerId ?? ''), systemChannel: (x.system_channel_id as string | null | undefined) ?? prev?.systemChannel ?? null, roles: roles.size ? roles : prev?.roles ?? roles, staff: prev?.staff ?? new Map() };
    this.guilds.set(id, g);
    for (const m of (x.members as MemberLike[] | undefined) ?? []) this.track(g, m);
    if (!prev) await this.loadStaff(g);
  }

  private isStaff(g: Guild, m: MemberLike): string | null {
    if (!m.user) return null;
    if (m.user.id === g.ownerId) return 'owner';
    let perms = g.roles.get(g.id) ?? 0n; // @everyone
    for (const r of m.roles ?? []) perms |= g.roles.get(r) ?? 0n;
    if (perms & P.ADMIN) return 'admin';
    return perms & STAFF_MASK ? 'moderator' : null;
  }

  /** Keep the protected list in step with a member seen in an event. */
  private track(g: Guild, m: MemberLike): string | null {
    if (!m.user || m.user.bot) return null;
    const role = this.isStaff(g, m);
    if (role) g.staff.set(m.user.id, { id: m.user.id, label: displayName(m), role, names: memberNames(m) });
    else g.staff.delete(m.user.id);
    return role;
  }

  /** The owner and members with moderating roles (first 5,000 members read through REST). */
  async loadStaff(g: Guild): Promise<void> {
    let after = '0';
    for (let page = 0; page < 5; page++) {
      const r = await this.rest.call<MemberLike[]>('GET', `/guilds/${g.id}/members?limit=1000&after=${after}`);
      if (!r.ok || !r.data?.length) break;
      for (const m of r.data) this.track(g, m);
      after = r.data.at(-1)!.user?.id ?? after;
      if (r.data.length < 1000) break;
    }
    if (g.ownerId && !g.staff.has(g.ownerId)) {
      const r = await this.rest.call<MemberLike>('GET', `/guilds/${g.id}/members/${g.ownerId}`);
      if (r.ok && r.data) this.track(g, r.data);
    }
  }

  private async onMember(guildId: string, m: MemberLike, what: string): Promise<void> {
    const g = this.guilds.get(guildId);
    if (!g || !m.user || m.user.bot) return;
    if (this.track(g, m)) return; // staff are not checked against each other
    const names = memberNames(m).join('|');
    const seenKey = `${guildId}:${m.user.id}`;
    if (this.seenNames.get(seenKey) === names) return; // a role change, not a new name
    this.seenNames.set(seenKey, names);
    if (this.seenNames.size > 50_000) this.seenNames.delete(this.seenNames.keys().next().value!);
    const hit = findImpersonation(m, g.staff.values());
    if (!hit) return;
    const warnKey = `${seenKey}:${hit.id}:${names}`;
    if ((this.warned.get(warnKey) ?? 0) > this.now() - 86_400_000) return;
    this.warned.set(warnKey, this.now());
    const channel = guildSettings(this.ctx, guildId).logChannel ?? g.systemChannel;
    const text = `Possible impersonation: <@${m.user.id}> ${what} as "${short(displayName(m), 60)}", which reads the same as ${hit.role} <@${hit.id}> once look-alike letters are folded. Check before trusting messages from this account.`;
    if (!channel) { this.log(`impersonation in ${guildId}, but no log or system channel`); return; }
    await this.rest.call('POST', `/channels/${channel}/messages`, { content: text, allowed_mentions: NO_PINGS });
  }

  /** The URL check for one link, cached for six hours and limited per server per hour. */
  async linkVerdict(guildId: string, url: string): Promise<LinkVerdict | null> {
    const hit = this.cache.get(url);
    if (hit && this.now() - hit.at < CACHE_MS) return hit;
    const running = this.inflight.get(url);
    if (running) return running;
    const hour = Math.floor(this.now() / 3600_000);
    const b = this.budget.get(guildId);
    const used = b && b.hour === hour ? b.n : 0;
    if (used >= (this.opts.linksPerHour ?? 120)) return null;
    this.budget.set(guildId, { hour, n: used + 1 });
    const p = (async () => {
      try {
        const r = this.opts.checkUrl ? await this.opts.checkUrl(url) : (await urlCheck(this.ctx, url)).result;
        const v: LinkVerdict = { verdict: r.verdict, reasons: r.reasons.slice(0, 3), at: this.now() };
        this.cache.set(url, v);
        if (this.cache.size > 5000) this.cache.delete(this.cache.keys().next().value!);
        return v;
      } catch { return null; } finally { this.inflight.delete(url); }
    })();
    this.inflight.set(url, p);
    return p;
  }

  private async onMessage(x: Record<string, unknown>): Promise<void> {
    const guildId = x.guild_id ? String(x.guild_id) : null;
    const author = x.author as UserLike | undefined;
    if (!guildId || !author || author.bot || x.webhook_id || author.id === this.userId) return;
    const links = extractLinks(String(x.content ?? ''));
    if (!links.length) return;
    const checked: { url: string; v: LinkVerdict }[] = [];
    for (const url of links) { const v = await this.linkVerdict(guildId, url); if (v) checked.push({ url, v }); }
    const bad = checked.find((c) => c.v.verdict === 'malicious');
    const sus = checked.find((c) => c.v.verdict === 'suspicious');
    const channel = String(x.channel_id), msgId = String(x.id);
    const settings = guildSettings(this.ctx, guildId);
    if (bad) {
      const host = defang(new URL(bad.url).hostname);
      const why = bad.v.reasons.slice(0, 2).map((r) => short(r)).join('; ');
      let deleted = false;
      if (settings.autoDelete) deleted = (await this.rest.call('DELETE', `/channels/${channel}/messages/${msgId}`)).ok;
      const content = deleted
        ? `Removed a message from <@${author.id}>: the link ${host} is flagged as malicious (${why}).`
        : `Warning: the link ${host} in this message is flagged as malicious (${why}). Do not open it or connect a wallet.`;
      await this.rest.call('POST', `/channels/${channel}/messages`, { content: short(content, 1900), allowed_mentions: NO_PINGS, ...(deleted ? {} : { message_reference: { message_id: msgId, fail_if_not_exists: false } }) });
      if (settings.logChannel && settings.logChannel !== channel) {
        await this.rest.call('POST', `/channels/${settings.logChannel}/messages`, { content: short(`Malicious link from <@${author.id}> in <#${channel}>: ${host} (${why}). Message ${deleted ? 'deleted' : 'not deleted'}.`, 1900), allowed_mentions: NO_PINGS });
      }
      return;
    }
    if (sus) {
      const why = sus.v.reasons.slice(0, 2).map((r) => short(r)).join('; ');
      await this.rest.call('POST', `/channels/${channel}/messages`, { content: short(`Careful: the link ${defang(new URL(sus.url).hostname)} looks suspicious (${why}). Check it before you open it.`, 1900), allowed_mentions: NO_PINGS, message_reference: { message_id: msgId, fail_if_not_exists: false } });
    }
  }

  private async onInteraction(x: Record<string, unknown>): Promise<void> {
    if (x.type !== 2) return;
    const data = x.data as { name?: string; options?: { name: string; type: number; value?: unknown; options?: { name: string; value?: unknown }[] }[] } | undefined;
    const id = String(x.id), token = String(x.token);
    const appId = String(x.application_id ?? this.appId ?? '');
    const answer = (content: string) => this.rest.call('POST', `/interactions/${id}/${token}/callback`, { type: 4, data: { content: short(content, 1900), flags: 64, allowed_mentions: NO_PINGS } });
    if (data?.name === 'sentinel') {
      const guildId = x.guild_id ? String(x.guild_id) : null;
      if (!guildId) { await answer('Use this command in a server.'); return; }
      const perms = BigInt(String((x.member as { permissions?: string } | undefined)?.permissions ?? '0'));
      if (!(perms & (P.ADMIN | P.MANAGE_GUILD))) { await answer('Only members with Manage Server can change Sentinel settings.'); return; }
      const opts = data.options?.[0]?.options ?? [];
      const patch: Partial<GuildSettings> = {};
      for (const o of opts) {
        if (o.name === 'log_channel' && typeof o.value === 'string') patch.logChannel = o.value;
        if (o.name === 'auto_delete' && typeof o.value === 'boolean') patch.autoDelete = o.value;
      }
      const s = Object.keys(patch).length ? setGuildSettings(this.ctx, guildId, patch) : guildSettings(this.ctx, guildId);
      await answer(`${Object.keys(patch).length ? 'Saved. ' : ''}Log channel: ${s.logChannel ? `<#${s.logChannel}>` : 'not set (the system channel is used)'}. Auto-delete of malicious links: ${s.autoDelete ? 'on' : 'off'}.`);
      return;
    }
    if (data?.name === 'check') {
      const input = String(data.options?.find((o) => o.name === 'input')?.value ?? '').trim();
      if (!input) { await answer('Give a link or the text of a message.'); return; }
      await this.rest.call('POST', `/interactions/${id}/${token}/callback`, { type: 5, data: { flags: 64 } });
      let content: string;
      try { content = await this.checkText(input); } catch (e) { content = `Could not check that: ${short((e as Error).message, 200)}`; }
      await this.rest.call('PATCH', `/webhooks/${appId}/${token}/messages/@original`, { content: short(content, 1900), allowed_mentions: NO_PINGS });
    }
  }

  /** /check: one link goes through the URL check, anything else through the scam check. */
  async checkText(input: string): Promise<string> {
    const oneLink = /^(https?:\/\/)?[^\s/]+\.[a-z]{2,}(\/\S*)?$/i.test(input);
    const { value, check } = oneLink
      ? await recordCheck(this.ctx, 'url', input, () => urlCheck(this.ctx, input), { label: input.slice(0, 90) })
      : await recordCheck(this.ctx, 'scam', input, () => scamCheck(this.ctx, input));
    const v = verdictOf(value);
    const base = (this.opts.base ?? '').replace(/\/+$/, '');
    return [
      `**${v.verdict ?? 'checked'}**${v.risk !== null ? ` (risk ${v.risk}/100)` : ''}`,
      ...v.points.slice(0, 4).map((p) => `- ${short(p)}`),
      base ? `Full report: ${base}/replay/${check.id}` : null,
      'A verdict is what the sources found now, not a guarantee.',
    ].filter((l): l is string => l !== null).join('\n');
  }
}

/**
 * Start the bot when DISCORD_BOT_TOKEN (or opts.token) is set. Returns a function that stops it, or null when no
 * token is configured.
 */
export function startDiscordSentinel(oculon: { ctx: Ctx }, opts: SentinelOptions = {}): (() => void) | null {
  const token = opts.token ?? key('DISCORD_BOT_TOKEN');
  if (!token) return null;
  const s = new Sentinel(oculon.ctx, { ...opts, token });
  s.start();
  return () => s.stop();
}
