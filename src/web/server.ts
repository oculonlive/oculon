/**
 * Oculon web dashboard: a dependency-free HTTP server (node:http) with a JSON API over the SDK
 * and a single-page UI. Binds to 127.0.0.1 by default.
 * Optional watch loop runs the radar, military scan and natural events on an interval so history
 * (surge baselines, signal feed) builds up while the dashboard is open.
 */
import { spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Oculon, summarizeProvenance } from '../index.js';
import type { ModuleResult } from '../core/types.js';
import { startScheduler } from '../scheduler.js';
import { isOnchainEntity, isOnchainSource, ONCHAIN_MODULES, ONCHAIN_WATCH_KINDS, onchainEnabled } from '../core/features.js';
import { adminCookieValue, clientIp, isAdmin, lockedPage, PUBLIC_API, publicGraph, publicSignals, RateLimiter, tokenMatches } from './public.js';
import { accuracy, entityProfile, rhDeployers, searchEntities, signalsSince, sourceHealth, timeline } from './insights.js';

const HERE = dirname(fileURLToPath(import.meta.url));

export interface WebOptions {
  port?: number;
  host?: string;
  /** Open to the internet: read-only overview and docs for visitors, full app only with the admin cookie. */
  publicMode?: boolean;
  /** Owner token for public mode (default OCULON_ADMIN_TOKEN). Without one the app cannot be opened remotely. */
  adminToken?: string;
  /** Public domain (default OCULON_DOMAIN): app.<domain> serves the dashboard and docs.<domain> the docs. */
  domain?: string;
  /** Minutes between background scans; 0 disables. */
  watchMinutes?: number;
  oculon?: Oculon;
  log?: (msg: string) => void;
  /** Called with new signals and the daily brief from the schedule (used to forward them to Telegram). */
  onSignals?: (signals: import('../core/types.js').Signal[]) => Promise<void> | void;
  onBrief?: (markdown: string) => Promise<void> | void;
  onReport?: (file: string) => Promise<void> | void;
}

type Handler = (q: URLSearchParams, o: Oculon) => Promise<unknown> | unknown;

const slim = (r: ModuleResult<unknown>) => ({ module: r.module, input: r.input, generatedAt: r.generatedAt, result: r.result, signals: r.signals, provenance: summarizeProvenance(r.provenance) });

function need(q: URLSearchParams, key: string, max = 200): string {
  const v = q.get(key)?.trim();
  if (!v) throw new HttpError(400, `missing parameter: ${key}`);
  if (v.length > max) throw new HttpError(400, `parameter too long: ${key}`);
  return v;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/* ---------- console: real CLI output for the landing page ---------- */

const HEX_ADDR = /^0x[0-9a-fA-F]{40}$/;
/**
 * Commands the public console may run, each mapped to the exact argv it spawns. Anything else is refused,
 * so the page can never reach a command that writes (watch add, case new) or costs paid quota (ask, social).
 */
export function consoleArgv(input: string): string[] | null {
  const parts = input.trim().replace(/^oculon\s+/, '').split(/\s+/).filter(Boolean);
  if (!parts.length || parts.length > 4) return null;
  const [cmd, a1, a2, a3] = parts;
  const onchain = onchainEnabled();
  const bare = ['bgp', 'vulns', 'hazards', 'cloud', 'defi', 'squawk', 'blackout', 'regs', 'calendar', 'quota', 'help', ...(onchain ? ['rh'] : [])];
  if (parts.length === 1 && bare.includes(cmd!)) return [cmd!];
  if (onchain && cmd === 'deployer' && parts.length === 2 && HEX_ADDR.test(a1!)) return ['deployer', a1!];
  if (onchain && cmd === 'token' && HEX_ADDR.test(a1!) && ((parts.length === 2) || (a2 === '--chain' && /^(eth|base|arbitrum|bsc|polygon|robinhood)$/.test(a3 ?? '')))) return parts as string[];
  if (cmd === 'cve' && parts.length === 2 && /^CVE-\d{4}-\d{4,7}$/i.test(a1!)) return ['cve', a1!.toUpperCase()];
  if (cmd === 'bgp' && parts.length === 2 && /^(AS\d{1,10}|[A-Za-z]{2})$/i.test(a1!)) return ['bgp', a1!.toUpperCase()];
  if (cmd === 'vulns' && parts.length === 2 && /^\d{1,2}$/.test(a1!)) return ['vulns', a1!];
  return null;
}

const CONSOLE_TTL = 10 * 60_000;
const consoleCache = new Map<string, { at: number; text: string; ok: boolean }>();
const consoleRunning = new Map<string, Promise<{ at: number; text: string; ok: boolean }>>();

function cliEntry(): string {
  const js = join(HERE, '..', 'cli.js');
  return existsSync(js) ? js : join(HERE, '..', 'cli.ts');
}

function runCli(argv: string[]): Promise<{ at: number; text: string; ok: boolean }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...process.execArgv, cliEntry(), ...argv], {
      env: { ...process.env, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let text = '';
    const take = (b: Buffer) => {
      if (text.length < 200_000) text += b.toString('utf8');
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    const timer = setTimeout(() => child.kill(), 120_000);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ at: Date.now(), text: text.replace(/\r\n/g, '\n').trimEnd(), ok: code === 0 });
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ at: Date.now(), text: e.message, ok: false });
    });
  });
}

export async function runConsole(input: string): Promise<{ command: string; output: string; ok: boolean; ranAt: string; cached: boolean }> {
  const argv = consoleArgv(input);
  if (!argv) throw new HttpError(400, 'not available in the web console; try: bgp, vulns, hazards, rh, cloud, defi, squawk, token <0x…> --chain robinhood, deployer <0x…>, cve <id>');
  const key = argv.join(' ');
  const hit = consoleCache.get(key);
  if (hit && Date.now() - hit.at < CONSOLE_TTL) return { command: `oculon ${key}`, output: hit.text, ok: hit.ok, ranAt: new Date(hit.at).toISOString(), cached: true };
  if (!consoleRunning.has(key) && consoleRunning.size >= 4) throw new HttpError(429, 'console busy, try again in a moment');
  let p = consoleRunning.get(key);
  if (!p) {
    p = runCli(argv).finally(() => consoleRunning.delete(key));
    consoleRunning.set(key, p);
  }
  const r = await p;
  if (r.ok) consoleCache.set(key, r);
  return { command: `oculon ${key}`, output: r.text, ok: r.ok, ranAt: new Date(r.at).toISOString(), cached: false };
}

/** Graph slice for the UI: walk the most recent edges and keep entities until `limit` nodes are collected. */
export function graphSlice(o: Oculon, limit: number) {
  const db = o.ctx.store.db;
  const recent = db.prepare('SELECT src, dst, rel, source FROM edges ORDER BY updated_at DESC LIMIT 5000').all() as { src: string; dst: string; rel: string; source: string }[];
  const ids = new Set<string>();
  const edges: typeof recent = [];
  for (const e of recent) {
    const extra = Number(!ids.has(e.src)) + Number(!ids.has(e.dst));
    if (ids.size + extra > limit) continue;
    ids.add(e.src);
    ids.add(e.dst);
    edges.push(e);
  }
  const get = db.prepare('SELECT id, kind, name FROM entities WHERE id = ?');
  const nodes = [...ids].map((id) => get.get(id) as { id: string; kind: string; name: string } | undefined).filter((n) => n !== undefined);
  return { nodes, edges };
}

export const ROUTES: Record<string, Handler> = {
  '/api/signals': (q, o) => o.signals(Math.min(200, Number(q.get('limit') ?? 50) || 50)),
  '/api/radar': async (_q, o) => slim(await o.radar()),
  '/api/military': async (_q, o) => {
    const r = await o.military();
    // Positions for the map come from the cached adsb.lol response the scan just used.
    const cached = o.ctx.store.cacheGet('https://api.adsb.lol/v2/mil');
    const ac = cached ? ((JSON.parse(cached.body) as { ac?: { hex: string; r?: string; t?: string; flight?: string; lat?: number; lon?: number; alt_baro?: number | string }[] }).ac ?? []) : [];
    return { ...slim(r), aircraft: ac.filter((a) => typeof a.lat === 'number').map((a) => ({ hex: a.hex, reg: a.r ?? null, type: a.t ?? null, callsign: a.flight?.trim() ?? null, lat: a.lat, lon: a.lon, alt: a.alt_baro ?? null })) };
  },
  '/api/events': async (q, o) => slim(await o.naturalEvents(Number(q.get('days') ?? 7) || 7)),
  '/api/aircraft': async (q, o) => slim(await o.aircraft(need(q, 'q', 20))),
  '/api/dossier': async (q, o) => slim(await o.dossier(need(q, 'name'))),
  '/api/hype': async (q, o) => slim(await o.hype(need(q, 'topic'))),
  '/api/footprint': async (q, o) => slim(await o.footprint(need(q, 'domain', 100))),
  '/api/lights': async (q, o) => slim(await o.nightLights(need(q, 'place'))),
  '/api/ask': async (q, o) => o.ask(need(q, 'q', 500)),
  '/api/wallet': async (q, o) => slim(await o.wallet(need(q, 'address', 64))),
  '/api/token': async (q, o) => slim(await o.token(need(q, 'address', 64), q.get('chain') ?? 'eth')),
  '/api/space': async (_q, o) => slim(await o.spaceWeather()),
  '/api/air': async (q, o) => slim(await o.airQuality(need(q, 'place'))),
  '/api/narratives': async (_q, o) => (await o.narratives(14)).slice(0, 15),
  '/api/sanctions': async (q, o) => slim(await o.sanctions(need(q, 'q', 120))),
  '/api/health': async (q, o) => {
    const r = await o.health(need(q, 'company', 80));
    return { module: 'health', result: r.result, signals: r.signals.filter((s) => s.module === 'health'), provenance: summarizeProvenance(r.provenance) };
  },
  '/api/impact': async (q, o) => slim(await o.impact(q.get('place')?.trim() || undefined, Number(q.get('radius') ?? 50) || 50)),
  '/api/contradictions': async (q, o) => slim(await o.contradictions(need(q, 'topic', 120))),
  '/api/robinhood': async (_q, o) => slim(await o.robinhood()),
  '/api/rhtoken': async (q, o) => slim(await o.robinhoodToken(need(q, 'address', 64))),
  '/api/deployer': async (q, o) => slim(await o.robinhoodDeployer(need(q, 'address', 64))),
  '/api/markets': async (_q, o) => slim(await o.markets()),
  '/api/launches': async (q, o) => slim(await o.launches(need(q, 'company', 80), q.get('domain') ? { domain: q.get('domain')! } : {})),
  '/api/rewind': async (q, o) => slim(await o.rewind(need(q, 'date', 10))),
  '/api/scoops': (_q, o) => o.scoops(),
  '/api/cases': async (_q, o) => (await o.caseList()).map((k) => ({ id: k.id, question: k.question, confidence: k.report?.confidence ?? null, findings: k.report?.findings.length ?? 0, runs: k.runs, watch: k.watch, updatedAt: k.updatedAt })),
  '/api/case': async (q, o) => o.caseGet(Number(need(q, 'id', 10))),
  '/api/fences': (_q, o) => o.fenceList().map((f) => ({ id: f.id, name: f.name, box: [f.south, f.west, f.north, f.east], kinds: f.kinds, lastRun: f.lastRun, now: f.lastState ? { milAircraft: Object.values(f.lastState.milAircraft), milVessels: Object.values(f.lastState.milVessels), quakes: Object.values(f.lastState.quakes), events: Object.values(f.lastState.events) } : null })),
  '/api/quakes': async (_q, o) => {
    const { recentQuakes } = await import('../sources/usgs.js');
    return (await recentQuakes(o.ctx)).data ?? [];
  },
  '/api/brief': async (q, o) => o.brief({ refresh: q.get('refresh') === '1' }),
  '/api/watch': (_q, o) => o.watchList(),
  '/api/quota': (_q, o) => o.quota(),
  '/api/forecasts': (_q, o) => ({ scoreboard: o.scoreboard(), forecasts: o.forecasts('all', 200) }),
  '/api/verify': async (q, o) => slim(await o.verifyProof(need(q, 'id', 64))),
  '/api/entity': (q, o) => o.entity(need(q, 'id', 300)),
  '/api/exposure': async (q, o) => slim(await o.exposure(need(q, 'domain', 120))),
  '/api/podcast': async (q, o) => slim(await o.podcast(need(q, 'q', 120))),
  '/api/darkships': async (q, o) => slim(await o.darkShips(need(q, 'place', 120), Math.min(90, Number(q.get('days') ?? 30) || 30))),
  '/api/vessel': async (q, o) => slim(await o.vessel(need(q, 'q', 80))),
  '/api/fires': async (q, o) => slim(await o.fires(need(q, 'place', 120), Math.min(5, Number(q.get('days') ?? 2) || 2))),
  '/api/cloud': async (_q, o) => slim(await o.cloud()),
  '/api/bgp': async (q, o) => slim(await o.bgp(q.get('q')?.trim().slice(0, 45) || 'world', Math.min(14, Number(q.get('days') ?? 2) || 2))),
  '/api/vulns': async (q, o) => slim(await o.vulns({ days: Math.min(30, Number(q.get('days') ?? 7) || 7), ...(q.get('vendor') ? { vendor: need(q, 'vendor', 60) } : {}) })),
  '/api/cve': async (q, o) => slim(await o.cve(need(q, 'id', 30))),
  '/api/regs': async (q, o) => slim(await o.regs({ days: Math.min(60, Number(q.get('days') ?? 7) || 7), ...(q.get('q') ? { query: need(q, 'q', 120) } : {}), ...(q.get('agency') ? { agency: need(q, 'agency', 80) } : {}) })),
  '/api/defi': async (_q, o) => slim(await o.defi()),
  '/api/protocol': async (q, o) => slim(await o.protocol(need(q, 'name', 80))),
  '/api/squawks': async (_q, o) => slim(await o.squawks()),
  '/api/filings': async (q, o) => slim(await o.filings(need(q, 'q', 160), { days: Math.min(365, Number(q.get('days') ?? 30) || 30), ...(q.get('forms') ? { forms: need(q, 'forms', 60).split(',') } : {}) })),
  '/api/sec-events': async (q, o) => slim(await o.secEvents(need(q, 'company', 20), Math.min(365, Number(q.get('days') ?? 90) || 90))),
  '/api/blackout': async (q, o) => slim(await o.blackout(Math.min(14, Number(q.get('days') ?? 2) || 2))),
  '/api/hazards': async (q, o) => {
    // The bulletins hang off the result array and would be dropped by JSON, so they are sent beside it.
    const r = await o.hazards(Math.min(30, Number(q.get('days') ?? 7) || 7));
    return { ...slim(r), bulletins: r.result.bulletins ?? [] };
  },
  '/api/pulse': async (q, o) => slim(await o.pulse(need(q, 'q', 120))),
  '/api/calendar': async (q, o) => slim(await o.calendar(Math.min(60, Number(q.get('days') ?? 14) || 14))),
  '/api/connect': (q, o) => o.connect(need(q, 'a', 120), need(q, 'b', 120)),
  '/api/live': (_q, o) => o.signals(300).filter((x) => x.module === 'live').slice(0, 40),
  '/api/feedback': (_q, o) => o.feedbackStats(),
  '/api/graph': (q, o) => graphSlice(o, Math.min(400, Number(q.get('limit') ?? 150) || 150)),
  '/api/console': (q) => runConsole(need(q, 'cmd', 120)),
  '/api/search': (q, o) => searchEntities(o, need(q, 'q', 120), Math.min(30, Number(q.get('limit') ?? 12) || 12)),
  '/api/profile': (q, o) => entityProfile(o, need(q, 'id', 300)) ?? (() => { throw new HttpError(404, 'no such entity'); })(),
  '/api/rh/deployers': (q, o) => rhDeployers(o, Math.min(100, Number(q.get('limit') ?? 25) || 25)),
  '/api/sources': (_q, o) => sourceHealth(o),
  '/api/accuracy': (_q, o) => accuracy(o),
  '/api/timeline': (q, o) => timeline(o, Math.min(24 * 14, Number(q.get('hours') ?? 72) || 72)),
  '/api/meta': async () => {
    const { activeTools, SERVER_INFO } = await import('../mcp.js');
    const modules = readdirSync(join(HERE, '..', 'modules')).filter((f) => /\.(ts|js)$/.test(f) && !f.endsWith('.d.ts')).length;
    return { version: SERVER_INFO.version, mcpTools: activeTools().length, modules, onchain: onchainEnabled() };
  },
  '/api/readme': () => {
    for (const p of [join(HERE, '..', '..', 'README.md'), join(HERE, '..', 'README.md')]) if (existsSync(p)) return { markdown: readFileSync(p, 'utf8') };
    throw new HttpError(404, 'README not found');
  },
};

async function readJson(req: IncomingMessage, limit = 10_000): Promise<Record<string, unknown>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > limit) throw new HttpError(413, 'body too large');
    chunks.push(c as Buffer);
  }
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as unknown;
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error();
    return v as Record<string, unknown>;
  } catch {
    throw new HttpError(400, 'invalid JSON body');
  }
}

type PostHandler = (body: Record<string, unknown>, o: Oculon) => Promise<unknown> | unknown;

export const POST_ROUTES: Record<string, PostHandler> = {
  '/api/fences': (b, o) => {
    const box = Array.isArray(b.box) ? (b.box.map(Number) as [number, number, number, number]) : null;
    if (!box || box.length !== 4) throw new HttpError(400, 'box must be [south, west, north, east]');
    return o.fenceAdd(String(b.name ?? 'fence').slice(0, 60), box, Array.isArray(b.kinds) ? b.kinds.map(String) : undefined);
  },
  '/api/fences/delete': (b, o) => ({ removed: o.fenceRemove(Number(b.id)) }),
  '/api/feedback': (b, o) => {
    const verdict = String(b.verdict);
    if (verdict !== 'useful' && verdict !== 'noise') throw new HttpError(400, 'verdict must be useful or noise');
    const id = String(b.signalId ?? '').slice(0, 200);
    if (!id) throw new HttpError(400, 'missing signalId');
    return o.feedback(id, verdict, 'web');
  },
  '/api/cases': async (b, o) => {
    const q = String(b.question ?? '').trim();
    if (q.length < 8 || q.length > 500) throw new HttpError(400, 'question must be 8-500 characters');
    const r = await o.caseInvestigate({ question: q });
    return { id: r.case.id, markdown: r.case.markdown };
  },
};

const ASSET_TYPES: Record<string, string> = { '.jpg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.js': 'text/javascript; charset=utf-8' };

/** Server-sent events: new signals as they are stored, checked every 5 seconds. */
function streamSignals(req: IncomingMessage, res: ServerResponse, o: Oculon, onlyPublic = false) {
  res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store', connection: 'keep-alive', 'x-content-type-options': 'nosniff' });
  let last = Date.now();
  res.write('retry: 5000\n\n');
  const tick = () => {
    try {
      const all = signalsSince(o, last);
      const visible = onchainEnabled() ? all : all.filter((r) => !ONCHAIN_MODULES.has(r.module));
      const rows = onlyPublic ? publicSignals(visible) : visible;
      for (const r of all) last = Math.max(last, r.ts);
      for (const r of rows) {
        last = Math.max(last, r.ts);
        res.write(`event: signal\ndata: ${JSON.stringify(r)}\n\n`);
      }
      res.write(': ping\n\n');
    } catch {
      /* database busy; try again next tick */
    }
  };
  const timer = setInterval(tick, 5000);
  req.on('close', () => clearInterval(timer));
}

/** Endpoints that only exist for the on-chain features. */
const ONCHAIN_ROUTES = new Set(['/api/robinhood', '/api/rhtoken', '/api/deployer', '/api/rh/deployers', '/api/wallet', '/api/token']);

/** Drops on-chain signals, entities and watch items from shared views while those features are paused. */
function withoutOnchain(path: string, out: unknown): unknown {
  type Sig = { module: string; entity?: string | null };
  if (path === '/api/signals' || path === '/api/timeline') return (out as Sig[]).filter((s) => !ONCHAIN_MODULES.has(s.module) && !(s.entity && isOnchainEntity(s.entity)));
  if (path === '/api/graph') {
    const g = out as { nodes: { id: string }[]; edges: { src: string; dst: string }[] };
    const hidden = new Set(g.nodes.filter((n) => isOnchainEntity(n.id)).map((n) => n.id));
    return { nodes: g.nodes.filter((n) => !hidden.has(n.id)), edges: g.edges.filter((e) => !hidden.has(e.src) && !hidden.has(e.dst)) };
  }
  if (path === '/api/quota') return (out as { source: string }[]).filter((q) => !isOnchainSource(q.source));
  if (path === '/api/search') return (out as { id: string }[]).filter((e) => !isOnchainEntity(e.id));
  if (path === '/api/watch') return (out as { kind: string; target: string }[]).filter((w) => !ONCHAIN_WATCH_KINDS.has(w.kind) && !/@robinhood$/i.test(w.target));
  if (path === '/api/profile' && out && isOnchainEntity((out as { id: string }).id)) throw new HttpError(404, 'on-chain features are paused');
  return out;
}

/**
 * Prepares a page: keeps or removes the blocks marked for the on-chain features
 * (<!--onchain-->…<!--/onchain--> and /*onchain*\/…/*\/onchain*\/; the offchain markers are the reverse),
 * and on the public domain points /app and /docs links at their subdomains.
 */
export function renderPage(html: string, domain: string | null): string {
  const on = onchainEnabled();
  const drop = (name: string) => (h: string) => h.replace(new RegExp(`<!--${name}-->[\\s\\S]*?<!--/${name}-->`, 'g'), '').replace(new RegExp(`/\\*${name}\\*/[\\s\\S]*?/\\*/${name}\\*/`, 'g'), '');
  let out = on ? drop('offchain')(html) : drop('onchain')(html);
  // the markers themselves are not needed once the blocks are resolved
  out = out.replace(/<!--\/?(on|off)chain-->/g, '').replace(/\/\*\/?(on|off)chain\*\//g, '');
  if (domain) {
    const main = `https://${domain}`;
    out = out
      .replace(/href="\/app(#[^"]*)?"/g, (_m, h: string | undefined) => `href="https://app.${domain}/${h ?? ''}"`)
      .replace(/href="\/report"/g, `href="https://app.${domain}/report"`)
      .replace(/href="\/docs(#[^"]*)?"/g, (_m, h: string | undefined) => `href="https://docs.${domain}/${h ?? ''}"`)
      .replace(/href="\/(privacy|terms)(#[^"]*)?"/g, (_m, p: string, h: string | undefined) => `href="${main}/${p}${h ?? ''}"`)
      .replace(/href="\/"/g, `href="${main}/"`);
  }
  return out;
}

function send(res: ServerResponse, status: number, body: string | Buffer, type: string, cache = 'no-store') {
  res.writeHead(status, {
    'content-type': type,
    'cache-control': cache,
    'x-content-type-options': 'nosniff',
    // OSM tile policy requires a Referer; send only the origin.
    'referrer-policy': 'strict-origin-when-cross-origin',
  });
  res.end(body);
}

export function createWebServer(opts: WebOptions = {}): { server: Server; oculon: Oculon; stop: () => Promise<void> } {
  const oculon = opts.oculon ?? new Oculon();
  const log = opts.log ?? (() => {});
  // Pages are small and read per request, so edits to them show up without a restart.
  const PAGE_FILES = { app: 'index.html', landing: 'landing.html', docs: 'docs.html', legal: 'legal.html' } as const;

  const publicMode = Boolean(opts.publicMode);
  const adminToken = opts.adminToken ?? (process.env.OCULON_ADMIN_TOKEN?.trim() || undefined);
  const limiter = new RateLimiter();

  // OCULON_DOMAIN (e.g. oculon.live) turns on subdomain links and redirects for app.* and docs.*.
  const siteDomain = (opts.domain ?? process.env.OCULON_DOMAIN ?? '').trim().toLowerCase() || null;

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const locked = (failed: boolean) => renderPage(lockedPage(Boolean(adminToken), failed), siteDomain);
    const url = new URL(req.url ?? '/', 'http://localhost');
    const hostName = String(req.headers.host ?? '').split(':')[0]!.toLowerCase();
    const admin = !publicMode || isAdmin(req, adminToken);
    if (publicMode) {
      const ip = clientIp(req);
      if (url.pathname === '/login' && req.method === 'POST') {
        if (!limiter.allow(ip, '/api/console')) return send(res, 429, locked(true), 'text/html; charset=utf-8');
        let raw = '';
        for await (const c of req) { raw += c; if (raw.length > 2048) break; }
        const given = new URLSearchParams(raw).get('token') ?? '';
        if (!tokenMatches(given, adminToken)) { log('login refused'); return send(res, 401, locked(true), 'text/html; charset=utf-8'); }
        res.writeHead(303, { location: hostName.startsWith('app.') ? '/' : '/app', 'set-cookie': `oculon_admin=${adminCookieValue(adminToken!)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`, 'cache-control': 'no-store' });
        log('login ok');
        return res.end();
      }
      if (url.pathname === '/logout') {
        res.writeHead(303, { location: '/', 'set-cookie': 'oculon_admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0', 'cache-control': 'no-store' });
        return res.end();
      }
      if (!admin) {
        if (req.method !== 'GET') return send(res, 403, '{"error":"this install is read-only"}', 'application/json');
        if (url.pathname.startsWith('/api/')) {
          if (!PUBLIC_API.has(url.pathname)) return send(res, 403, '{"error":"private endpoint"}', 'application/json');
          if (!limiter.allow(ip, url.pathname)) return send(res, 429, '{"error":"slow down, try again in a minute"}', 'application/json');
        }
        if (url.pathname === '/app' || url.pathname === '/app/' || url.pathname === '/index.html' || url.pathname === '/report' || url.pathname === '/api/image') {
          return send(res, 200, locked(false), 'text/html; charset=utf-8');
        }
      }
    }
    if (req.method === 'POST' && POST_ROUTES[url.pathname]) {
      // Writes only from this dashboard: a custom header (forces a CORS preflight that this server never
      // grants), a JSON body, and a same-host Origin when the browser sends one.
      const origin = req.headers.origin;
      const host = req.headers.host ?? '';
      if (req.headers['x-oculon'] !== '1' || !String(req.headers['content-type'] ?? '').startsWith('application/json') || (origin && origin !== `http://${host}`)) {
        return send(res, 403, '{"error":"forbidden"}', 'application/json');
      }
      try {
        const body = await readJson(req);
        const out = await POST_ROUTES[url.pathname]!(body, oculon);
        log(`POST ${url.pathname}`);
        return send(res, 200, JSON.stringify(out), 'application/json; charset=utf-8');
      } catch (e) {
        return send(res, e instanceof HttpError ? e.status : 400, JSON.stringify({ error: (e as Error).message }), 'application/json; charset=utf-8');
      }
    }
    if (req.method !== 'GET') return send(res, 405, '{"error":"method not allowed"}', 'application/json');
    // Pages: landing at /, dashboard at /app, docs at /docs. On app.* and docs.* hosts the root serves that page.
    const sub = (req.headers.host ?? '').split('.')[0];
    const page = url.pathname === '/' ? (sub === 'app' ? 'app' : sub === 'docs' ? 'docs' : 'landing') : url.pathname === '/app' || url.pathname === '/app/' || url.pathname === '/index.html' ? 'app' : url.pathname === '/docs' || url.pathname === '/docs/' ? 'docs' : /^\/(privacy|terms)\/?$/.test(url.pathname) ? 'legal' : null;
    if (page) {
      // On the public domain, /app and /docs live on their own subdomains.
      if (siteDomain && hostName === siteDomain && (page === 'app' || page === 'docs') && url.pathname !== '/') {
        res.writeHead(301, { location: `https://${page}.${siteDomain}/${url.search}`, 'cache-control': 'no-store' });
        return res.end();
      }
      return send(res, 200, renderPage(readFileSync(join(HERE, PAGE_FILES[page]), 'utf8'), siteDomain && hostName.endsWith(siteDomain) ? siteDomain : null), 'text/html; charset=utf-8');
    }
    if (url.pathname === '/manifest.webmanifest') return send(res, 200, readFileSync(join(HERE, 'manifest.webmanifest'), 'utf8'), 'application/manifest+json; charset=utf-8', 'no-cache');
    if (url.pathname === '/sw.js') return send(res, 200, readFileSync(join(HERE, 'sw.js'), 'utf8'), 'text/javascript; charset=utf-8', 'no-cache');
    if (url.pathname === '/favicon.ico') return send(res, 200, readFileSync(join(HERE, 'assets', 'favicon-32.png')), 'image/png', 'public, max-age=86400');
    if (url.pathname === '/api/stream') return streamSignals(req, res, oculon, !admin);
    const asset = /^\/assets\/([a-z0-9-]+\.(jpg|png|svg|woff2|js))$/.exec(url.pathname);
    if (asset) {
      const file = join(HERE, 'assets', asset[1]!);
      if (!existsSync(file)) return send(res, 404, '{"error":"not found"}', 'application/json');
      return send(res, 200, readFileSync(file), ASSET_TYPES[extname(file)] ?? 'application/octet-stream', extname(file) === '.js' ? 'no-cache' : 'public, max-age=86400');
    }

    if (url.pathname === '/report') {
      try {
        const r = await oculon.report(Number(url.searchParams.get('days') ?? 7) || 7);
        return send(res, 200, r.html, 'text/html; charset=utf-8');
      } catch (e) {
        return send(res, 500, JSON.stringify({ error: (e as Error).message }), 'application/json');
      }
    }

    if (url.pathname === '/api/image') {
      try {
        const r = await oculon.satelliteImage(need(url.searchParams, 'place'), url.searchParams.get('date') ?? undefined);
        if (!r.result.file) return send(res, 404, '{"error":"no image for that place/date"}', 'application/json');
        return send(res, 200, readFileSync(r.result.file), 'image/png');
      } catch (e) {
        return send(res, e instanceof HttpError ? e.status : 500, JSON.stringify({ error: (e as Error).message }), 'application/json');
      }
    }

    const route = ROUTES[url.pathname];
    if (!route) return send(res, 404, '{"error":"not found"}', 'application/json');
    const t0 = Date.now();
    try {
      if (!onchainEnabled() && ONCHAIN_ROUTES.has(url.pathname)) return send(res, 404, '{"error":"on-chain features are paused"}', 'application/json');
      let out = await route(url.searchParams, oculon);
      if (!onchainEnabled()) out = withoutOnchain(url.pathname, out);
      if (!admin && url.pathname === '/api/signals') out = publicSignals(out as { module: string }[]);
      if (!admin && url.pathname === '/api/graph') out = publicGraph(out as Parameters<typeof publicGraph>[0]);
      log(`${url.pathname}${url.search} ${Date.now() - t0}ms`);
      send(res, 200, JSON.stringify(out), 'application/json; charset=utf-8');
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      log(`${url.pathname} ${status} ${(e as Error).message}`);
      send(res, status, JSON.stringify({ error: (e as Error).message }), 'application/json; charset=utf-8');
    }
  });

  const scheduler =
    opts.watchMinutes && opts.watchMinutes > 0
      ? startScheduler(oculon, { scanMinutes: opts.watchMinutes, log: (m) => log(`schedule ${m}`), ...(opts.onSignals ? { onSignals: opts.onSignals } : {}), ...(opts.onBrief ? { onBrief: opts.onBrief } : {}), ...(opts.onReport ? { onReport: opts.onReport } : {}) })
      : null;

  server.listen(opts.port ?? 4747, opts.host ?? '127.0.0.1');
  return {
    server,
    oculon,
    stop: () =>
      new Promise((resolve) => {
        scheduler?.stop();
        server.close(() => {
          if (!opts.oculon) oculon.close();
          resolve();
        });
      }),
  };
}
