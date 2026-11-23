/**
 * Public mode: what a server open to the internet may show.
 *
 * Without the admin cookie a visitor gets the overview page, the docs, the legal pages and a read-only
 * API limited to the endpoints those pages use. Writes, the dashboard, LLM-backed endpoints and anything
 * personal (watchlist, cases, geofences, feedback) stay closed. Requests are rate limited per client.
 * The owner signs in once with OCULON_ADMIN_TOKEN and then has the full app.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';

/** Read-only endpoints the public pages call. Everything else needs the admin cookie. */
export const PUBLIC_API = new Set([
  '/api/meta',
  '/api/readme',
  '/api/console',
  '/api/signals',
  '/api/stream',
  '/api/bgp',
  '/api/vulns',
  '/api/hazards',
  '/api/robinhood',
  '/api/rhtoken',
  '/api/squawks',
  '/api/defi',
  '/api/quakes',
  '/api/military',
  '/api/events',
  '/api/space',
  '/api/cloud',
  '/api/blackout',
  '/api/calendar',
  '/api/narratives',
  '/api/forecasts',
  '/api/verify',
  '/api/graph',
  '/api/quota',
  '/api/url',
  '/api/travel',
  '/api/audit',
  '/api/recall',
  '/api/emailsec',
  '/api/country',
  '/api/airport',
  '/api/share',
  '/api/scam',
]);

/** Endpoints that start outside work (a CLI process or several upstream calls) get a tighter budget. */
const HEAVY = new Set(['/api/console', '/api/rhtoken', '/api/verify', '/api/url', '/api/travel', '/api/audit', '/api/recall', '/api/emailsec', '/api/country', '/api/airport', '/api/scam']);

/** Signals from these modules describe the owner's own watchlist, cases, fences, votes or raw social streams. */
const PRIVATE_MODULES = new Set(['meerkat', 'case', 'fence', 'feedback', 'live']);

export function publicSignals<T extends { module: string }>(list: T[]): T[] {
  return list.filter((s) => !PRIVATE_MODULES.has(s.module));
}

/** Drops case and watch entities (and their edges) from a graph slice. */
export function publicGraph(g: { nodes: { id: string; kind: string; name: string }[]; edges: { src: string; dst: string }[] }) {
  const hide = (n: { id: string; name: string }) => /^event:(case|watch|fence)/i.test(n.id) || /^(case #|watch:|fence:)/i.test(n.name);
  const hidden = new Set(g.nodes.filter(hide).map((n) => n.id));
  return { nodes: g.nodes.filter((n) => !hidden.has(n.id)), edges: g.edges.filter((e) => !hidden.has(e.src) && !hidden.has(e.dst)) };
}

/** The client address: Cloudflare and Railway put the real one in a header. */
export function clientIp(req: IncomingMessage): string {
  const h = (name: string) => {
    const v = req.headers[name];
    return (Array.isArray(v) ? v[0] : v)?.split(',')[0]?.trim();
  };
  return h('cf-connecting-ip') || h('x-real-ip') || h('x-forwarded-for') || req.socket.remoteAddress || 'unknown';
}

/** Fixed-window limiter: `perMinute` requests per client per minute, separately for heavy endpoints. */
export class RateLimiter {
  private hits = new Map<string, { start: number; n: number }>();
  constructor(
    private perMinute = 180,
    private heavyPerMinute = 10,
  ) {}
  allow(ip: string, path: string, now = Date.now()): boolean {
    const heavy = HEAVY.has(path);
    const key = `${heavy ? 'h' : 'n'}:${ip}`;
    const w = this.hits.get(key);
    if (!w || now - w.start >= 60_000) {
      this.hits.set(key, { start: now, n: 1 });
      if (this.hits.size > 20_000) this.prune(now);
      return true;
    }
    w.n++;
    return w.n <= (heavy ? this.heavyPerMinute : this.perMinute);
  }
  private prune(now: number) {
    for (const [k, w] of this.hits) if (now - w.start >= 60_000) this.hits.delete(k);
  }
}

const digest = (s: string) => createHash('sha256').update(`oculon-admin:${s}`).digest('hex');

/** Cookie value for a valid token. The token itself is never stored in the browser. */
export function adminCookieValue(token: string): string {
  return digest(token);
}

export function isAdmin(req: IncomingMessage, token: string | undefined): boolean {
  if (!token) return false;
  const m = /(?:^|;\s*)oculon_admin=([a-f0-9]{64})/.exec(String(req.headers.cookie ?? ''));
  if (!m) return false;
  const a = Buffer.from(m[1]!, 'hex');
  const b = Buffer.from(digest(token), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export function tokenMatches(given: string, token: string | undefined): boolean {
  if (!token || !given) return false;
  const a = Buffer.from(digest(given), 'hex');
  const b = Buffer.from(digest(token), 'hex');
  return timingSafeEqual(a, b);
}

/** Shown at /app to visitors of a public install. */
export function lockedPage(signInAvailable: boolean, failed = false): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Oculon</title>
<link rel="icon" type="image/png" href="/favicon.ico"><meta name="theme-color" content="#000000">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;600&family=Space+Mono&display=swap" rel="stylesheet">
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(ellipse at 70% 10%,rgba(0,240,255,.12),transparent 60%),#000;color:#fff;font-family:'Space Grotesk',system-ui,sans-serif;padding:24px}
.box{max-width:560px}.k{font:12px 'Space Mono',monospace;letter-spacing:.14em;text-transform:uppercase;color:#00f0ff}
h1{font-size:clamp(34px,6vw,54px);font-weight:300;letter-spacing:-.03em;line-height:1.05;margin:14px 0}
p{color:#b9c9cc;font-size:17px;line-height:1.65}code{font:14px 'Space Mono',monospace;background:#071114;border:1px solid #163038;padding:2px 7px;color:#e6fbff}
.cmd{margin:22px 0;display:flex;gap:12px;align-items:center;border:1px solid #1d3a41;background:#050b0c;padding:14px 16px;font:15px 'Space Mono',monospace}.cmd b{color:#00f0ff}
a{color:#fff;text-decoration-color:#00f0ff;text-underline-offset:3px}form{margin-top:26px;display:flex;gap:8px}input{flex:1;background:#050b0c;border:1px solid #1d3a41;color:#fff;padding:11px 12px;font:14px 'Space Mono',monospace}
button{background:#00f0ff;color:#001418;border:0;padding:11px 16px;font:600 14px 'Space Grotesk',sans-serif;cursor:pointer}.err{color:#ff6b6b;font:13px 'Space Mono',monospace;margin-top:10px}</style></head>
<body><div class="box"><div class="k">Oculon · dashboard</div><h1>The dashboard runs on your own machine.</h1>
<p>This site shows the public overview. The full app, with your watchlist, cases, inbox and agent, is part of every install and stays private to you.</p>
<div class="cmd"><b>$</b><span>npm i -g oculon &amp;&amp; oculon serve</span></div>
<p>Then open <code>http://127.0.0.1:4747/app</code>. Back to the <a href="/">overview</a> or read the <a href="/docs">docs</a>.</p>
${signInAvailable ? `<form method="post" action="/login"><input type="password" name="token" placeholder="Owner token" autocomplete="current-password" aria-label="Owner token"><button>Sign in</button></form>${failed ? '<div class="err">That token is not right.</div>' : ''}` : ''}
</div></body></html>`;
}
