import { breakerOpenUntil, breakerResult, logCall, MIRRORS, recordSourceCall } from './calls.js';
import { scrubSecrets } from './keys.js';
import { takeQuota } from './quota.js';
import type { Store } from './store.js';
import type { Provenance, Sourced, Status } from './types.js';

/** Minimum gap between requests per host, following each provider's published guidance. */
const HOST_GAP_MS: Record<string, number> = {
  'crt.sh': 2000,
  'api.honeypot.is': 600,
  'mempool.space': 300,
  'api.mainnet-beta.solana.com': 300,
  'api.gdeltproject.org': 5500,
  'export.arxiv.org': 3100,
  'api.github.com': 1500,
  'web.archive.org': 1000,
  'api.certspotter.com': 1000,
  'opensky-network.org': 1000,
  'wikimedia.org': 400,
  'www.sec.gov': 150,
  'data.sec.gov': 150,
  'hexdb.io': 500,
  'api.adsb.lol': 1000,
  'nominatim.openstreetmap.org': 1100,
  'gibs.earthdata.nasa.gov': 150,
  'content.guardianapis.com': 1100,
  'api.nytimes.com': 12_500,
  'gnews.io': 1100,
  'finnhub.io': 1100,
  'api.openalex.org': 120,
  'www.courtlistener.com': 800,
  'api.adzuna.com': 500,
  'urlscan.io': 1000,
  'api.zerion.io': 1100,
  'api.etherscan.io': 250,
  'api.gopluslabs.io': 500,
  'api.webacy.com': 500,
  'api.dexscreener.com': 250,
  'api.coingecko.com': 2100,
  'api.openaq.org': 1100,
  'www.googleapis.com': 200,
  'bsky.social': 300,
  'r.jina.ai': 500,
  'api.tavily.com': 300,
  'api.exa.ai': 300,
  'api.stlouisfed.org': 600,
  'api.elections.kalshi.com': 500,
  'api.manifold.markets': 300,
  'itunes.apple.com': 3100,
  'huggingface.co': 300,
  'registry.npmjs.org': 200,
  'clob.polymarket.com': 300,
  'archive.org': 1000,
  'www.treasury.gov': 1000,
  'query.wikidata.org': 1100,
  'api.geckoterminal.com': 2100,
  'api.blockscout.com': 300,
  'services.nvd.nist.gov': 6500, // keyless: 5 requests per 30 seconds
  'efts.sec.gov': 150,
  'api.fda.gov': 300,
  'clinicaltrials.gov': 1300,
  'www.federalregister.gov': 300,
  'api.osv.dev': 100,
  'www.4byte.directory': 500,
  'api.semanticscholar.org': 1100, // 1 request per second with a key
  'www.virustotal.com': 15_500, // public API: 4 requests a minute
  'ip-api.com': 1400, // 45 requests a minute
  'api.greynoise.io': 1000,
  'www.peeringdb.com': 3100, // anonymous: 20 requests a minute
};

const chains = new Map<string, Promise<void>>();

async function throttle(host: string): Promise<void> {
  const gap = HOST_GAP_MS[host];
  if (!gap) return;
  const prev = chains.get(host) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((r) => (release = r));
  chains.set(host, prev.then(() => mine));
  await prev;
  setTimeout(release, gap);
}

/** Hosts that require contact details in the User-Agent. Every other host gets no personal data. */
const CONTACT_HOSTS = /(^|\.)sec\.gov$/;

export function userAgent(url?: string): string {
  let host = '';
  try {
    host = url ? new URL(url).hostname : '';
  } catch {}
  const contact = CONTACT_HOSTS.test(host) ? process.env.OCULON_CONTACT?.trim() : undefined;
  return `Oculon/0.1 (open-source OSINT engine${contact ? `; ${contact}` : ''})`;
}

export interface GetOptions {
  source: string;
  as?: 'json' | 'text';
  /** How long a cached response counts as fresh. Default 15 minutes. */
  ttlSec?: number;
  timeoutMs?: number;
  retries?: number;
  headers?: Record<string, string>;
  /** Some APIs (GDELT) answer 200 with a plain-text rate-limit message; treat a match as HTTP 429. */
  rateLimitText?: RegExp;
  /** Keep only what the caller needs before caching (JSON only). Huge documents such as npm packuments shrink to a few bytes. */
  keep?: (data: any) => unknown;
}

export interface HttpConfig {
  fetch?: typeof fetch;
  throttle?: boolean;
  retryDelayMs?: number;
  /** Skip a host for a few minutes after it fails several times in a row (default on). */
  breaker?: boolean;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Provenance is shown to users, LLMs and dashboards, so API keys in URLs or notes are always masked. */
function prov(source: string, url: string, status: Status, fetchedAt: number, note?: string): Provenance {
  return { source, url: scrubSecrets(url), status, fetchedAt: new Date(fetchedAt).toISOString(), ...(note ? { note: scrubSecrets(note) } : {}) };
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.name === 'TimeoutError' ? 'timeout' : e.message;
  return String(e);
}

/** A short reason from a JSON error body (Cloudflare `errors[0]`, or `message` / `error`), as " (reason)". */
function errorReason(text: string): string {
  try {
    const j = JSON.parse(text) as { errors?: { code?: number; message?: string }[]; message?: unknown; error?: unknown };
    const e = j.errors?.[0];
    const why = e?.message ? `${e.code ? `${e.code} ` : ''}${e.message}` : typeof j.message === 'string' ? j.message : typeof j.error === 'string' ? j.error : '';
    return why ? ` (${scrubSecrets(why).slice(0, 120)})` : '';
  } catch {
    return '';
  }
}

class ParseError extends Error {}

export class Http {
  constructor(
    private readonly store: Store,
    private readonly cfg: HttpConfig = {},
  ) {}

  private parse<T>(body: string, as: 'json' | 'text'): T {
    if (as === 'text') return body as T;
    try {
      return JSON.parse(body) as T;
    } catch {
      throw new ParseError(`invalid JSON: ${body.slice(0, 120).replace(/\s+/g, ' ')}`);
    }
  }

  /** Uncached binary POST (used for timestamp calendars). Returns the raw response bytes. */
  async postBytes(url: string, body: Uint8Array, o: { source: string; headers?: Record<string, string>; timeoutMs?: number; retries?: number }): Promise<Sourced<Buffer>> {
    const t0 = Date.now();
    const r = await this.postBytesRaw(url, body, o);
    this.note(o.source, url, r.prov.status, Date.now() - t0, r.prov.note, undefined, r.prov.note !== 'daily quota reached');
    return r;
  }

  private async postBytesRaw(url: string, body: Uint8Array, o: { source: string; headers?: Record<string, string>; timeoutMs?: number; retries?: number }): Promise<Sourced<Buffer>> {
    if (!takeQuota(this.store, o.source)) return { data: null, prov: prov(o.source, url, 'UNAVAILABLE', Date.now(), 'daily quota reached') };
    const doFetch = this.cfg.fetch ?? fetch;
    const retries = o.retries ?? 1;
    let lastErr = 'unknown error';
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (this.cfg.throttle !== false) await throttle(new URL(url).host);
      try {
        const res = await doFetch(url, {
          method: 'POST',
          body: body as unknown as BodyInit,
          headers: { 'user-agent': userAgent(url), ...o.headers },
          signal: AbortSignal.timeout(o.timeoutMs ?? 20_000),
        });
        if (!res.ok) {
          lastErr = `HTTP ${res.status}`;
          if (res.status < 500 && res.status !== 429) break;
          continue;
        }
        return { data: Buffer.from(await res.arrayBuffer()), prov: prov(o.source, url, 'LIVE', Date.now()) };
      } catch (e) {
        lastErr = errMsg(e);
      }
    }
    return { data: null, prov: prov(o.source, url, 'ERROR', Date.now(), lastErr) };
  }

  /** Uncached binary GET; 404 is reported as UNAVAILABLE. Network errors and 5xx are retried once. */
  async getBytes(url: string, o: { source: string; headers?: Record<string, string>; timeoutMs?: number; retries?: number }): Promise<Sourced<Buffer>> {
    const t0 = Date.now();
    const r = await this.getBytesRaw(url, o);
    this.note(o.source, url, r.prov.status, Date.now() - t0, r.prov.note);
    return r;
  }

  private async getBytesRaw(url: string, o: { source: string; headers?: Record<string, string>; timeoutMs?: number; retries?: number }): Promise<Sourced<Buffer>> {
    const doFetch = this.cfg.fetch ?? fetch;
    const retries = o.retries ?? 1;
    let lastErr = 'unknown error';
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (this.cfg.throttle !== false) await throttle(new URL(url).host);
      try {
        const res = await doFetch(url, { headers: { 'user-agent': userAgent(url), ...o.headers }, signal: AbortSignal.timeout(o.timeoutMs ?? 20_000) });
        if (res.status === 404) return { data: null, prov: prov(o.source, url, 'UNAVAILABLE', Date.now(), 'HTTP 404') };
        if (res.ok) return { data: Buffer.from(await res.arrayBuffer()), prov: prov(o.source, url, 'LIVE', Date.now()) };
        lastErr = `HTTP ${res.status}`;
        if (res.status < 500 && res.status !== 429) break;
      } catch (e) {
        lastErr = errMsg(e);
      }
      if (attempt < retries) await sleep(this.cfg.retryDelayMs ?? 1500);
    }
    return { data: null, prov: prov(o.source, url, 'ERROR', Date.now(), lastErr) };
  }

  /**
   * Uncached GET of a web page that keeps what a page check needs: the final URL after redirects, the status,
   * the response headers and the body (capped at `maxBytes`). Not retried: a page that fails is reported as is.
   */
  async getPage(url: string, o: { source: string; headers?: Record<string, string>; timeoutMs?: number; maxBytes?: number }): Promise<{ data: { status: number; finalUrl: string; headers: Record<string, string>; body: Buffer } | null; prov: Provenance }> {
    const doFetch = this.cfg.fetch ?? fetch;
    const t0 = Date.now();
    try {
      if (this.cfg.throttle !== false) await throttle(new URL(url).host);
      const res = await doFetch(url, { headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', accept: 'text/html,application/xhtml+xml,*/*', ...o.headers }, redirect: 'follow', signal: AbortSignal.timeout(o.timeoutMs ?? 20_000) });
      const buf = Buffer.from(await res.arrayBuffer());
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      const data = { status: res.status, finalUrl: res.url || url, headers, body: buf.subarray(0, o.maxBytes ?? 3_000_000) };
      const st: Status = res.ok ? 'LIVE' : res.status === 404 ? 'UNAVAILABLE' : 'ERROR';
      this.note(o.source, url, st, Date.now() - t0, res.ok ? undefined : `HTTP ${res.status}`);
      return { data, prov: prov(o.source, url, st, Date.now(), res.ok ? undefined : `HTTP ${res.status}`) };
    } catch (e) {
      this.note(o.source, url, 'ERROR', Date.now() - t0, errMsg(e));
      return { data: null, prov: prov(o.source, url, 'ERROR', Date.now(), errMsg(e)) };
    }
  }

  /** Record a finished call: the running check's replay log, and (for live calls) the /status stats. */
  private note(source: string, url: string, status: Status, ms: number, note?: string, via?: string, live = true): void {
    let host = '';
    try { host = new URL(url).host; } catch {}
    logCall({ source, host, status, ms: Math.round(ms), at: new Date().toISOString(), ...(note ? { note: scrubSecrets(note).slice(0, 200) } : {}), ...(via ? { via } : {}) });
    if (live) recordSourceCall(this.store, source, via ?? host, status === 'LIVE' || (status === 'UNAVAILABLE' && note === 'HTTP 404'), ms, note ? scrubSecrets(note) : undefined);
  }

  /**
   * One live request with retries. `hostDown` is true when the failure says the host is unhealthy (network error,
   * timeout, 5xx, 429), which feeds the breaker; a 4xx answer means the host is up.
   */
  private async live(url: string, o: GetOptions, as: 'json' | 'text', retries: number, extraHeaders: Record<string, string> = {}): Promise<{ ok: true; body: string } | { ok: false; notFound: boolean; err: string; hostDown: boolean }> {
    const doFetch = this.cfg.fetch ?? fetch;
    const host = new URL(url).host;
    const baseDelay = this.cfg.retryDelayMs ?? 1500;
    let lastErr = 'unknown error';
    let hostDown = false;
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (this.cfg.throttle !== false) await throttle(host);
      try {
        const res = await doFetch(url, {
          headers: { 'user-agent': userAgent(url), accept: as === 'json' ? 'application/json' : '*/*', ...o.headers, ...extraHeaders },
          signal: AbortSignal.timeout(o.timeoutMs ?? 20_000),
        });
        if (res.status === 404) return { ok: false, notFound: true, err: 'HTTP 404', hostDown: false };
        if (res.status === 429 || res.status >= 500) {
          lastErr = `HTTP ${res.status}`;
          hostDown = true;
          const retryAfter = Number(res.headers.get('retry-after'));
          const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 30_000) : baseDelay * 2 ** attempt;
          if (attempt < retries) await sleep(this.cfg.retryDelayMs !== undefined ? baseDelay : wait);
          continue;
        }
        if (!res.ok) {
          const text = await res.text().catch(() => '');
          lastErr = `HTTP ${res.status}${errorReason(text)}`;
          hostDown = false;
          // GitHub signals (secondary) rate limits with 403.
          if (res.status === 403 && (res.headers.get('x-ratelimit-remaining') === '0' || /rate limit/i.test(text))) {
            lastErr = 'HTTP 403 rate limited';
            if (attempt < retries) await sleep(this.cfg.retryDelayMs !== undefined ? baseDelay : 8000 * 2 ** attempt);
            continue;
          }
          break;
        }
        const body = await res.text();
        if (o.rateLimitText?.test(body.slice(0, 300))) {
          lastErr = 'rate limited';
          hostDown = false;
          if (attempt < retries) await sleep(Math.max(baseDelay, 6000) * 2 ** attempt);
          continue;
        }
        this.parse(body, as); // throws ParseError on a broken body
        return { ok: true, body };
      } catch (e) {
        lastErr = errMsg(e);
        if (e instanceof ParseError) { hostDown = false; break; }
        hostDown = true;
        if (attempt < retries) await sleep(baseDelay * 2 ** attempt);
      }
    }
    return { ok: false, notFound: false, err: lastErr, hostDown };
  }

  async get<T = unknown>(url: string, o: GetOptions): Promise<Sourced<T>> {
    const as = o.as ?? 'json';
    const ttl = (o.ttlSec ?? 900) * 1000;
    const retries = o.retries ?? 2;
    const cached = this.store.cacheGet(url);
    const now = Date.now();

    if (cached && now - cached.fetchedAt < ttl) {
      this.note(o.source, url, 'CACHED', 0, undefined, undefined, false);
      return { data: this.parse<T>(cached.body, as), prov: prov(o.source, url, 'CACHED', cached.fetchedAt) };
    }

    if (!takeQuota(this.store, o.source)) {
      this.note(o.source, url, cached ? 'CACHED' : 'UNAVAILABLE', 0, 'daily quota reached', undefined, false);
      if (cached) return { data: this.parse<T>(cached.body, as), prov: prov(o.source, url, 'CACHED', cached.fetchedAt, 'daily quota reached; showing last cached result') };
      return { data: null, prov: prov(o.source, url, 'UNAVAILABLE', Date.now(), 'daily quota reached') };
    }

    const host = new URL(url).host;
    const useBreaker = this.cfg.breaker !== false;
    const keep = (body: string): { data: T; stored: string } => {
      let data = this.parse<T>(body, as);
      let stored = body;
      if (o.keep && as === 'json' && data != null) {
        data = o.keep(data) as T;
        stored = JSON.stringify(data);
      }
      return { data, stored };
    };

    let lastErr: string;
    const skipped = useBreaker ? breakerOpenUntil(host) : null;
    if (skipped) {
      lastErr = `skipped: ${host} kept failing, retrying it after ${new Date(skipped).toISOString().slice(11, 16)} UTC`;
    } else {
      const t0 = Date.now();
      const r = await this.live(url, o, as, retries);
      if (useBreaker) breakerResult(host, r.ok || !r.hostDown);
      if (r.ok) {
        const { data, stored } = keep(r.body);
        this.store.cachePut(url, stored);
        this.note(o.source, url, 'LIVE', Date.now() - t0);
        return { data, prov: prov(o.source, url, 'LIVE', Date.now()) };
      }
      if (r.notFound) {
        this.note(o.source, url, 'UNAVAILABLE', Date.now() - t0, 'HTTP 404');
        return { data: null, prov: prov(o.source, url, 'UNAVAILABLE', Date.now(), 'HTTP 404') };
      }
      lastErr = r.err;
      this.note(o.source, url, 'ERROR', Date.now() - t0, r.err);
    }

    // Auto fallback: the same request on a mirror host, when there is one.
    const mirror = MIRRORS[host];
    const alt = mirror?.rewrite(new URL(url));
    if (mirror && alt && !(useBreaker && breakerOpenUntil(mirror.host))) {
      const t0 = Date.now();
      const r = await this.live(alt.url, o, as, 1, alt.headers);
      if (useBreaker) breakerResult(mirror.host, r.ok || !r.hostDown);
      if (r.ok) {
        const { data, stored } = keep(r.body);
        this.store.cachePut(url, stored);
        const why = `${host} failed (${lastErr}); answered by ${mirror.host}`;
        this.note(o.source, alt.url, 'LIVE', Date.now() - t0, why, mirror.host);
        return { data, prov: prov(o.source, url, 'LIVE', Date.now(), why) };
      }
      this.note(o.source, alt.url, 'ERROR', Date.now() - t0, r.err, mirror.host);
    }

    if (cached) {
      return {
        data: this.parse<T>(cached.body, as),
        prov: prov(o.source, url, 'CACHED', cached.fetchedAt, `stale, live fetch failed: ${lastErr}`),
      };
    }
    return { data: null, prov: prov(o.source, url, 'ERROR', Date.now(), lastErr) };
  }
}
