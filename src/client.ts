/**
 * OculonClient: call the hosted Oculon API with an API key, from Node, Deno, Bun or the browser.
 *
 *   const oc = new OculonClient({ apiKey: process.env.OCULON_API_KEY });
 *   const r = await oc.get('/api/url', { url: 'paypa1-secure-login.top' });
 *
 * Keys come from https://console.oculon.live (free key for everyday checks, holder key for every service).
 * The local `Oculon` class runs the checks on your own machine instead and needs no key.
 */

export interface OculonClientOptions {
  /** ocl_... key from the console. Defaults to the OCULON_API_KEY environment variable. */
  apiKey?: string;
  /** API origin. Defaults to OCULON_API_URL or https://oculon.live */
  baseUrl?: string;
  fetch?: typeof fetch;
  /** Milliseconds before a call is abandoned (default 60 s). */
  timeoutMs?: number;
}

export interface KeyStatus { key: string | null; tier: 'free' | 'holder' | null; limit?: number; remaining?: number; holderMin?: string; resetsAt?: string }

export class OculonApiError extends Error {
  constructor(message: string, readonly status: number, readonly body: unknown) { super(message); this.name = 'OculonApiError'; }
}

const env = (k: string): string | undefined => (typeof process !== 'undefined' ? process.env?.[k] : undefined);

export class OculonClient {
  readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly f: typeof fetch;
  private readonly timeoutMs: number;
  /** Quota left today after the last call, from the x-ratelimit-remaining header. */
  remaining: number | null = null;

  constructor(opts: OculonClientOptions = {}) {
    this.apiKey = opts.apiKey ?? env('OCULON_API_KEY');
    this.baseUrl = (opts.baseUrl ?? env('OCULON_API_URL') ?? 'https://oculon.live').replace(/\/+$/, '');
    this.f = opts.fetch ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  private async request<T>(method: 'GET' | 'POST', path: string, params?: Record<string, string | number | boolean | undefined>, body?: unknown): Promise<T> {
    if (!path.startsWith('/')) path = `/${path}`;
    if (!path.startsWith('/api/')) path = `/api${path}`;
    const u = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(params ?? {})) if (v !== undefined) u.searchParams.set(k, String(v));
    const headers: Record<string, string> = { accept: 'application/json' };
    if (this.apiKey) headers.authorization = `Bearer ${this.apiKey}`;
    if (body !== undefined) headers['content-type'] = 'application/json';
    const r = await this.f(u, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(this.timeoutMs) });
    const left = r.headers.get('x-ratelimit-remaining');
    if (left !== null) this.remaining = Number(left);
    const text = await r.text();
    let data: unknown = text;
    try { data = JSON.parse(text); } catch { /* not JSON */ }
    if (!r.ok) throw new OculonApiError((data as { error?: string })?.error ?? `HTTP ${r.status}`, r.status, data);
    return data as T;
  }

  /** GET any endpoint, e.g. get('/api/url', { url: 'example.com' }). */
  get<T = any>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> { return this.request<T>('GET', path, params); }
  /** POST a JSON body, e.g. post('/api/job', { message }). */
  post<T = any>(path: string, body: unknown): Promise<T> { return this.request<T>('POST', path, undefined, body); }
  /** The key's tier and what is left today. */
  key(): Promise<KeyStatus> { return this.get<KeyStatus>('/api/key'); }
  /** Every endpoint and MCP tool with the tier it needs. */
  catalog(): Promise<{ endpoints: { path: string; method: string; summary: string; tier: string }[]; tools: { name: string; summary: string; tier: string }[] }> { return this.get('/api/catalog'); }

  url(url: string) { return this.get('/api/url', { url }); }
  scam(message: string) { return this.get('/api/scam', { message }); }
  emailSecurity(domain: string) { return this.get('/api/emailsec', { domain }); }
  ip(ip: string) { return this.get('/api/ip', { ip }); }
  phone(number: string, country?: string) { return this.get('/api/phone', { number, country }); }
  site(url: string) { return this.get('/api/site', { url }); }
  contract(address: string, chain?: string) { return this.get('/api/contract', { address, chain }); }
  approvals(address: string, chain?: string) { return this.get('/api/approvals', { address, chain }); }
}
