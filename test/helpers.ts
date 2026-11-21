import { createContext, type Ctx } from '../src/core/context.js';

export type Route = [match: string | RegExp, respond: (url: string) => { status?: number; body: unknown } | Promise<{ status?: number; body: unknown }>];

export interface MockFetch {
  fetch: typeof fetch;
  calls: string[];
}

/** A fetch stand-in that answers by URL pattern; unmatched URLs return 404. */
export function mockFetch(routes: Route[]): MockFetch {
  const calls: string[] = [];
  const fn = (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    calls.push(url);
    const route = routes.find(([m]) => (typeof m === 'string' ? url.includes(m) : m.test(url)));
    if (!route) return new Response('not found', { status: 404 });
    const { status = 200, body } = await route[1](url);
    return new Response(typeof body === 'string' || body instanceof Uint8Array ? (body as BodyInit) : JSON.stringify(body), { status });
  }) as typeof fetch;
  return { fetch: fn, calls };
}

export const NOW = new Date('2026-11-18T12:00:00Z');

export function testContext(routes: Route[]): Ctx & { calls: string[] } {
  const m = mockFetch(routes);
  const ctx = createContext({ dbPath: ':memory:', fetch: m.fetch, throttle: false, retryDelayMs: 1, now: () => NOW });
  return Object.assign(ctx, { calls: m.calls });
}

export const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
