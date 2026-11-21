import { DAY_MS, enc, ymd, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface Capture {
  url: string;
  timestamp: string;
}

const ASSET = /\.(css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map|json|xml|txt|pdf|mp4|webm)$/i;

/** Normalize a captured URL to host + path so the same page is not counted twice. */
export function normalizePath(raw: string): string | null {
  try {
    const u = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
    if (ASSET.test(u.pathname)) return null;
    const path = u.pathname.replace(/\/+$/, '') || '/';
    return `${u.hostname.replace(/^www\./, '').toLowerCase()}${path.toLowerCase()}`;
  } catch {
    return null;
  }
}

/** HTML pages under `domain` captured by the Wayback Machine between two dates. */
export async function captures(ctx: Ctx, domain: string, fromDaysAgo: number, toDaysAgo: number, limit = 3000): Promise<Sourced<Capture[]>> {
  const now = ctx.now().getTime();
  const from = ymd(new Date(now - fromDaysAgo * DAY_MS));
  const to = ymd(new Date(now - toDaysAgo * DAY_MS));
  const url =
    `https://web.archive.org/cdx/search/cdx?url=${enc(`${domain}/*`)}&output=json&fl=original,timestamp` +
    `&collapse=urlkey&filter=statuscode:200&filter=mimetype:text/html&from=${from}&to=${to}&limit=${limit}`;
  const r = await ctx.http.get<string[][]>(url, { source: 'wayback', ttlSec: 12 * 3600, timeoutMs: 45_000, retries: 0 });
  const rows = r.data?.slice(1) ?? null;
  const data = rows?.map(([u, ts]) => ({ url: u ?? '', timestamp: ts ?? '' })) ?? null;
  const truncated = rows && rows.length >= limit;
  return { data, prov: truncated ? { ...r.prov, note: `sample: capped at ${limit} URLs` } : r.prov };
}
