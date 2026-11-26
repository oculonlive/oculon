/**
 * Chainabuse (TRM Labs): scam reports filed by victims, by crypto address or by domain. Free key
 * (CHAINABUSE_API_KEY) with 750 calls a month, so answers are cached for a week and the daily budget is small.
 */
import { enc, type Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import type { Provenance } from '../core/types.js';

export interface AbuseReports { count: number; categories: string[]; latest: string | null; trusted: number; url: string }

export async function chainabuse(ctx: Ctx, by: 'address' | 'domain', value: string): Promise<{ data: AbuseReports | null; prov: Provenance | null }> {
  const k = key('CHAINABUSE_API_KEY');
  if (!k) return { data: null, prov: null };
  const r = await ctx.http.get<{ count?: number; reports?: { createdAt?: string; scamCategory?: string; trusted?: boolean }[] }>(
    `https://api.chainabuse.com/v0/reports?${by}=${enc(value)}&perPage=50`,
    { source: 'chainabuse', ttlSec: 7 * 86_400, retries: 0, headers: { authorization: `Basic ${Buffer.from(`${k}:${k}`).toString('base64')}`, accept: 'application/json' } },
  );
  if (!r.data) return { data: null, prov: r.prov };
  const reports = r.data.reports ?? [];
  const count = r.data.count ?? reports.length;
  const cats = [...new Set(reports.map((x) => (x.scamCategory ?? '').toLowerCase().replace(/_/g, ' ')).filter((c) => c && c !== 'other'))];
  const latest = reports.map((x) => x.createdAt ?? '').sort().pop() || null;
  return { data: count ? { count, categories: cats.slice(0, 5), latest, trusted: reports.filter((x) => x.trusted).length, url: `https://www.chainabuse.com/${by}/${enc(value)}` } : { count: 0, categories: [], latest: null, trusted: 0, url: `https://www.chainabuse.com/${by}/${enc(value)}` }, prov: r.prov };
}
