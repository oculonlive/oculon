import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface Paper {
  id: string;
  title: string;
  published: string;
}

export function arxivQuery(q: string): string {
  const t = q.trim().replace(/"/g, '');
  return /\s/.test(t) ? `all:"${t}"` : `all:${t}`;
}

const tag = (xml: string, name: string) => new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`).exec(xml)?.[1]?.trim() ?? '';

export function parseAtom(xml: string): Paper[] {
  return [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map((m) => {
    const e = m[1] ?? '';
    return { id: tag(e, 'id'), title: tag(e, 'title').replace(/\s+/g, ' '), published: tag(e, 'published') };
  });
}

const arxivStamp = (ms: number) => new Date(ms).toISOString().slice(0, 16).replace(/[-T:]/g, '');

/** Number of papers submitted between two instants (uses opensearch:totalResults, no entries fetched). */
export async function paperCount(ctx: Ctx, query: string, fromMs: number, toMs: number): Promise<Sourced<number>> {
  const q = `${arxivQuery(query)} AND submittedDate:[${arxivStamp(fromMs)} TO ${arxivStamp(toMs)}]`;
  const url = `https://export.arxiv.org/api/query?search_query=${enc(q)}&max_results=1`;
  const r = await ctx.http.get<string>(url, { source: 'arxiv', as: 'text', ttlSec: 12 * 3600, timeoutMs: 45_000 });
  const total = r.data === null ? null : Number(tag(r.data, 'opensearch:totalResults'));
  return { data: total !== null && Number.isFinite(total) ? total : null, prov: r.prov };
}

/** Newest papers matching the query. */
export async function recentPapers(ctx: Ctx, query: string, max = 300): Promise<Sourced<Paper[]>> {
  const url = `https://export.arxiv.org/api/query?search_query=${enc(arxivQuery(query))}&sortBy=submittedDate&sortOrder=descending&max_results=${max}`;
  const r = await ctx.http.get<string>(url, { source: 'arxiv', as: 'text', ttlSec: 6 * 3600, timeoutMs: 45_000 });
  return { data: r.data === null ? null : parseAtom(r.data), prov: r.prov };
}
