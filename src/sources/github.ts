import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface Repo {
  name: string;
  full_name: string;
  html_url: string;
  description: string | null;
  created_at: string;
  pushed_at: string;
  stargazers_count: number;
  language: string | null;
  fork: boolean;
}

function headers(): Record<string, string> {
  const h: Record<string, string> = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) h.authorization = `Bearer ${token}`;
  return h;
}

/** Most recently created public repos of an org (falls back to a user account). */
export async function recentRepos(ctx: Ctx, owner: string): Promise<Sourced<Repo[]>> {
  const q = 'sort=created&direction=desc&per_page=50';
  const org = await ctx.http.get<Repo[]>(`https://api.github.com/orgs/${enc(owner)}/repos?${q}`, {
    source: 'github',
    ttlSec: 3 * 3600,
    headers: headers(),
  });
  if (org.prov.status !== 'UNAVAILABLE') return org;
  return ctx.http.get<Repo[]>(`https://api.github.com/users/${enc(owner)}/repos?${q}`, {
    source: 'github',
    ttlSec: 3 * 3600,
    headers: headers(),
  });
}

/** Number of repositories matching a search query (e.g. `"ai agent" created:2026-10-01..2026-10-28`). */
export async function repoCount(ctx: Ctx, query: string): Promise<Sourced<number>> {
  const r = await ctx.http.get<{ total_count?: number }>(`https://api.github.com/search/repositories?q=${enc(query)}&per_page=1`, {
    source: 'github-search',
    ttlSec: 6 * 3600,
    headers: headers(),
  });
  return { data: r.data?.total_count ?? null, prov: r.prov };
}
