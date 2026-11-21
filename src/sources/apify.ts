/**
 * Apify (pay per result): X/Twitter, Reddit and TikTok search through public Store actors.
 * Each call runs an actor synchronously and returns its dataset. Results are cached for 3 hours and every run
 * counts against a small daily budget (OCULON_QUOTA_APIFY), so a free plan's monthly credit lasts.
 */
import type { Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Sourced } from '../core/types.js';
import { postJson } from './press.js';

export interface SocialPost {
  platform: 'x' | 'reddit' | 'tiktok' | 'bluesky';
  text: string;
  author: string;
  date: string;
  /** Likes + reposts/shares + replies/comments, as each platform reports them. */
  engagement: number;
  views: number | null;
  url: string;
}

/** Actor ids; override if one disappears from the Store. */
export const ACTORS = {
  x: process.env.OCULON_APIFY_X_ACTOR || 'apidojo~tweet-scraper',
  reddit: process.env.OCULON_APIFY_REDDIT_ACTOR || 'fatihtahta~reddit-scraper-search-fast',
  tiktok: process.env.OCULON_APIFY_TIKTOK_ACTOR || 'clockworks~free-tiktok-scraper',
};

async function runActor<T>(ctx: Ctx, actor: string, input: Record<string, unknown>): Promise<Sourced<T[]>> {
  const k = key('APIFY_TOKEN');
  if (!k) return noKey('apify', 'APIFY_TOKEN');
  const url = `https://api.apify.com/v2/acts/${actor}/run-sync-get-dataset-items?timeout=120&memory=1024`;
  const r = await postJson<T[] | { error?: { message?: string } }>(ctx, url, input, { authorization: `Bearer ${k}` }, 'apify', 3 * 3600);
  if (r.data && !Array.isArray(r.data)) return { data: null, prov: { ...r.prov, status: 'ERROR', note: r.data.error?.message?.slice(0, 160) ?? 'actor failed' } };
  // Some actors answer [{noResults:true}] on a transient miss; never cache that.
  if (Array.isArray(r.data) && (!r.data.length || (r.data[0] as { noResults?: boolean }).noResults)) {
    ctx.store.db.prepare('DELETE FROM cache WHERE key = ?').run(`post:${url}:${JSON.stringify(input)}`);
    return { data: [], prov: { ...r.prov, note: 'no results' } };
  }
  return { data: (r.data as T[] | null) ?? null, prov: r.prov };
}

/** Seconds, milliseconds or a date string to ISO; '' when unparseable. */
export function isoDate(v: unknown): string {
  const t = typeof v === 'number' ? (v < 1e11 ? v * 1000 : v) : typeof v === 'string' ? (/^\d+(\.\d+)?$/.test(v) ? Number(v) * (Number(v) < 1e11 ? 1000 : 1) : Date.parse(v)) : NaN;
  return Number.isFinite(t) ? new Date(t).toISOString() : '';
}

const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

export async function xPosts(ctx: Ctx, q: string, max = 40): Promise<Sourced<SocialPost[]>> {
  const r = await runActor<{ type?: string; url?: string; fullText?: string; text?: string; createdAt?: string; likeCount?: number; retweetCount?: number; replyCount?: number; quoteCount?: number; viewCount?: number; author?: { userName?: string } }>(ctx, ACTORS.x, { searchTerms: [q], maxItems: max, sort: 'Top' });
  return {
    data:
      r.data
        ?.filter((t) => t.type === 'tweet' && t.url)
        .map((t) => ({
          platform: 'x' as const,
          text: (t.fullText ?? t.text ?? '').slice(0, 280),
          author: t.author?.userName ?? '?',
          date: isoDate(t.createdAt),
          engagement: n(t.likeCount) + n(t.retweetCount) + n(t.replyCount) + n(t.quoteCount),
          views: t.viewCount ?? null,
          url: t.url!,
        })) ?? null,
    prov: r.prov,
  };
}

export async function redditPosts(ctx: Ctx, q: string, max = 25): Promise<Sourced<SocialPost[]>> {
  const r = await runActor<{ kind?: string; title?: string; body?: string; author?: string; created_utc?: number | string; score?: number; num_comments?: number; permalink?: string; url?: string; subreddit?: string }>(ctx, ACTORS.reddit, { queries: [q], sort: 'new', maxPosts: max, scrapeComments: false });
  return {
    data:
      r.data
        ?.filter((p) => p.kind !== 'comment' && (p.title || p.body))
        .map((p) => ({
          platform: 'reddit' as const,
          text: `${p.subreddit ? `r/${p.subreddit}: ` : ''}${p.title ?? ''}${p.body ? ` ${p.body}` : ''}`.slice(0, 280),
          author: p.author ?? '?',
          date: isoDate(p.created_utc),
          engagement: n(p.score) + n(p.num_comments),
          views: null,
          url: p.permalink ? (p.permalink.startsWith('http') ? p.permalink : `https://www.reddit.com${p.permalink}`) : (p.url ?? ''),
        })) ?? null,
    prov: r.prov,
  };
}

export async function tiktokPosts(ctx: Ctx, q: string, max = 20): Promise<Sourced<SocialPost[]>> {
  const r = await runActor<{ text?: string; createTimeISO?: string; diggCount?: number; shareCount?: number; commentCount?: number; playCount?: number; webVideoUrl?: string; authorMeta?: { name?: string } }>(ctx, ACTORS.tiktok, { searchQueries: [q], resultsPerPage: max });
  return {
    data:
      r.data
        ?.filter((v) => v.webVideoUrl)
        .map((v) => ({
          platform: 'tiktok' as const,
          text: (v.text ?? '').slice(0, 280),
          author: v.authorMeta?.name ?? '?',
          date: isoDate(v.createTimeISO),
          engagement: n(v.diggCount) + n(v.shareCount) + n(v.commentCount),
          views: v.playCount ?? null,
          url: v.webVideoUrl!,
        })) ?? null,
    prov: r.prov,
  };
}
