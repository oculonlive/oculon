/** Social and research reach: YouTube, Bluesky, OpenAlex. */
import { DAY_MS, enc, type Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Sourced } from '../core/types.js';
import { postJson } from './press.js';

export interface Video {
  title: string;
  channel: string;
  date: string;
  url: string;
}

export async function youtube(ctx: Ctx, q: string, days = 7, max = 10): Promise<Sourced<Video[]>> {
  const k = key('YOUTUBE_API_KEY');
  if (!k) return noKey('youtube', 'YOUTUBE_API_KEY');
  // Hour-aligned "after" keeps the cache key stable; search costs 100 quota units, so cache for 6 hours.
  const after = new Date(Math.floor((ctx.now().getTime() - days * DAY_MS) / 3_600_000) * 3_600_000).toISOString();
  const r = await ctx.http.get<{ items?: { id: { videoId?: string }; snippet: { title: string; channelTitle: string; publishedAt: string } }[] }>(
    `https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&order=viewCount&maxResults=${max}&publishedAfter=${enc(after)}&q=${enc(q)}&key=${k}`,
    { source: 'youtube', ttlSec: 6 * 3600 },
  );
  return {
    data: r.data?.items?.filter((i) => i.id.videoId).map((i) => ({ title: decodeEntities(i.snippet.title), channel: i.snippet.channelTitle, date: i.snippet.publishedAt, url: `https://www.youtube.com/watch?v=${i.id.videoId}` })) ?? null,
    prov: r.prov,
  };
}

const decodeEntities = (s: string) => s.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');

export interface Post {
  text: string;
  author: string;
  date: string;
  likes: number;
  reposts: number;
  url: string;
}

let bskySession: { jwt: string; until: number } | null = null;

async function bskyToken(ctx: Ctx): Promise<{ jwt: string | null; prov: Sourced<unknown>['prov'] }> {
  if (bskySession && bskySession.until > Date.now()) return { jwt: bskySession.jwt, prov: { source: 'bluesky', url: 'session', status: 'CACHED', fetchedAt: new Date().toISOString() } };
  const id = key('BLUESKY_HANDLE');
  const pw = key('BLUESKY_APP_PASSWORD');
  if (!id || !pw) return { jwt: null, prov: noKey('bluesky', 'BLUESKY_HANDLE and BLUESKY_APP_PASSWORD').prov };
  // Session tokens are never cached on disk: ttl 0 and a unique cache key per minute.
  const r = await postJson<{ accessJwt?: string }>(ctx, 'https://bsky.social/xrpc/com.atproto.server.createSession', { identifier: id, password: pw, _t: Math.floor(Date.now() / 60_000) }, {}, 'bluesky', 0);
  ctx.store.db.prepare("DELETE FROM cache WHERE key LIKE 'post:https://bsky.social/xrpc/com.atproto.server.createSession%'").run();
  if (r.data?.accessJwt) bskySession = { jwt: r.data.accessJwt, until: Date.now() + 60 * 60_000 };
  return { jwt: r.data?.accessJwt ?? null, prov: r.prov };
}

/** Most-liked recent Bluesky posts matching the query. */
export async function bluesky(ctx: Ctx, q: string, max = 25): Promise<Sourced<Post[]>> {
  const t = await bskyToken(ctx);
  if (!t.jwt) return { data: null, prov: t.prov };
  const r = await ctx.http.get<{ posts?: { uri: string; author: { handle: string }; record: { text?: string; createdAt?: string }; likeCount?: number; repostCount?: number }[] }>(
    `https://bsky.social/xrpc/app.bsky.feed.searchPosts?q=${enc(q)}&sort=top&limit=${max}`,
    { source: 'bluesky', ttlSec: 1800, headers: { authorization: `Bearer ${t.jwt}` } },
  );
  return {
    data:
      r.data?.posts?.map((p) => ({
        text: (p.record.text ?? '').slice(0, 280),
        author: p.author.handle,
        date: p.record.createdAt ?? '',
        likes: p.likeCount ?? 0,
        reposts: p.repostCount ?? 0,
        url: `https://bsky.app/profile/${p.author.handle}/post/${p.uri.split('/').pop()}`,
      })) ?? null,
    prov: r.prov,
  };
}

/** Number of scholarly works (OpenAlex) matching `q` published between two dates. */
export async function openalexCount(ctx: Ctx, q: string, from: string, to: string): Promise<Sourced<number>> {
  const k = key('OPENALEX_API_KEY');
  const r = await ctx.http.get<{ meta?: { count?: number } }>(
    `https://api.openalex.org/works?search=${enc(q)}&filter=from_publication_date:${from},to_publication_date:${to}&per-page=1${k ? `&api_key=${k}` : ''}`,
    { source: 'openalex', ttlSec: 12 * 3600 },
  );
  return { data: r.data?.meta?.count ?? null, prov: r.prov };
}
