/**
 * Social pulse: what people are posting about a subject right now on X, Reddit, TikTok and Bluesky.
 * Reports volume, how fast posts are arriving (last 6 hours vs the rest of the day), the most engaged
 * posts, and each platform's share. A sharp acceleration becomes a signal.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { redditPosts, tiktokPosts, xPosts, type SocialPost } from '../sources/apify.js';
import { bluesky } from '../sources/social.js';

export interface Pulse {
  query: string;
  posts: number;
  byPlatform: Record<string, number>;
  /** Reddit posts in the last 6 hours divided by the 6-hour average over the previous 18 hours; null when the sample spans less than a day. */
  acceleration: number | null;
  top: SocialPost[];
  latest: SocialPost[];
}

export type Platform = 'x' | 'reddit' | 'tiktok' | 'bluesky';

export async function pulse(ctx: Ctx, query: string, platforms: Platform[] = ['x', 'reddit', 'tiktok', 'bluesky']): Promise<ModuleResult<Pulse>> {
  const now = ctx.now();
  const provenance: Provenance[] = [];
  const calls: Promise<{ data: SocialPost[] | null; prov: Provenance }>[] = [];
  if (platforms.includes('x')) calls.push(xPosts(ctx, query));
  if (platforms.includes('reddit')) calls.push(redditPosts(ctx, query));
  if (platforms.includes('tiktok')) calls.push(tiktokPosts(ctx, query));
  if (platforms.includes('bluesky'))
    calls.push(
      bluesky(ctx, query, 25).then((r) => ({
        data: r.data?.map((p) => ({ platform: 'bluesky' as const, text: p.text, author: p.author, date: p.date, engagement: p.likes + p.reposts, views: null, url: p.url })) ?? null,
        prov: r.prov,
      })),
    );
  const results = await Promise.all(calls);
  const all: SocialPost[] = [];
  const seen = new Set<string>();
  for (const r of results) {
    provenance.push(r.prov);
    for (const p of r.data ?? []) if (p.url && !seen.has(p.url)) seen.add(p.url), all.push(p);
  }
  const byPlatform: Record<string, number> = {};
  for (const p of all) byPlatform[p.platform] = (byPlatform[p.platform] ?? 0) + 1;

  // Acceleration from timestamps over the last 24 hours. Searches return a capped number of posts, so a busy
  // topic can fill the whole sample with the last hour; such a platform says nothing about pace and is left out.
  // Only platforms whose oldest returned post is over 24 hours old (the day is fully covered) count.
  const t = now.getTime();
  const ageOf = (p: SocialPost) => (t - Date.parse(p.date)) / 3_600_000;
  // X, TikTok and Bluesky are fetched sorted by popularity, so their timestamps say nothing about pace; only
  // Reddit's newest-first sample can.
  const covered = Object.keys(byPlatform).filter((pl) => pl === 'reddit' && Math.max(...all.filter((p) => p.platform === pl).map(ageOf).filter(Number.isFinite)) > 24);
  const ages = all.filter((p) => covered.includes(p.platform)).map(ageOf).filter((h) => Number.isFinite(h) && h >= 0 && h <= 24);
  const last6 = ages.filter((h) => h <= 6).length;
  const prev18 = ages.filter((h) => h > 6).length;
  const acceleration = ages.length >= 15 ? last6 / Math.max(1, prev18 / 3) : null;

  const top = [...all].sort((a, b) => b.engagement - a.engagement).slice(0, 8);
  const latest = [...all].filter((p) => p.date).sort((a, b) => b.date.localeCompare(a.date)).slice(0, 8);
  const signals: Signal[] = [];
  if (acceleration !== null && acceleration >= 3 && last6 >= 10) {
    signals.push({
      id: signalId('pulse', query.toLowerCase(), now.toISOString().slice(0, 13)),
      module: 'pulse',
      title: `Social posts about ${query} accelerating: ${last6} in the last 6 hours (${acceleration.toFixed(1)}x the earlier pace)`,
      score: Math.min(85, Math.round(50 + Math.log2(acceleration) * 10)),
      evidence: top.slice(0, 3).map((p) => ({ source: p.platform, text: `${p.author}: ${p.text.slice(0, 140)} (${p.engagement} engagements)`, url: p.url })),
      createdAt: now.toISOString(),
    });
  }
  for (const s of signals) ctx.graph.saveSignal(s);
  return { module: 'pulse', input: query, generatedAt: now.toISOString(), result: { query, posts: all.length, byPlatform, acceleration, top, latest }, signals, provenance };
}
