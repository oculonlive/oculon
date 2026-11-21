/**
 * Owl: global anomaly radar. Looks at what the world is suddenly paying attention to
 * (Wikipedia spikes, Hacker News front page, prediction-market swings, strong earthquakes)
 * and fuses items that point at the same subject into one corroborated signal.
 */
import type { Ctx } from '../core/context.js';
import { entityId } from '../core/graph.js';
import { clamp, robustZ, spikeRatio } from '../core/stats.js';
import { articleTitle, keywords, overlap, signalId } from '../core/text.js';
import type { Evidence, ModuleResult, Provenance, Signal } from '../core/types.js';
import { frontPage, hnItemUrl } from '../sources/hackernews.js';
import { topMarkets, type Market } from '../sources/polymarket.js';
import { eonetEvents } from '../sources/earth.js';
import { trendingCoins } from '../sources/finance.js';
import { nytTopStories } from '../sources/press.js';
import { flareFlux, kpIndex, xrayFlares } from '../sources/space.js';
import { recentQuakes } from '../sources/usgs.js';
import { eventSeverity } from './condor.js';
import { signalThreshold, sourceWeights } from './calibrate.js';
import { dailyViews, isNoiseArticle, topArticles } from '../sources/wikimedia.js';

export interface Blip {
  source: 'wikipedia' | 'hackernews' | 'polymarket' | 'usgs' | 'eonet' | 'nyt' | 'guardian' | 'coingecko' | 'noaa-swpc';
  title: string;
  url: string;
  /** 0-100 strength of this single observation. */
  strength: number;
  detail: string;
  value: number;
  keys: string[];
}

export interface OwlResult {
  blips: Blip[];
  fused: { title: string; score: number; sources: string[]; shared: string[]; blips: Blip[]; linkedBy?: string }[];
  /** Groups an LLM linked as the same event, with its reasons. Empty when no LLM key is set. */
  aiLinks: { subject: string; why: string; titles: string[] }[];
}

export interface OwlOptions {
  /** How many of the day's top Wikipedia articles to check for spikes. */
  wikiDepth?: number;
  /** Link same-event items with an LLM (default on when an LLM key is configured). */
  aiLink?: boolean;
  llmFetch?: typeof fetch;
}

const SPORTS = /\b(spread|o\/u|over\/under|moneyline|vs\.?|map \d|game \d|set \d|total (points|goals|kills)|both teams to score|handicap)\b|:\s*\w+\s*\(([+-]?\d+(\.\d+)?)\)/i;

const SPORTS_WIN_ON_DATE = /\bwin on \d{4}-\d{2}-\d{2}\b|\b(fc|united|city)\b.*\b(win|draw)\b/i;

export function isSportsLine(m: Market): boolean {
  return SPORTS.test(m.question) || SPORTS_WIN_ON_DATE.test(m.question);
}

/** Markets about to resolve drift to 0/100 mechanically; that is not news. */
export function isResolving(m: Market, nowMs: number): boolean {
  const end = m.endDate ? Date.parse(m.endDate) : NaN;
  return Number.isFinite(end) && end - nowMs < 2 * 86_400_000;
}

/** Strongest a single uncorroborated observation can score; corroboration adds the rest. */
export const SINGLE_SOURCE_CAP = 70;
export const CORROBORATION_BONUS = 25;

const mkBlip = (b: Omit<Blip, 'keys'>): Blip => ({ ...b, keys: [...keywords(b.title)] });

export function fuse(blips: Blip[], minOverlap = 0.5): OwlResult['fused'] {
  const groups: Blip[][] = [];
  for (const b of [...blips].sort((x, y) => y.strength - x.strength)) {
    const kb = new Set(b.keys);
    const g = groups.find((grp) =>
      grp.some((o) => {
        const ov = overlap(new Set(o.keys), kb);
        if (!ov.shared.length) return false;
        // Across sources a partial match is enough; within one source only near-identical subjects merge
        // ("Robert Pattinson" + "Robert Pattinson filmography").
        return o.source !== b.source ? ov.score >= minOverlap : ov.score >= 1 && ov.shared.length >= 2;
      }),
    );
    if (g) g.push(b);
    else groups.push([b]);
  }
  return groups.map((g) => scoreGroup(g)).sort((a, b) => b.score - a.score);
}

/** Score one group: its strongest blip, plus a bonus per extra independent source. */
export function scoreGroup(g: Blip[], linkedBy?: string): Fused {
  const sources = [...new Set(g.map((b) => b.source))];
  const lead = [...g].sort((a, b) => b.strength - a.strength)[0]!;
  const shared = g.length > 1 ? [...g.slice(1).reduce((acc, b) => new Set(overlap(acc, new Set(b.keys)).shared), new Set(lead.keys))] : lead.keys;
  // Corroboration from independent sources is what turns a blip into a signal.
  const best = Math.round((Math.max(...g.map((b) => b.strength)) / 100) * SINGLE_SOURCE_CAP);
  const score = clamp(best + (sources.length - 1) * CORROBORATION_BONUS, 0, 100);
  return { title: lead.title, score, sources, shared, blips: g, ...(linkedBy ? { linkedBy } : {}) };
}

type Fused = OwlResult['fused'][number];

/**
 * Second pass with an LLM: link groups that are about the same real-world event even when they share
 * no words (a celebrity and their partner's engagement, a company and its CEO's scandal). Strict: same
 * event or same entity only, never "same theme". Each merge keeps the model's stated reason.
 */
export async function aiLink(fused: Fused[], opts: { fetch?: typeof fetch; max?: number } = {}): Promise<{ fused: Fused[]; links: { subject: string; why: string; titles: string[] }[]; model: string | null }> {
  const { availableProviders, chat } = await import('../core/llm.js');
  if (!availableProviders().length || fused.length < 2) return { fused, links: [], model: null };
  const top = fused.slice(0, opts.max ?? 30);
  const list = top.map((f, i) => `${i}. [${f.sources.join('+')}] ${f.title}${f.blips[0]?.detail ? ` — ${f.blips[0].detail.slice(0, 80)}` : ''}`).join('\n');
  let raw: string;
  let model: string;
  try {
    const r = await chat(
      [
        {
          role: 'system',
          content:
            'You group news items. Link items ONLY if they are about the same specific real-world event or the same person/organization in the same story. Never link items that merely share a theme (e.g. two different AI stories). Most items should stay unlinked. Respond with JSON: {"links":[{"items":[indexes],"subject":"short subject","why":"one sentence"}]}',
        },
        { role: 'user', content: list },
      ],
      { json: true, temperature: 0, maxTokens: 800, ...(opts.fetch ? { fetch: opts.fetch } : {}) },
    );
    raw = r.message.content ?? '{}';
    model = `${r.provider}:${r.model}`;
  } catch {
    return { fused, links: [], model: null };
  }
  let parsed: { links?: { items?: unknown[]; subject?: unknown; why?: unknown }[] };
  try {
    parsed = JSON.parse(raw.replace(/^```(?:json)?|```$/g, '').trim());
  } catch {
    return { fused, links: [], model };
  }
  const used = new Set<number>();
  const merged: Fused[] = [];
  const links: { subject: string; why: string; titles: string[] }[] = [];
  for (const l of parsed.links ?? []) {
    const idx = [...new Set((l.items ?? []).map(Number))].filter((i) => Number.isInteger(i) && i >= 0 && i < top.length && !used.has(i));
    if (idx.length < 2) continue;
    idx.forEach((i) => used.add(i));
    const why = String(l.why ?? '').slice(0, 200);
    const subject = String(l.subject ?? '').slice(0, 80);
    const group = scoreGroup(idx.flatMap((i) => top[i]!.blips), `${model}: ${why}`);
    if (subject) group.title = subject;
    merged.push(group);
    links.push({ subject, why, titles: idx.map((i) => top[i]!.title) });
  }
  const rest = fused.filter((_, i) => !(i < top.length && used.has(i)));
  return { fused: [...merged, ...rest].sort((a, b) => b.score - a.score), links, model };
}

function blipKind(source: Blip['source']): 'market' | 'event' | 'story' | 'article' {
  if (source === 'polymarket' || source === 'coingecko') return 'market';
  if (source === 'usgs' || source === 'eonet' || source === 'noaa-swpc') return 'event';
  if (source === 'hackernews' || source === 'nyt' || source === 'guardian') return 'story';
  return 'article';
}

export async function owl(ctx: Ctx, opts: OwlOptions = {}): Promise<ModuleResult<OwlResult>> {
  const provenance: Provenance[] = [];
  const blips: Blip[] = [];
  const nowMs = ctx.now().getTime();

  const [top, hn, markets, quakes, natural, nyt, coins, kp, flares] = await Promise.all([
    topArticles(ctx),
    frontPage(ctx),
    topMarkets(ctx, 200),
    recentQuakes(ctx),
    eonetEvents(ctx, 3),
    nytTopStories(ctx),
    trendingCoins(ctx),
    kpIndex(ctx),
    xrayFlares(ctx),
  ]);
  provenance.push(top.prov, hn.prov, markets.prov, quakes.prov, natural.prov, nyt.prov, coins.prov, kp.prov, flares.prov);

  // Wikipedia: which of today's most-read articles are far above their own normal?
  if (top.data) {
    const candidates = top.data.articles.filter((a) => !isNoiseArticle(a.article)).slice(0, opts.wikiDepth ?? 25);
    const series = await Promise.all(candidates.map((a) => dailyViews(ctx, a.article, 30)));
    series.forEach((s, i) => {
      provenance.push(s.prov);
      const a = candidates[i]!;
      const vals = s.data?.map((d) => d.views);
      if (!vals || vals.length < 10) return;
      const last = vals[vals.length - 1]!;
      const base = vals.slice(0, -3);
      const ratio = spikeRatio(last, base);
      const z = robustZ(last, base);
      if (ratio < 3 || z < 4) return;
      blips.push(
        mkBlip({
          source: 'wikipedia',
          title: articleTitle(a.article),
          url: `https://en.wikipedia.org/wiki/${encodeURIComponent(a.article)}`,
          // Ratio is capped so a spike from a near-zero baseline is not overrated; absolute reach counts too.
          strength: clamp(Math.round(10 + 6 * Math.log2(Math.min(ratio, 256)) + 5 * Math.log10(Math.max(10, last))), 0, 90),
          detail: `${last.toLocaleString('en-US')} views on ${top.data!.date}, ${Number.isFinite(ratio) ? `${ratio.toFixed(1)}x` : 'up from ~0'} its usual`,
          value: ratio,
        }),
      );
    });
  }

  // Hacker News: front-page stories with unusual traction for their age.
  if (hn.data) {
    for (const s of hn.data) {
      const ageH = Math.max(1, (nowMs / 1000 - s.created_at_i) / 3600);
      const velocity = s.points / ageH;
      if (s.points < 150 && velocity < 40) continue;
      blips.push(
        mkBlip({
          source: 'hackernews',
          title: s.title,
          url: hnItemUrl(s.objectID),
          strength: clamp(Math.round(25 + 10 * Math.log2(Math.max(1, velocity))), 0, 85),
          detail: `${s.points} points, ${s.num_comments} comments in ${ageH.toFixed(0)}h`,
          value: velocity,
        }),
      );
    }
  }

  // Polymarket: big 24h swings in non-sports markets with real volume.
  if (markets.data) {
    for (const m of markets.data) {
      if (m.change1d === null || isSportsLine(m) || isResolving(m, nowMs) || m.volume24h < 25_000) continue;
      const pp = Math.abs(m.change1d) * 100;
      if (pp < 8) continue;
      const lead = m.outcomes[0] ?? 'Yes';
      blips.push(
        mkBlip({
          source: 'polymarket',
          title: m.question,
          url: m.url,
          strength: clamp(Math.round(30 + pp * 1.5), 0, 90),
          detail: `"${lead}" ${m.change1d > 0 ? '+' : '-'}${pp.toFixed(0)}pp in 24h to ${((m.prices[0] ?? 0) * 100).toFixed(0)}%, $${Math.round(m.volume24h).toLocaleString('en-US')} volume`,
          value: m.change1d,
        }),
      );
    }
  }

  // USGS: strong or alert-level earthquakes.
  if (quakes.data) {
    for (const q of quakes.data) {
      if (q.mag < 6 && !q.alert && !q.tsunami) continue;
      blips.push(
        mkBlip({
          source: 'usgs',
          title: `M${q.mag.toFixed(1)} earthquake ${q.place}`,
          url: q.url,
          strength: clamp(Math.round(20 + (q.mag - 5) * 20 + (q.alert ? 15 : 0) + (q.tsunami ? 10 : 0)), 0, 95),
          detail: `${new Date(q.time).toISOString().slice(0, 16)}Z${q.alert ? `, PAGER alert ${q.alert}` : ''}${q.tsunami ? ', tsunami flag' : ''}`,
          value: q.mag,
        }),
      );
    }
  }

  // NYT top stories: weak on their own (always "top"), but they corroborate other blips about the same subject.
  for (const n of (nyt.data ?? []).slice(0, 15)) {
    blips.push(mkBlip({ source: 'nyt', title: n.title, url: n.url, strength: 30, detail: `${n.source} top story`, value: 0 }));
  }

  // CoinGecko trending coins with a sharp 24h move.
  for (const c of coins.data ?? []) {
    if (c.change24h === null || Math.abs(c.change24h) < 15) continue;
    blips.push(
      mkBlip({
        source: 'coingecko',
        title: `${c.name} (${c.symbol.toUpperCase()}) trending`,
        url: `https://www.coingecko.com/en/coins/${c.id}`,
        strength: clamp(Math.round(30 + Math.abs(c.change24h)), 0, 80),
        detail: `${c.change24h > 0 ? '+' : ''}${c.change24h.toFixed(0)}% in 24h, trending on CoinGecko${c.rank ? `, rank #${c.rank}` : ''}`,
        value: c.change24h,
      }),
    );
  }

  // Space weather: a geomagnetic storm now (Kp >= 5) and M/X-class flares in the last day.
  const kpLast = kp.data?.length ? kp.data[kp.data.length - 1]! : null;
  if (kpLast && kpLast.kp >= 5) {
    blips.push(
      mkBlip({
        source: 'noaa-swpc',
        title: `Geomagnetic storm Kp ${kpLast.kp.toFixed(1)}`,
        url: 'https://www.swpc.noaa.gov/products/planetary-k-index',
        strength: clamp(Math.round(40 + (kpLast.kp - 5) * 12), 0, 90),
        detail: `planetary K index ${kpLast.kp} at ${kpLast.time}Z`,
        value: kpLast.kp,
      }),
    );
  }
  for (const f of (flares.data ?? []).filter((x) => flareFlux(x.maxClass) >= 1e-5 && Date.parse(x.maxTime) > nowMs - 86_400_000)) {
    blips.push(
      mkBlip({
        source: 'noaa-swpc',
        title: `Solar flare ${f.maxClass}`,
        url: 'https://www.swpc.noaa.gov/products/goes-x-ray-flux',
        strength: flareFlux(f.maxClass) >= 1e-4 ? 75 : 45,
        detail: `peaked ${f.maxTime.slice(0, 16)}Z`,
        value: flareFlux(f.maxClass),
      }),
    );
  }

  // NASA EONET: severe natural events (major storms, big wildfires, volcanoes, floods).
  if (natural.data) {
    for (const e of natural.data) {
      const sev = eventSeverity(e);
      if (!sev) continue;
      blips.push(mkBlip({ source: 'eonet', title: e.title, url: e.url, strength: sev.score, detail: `${sev.why}, updated ${e.date.slice(0, 16)}Z`, value: e.magnitude ?? 0 }));
    }
  }

  // Calibrated per-source weights (from `oculon calibrate`), bounded so no source dominates.
  const weights = sourceWeights(ctx);
  for (const b of blips) if (weights[b.source]) b.strength = clamp(Math.round(b.strength * weights[b.source]!), 0, 95);
  const linked = opts.aiLink === false ? { fused: fuse(blips), links: [], model: null } : await aiLink(fuse(blips), opts.llmFetch ? { fetch: opts.llmFetch } : {});
  const fused = linked.fused;
  const threshold = signalThreshold(ctx);
  const createdAt = new Date(nowMs).toISOString();
  const signals: Signal[] = fused
    // Threshold measured by `oculon calibrate` when available; 55 until then.
    .filter((f) => f.score >= threshold)
    .slice(0, 15)
    .map((f) => {
      const evidence: Evidence[] = f.blips.map((b) => ({ source: b.source, text: `${b.title}: ${b.detail}`, url: b.url, value: b.value }));
      if (f.linkedBy) evidence.push({ source: 'ai-link', text: `linked as one event by ${f.linkedBy}` });
      const kind = blipKind(f.blips[0]!.source);
      const id = ctx.graph.upsert(kind, f.title);
      for (const b of f.blips.slice(f.linkedBy ? 0 : 1)) {
        const other = ctx.graph.upsert(blipKind(b.source), b.title);
        if (other !== id) ctx.graph.link(id, other, f.linkedBy ? 'same_event_as' : 'corroborated_by', f.linkedBy ? 'ai-link' : b.source);
      }
      ctx.graph.observe(id, 'owl', 'signal_score', f.score, f.sources.join('+'));
      return { id: signalId('owl', f.title, createdAt.slice(0, 10)), module: 'owl', title: f.title, score: f.score, entity: entityId(kind, f.title), evidence, createdAt };
    });
  signals.forEach((s) => ctx.graph.saveSignal(s));

  return { module: 'owl', input: 'global', generatedAt: createdAt, result: { blips, fused, aiLinks: linked.links }, signals, provenance };
}
