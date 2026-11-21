/**
 * Hound: builds a dossier on one entity (company, person, project) from every public trail Oculon can reach,
 * merges it into one timeline, links it into the entity graph, and raises signals when several trails move at once.
 *
 * Trails: Wikipedia, Hacker News, GDELT, GNews, The Guardian, NYT, web search (Tavily/Exa), Polymarket, GitHub,
 * SEC EDGAR (filings, decoded 8-K items), Finnhub (quote, profile, insiders, company news, analyst recommendations,
 * insider sentiment, peers, key metrics, earnings surprises; with deep: lobbying, federal contracts, visa filings,
 * patents), openFDA recalls and ClinicalTrials.gov (health and food companies only), Adzuna (hiring), CourtListener (federal dockets),
 * Companies House (UK registry), Brandfetch, YouTube, Bluesky. Sources without a key are skipped and labeled.
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { clamp, spikeRatio } from '../core/stats.js';
import { keywords, signalId } from '../core/text.js';
import type { Evidence, ModuleResult, Provenance, Signal } from '../core/types.js';
import { brand, courtCases, hiring, ukCompany, type Brand, type CourtCase, type Hiring, type UkCompany } from '../sources/corp.js';
import { recalls, sponsorTrials, isPhase3, type FirmRecalls, type SponsorTrials } from '../sources/fda.js';
import {
  bullishShare,
  companyNews,
  earningsSurprises,
  findSymbol,
  govContracts,
  insiderSentiment,
  insiders,
  lobbying,
  metrics,
  patents,
  peers,
  profile,
  quote,
  recommendations,
  visaApplications,
  type CompanyProfile,
  type EarningsSurprise,
  type GovContracts,
  type Insider,
  type InsiderSentimentMonth,
  type KeyMetrics,
  type Lobbying,
  type NewsItem,
  type Patents,
  type Quote,
  type Recommendation,
  type VisaFilings,
} from '../sources/finance.js';
import { decodeEvents, eventEvidence, type CorporateEvent } from './filings.js';
import { latestArticles } from '../sources/gdelt.js';
import { recentRepos, type Repo } from '../sources/github.js';
import { hnItemUrl, recentMentions, type HnStory } from '../sources/hackernews.js';
import { searchMarkets, type Market } from '../sources/polymarket.js';
import { gnews, guardian, nytSearch, webSearch, type WebResult } from '../sources/press.js';
import { companies, matchCompany, recentFilings, type Company, type Filing } from '../sources/sec.js';
import { bluesky, youtube, type Post, type Video } from '../sources/social.js';
import { dailyViews, resolveTitle, summary, type Summary } from '../sources/wikimedia.js';

export interface TimelineItem {
  date: string;
  source: string;
  text: string;
  url?: string;
}

export interface Dossier {
  query: string;
  wikipedia: (Summary & { lastDayViews: number | null; spike: number | null }) | null;
  stock: { symbol: string; quote: Quote | null; profile: CompanyProfile | null; insiders: Insider[] } | null;
  sec: { company: Company; filings: Filing[] } | null;
  /** 8-Ks in the window with item codes decoded (from the same SEC submissions feed). */
  events?: CorporateEvent[];
  /** Finnhub free-tier extras; present only when the ticker matched the query. */
  recommendations?: Recommendation[];
  insiderSentiment?: InsiderSentimentMonth[];
  peers?: string[];
  metrics?: KeyMetrics;
  earnings?: EarningsSurprise[];
  /** Only with HoundOptions.deep. */
  lobbying?: Lobbying;
  govContracts?: GovContracts;
  visa?: VisaFilings;
  patents?: Patents;
  /** openFDA recalls; only for health, pharma, device or food companies with at least one recall. */
  fda?: FirmRecalls;
  /** ClinicalTrials.gov; only for health or pharma companies with registered trials. */
  trials?: SponsorTrials;
  uk: UkCompany | null;
  brand: Brand | null;
  hiring: (Hiring[] & { change?: number | null }) | null;
  /** Same as hiring.change, kept as its own field because JSON drops properties attached to an array. */
  hiringChange: number | null;
  court: { total: number; cases: CourtCase[] } | null;
  github: { owner: string; repos: Repo[] } | null;
  /** News from GDELT, GNews, Guardian, NYT and company news, deduplicated by title. */
  news: NewsItem[];
  web: WebResult[];
  stories: HnStory[];
  markets: Market[];
  videos: Video[];
  posts: Post[];
  timeline: TimelineItem[];
}

export interface HoundOptions {
  /** GitHub org/user; defaults to the query with spaces removed. false to skip. */
  github?: string | false;
  days?: number;
  /** Also fetch lobbying, federal contracts, visa filings and patents (four more Finnhub calls). */
  deep?: boolean;
}

/** Industries (Finnhub) or descriptions (Wikipedia) where FDA recalls and clinical trials are relevant. */
const FDA_RELEVANT = /pharma|biotech|bio-?pharm|health ?care|medical|life sciences|drug|diagnostic|food|beverage|tobacco|cosmetic|nutrition|vaccine/i;
const TRIALS_RELEVANT = /pharma|biotech|bio-?pharm|health ?care|medical|life sciences|drug|diagnostic|vaccine|therapeutic/i;

/** "Examplecorp Holdings, Inc." -> "Examplecorp" (for registry searches). */
export const coreName = (name: string) =>
  name
    .replace(/[,.]/g, ' ')
    .replace(/\b(inc|incorporated|corp|corporation|co|company|ltd|limited|plc|llc|lp|sa|ag|nv|se|group|holdings?|the)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim() || name.trim();

/** Keep only items that actually mention the entity, so a common word does not drag in noise. */
export function mentions(text: string, query: string): boolean {
  const q = [...keywords(query)];
  if (!q.length) return text.toLowerCase().includes(query.toLowerCase());
  const k = keywords(text);
  return q.every((w) => k.has(w)) || text.toLowerCase().includes(query.toLowerCase());
}

const gdeltDate = (s: string) => (/^\d{8}T\d{6}Z$/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(9, 11)}:${s.slice(11, 13)}:00Z` : s);

/** Merge news lists, newest first, dropping near-duplicate headlines. */
export function mergeNews(lists: NewsItem[][]): NewsItem[] {
  const seen = new Set<string>();
  const out: NewsItem[] = [];
  for (const n of lists.flat().sort((a, b) => b.date.localeCompare(a.date))) {
    const k = n.title.toLowerCase().replace(/[^a-z0-9 ]/g, '').split(' ').filter(Boolean).slice(0, 8).join(' ');
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(n);
  }
  return out;
}

const INSIDER_SELL_CODES = new Set(['S']);

export async function hound(ctx: Ctx, queryInput: string, opts: HoundOptions = {}): Promise<ModuleResult<Dossier>> {
  const query = queryInput.trim();
  const days = opts.days ?? 14;
  const nowMs = ctx.now().getTime();
  const nowIso = new Date(nowMs).toISOString();
  const provenance: Provenance[] = [];
  const owner = opts.github === false ? null : (opts.github ?? query.toLowerCase().replace(/[^a-z0-9-]/g, ''));

  const [title, hn, gd, markets, comps, repos, sym, gn, gu, ny, web, jobs, court, uk, vids, posts] = await Promise.all([
    resolveTitle(ctx, query),
    recentMentions(ctx, query, days, 30),
    latestArticles(ctx, query, 15),
    searchMarkets(ctx, query, 10),
    companies(ctx),
    owner ? recentRepos(ctx, owner) : Promise.resolve(null),
    findSymbol(ctx, query),
    gnews(ctx, query, 10),
    guardian(ctx, query, days, 10),
    nytSearch(ctx, query, days),
    webSearch(ctx, `${query} latest news`, 6, true),
    hiring(ctx, query),
    courtCases(ctx, query, 8),
    ukCompany(ctx, query),
    youtube(ctx, query, 7, 8),
    bluesky(ctx, query, 25),
  ]);
  provenance.push(title.prov, hn.prov, gd.prov, markets.prov, comps.prov, sym.prov, gn.prov, gu.prov, ny.prov, web.prov, jobs.prov, court.prov, uk.prov, vids.prov, posts.prov);
  if (repos) provenance.push(repos.prov);

  // Second wave: things that depend on the first (Wikipedia title, ticker, website).
  const [sumR, viewsR, q, prof, ins, cnews] = await Promise.all([
    title.data ? summary(ctx, title.data) : Promise.resolve(null),
    title.data ? dailyViews(ctx, title.data, 30) : Promise.resolve(null),
    sym.data ? quote(ctx, sym.data) : Promise.resolve(null),
    sym.data ? profile(ctx, sym.data) : Promise.resolve(null),
    sym.data ? insiders(ctx, sym.data, 30) : Promise.resolve(null),
    sym.data ? companyNews(ctx, sym.data, 7) : Promise.resolve(null),
  ]);
  for (const r of [sumR, viewsR, q, prof, ins, cnews]) if (r) provenance.push(r.prov);

  let wikipedia: Dossier['wikipedia'] = null;
  if (sumR?.data) {
    const vals = viewsR?.data?.map((v) => v.views) ?? [];
    const last = vals.length ? vals[vals.length - 1]! : null;
    wikipedia = { ...sumR.data, lastDayViews: last, spike: last !== null && vals.length > 7 ? spikeRatio(last, vals.slice(0, -3)) : null };
  }

  // Only trust the ticker when the company profile actually matches the query.
  const stockOk = Boolean(sym.data && prof?.data && (mentions(prof.data.name, query) || sym.data.toLowerCase() === query.toLowerCase()));
  const stock: Dossier['stock'] = stockOk ? { symbol: sym.data!, quote: q?.data ?? null, profile: prof?.data ?? null, insiders: ins?.data ?? [] } : null;

  const website = stock?.profile?.weburl ? (() => { try { return new URL(stock.profile.weburl).hostname.replace(/^www\./, ''); } catch { return null; } })() : null;
  let sec: Dossier['sec'] = null;
  const company = comps.data ? matchCompany(comps.data, stock?.symbol ?? query) : null;
  const sector = `${stock?.profile?.industry ?? ''} ${wikipedia?.description ?? ''}`;
  const firm = stock?.profile ? coreName(stock.profile.name) : query;
  const S = stockOk ? sym.data! : null;
  const none = Promise.resolve(null);

  // Third wave: everything that needs the ticker, website, CIK or sector, in parallel.
  const [br, f, recR, isR, peerR, metR, earnR, lobR, govR, visaR, patR, fdaR, ctR] = await Promise.all([
    website ? brand(ctx, website) : none,
    company ? recentFilings(ctx, company.cik, 40) : none,
    S ? recommendations(ctx, S) : none,
    S ? insiderSentiment(ctx, S, 12) : none,
    S ? peers(ctx, S) : none,
    S ? metrics(ctx, S) : none,
    S ? earningsSurprises(ctx, S) : none,
    S && opts.deep ? lobbying(ctx, S) : none,
    S && opts.deep ? govContracts(ctx, S) : none,
    S && opts.deep ? visaApplications(ctx, S) : none,
    S && opts.deep ? patents(ctx, S) : none,
    FDA_RELEVANT.test(sector) ? recalls(ctx, firm, { days: 90 }) : none,
    TRIALS_RELEVANT.test(sector) ? sponsorTrials(ctx, firm, 180) : none,
  ]);
  for (const r of [br, f, recR, isR, peerR, metR, earnR, lobR, govR, visaR, patR]) if (r) provenance.push(r.prov);
  if (fdaR) provenance.push(...fdaR.provenance);
  if (ctR) provenance.push(...ctR.provenance);
  if (company && f?.data) sec = { company, filings: f.data };
  const fda = fdaR?.data && fdaR.data.recent.length ? fdaR.data : null;
  const trialsData = ctR?.data && Object.values(ctR.data.counts).some((n) => n > 0) ? ctR.data : null;
  // Reading 8-K text is one extra SEC request per filing; only the newest two 5.02s in the window.
  const events = sec ? await decodeEvents(ctx, sec.filings, { since: nowMs - days * DAY_MS, read502: 2, provenance }) : [];

  const since = nowMs - days * DAY_MS;
  const stories = (hn.data ?? []).filter((s) => mentions(s.title, query)).sort((a, b) => b.points - a.points).slice(0, 10);
  const gdeltNews: NewsItem[] = (gd.data ?? []).map((a) => ({ title: a.title, url: a.url, date: gdeltDate(a.seendate), source: a.domain }));
  const news = mergeNews([gdeltNews, gn.data ?? [], gu.data ?? [], ny.data ?? [], stockOk ? (cnews?.data ?? []) : []])
    // Company-news feeds also carry general market stories; keep only headlines that name the company or ticker.
    .filter((n) => mentions(n.title, query) || (stockOk && new RegExp(`\\b${sym.data}\\b`).test(n.title)))
    .slice(0, 25);
  const mkts = (markets.data ?? []).filter((m) => mentions(m.question, query)).slice(0, 8);
  const ghRepos = repos?.data?.filter((r) => !r.fork && Date.parse(r.created_at) >= since) ?? [];
  const github = owner && repos?.data ? { owner, repos: ghRepos } : null;
  const videos = (vids.data ?? []).filter((v) => mentions(v.title, query)).slice(0, 8);
  const topPosts = (posts.data ?? []).filter((p) => mentions(p.text, query)).sort((a, b) => b.likes + b.reposts * 2 - (a.likes + a.reposts * 2)).slice(0, 8);
  const courtData = court.data ? { total: court.data.total, cases: court.data.cases } : null;
  const ukData = uk.data && mentions(uk.data.name, query) ? uk.data : null;

  // Hiring trend: compare against the previous observation of this entity.
  const kind = sec || stock ? 'company' : 'org';
  const id = ctx.graph.upsert(kind, query, {
    ...(wikipedia ? { wikipedia: wikipedia.title, description: wikipedia.description } : {}),
    ...(sec ? { cik: sec.company.cik } : {}),
    ...(stock ? { ticker: stock.symbol } : {}),
    ...(website ? { website } : {}),
  });
  const openings = jobs.data ? jobs.data.reduce((a, j) => a + j.openings, 0) : null;
  const prevOpen = ctx.graph.history(id, 'job_openings', 5).find((h) => nowMs - h.observedAt > 6 * 3600_000)?.value ?? null;
  if (openings !== null) ctx.graph.observe(id, 'hound', 'job_openings', openings, 'adzuna');
  const hiringData: Dossier['hiring'] = jobs.data ? Object.assign(jobs.data, { change: prevOpen ? openings! / prevOpen - 1 : null }) : null;

  const timeline: TimelineItem[] = [
    ...stories.map((s) => ({ date: new Date(s.created_at_i * 1000).toISOString(), source: 'hackernews', text: `${s.title} (${s.points} pts)`, url: hnItemUrl(s.objectID) })),
    ...news.map((n) => ({ date: n.date, source: `news:${n.source}`, text: n.title, url: n.url })),
    ...ghRepos.map((r) => ({ date: r.created_at, source: 'github', text: `new repo ${r.full_name}${r.description ? `: ${r.description}` : ''}`, url: r.html_url })),
    ...(sec?.filings.filter((f) => Date.parse(f.date) >= since).map((f) => ({ date: `${f.date}T00:00:00Z`, source: 'sec-edgar', text: `${f.form}: ${events.find((e) => e.url === f.url)?.summary ?? f.description}`, url: f.url })) ?? []),
    ...(fda?.recent.map((r) => ({ date: `${r.reported}T00:00:00Z`, source: 'openfda', text: `${r.classification} ${r.category} recall: ${r.product.slice(0, 120)}`, url: r.url })) ?? []),
    ...(trialsData?.recentlyTerminated.filter((t) => /^\d{4}-\d{2}-\d{2}$/.test(t.completionDate ?? '')).map((t) => ({ date: `${t.completionDate}T00:00:00Z`, source: 'clinicaltrials', text: `trial terminated: ${t.title}`, url: t.url })) ?? []),
    ...(stock?.insiders.filter((t) => Date.parse(t.date) >= since).map((t) => ({ date: `${t.date}T00:00:00Z`, source: 'insider', text: `${t.name} ${t.change >= 0 ? 'acquired' : 'disposed of'} ${Math.abs(t.change).toLocaleString('en-US')} shares (code ${t.code})` })) ?? []),
    ...(courtData?.cases.filter((c) => Date.parse(c.filed) >= since).map((c) => ({ date: `${c.filed}T00:00:00Z`, source: 'court', text: `${c.name} (${c.court})`, url: c.url })) ?? []),
    ...videos.map((v) => ({ date: v.date, source: `youtube:${v.channel}`, text: v.title, url: v.url })),
  ]
    .filter((t) => t.date && Date.parse(t.date) >= since)
    .sort((a, b) => b.date.localeCompare(a.date));

  // Graph links.
  if (wikipedia) ctx.graph.link(id, ctx.graph.upsert('article', wikipedia.title), 'described_by', 'wikipedia');
  for (const s of stories) ctx.graph.link(id, ctx.graph.upsert('story', s.title, { url: hnItemUrl(s.objectID), points: s.points }), 'mentioned_in', 'hackernews');
  for (const m of mkts) ctx.graph.link(id, ctx.graph.upsert('market', m.question, { url: m.url }), 'subject_of', 'polymarket');
  for (const r of ghRepos) ctx.graph.link(id, ctx.graph.upsert('repo', r.full_name, { url: r.html_url }), 'owns_repo', 'github');
  for (const c of courtData?.cases.slice(0, 5) ?? []) ctx.graph.link(id, ctx.graph.upsert('event', `case: ${c.name}`, { url: c.url, filed: c.filed }), 'party_to', 'courtlistener');
  if (website) ctx.graph.link(id, ctx.graph.upsert('domain', website), 'operates', 'finnhub');
  for (const p of peerR?.data?.slice(0, 10) ?? []) ctx.graph.link(id, ctx.graph.upsert('company', p, { ticker: p }), 'peer_of', 'finnhub');
  if (wikipedia?.lastDayViews != null) ctx.graph.observe(id, 'hound', 'wiki_views', wikipedia.lastDayViews, 'wikimedia-pageviews');
  if (stock?.quote) ctx.graph.observe(id, 'hound', 'price', stock.quote.price, 'finnhub', { changePct: stock.quote.changePct });

  // Signals: each trail that is moving, then one fused signal.
  const recent = nowMs - 3 * DAY_MS;
  const moving: Evidence[] = [];
  if (wikipedia?.spike && wikipedia.spike >= 3) moving.push({ source: 'wikimedia-pageviews', text: `Wikipedia readers ${wikipedia.spike.toFixed(1)}x usual (${wikipedia.lastDayViews?.toLocaleString('en-US')} yesterday)`, url: wikipedia.url, value: wikipedia.spike });
  const hot = stories.filter((s) => s.created_at_i * 1000 >= recent && s.points >= 200);
  if (hot.length) moving.push({ source: 'hackernews', text: `${hot.length} HN stor${hot.length > 1 ? 'ies' : 'y'} with 200+ points in 3 days, top: ${hot[0]!.title}`, url: hnItemUrl(hot[0]!.objectID) });
  if (stock?.quote && Math.abs(stock.quote.changePct) >= 5) moving.push({ source: 'finnhub', text: `${stock.symbol} ${stock.quote.changePct > 0 ? '+' : ''}${stock.quote.changePct.toFixed(1)}% today at ${stock.quote.price}`, value: stock.quote.changePct });
  const sells = stock?.insiders.filter((t) => INSIDER_SELL_CODES.has(t.code) && Date.parse(t.date) >= nowMs - 14 * DAY_MS) ?? [];
  if (sells.length >= 3) moving.push({ source: 'finnhub', text: `${sells.length} insider open-market sales in 14 days (${new Set(sells.map((s) => s.name)).size} insiders)` });
  const eightK = sec?.filings.filter((f) => f.form.startsWith('8-K') && Date.parse(f.date) >= recent) ?? [];
  if (eightK.length) moving.push({ source: 'sec-edgar', text: `${eightK.length} 8-K filing(s) in 3 days`, url: eightK[0]!.url });
  for (const e of events.filter((x) => Date.parse(x.date) >= recent)) moving.push(...eventEvidence(e));
  const [rec0, rec1] = recR?.data ?? [];
  const bullNow = rec0 ? bullishShare(rec0) : null;
  const bullPrev = rec1 ? bullishShare(rec1) : null;
  if (bullNow !== null && bullPrev !== null && Math.abs(bullNow - bullPrev) >= 0.1)
    moving.push({ source: 'finnhub', text: `analyst buy ratings ${bullNow > bullPrev ? 'up' : 'down'} from ${Math.round(bullPrev * 100)}% to ${Math.round(bullNow * 100)}% (${rec1!.period} to ${rec0!.period})`, value: bullNow - bullPrev });
  for (const r of fda?.newClassI.slice(0, 3) ?? [])
    moving.push({ source: 'openfda', text: `new Class I ${r.category} recall ${r.recallNumber} (reported ${r.reported}): ${r.reason.slice(0, 140)}`, url: r.url });
  const stoppedP3 = trialsData?.recentlyTerminated.filter((t) => isPhase3(t) && (t.completionDate ?? '') >= new Date(nowMs - 90 * DAY_MS).toISOString().slice(0, 10).slice(0, (t.completionDate ?? '').length)) ?? [];
  for (const t of stoppedP3.slice(0, 3))
    moving.push({ source: 'clinicaltrials', text: `phase 3 trial ${t.nctId} terminated (stopped ${t.completionDate})${t.whyStopped ? `: ${t.whyStopped.slice(0, 140)}` : ''}`, url: t.url });
  const newCases = courtData?.cases.filter((c) => Date.parse(c.filed) >= recent) ?? [];
  if (newCases.length) moving.push({ source: 'courtlistener', text: `${newCases.length} new federal case(s) in 3 days, e.g. ${newCases[0]!.name}`, url: newCases[0]!.url });
  const swing = mkts.filter((m) => m.change1d !== null && Math.abs(m.change1d) >= 0.08);
  if (swing.length) moving.push({ source: 'polymarket', text: `${swing[0]!.question}: ${swing[0]!.change1d! > 0 ? '+' : ''}${Math.round(swing[0]!.change1d! * 100)}pp in 24h`, url: swing[0]!.url });
  const freshNews = news.filter((n) => Date.parse(n.date) >= nowMs - DAY_MS);
  if (freshNews.length >= 8) moving.push({ source: 'news', text: `${freshNews.length} news articles in 24h across ${new Set(freshNews.map((n) => n.source)).size} outlets` });
  if (hiringData?.change != null && Math.abs(hiringData.change) >= 0.25) moving.push({ source: 'adzuna', text: `job openings ${hiringData.change > 0 ? 'up' : 'down'} ${Math.round(Math.abs(hiringData.change) * 100)}% since last check (${openings})` });
  const viral = topPosts.filter((p) => p.likes >= 500);
  if (viral.length) moving.push({ source: 'bluesky', text: `${viral.length} Bluesky post(s) with 500+ likes, top by @${viral[0]!.author}`, url: viral[0]!.url });

  const signals: Signal[] = [];
  if (moving.length) {
    const sources = new Set(moving.map((m) => m.source));
    signals.push({
      id: signalId('hound', query, nowIso.slice(0, 10)),
      module: 'hound',
      title: sources.size >= 2 ? `${query}: activity across ${sources.size} independent sources` : `${query}: ${moving[0]!.text}`,
      score: clamp(35 + moving.length * 8 + (sources.size - 1) * 10, 0, 100),
      entity: id,
      evidence: moving,
      createdAt: nowIso,
    });
    signals.forEach((s) => ctx.graph.saveSignal(s));
  }

  return {
    module: 'hound',
    input: query,
    generatedAt: nowIso,
    result: {
      query,
      wikipedia,
      stock,
      sec,
      ...(events.length ? { events } : {}),
      ...(recR?.data?.length ? { recommendations: recR.data.slice(0, 6) } : {}),
      ...(isR?.data?.length ? { insiderSentiment: isR.data } : {}),
      ...(peerR?.data?.length ? { peers: peerR.data } : {}),
      ...(metR?.data ? { metrics: metR.data } : {}),
      ...(earnR?.data?.length ? { earnings: earnR.data } : {}),
      ...(lobR?.data ? { lobbying: lobR.data } : {}),
      ...(govR?.data ? { govContracts: govR.data } : {}),
      ...(visaR?.data ? { visa: visaR.data } : {}),
      ...(patR?.data ? { patents: patR.data } : {}),
      ...(fda ? { fda } : {}),
      ...(trialsData ? { trials: trialsData } : {}),
      uk: ukData,
      brand: br?.data ?? null,
      hiring: hiringData,
      hiringChange: hiringData?.change ?? null,
      court: courtData,
      github,
      news,
      web: web.data ?? [],
      stories,
      markets: mkts,
      videos,
      posts: topPosts,
      timeline,
    },
    signals,
    provenance,
  };
}
