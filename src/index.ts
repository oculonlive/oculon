/**
 * Oculon SDK.
 *
 *   import { Oculon } from 'oculon';
 *   const o = new Oculon();
 *   const radar = await o.radar();
 *   const dossier = await o.dossier('Nvidia');
 *   o.close();
 *
 * Every call returns a ModuleResult: { result, signals, provenance } where provenance labels each
 * underlying fetch LIVE / CACHED / UNAVAILABLE / ERROR with its source URL and time.
 */
import { createContext, type ContextOptions, type Ctx } from './core/context.js';
import type { Entity, Neighbor } from './core/graph.js';
import { setPaidQuota } from './core/llm.js';
import { takeQuota } from './core/quota.js';
import { catalysts } from './modules/calendar.js';
import { pulse, type Platform } from './modules/pulse.js';
import { exposure } from './modules/exposure.js';
import { blackout } from './modules/blackout.js';
import { hazards } from './modules/hazards.js';
import { fires } from './modules/fires.js';
import { cloudStatus } from './modules/cloud.js';
import { bgp } from './modules/bgp.js';
import { cve, packageVulns, vulns } from './modules/vulns.js';
import { regs } from './modules/regs.js';
import { defi, protocol } from './modules/defi.js';
import { squawks } from './modules/squawk.js';
import { filings, recentEvents } from './modules/filings.js';
import { darkShips, vesselIdentity } from './modules/darkships.js';
import { podcast, transcribe } from './modules/listen.js';
import { connect, resolveEntities } from './modules/connect.js';
import { feedbackStats, recordFeedback, type Verdict } from './modules/feedback.js';
import type { ModuleResult, Provenance, Signal } from './core/types.js';
import { events, lights, snapshot } from './modules/condor.js';
import { cricket } from './modules/cricket.js';
import { mil, track } from './modules/falcon.js';
import { ferret, type FerretOptions } from './modules/ferret.js';
import { hound, type HoundOptions } from './modules/hound.js';
import { owl, type OwlOptions } from './modules/owl.js';
import { auto, getPrediction, listPredictions, predict, resolve, scoreboard, type Prediction, type Scoreboard } from './modules/raven.js';
import { stamp, verify } from './modules/tortoise.js';
import { token, wallet } from './modules/magpie.js';
import { deployerProfile, overview, rhTokenCheck } from './modules/heron.js';
import { addWatch, listWatch, removeWatch, runWatch } from './modules/meerkat.js';
import { makeBrief } from './modules/brief.js';
import { shipsNear, shipTrack } from './modules/ships.js';
import { checkScoops, scoreboard as scoopBoard } from './modules/scoop.js';
import { addFence, boxAround, checkFences, listFences, removeFence } from './modules/fence.js';
import { lynx } from './modules/lynx.js';
import { screen } from './modules/sanctions.js';
import { launches } from './modules/launches.js';
import { rewind } from './modules/rewind.js';
import { quotaUsage } from './core/quota.js';
import { air, spaceWeather } from './modules/sky.js';
import { readPage, webSearch } from './sources/press.js';

export interface OculonOptions extends Pick<ContextOptions, 'dbPath' | 'fetch' | 'throttle' | 'now'> {
  /** Contact string for User-Agents (enables SEC EDGAR). Falls back to OCULON_CONTACT. */
  contact?: string;
  /** GitHub token for higher rate limits. Falls back to GITHUB_TOKEN. */
  githubToken?: string;
}

export class Oculon {
  readonly ctx: Ctx;

  constructor(opts: OculonOptions = {}) {
    if (opts.contact) process.env.OCULON_CONTACT = opts.contact;
    if (opts.githubToken) process.env.GITHUB_TOKEN = opts.githubToken;
    this.ctx = createContext(opts);
    // Paid LLM calls count against a daily budget in this install's database.
    setPaidQuota((source) => takeQuota(this.ctx.store, source));
  }

  /** Owl: what the world is suddenly paying attention to, fused across sources. */
  radar(opts?: OwlOptions) {
    return owl(this.ctx, opts);
  }
  /** Ferret: pre-release footprints of a domain (new hostnames, pages, repos). */
  footprint(domain: string, opts?: FerretOptions) {
    return ferret(this.ctx, domain, opts);
  }
  /** Cricket: hype phase of a topic across readers, developers, news, research, builders. */
  hype(topic: string) {
    return cricket(this.ctx, topic);
  }
  /** Falcon: one aircraft by registration or ICAO hex. */
  aircraft(query: string) {
    return track(this.ctx, query);
  }
  /** Falcon: worldwide military air traffic by region. */
  military() {
    return mil(this.ctx);
  }
  /** Hound: dossier on a company, person or project. */
  dossier(name: string, opts?: HoundOptions) {
    return hound(this.ctx, name, opts);
  }
  /** Condor: open natural events (NASA EONET). */
  naturalEvents(days?: number) {
    return events(this.ctx, days);
  }
  /** Condor: night-time lights of a place, recent vs baseline. */
  nightLights(place: string, opts?: { recentDays?: number; baselineDays?: number }) {
    return lights(this.ctx, place, opts);
  }
  /** Condor: true-color satellite image of a place, saved as PNG. */
  satelliteImage(place: string, date?: string, dir?: string) {
    return snapshot(this.ctx, place, date, dir);
  }
  /** Raven: record a forecast for the first outcome of a Polymarket market. */
  forecast(marketSlug: string, probability: number, rationale?: string) {
    return predict(this.ctx, marketSlug, probability, rationale);
  }
  /** Raven: automatic forecasts where a market swing is corroborated by another source. */
  autoForecast() {
    return auto(this.ctx);
  }
  /** Raven: score forecasts whose markets resolved. */
  resolveForecasts() {
    return resolve(this.ctx);
  }
  scoreboard(): Scoreboard {
    return scoreboard(this.ctx);
  }
  forecasts(filter: 'all' | 'open' | 'resolved' = 'all', limit = 100): Prediction[] {
    return listPredictions(this.ctx, filter, limit);
  }
  getForecast(id: string): Prediction | null {
    return getPrediction(this.ctx, id);
  }
  /** Tortoise: timestamp all unstamped forecasts on Bitcoin via OpenTimestamps. */
  stampProofs() {
    return stamp(this.ctx);
  }
  /** Tortoise: verify a forecast's proof down to the Bitcoin block. */
  verifyProof(predictionId: string) {
    return verify(this.ctx, predictionId);
  }
  /** Magpie: wallet portfolio, history and risk (EVM or Solana address). */
  wallet(address: string) {
    return wallet(this.ctx, address);
  }
  /** Magpie: token contract risk, DEX pairs and price. On chain "robinhood" this uses Heron's own rules. */
  token(address: string, chain = 'eth') {
    return token(this.ctx, address, chain);
  }
  /** Heron: Robinhood Chain activity, trending pools and new pools with risk flags. */
  robinhood() {
    return overview(this.ctx);
  }
  /** Heron: everything a Robinhood Chain deployer launched (token or deployer address) and how many tokens died. */
  robinhoodDeployer(address: string) {
    return deployerProfile(this.ctx, address);
  }
  /** Heron: risk read on a Robinhood Chain token (verification, holder concentration, pool behavior). */
  robinhoodToken(address: string) {
    return rhTokenCheck(this.ctx, address);
  }
  /** Condor: geomagnetic storms and solar flares (NOAA SWPC). */
  spaceWeather(days = 7, opts: { nasa?: boolean } = {}) {
    return spaceWeather(this.ctx, days, opts);
  }
  /** Condor: PM2.5 air quality near a place (OpenAQ). */
  airQuality(place: string) {
    return air(this.ctx, place);
  }
  /** Web search (Tavily, Exa fallback). */
  webSearch(query: string, max = 6) {
    return webSearch(this.ctx, query, max);
  }
  /** Readable text of a web page (Jina Reader, Firecrawl fallback). */
  readPage(url: string) {
    return readPage(this.ctx, url);
  }
  /** Octopus: answer a question in plain language using Oculon's tools and a free-tier LLM. */
  async ask(question: string, opts?: { maxSteps?: number; onStep?: (s: string) => void }) {
    const { ask } = await import('./agent.js');
    return ask(this, question, opts);
  }
  /** Narrative tracker: group new headlines into storylines and flag new or fast-growing ones. */
  async narrativesRun() {
    return (await import('./modules/narratives.js')).runNarratives(this.ctx);
  }
  async narratives(activeDays = 14) {
    return (await import('./modules/narratives.js')).listNarratives(this.ctx, activeDays);
  }
  /** Company early-warning score (0-100) with each component explained. */
  async health(company: string) {
    return (await import('./modules/health.js')).health(this.ctx, company);
  }
  /** Disaster impact of current strong quakes and severe storms, or around a named place. */
  async impact(place?: string, radiusKm = 50) {
    const m = await import('./modules/impact.js');
    if (!place) return m.impact(this.ctx);
    const { geocode } = await import('./sources/earth.js');
    const g = await geocode(this.ctx, place);
    const p = g.data?.[0];
    if (!p) throw new Error(`place not found: ${place}`);
    return m.impact(this.ctx, { place: { name: p.name, lat: p.lat, lon: p.lon }, radiusKm });
  }
  /** Conflicting factual claims across independent sources on a topic. */
  async contradictions(topic: string) {
    return (await import('./modules/contradictions.js')).contradictions(this.ctx, topic);
  }
  /** Replay past days, measure which radar items became news, and tune the radar threshold. */
  async calibrate(days = 10) {
    return (await import('./modules/calibrate.js')).calibrate(this.ctx, { days });
  }
  /** Write a self-contained HTML report of the last `days` days; returns the file path. */
  async report(days = 7, out?: string) {
    return (await import('./report.js')).buildReport(this, { days, ...(out ? { out } : {}) });
  }
  /** Installed plugins and any that failed to load. */
  async plugins() {
    return (await import('./plugins.js')).loadPlugins();
  }
  async pluginRun(ref: string, args: Record<string, unknown> = {}) {
    return (await import('./plugins.js')).runPluginTool(this, ref, args);
  }
  /** OFAC sanctions screening: wallet address (plus direct counterparties), vessel IMO, or exact name. */
  sanctions(query: string) {
    return screen(this.ctx, query);
  }
  /** Lynx: Polymarket vs Kalshi and Manifold on the same questions; big verified gaps become signals. */
  markets(opts?: { limit?: number; minGapPp?: number }) {
    return lynx(this.ctx, opts);
  }
  /** Launch Radar: new models, apps, packages, hosts, pages and repos for a company. */
  launches(company: string, opts?: { domain?: string; org?: string; days?: number }) {
    return launches(this.ctx, company, opts);
  }
  /** Time Machine: what Oculon would have seen on a past date (YYYY-MM-DD). */
  rewind(date: string) {
    return rewind(this.ctx, date);
  }
  /** Geofence: a named box (south, west, north, east) watched for military aircraft/vessels, quakes and events. */
  fenceAdd(name: string, box: [number, number, number, number], kinds?: string[]) {
    return addFence(this.ctx, name, box, kinds);
  }
  /** Geofence around a place, `radiusKm` each way. */
  async fenceAddAround(name: string, place: string, radiusKm = 100, kinds?: string[]) {
    return addFence(this.ctx, name, await boxAround(this.ctx, place, radiusKm), kinds);
  }
  fenceList() {
    return listFences(this.ctx);
  }
  fenceRemove(id: number) {
    return removeFence(this.ctx, id);
  }
  /** Check every fence and report what is new inside it. */
  fenceCheck() {
    return checkFences(this.ctx);
  }
  /** First to Know: check strong signals against when major media first covered them. */
  scoopsCheck(max = 8) {
    return checkScoops(this.ctx, max);
  }
  /** First to Know scoreboard: how often and by how much Oculon was ahead of the media. */
  scoops() {
    return scoopBoard(this.ctx);
  }
  /** Case Files: open a new investigation, or re-run case `id`. Long-running (about 1-3 minutes). */
  async caseInvestigate(input: { question?: string; id?: number }, opts?: { onStep?: (s: string) => void }) {
    const { investigate } = await import('./cases.js');
    return investigate(this, input, opts);
  }
  async caseList() {
    return (await import('./cases.js')).listCases(this);
  }
  async caseGet(id: number) {
    return (await import('./cases.js')).getCase(this, id);
  }
  async caseWatch(id: number, on: boolean) {
    return (await import('./cases.js')).setCaseWatch(this, id, on);
  }
  /** Falcon at sea: live vessels around a place for `seconds` (aisstream.io). */
  ships(place: string, seconds = 30) {
    return shipsNear(this.ctx, place, seconds);
  }
  /** Falcon at sea: follow one ship by MMSI for up to `seconds`. */
  ship(mmsi: string, seconds = 60) {
    return shipTrack(this.ctx, mmsi, seconds);
  }
  /** Meerkat: add a watchlist target (company, domain, wallet, token, plane, topic, lights, air). */
  watchAdd(kind: string, target: string, label?: string) {
    return addWatch(this.ctx, kind, target, label);
  }
  watchList() {
    return listWatch(this.ctx);
  }
  watchRemove(id: number) {
    return removeWatch(this.ctx, id);
  }
  /** Meerkat: re-check every watch item and report what changed since last time. */
  watchRun(ids?: number[]) {
    return runWatch(this.ctx, ids);
  }
  /** Today's brief (stored once per day; refresh to rewrite). */
  brief(opts?: { refresh?: boolean; lang?: string }) {
    return makeBrief(this.ctx, opts);
  }
  /** Today's API usage against the free-tier budgets. */
  quota() {
    return quotaUsage(this.ctx.store);
  }
  /** Most recent signals from every module. */
  signals(limit = 50): Signal[] {
    return this.ctx.graph.recentSignals(limit);
  }
  /** An entity and its neighbors in the graph, e.g. "domain:openai.com". */
  entity(id: string): { entity: Entity | undefined; neighbors: Neighbor[] } {
    return { entity: this.ctx.graph.get(id), neighbors: this.ctx.graph.neighbors(id) };
  }
  /** Social pulse: recent posts about a subject on X, Reddit, TikTok (Apify) and Bluesky, with pace and top posts. */
  pulse(query: string, platforms?: Platform[]) {
    return pulse(this.ctx, query, platforms);
  }
  /** Listen: transcribe a public audio or video file (Deepgram), with summary, topics and passages about `subject`. */
  listen(url: string, subject = '') {
    return transcribe(this.ctx, url, subject);
  }
  /** Recent podcast episodes about a subject; transcribes episode number `pick` (default: newest English one). */
  podcast(subject: string, pick?: number) {
    return podcast(this.ctx, subject, pick);
  }
  /** Exposure: open ports, software and known CVEs on a domain's machines (Shodan InternetDB, free). */
  exposure(domain: string) {
    return exposure(this.ctx, domain);
  }
  /** Blackout radar: internet outages by country and network (Cloudflare Radar, IODA). */
  blackout(days = 2) {
    return blackout(this.ctx, days);
  }
  /** Official orange and red disaster alerts (GDACS). */
  hazards(days = 7) {
    return hazards(this.ctx, days);
  }
  /** Vessels that switched off AIS near a place (Global Fishing Watch). */
  darkShips(place: string, days = 30) {
    return darkShips(this.ctx, place, days);
  }
  /** Vessel identity by name, MMSI or IMO: flag, type, owners, earlier names, OFAC check. */
  vessel(query: string) {
    return vesselIdentity(this.ctx, query);
  }
  /** Sentinel-2 (10 m) or Sentinel-1 radar image of a place from Copernicus; optional before/after pair. */
  async sentinel(place: string, opts?: { date?: string; days?: number; kind?: 'optical' | 'radar'; compareTo?: string }) {
    return (await import('./modules/condor.js')).sentinel(this.ctx, place, opts);
  }
  /** Active fires and thermal hotspots near a place (NASA FIRMS, VIIRS). */
  fires(place: string, days = 2) {
    return fires(this.ctx, place, days);
  }
  /** Outages on the platforms the internet runs on: status pages of major services, AWS, Azure, Google Cloud. */
  cloud() {
    return cloudStatus(this.ctx);
  }
  /**
   * BGP: a country (two-letter code), a network (AS number), an IP address, or "world" for global hijacks,
   * route leaks and DDoS target countries (RIPEstat, Cloudflare Radar).
   */
  bgp(resource = 'world', days = 2) {
    return bgp(this.ctx, resource, days);
  }
  /** Vulnerabilities newly exploited in the wild (CISA KEV), new critical CVEs (NVD) and advisories (GitHub). */
  vulns(opts: { days?: number; vendor?: string } = {}) {
    return vulns(this.ctx, opts);
  }
  /** One CVE in depth: CVSS, EPSS trend, KEV status, affected packages and fixes. */
  cve(id: string) {
    return cve(this.ctx, id);
  }
  /** Known vulnerabilities of a package version (OSV.dev), flagged when exploited in the wild. */
  packageVulns(ecosystem: string, name: string, version?: string) {
    return packageVulns(this.ctx, ecosystem, name, version);
  }
  /** US Federal Register: executive orders, rules, proposed rules and tomorrow's documents (public inspection). */
  regs(opts: Parameters<typeof regs>[1] = {}) {
    return regs(this.ctx, opts);
  }
  /** DeFi risk radar: TVL crashes, stablecoin depegs, hacks, chain moves, fear and greed (DefiLlama, alternative.me). */
  defi() {
    return defi(this.ctx);
  }
  /** One DeFi protocol in depth: TVL trend and drawdown, audits, hacks, funding, warnings. */
  protocol(name: string) {
    return protocol(this.ctx, name);
  }
  /** Aircraft squawking emergency codes right now: 7500 hijack, 7600 radio failure, 7700 emergency. */
  squawks() {
    return squawks(this.ctx);
  }
  /** SEC EDGAR full-text search across filings, e.g. "cybersecurity incident" in 8-Ks. */
  filings(query: string, opts: { forms?: string[]; days?: number } = {}) {
    return filings(this.ctx, query, opts);
  }
  /** A company's recent 8-K events decoded into plain English (restatements, CEO exits, cyber incidents...). */
  secEvents(tickerOrCik: string, days = 90) {
    return recentEvents(this.ctx, tickerOrCik, { days });
  }
  /** Catalyst calendar: earnings, key macro releases and prediction markets closing in the next `days`. */
  calendar(days = 14) {
    return catalysts(this.ctx, days);
  }
  /** Link nodes that are the same real thing (org:nvidia, company:nvidia, domain:nvidia.com). */
  resolveEntities() {
    return resolveEntities(this.ctx);
  }
  /** Shortest path between two things in the graph: "how is A connected to B". */
  connect(a: string, b: string, maxDepth = 6) {
    return connect(this.ctx, a, b, maxDepth);
  }
  /** Record a Useful/Noise vote on a signal; it moves that module's alert bar. */
  feedback(signalId: string, verdict: Verdict, voter = 'local') {
    return recordFeedback(this.ctx, signalId, verdict, voter);
  }
  feedbackStats() {
    return feedbackStats(this.ctx);
  }
  /** Start the live Wikipedia + Bluesky stream listeners. Call stop() on the result to end them. */
  async live(opts: import('./live.js').LiveOptions = {}) {
    const { LiveMonitor } = await import('./live.js');
    const m = new LiveMonitor(this, opts);
    m.start();
    return m;
  }
  close(): void {
    this.ctx.store.close();
  }
}

/** Collapse provenance into per-source status counts plus distinct notes. Handy for compact output. */
export function summarizeProvenance(provenance: Provenance[]): { sources: Record<string, Record<string, number>>; notes: string[] } {
  const sources: Record<string, Record<string, number>> = {};
  const notes = new Set<string>();
  for (const p of provenance) {
    const s = (sources[p.source] ??= {});
    s[p.status] = (s[p.status] ?? 0) + 1;
    if (p.note) notes.add(`${p.source}: ${p.status} ${p.note}`);
  }
  return { sources, notes: [...notes] };
}

export type { ModuleResult, Provenance, Signal, Prediction, Scoreboard, Entity, Neighbor };
export type { Evidence, Status } from './core/types.js';
