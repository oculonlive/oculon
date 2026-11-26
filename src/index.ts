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
import { proofBundle, proofOts, stamp, verify } from './modules/tortoise.js';
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
import { urlCheck } from './modules/urlcheck.js';
import { audit } from './modules/audit.js';
import { factCheck } from './modules/factcheck.js';
import { travel } from './modules/travel.js';
import { addMonitor, parseMonitor } from './modules/monitor.js';
import { recall } from './modules/recall.js';
import { emailSecurity } from './modules/emailsec.js';
import { papers } from './modules/papers.js';
import { countryBrief } from './modules/country.js';
import { airportStatus } from './modules/airport.js';
import { scamCheck } from './modules/scam.js';
import { ipCheck } from './modules/ipintel.js';
import { hashCheck } from './modules/hashcheck.js';
import { ransomware } from './modules/ransomware.js';
import { companyCheck } from './modules/company.js';
import { breaches, passwordCheck, pwnedRange } from './modules/breach.js';
import { phoneCheck } from './modules/phone.js';
import { ibanCheck } from './modules/iban.js';
import { checkup, type CheckupInput } from './modules/checkup.js';
import { rescuePlan } from './modules/rescue.js';
import { spotRound } from './modules/spot.js';
import { wireCardPng, wirePostText, wireToday, type WireDigest } from './modules/wire.js';
import { scamTrends, trendsPostText, type ScamTrends } from './modules/trends.js';
import { downStatus } from './modules/down.js';
import { charityCheck } from './modules/charity.js';
import { brandShield } from './modules/brandshield.js';
import { screenshotCheck } from './modules/screenshot.js';
import { termsRead } from './modules/terms.js';
import { proveOts, proveStatus, proveSubmit, proveUpgrade } from './modules/prove.js';
import { headerCheck } from './modules/headers.js';
import { docCheck } from './modules/doc.js';
import { checkHistory, getCheck, recordCheck } from './modules/checks.js';
import { sourceStatus } from './core/calls.js';
import { reportPdf } from './report-pdf.js';
import { lookalikes } from './modules/lookalike.js';
import { honeypotCheck } from './modules/honeypot.js';
import { addressCheck } from './modules/address.js';
import { satellites } from './modules/satellites.js';
import { approvalsCheck } from './modules/approvals.js';
import { contractRisk } from './modules/contract.js';
import { signatureCheck } from './modules/signature.js';
import { poisoningCheck } from './modules/poisoning.js';
import { traceFunds } from './modules/trace.js';
import { imageCheck } from './modules/image.js';
import { qrCheck } from './modules/qrcheck.js';
import { repoCheck } from './modules/repo.js';
import { domainReport, walletReport } from './modules/report.js';
import { siteCheck } from './modules/site.js';
import { explainTx } from './modules/txexplain.js';
import { deployerCheck } from './modules/deployer.js';
import { emlCheck } from './modules/eml.js';
import { apkCheck } from './modules/apk.js';
import { jobCheck } from './modules/job.js';
import { whereCheck } from './modules/where.js';
import { archivePage } from './modules/archive.js';
import { inviteCheck } from './modules/invite.js';
import { stockToken } from './modules/stocktoken.js';

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
  /** Tortoise: the forecast, its hash, Merkle path and root, for checking without this install. */
  proofBundle(predictionId: string) {
    return proofBundle(this.ctx, predictionId);
  }
  /** Tortoise: the standard OpenTimestamps `.ots` file for a forecast's batch, or null before stamping. */
  proofOts(predictionId: string) {
    return proofOts(this.ctx, predictionId);
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
  /** Monitor in plain language: "internet outages in Iran" becomes a watch rule that alerts on changes. */
  monitor(text: string) {
    return addMonitor(this.ctx, text);
  }
  /** Read a monitoring sentence into a rule without saving it. */
  monitorParse(text: string) {
    return parseMonitor(text);
  }
  /** Is a link dangerous? Safe Browsing, URLhaus, urlscan.io history, domain age and URL heuristics. */
  urlCheck(url: string) {
    return urlCheck(this.ctx, url);
  }
  /** Dependency audit of package.json, requirements.txt or "npm:name@version" items (deps.dev, OpenSSF Scorecard). */
  audit(manifest: string, opts: { max?: number } = {}) {
    return audit(this.ctx, manifest, opts);
  }
  /** Fact check a claim or a news link against published fact checks and current reporting. */
  factCheck(claimOrUrl: string) {
    return factCheck(this.ctx, claimOrUrl);
  }
  /** Travel risk brief for a place: official advice, weather, air, outbreaks, hazards, quakes and outages. */
  travel(place: string, opts: { fires?: boolean } = {}) {
    return travel(this.ctx, place, opts);
  }
  /** Recalls for a VIN, "year make model", or a product (NHTSA, CPSC, FDA). */
  recall(query: string) {
    return recall(this.ctx, query);
  }
  /** Can someone spoof email from this domain? SPF, DMARC, DKIM, MTA-STS, DNSSEC, with fixes. */
  emailSecurity(domain: string) {
    return emailSecurity(this.ctx, domain);
  }
  /** Research brief: most cited and newest papers on a topic, growth per year, an overview with citations. */
  papers(topic: string, opts: { years?: number } = {}) {
    return papers(this.ctx, topic, opts);
  }
  /** Country brief: economy, leaders, currency, IMF outlook, travel advice, outages, disasters, headlines. */
  country(name: string) {
    return countryBrief(this.ctx, name);
  }
  /** Is this message a scam? Checks its links, sender domain and known scam patterns. */
  scamCheck(message: string) {
    return scamCheck(this.ctx, message);
  }
  /** Who runs this IP (or domain), and is it known for abuse? AbuseIPDB, GreyNoise, OTX, VirusTotal, ThreatFox, Spamhaus DROP, Tor. */
  ipCheck(ipOrDomain: string) {
    return ipCheck(this.ctx, ipOrDomain);
  }
  /** Is this file hash (MD5, SHA-1, SHA-256) known malware or a known good file? */
  hashCheck(hash: string) {
    return hashCheck(this.ctx, hash);
  }
  /** Ransomware leak-site claims: newest, or by country code, sector, company or domain (ransomware.live). */
  ransomware(query = '') {
    return ransomware(this.ctx, query);
  }
  /** Company identity: EU VAT number (VIES), LEI or name (GLEIF), with status and ultimate parent. */
  companyCheck(nameLeiOrVat: string) {
    return companyCheck(this.ctx, nameLeiOrVat);
  }
  /** Is this password in known breaches? Only 5 characters of its SHA-1 hash leave the machine. */
  passwordCheck(password: string) {
    return passwordCheck(this.ctx, password);
  }
  /** Pwned Passwords suffix counts for a 5-character SHA-1 prefix (for checks that hash on the client). */
  pwnedRange(prefix: string) {
    return pwnedRange(this.ctx, prefix);
  }
  /** Newest breaches in Have I Been Pwned, or the breaches of one domain or company. */
  breaches(domain = '') {
    return breaches(this.ctx, domain);
  }
  /** Phone number check: country, line type, carrier, premium-rate and callback-scam warnings. */
  phoneCheck(number: string, opts: { country?: string } = {}) {
    return phoneCheck(this.ctx, number, opts);
  }
  /** IBAN check, offline: country, length, mod-97 check digits, bank code, and a warning when the account country differs from the supplier's. */
  /** Prove It: timestamp a file's SHA-256 on Bitcoin through OpenTimestamps. The same hash twice returns the existing proof. */
  proveSubmit(sha256: string, label?: string) {
    return proveSubmit(this.ctx, sha256, label);
  }
  /** Prove It: a proof by hash (pending, or confirmed in Bitcoin block N). A pending proof due for a check is checked now. */
  proveStatus(sha256: string, opts: { refresh?: boolean } = {}) {
    return proveStatus(this.ctx, sha256, opts);
  }
  /** Prove It: ask the calendars about due pending proofs, a limited number per pass. */
  proveUpgrade(opts: { limit?: number } = {}) {
    return proveUpgrade(this.ctx, opts);
  }
  /** Prove It: the proof as a standard detached .ots file, or null for an unknown hash. */
  proveOts(sha256: string) {
    return proveOts(this.ctx, sha256);
  }
  /** Is it down? Official status pages of ~30 services plus a labelled one-location probe for X, Google, YouTube, Instagram, WhatsApp, Telegram... */
  downStatus(service?: string) {
    return downStatus(this.ctx, service);
  }
  /** US nonprofit check by name or EIN (ProPublica Nonprofit Explorer, IRS data). */
  charityCheck(q: string, opts: { ein?: string } = {}) {
    return charityCheck(this.ctx, q, opts);
  }
  /** Domains imitating a brand: lookalikes, new certificates naming it, DNS, URL check on the top live ones. */
  brandShield(domain: string) {
    return brandShield(this.ctx, domain);
  }
  /** Oculon Wire: the strongest stored signals of the last 24 hours (or of a UTC day), at most six, one per desk first. */
  wire(date?: string): WireDigest {
    return wireToday(this.ctx, date);
  }
  /** The wire as one X post (plain text, no emoji, under 600 characters, ends with oculon.live/today). */
  wirePost(date?: string): string {
    return wirePostText(wireToday(this.ctx, date));
  }
  /** The wire as a 1200x675 PNG card. */
  wireCard(date?: string): Buffer {
    return wireCardPng(wireToday(this.ctx, date));
  }
  /** Scam Trends: counts and categories of the checks recorded in the last `days` (default 7) and the period before. Nothing that was checked is returned. */
  trends(days = 7): ScamTrends {
    return scamTrends(this.ctx, days);
  }
  /** Weekly "Scam of the week" post, or null when there is too little data to say anything honest. */
  trendsPost(days = 7): string | null {
    return trendsPostText(scamTrends(this.ctx, days));
  }
  /** "I got scammed" rescue: merged checklist (next 10 minutes, today, this week) and official reporting links by country. */
  rescuePlan(situation?: string | string[], country?: string) {
    return rescuePlan(this.ctx, situation, country);
  }
  /** Security Checkup: 0-100 score, grade A-F and the top fixes, from browser-collected results and six habit answers. */
  checkup(input: CheckupInput) {
    return checkup(this.ctx, input);
  }
  /** Spot the Scam: the day's 8 links (real blocklisted phishing domains and real official pages), answers included. */
  spotRound(date?: string) {
    return spotRound(this.ctx, date);
  }
  ibanCheck(iban: string, opts: { country?: string } = {}) {
    return ibanCheck(this.ctx, iban, opts);
  }
  /** Raw email headers: SPF, DKIM and DMARC results, the delivery path, the origin IP and spoofing signs. */
  headerCheck(rawHeaders: string) {
    return headerCheck(this.ctx, rawHeaders);
  }
  /** Was this invoice, bank statement or screenshot edited? PDF, JPEG or PNG bytes; IBANs in the text are checked. */
  /** Is the message in this screenshot a scam? Gemini transcribes the image; the scam check judges the text. PNG, JPEG or WebP, max 8 MB. */
  screenshotCheck(file: Buffer, name?: string) {
    return screenshotCheck(this.ctx, file, name);
  }
  /** Which clauses in these terms or this contract are worth reading twice? Pasted text (max 60,000 chars) or a URL; rule-based, every finding quotes the sentence. */
  termsRead(input: { text?: string; url?: string }) {
    return termsRead(this.ctx, input);
  }
  docCheck(file: Buffer, name?: string) {
    return docCheck(this.ctx, file, name);
  }
  /** Run a check and keep it: returns the value plus a check id, a replay link and what changed since the last check of the same target. */
  recordCheck<T>(kind: string, target: string, run: () => Promise<T>, opts: { label?: string } = {}) {
    return recordCheck(this.ctx, kind, target, run, opts);
  }
  /** A stored check: verdict, every source call it made (the replay log) and the full result. */
  check(id: string) {
    return getCheck(this.ctx, id);
  }
  /** Earlier checks of the same target as check `id`, newest first. */
  checkHistory(id: string, limit = 10) {
    return checkHistory(this.ctx, id, limit);
  }
  /** One stored check as a PDF report. */
  checkPdf(id: string, baseUrl?: string) {
    const c = getCheck(this.ctx, id);
    return c ? reportPdf(c, checkHistory(this.ctx, id), baseUrl) : null;
  }
  /** Which sources are up, slow or down: live calls of the last `hours`. */
  sourceStatus(hours = 24) {
    return sourceStatus(this.ctx.store, hours);
  }
  /** Lookalike domains of a brand that exist in DNS, and new certificates naming the brand (crt.sh). */
  lookalikes(domain: string) {
    return lookalikes(this.ctx, domain);
  }
  /** Can this token be sold? Buy and sell simulation with taxes (honeypot.is): Ethereum, BNB Chain, Base. */
  honeypotCheck(address: string, opts: { chain?: string } = {}) {
    return honeypotCheck(this.ctx, address, opts);
  }
  /** Crypto address without keys: chain from format, OFAC sanctions, balance and activity from free explorers. */
  addressCheck(address: string, opts: { network?: string } = {}) {
    return addressCheck(this.ctx, address, opts);
  }
  /** Token and NFT approvals still active on a wallet, with risky spenders flagged (Ethereum, Arbitrum, Polygon). */
  approvalsCheck(address: string, opts: { chain?: string } = {}) {
    return approvalsCheck(this.ctx, address, opts);
  }
  /** What the owner of a token contract can still do: mint, blacklist, taxes, upgrades, plus holders and liquidity. */
  contractRisk(address: string, opts: { chain?: string } = {}) {
    return contractRisk(this.ctx, address, opts);
  }
  /** What a wallet signature request really allows: permits, Permit2, Seaport orders, approvals, calldata. */
  signatureCheck(request: string, opts: { chain?: string; to?: string } = {}) {
    return signatureCheck(this.ctx, request, opts);
  }
  /** Lookalike addresses, zero-value transfers and fake tokens planted in a wallet's history. */
  poisoningCheck(address: string, opts: { chain?: string } = {}) {
    return poisoningCheck(this.ctx, address, opts);
  }
  /** Follow funds out of an address for a few hops, until exchanges, mixers, bridges or sanctioned addresses. */
  traceFunds(address: string, opts: { chain?: string; hops?: number; width?: number } = {}) {
    return traceFunds(this.ctx, address, opts);
  }
  /** Was this image made by AI, edited, or taken with a camera? C2PA credentials, IPTC, generator settings, EXIF. */
  imageCheck(file: Buffer, name?: string) {
    return imageCheck(this.ctx, file, name);
  }
  /** Read the QR code in an image and check where it leads: link, crypto or bank payment, Wi-Fi. */
  qrCheck(file: Buffer, name?: string) {
    return qrCheck(this.ctx, file, name);
  }
  /** Is this GitHub repo safe to run? Install hooks, remote code, wallet and browser theft, obfuscation, fake stars. */
  repoCheck(repo: string) {
    return repoCheck(this.ctx, repo);
  }
  /** One report for a domain: link check, email protection, exposure, lookalikes and the company. */
  domainReport(domain: string) {
    return domainReport(this.ctx, domain);
  }
  /** One report for a wallet or token: address, approvals, poisoning, fund trace, or contract risk and sell test. */
  walletReport(address: string, opts: { chain?: string } = {}) {
    return walletReport(this.ctx, address, opts);
  }
  /** Open a page and look for wallet drainer code and phishing (forms, brand copies, Telegram exfiltration). */
  siteCheck(url: string, opts: { browser?: boolean } = {}) {
    return siteCheck(this.ctx, url, opts);
  }
  /** What happened in a transaction: function, token transfers, approvals, tokens taken with an earlier approval. */
  explainTx(hash: string, opts: { chain?: string } = {}) {
    return explainTx(this.ctx, hash, opts);
  }
  /** Who created a token and how many of their other tokens are dead (Ethereum, Arbitrum, Polygon). */
  creatorCheck(token: string, opts: { chain?: string } = {}) {
    return deployerCheck(this.ctx, token, opts);
  }
  /** A whole .eml email: headers, message and links, and every attachment through the matching check. */
  emlCheck(file: Buffer, name?: string) {
    return emlCheck(this.ctx, file, name);
  }
  /** Is this Android app safe to install? Permissions, accessibility and SMS abuse, signer, known malware. */
  apkCheck(file: Buffer, name?: string) {
    return apkCheck(this.ctx, file, name);
  }
  /** Is this job offer a scam? Fees, paid tasks, crypto pay, chat-only contact, test-task repos. */
  jobCheck(message: string) {
    return jobCheck(this.ctx, message);
  }
  /** Where and when a photo was taken (EXIF GPS and time), the place, and the weather and daylight at that hour. */
  whereCheck(file: Buffer, name?: string) {
    return whereCheck(this.ctx, file, name);
  }
  /** Save a page as evidence in the Wayback Machine and record its hash, status and final address. */
  archivePage(url: string) {
    return archivePage(this.ctx, url);
  }
  /** What is behind a Telegram or Discord invite: members, age, verified badge, scam labels, impersonation. */
  inviteCheck(link: string) {
    return inviteCheck(this.ctx, link);
  }
  /** Robinhood Stock Tokens: official contract, live price, corporate actions; or whether an address is a fake one. */
  stockToken(query = '') {
    return stockToken(this.ctx, query);
  }
  /** Satellites: launches of the last 30 days, or one object's orbit, owner and status (CelesTrak). */
  satellites(query = '') {
    return satellites(this.ctx, query);
  }
  /** Airport status: METAR and TAF, FAA delays and ground stops (US), emergency squawks nearby. */
  airport(code: string) {
    return airportStatus(this.ctx, code);
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
export { OculonClient, OculonApiError, type OculonClientOptions, type KeyStatus } from './client.js';
