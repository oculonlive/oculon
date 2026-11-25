/**
 * Oculon MCP server over stdio (JSON-RPC 2.0, one message per line). No dependencies.
 * Lets Claude and other MCP clients call every Oculon module as a tool.
 */
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Oculon, summarizeProvenance } from './index.js';
import type { ModuleResult } from './core/types.js';
import { ONCHAIN_TOOLS, onchainEnabled } from './core/features.js';
import { availableKinds } from './modules/monitor.js';

export const SERVER_INFO = { name: 'oculon', version: '0.1.5' };
const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];

type Json = Record<string, unknown>;

export interface Tool {
  name: string;
  description: string;
  inputSchema: Json;
  run: (o: Oculon, a: Json) => Promise<unknown> | unknown;
}

const str = (d: string) => ({ type: 'string', description: d });
const num = (d: string) => ({ type: 'number', description: d });
const schema = (props: Json = {}, required: string[] = []) => ({ type: 'object', properties: props, required, additionalProperties: false });

/**
 * Checks tool arguments against the tool's input schema before running it. A misspelled argument used
 * to be dropped silently, so a scam check called with `text` instead of `message` ran on nothing and
 * answered "no strong signs": the agent got a confident wrong answer instead of an error it can fix.
 * Numeric strings are accepted for number fields and converted in place. Returns a message, or null.
 */
export function checkArgs(inputSchema: Json, args: Json): string | null {
  const props = (inputSchema.properties ?? {}) as Record<string, Json>;
  const required = (inputSchema.required ?? []) as string[];
  const allowed = Object.keys(props);
  if (inputSchema.additionalProperties === false) {
    const unknown = Object.keys(args).filter((k) => !(k in props));
    if (unknown.length) return `unknown argument${unknown.length > 1 ? 's' : ''} ${unknown.map((k) => `"${k}"`).join(', ')}; this tool takes ${allowed.length ? allowed.map((k) => `"${k}"`).join(', ') : 'no arguments'}`;
  }
  for (const k of required) {
    const v = args[k];
    if (v === undefined || v === null || (typeof v === 'string' && !v.trim())) return `missing required argument "${k}"`;
  }
  for (const [k, v] of Object.entries(args)) {
    const p = props[k];
    if (!p || v === undefined || v === null) continue;
    if (p.type === 'string' && typeof v !== 'string') return `argument "${k}" must be a string`;
    if (p.type === 'number' || p.type === 'integer') {
      const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
      if (typeof n !== 'number' || !Number.isFinite(n)) return `argument "${k}" must be a number`;
      args[k] = n;
    }
    if (p.type === 'boolean' && typeof v !== 'boolean') return `argument "${k}" must be true or false`;
    if (Array.isArray(p.enum) && !p.enum.includes(v)) return `argument "${k}" must be one of ${(p.enum as unknown[]).join(', ')}`;
  }
  return null;
}

/** Module results go out as result + signals + a compact provenance summary (full per-request provenance is noisy). */
function compact(r: ModuleResult<unknown>) {
  return { module: r.module, input: r.input, generatedAt: r.generatedAt, result: r.result, signals: r.signals, provenance: summarizeProvenance(r.provenance) };
}

export const TOOLS: Tool[] = [
  {
    name: 'oculon_radar',
    description:
      'Global anomaly radar. Finds what the world is suddenly paying attention to right now (Wikipedia readership spikes, Hacker News traction, Polymarket swings, strong earthquakes, severe natural events) and fuses items about the same subject into corroborated signals with evidence.',
    inputSchema: schema(),
    run: async (o) => compact(await o.radar()),
  },
  {
    name: 'oculon_footprint',
    description: 'Pre-release footprints of a domain: hostnames that newly appeared in Certificate Transparency logs, pages newly archived by the Wayback Machine, and newly created public GitHub repos. Good for spotting unannounced products.',
    inputSchema: schema({ domain: str('Domain, e.g. openai.com'), days: num('Look-back window in days (default 30)'), github_org: str('GitHub org to check (default: first label of the domain)') }, ['domain']),
    run: async (o, a) => compact(await o.footprint(String(a.domain), { ...(a.days ? { days: Number(a.days) } : {}), ...(a.github_org ? { org: String(a.github_org) } : {}) })),
  },
  {
    name: 'oculon_hype',
    description: 'Hype-cycle phase of a topic (DORMANT, EMERGING, RISING, PEAK, COOLING, STEADY) from 8 weeks of Wikipedia readers, Hacker News stories, global news share (GDELT), arXiv papers and new GitHub repos.',
    inputSchema: schema({ topic: str('Topic, e.g. "ai agent"') }, ['topic']),
    run: async (o, a) => compact(await o.hype(String(a.topic))),
  },
  {
    name: 'oculon_aircraft',
    description: 'Track one aircraft by registration (e.g. N628TS) or ICAO hex: type, registered owner, live position from ADS-B, nearest airport, and movement since the previous check.',
    inputSchema: schema({ query: str('Registration or 6-character ICAO hex') }, ['query']),
    run: async (o, a) => compact(await o.aircraft(String(a.query))),
  },
  {
    name: 'oculon_military_air',
    description: 'Worldwide military air traffic from open ADS-B data, grouped by region, with notable roles (tanker, AWACS, ISR, bomber, maritime patrol) and surges versus the region history.',
    inputSchema: schema(),
    run: async (o) => compact(await o.military()),
  },
  {
    name: 'oculon_dossier',
    description: 'Dossier on a company, person or project: Wikipedia profile and readership spike, Hacker News stories, news, related Polymarket markets, new GitHub repos, SEC filings (if enabled), merged into one timeline with a fused signal.',
    inputSchema: schema({ name: str('Entity name, e.g. Nvidia'), github: str('GitHub org/user to check (default: name without spaces)') }, ['name']),
    run: async (o, a) => compact(await o.dossier(String(a.name), a.github ? { github: String(a.github) } : {})),
  },
  {
    name: 'oculon_natural_events',
    description: 'Open natural events from NASA EONET (tropical cyclones, wildfires, volcanoes, floods, icebergs) with a severity score.',
    inputSchema: schema({ days: num('Events updated in the last N days (default 7)') }),
    run: async (o, a) => compact(await o.naturalEvents(a.days ? Number(a.days) : undefined)),
  },
  {
    name: 'oculon_night_lights',
    description: 'Night-time lights of a place from NASA VIIRS satellite data: recent nights versus a baseline month. A sharp drop can indicate blackout, conflict or evacuation; a rise can indicate new activity.',
    inputSchema: schema({ place: str('Place name, e.g. "Gaza Strip" or "Kyiv"') }, ['place']),
    run: async (o, a) => compact(await o.nightLights(String(a.place))),
  },
  {
    name: 'oculon_satellite_image',
    description: 'True-color satellite image (NASA MODIS, about 250 m) of a place for a date. Returns the image.',
    inputSchema: schema({ place: str('Place name'), date: str('YYYY-MM-DD (default: yesterday)') }, ['place']),
    run: async (o, a) => {
      const r = await o.satelliteImage(String(a.place), a.date ? String(a.date) : undefined);
      return { __image: r.result.file, meta: { place: r.result.place.name, date: r.result.date, file: r.result.file } };
    },
  },
  {
    name: 'oculon_sentinel_image',
    description: 'Sharp satellite image (Copernicus Sentinel-2, 10 m per pixel; or Sentinel-1 radar that sees through clouds) of a place, least cloudy pass in the window ending on the date. Returns the image.',
    inputSchema: schema({ place: str('Place name'), date: str('YYYY-MM-DD window end (default today)'), radar: { type: 'boolean', description: 'Use Sentinel-1 radar instead of optical' } }, ['place']),
    run: async (o, a) => {
      const r = await o.sentinel(String(a.place), { ...(a.date ? { date: String(a.date) } : {}), kind: a.radar === true ? 'radar' : 'optical' });
      const s = r.result.shots[0]!;
      return { __image: s.file, meta: { place: s.place.name, window: `${s.from} to ${s.to}`, kind: s.kind, file: s.file } };
    },
  },
  {
    name: 'oculon_forecast',
    description: 'Record a probability forecast for the first outcome of an open Polymarket market. The market price at that moment is stored as the baseline, and the forecast is hashed for later proof.',
    inputSchema: schema({ market_slug: str('Polymarket market slug'), probability: num('Probability between 0 and 1 (exclusive)'), rationale: str('Why') }, ['market_slug', 'probability']),
    run: async (o, a) => compact(await o.forecast(String(a.market_slug), Number(a.probability), a.rationale ? String(a.rationale) : '')),
  },
  {
    name: 'oculon_auto_forecast',
    description: 'Make automatic forecasts on Polymarket markets whose 24h swing is corroborated by another independent source (documented momentum rule).',
    inputSchema: schema(),
    run: async (o) => compact(await o.autoForecast()),
  },
  {
    name: 'oculon_resolve_forecasts',
    description: 'Check open forecasts against Polymarket and score the resolved ones (Brier score versus the market price at forecast time).',
    inputSchema: schema(),
    run: async (o) => compact(await o.resolveForecasts()),
  },
  {
    name: 'oculon_scoreboard',
    description: 'Forecast track record: counts, Brier scores of the model and of the market, and skill versus the market.',
    inputSchema: schema(),
    run: (o) => o.scoreboard(),
  },
  {
    name: 'oculon_stamp_proofs',
    description: 'Timestamp all not-yet-stamped forecasts on Bitcoin via OpenTimestamps (Merkle batch, free).',
    inputSchema: schema(),
    run: async (o) => compact(await o.stampProofs()),
  },
  {
    name: 'oculon_verify_proof',
    description: 'Verify a forecast proof: recompute its hash, check the Merkle path, and check the Bitcoin attestation against the block merkle root. Returns VERIFIED, PENDING, NOT_STAMPED, TAMPERED or ERROR.',
    inputSchema: schema({ prediction_id: str('Forecast id, e.g. raven-2538036424ba') }, ['prediction_id']),
    run: async (o, a) => compact(await o.verifyProof(String(a.prediction_id))),
  },
  {
    name: 'oculon_wallet',
    description: 'On-chain wallet intelligence for an EVM (0x...) or Solana address: portfolio value and top holdings, first transaction and age, recent transactions, risk labels (GoPlus, Webacy), and balance on Robinhood Chain.',
    inputSchema: schema({ address: str('Wallet address') }, ['address']),
    run: async (o, a) => compact(await o.wallet(String(a.address))),
  },
  {
    name: 'oculon_token',
    description: 'Token contract check: honeypot and owner-power flags, buy/sell tax and holders (GoPlus), DEX pairs and liquidity (DexScreener), price and market cap (CoinGecko). Returns DANGER, CAUTION, OK or UNKNOWN with reasons.',
    inputSchema: schema({ address: str('Token contract address (0x...)'), chain: { type: 'string', enum: ['eth', 'base', 'arbitrum', 'bsc', 'polygon', 'robinhood'], description: 'Chain (default eth)' } }, ['address']),
    run: async (o, a) => compact(await o.token(String(a.address), a.chain ? String(a.chain) : 'eth')),
  },
  {
    name: 'oculon_ships',
    description: 'Live vessels around a port or sea area from AIS (aisstream.io), listening for a number of seconds: totals, moving vs anchored/moored, vessel types (cargo, tanker, military...), names. Coverage depends on community receivers; an empty result says so.',
    inputSchema: schema({ place: str('Port or sea area, e.g. "Port of Rotterdam" or "Singapore Strait"'), seconds: num('Listening window, 10-120 (default 30)') }, ['place']),
    run: async (o, a) => compact(await o.ships(String(a.place), a.seconds ? Number(a.seconds) : 30)),
  },
  {
    name: 'oculon_ship',
    description: 'Follow one ship by its 9-digit MMSI and return its latest AIS position, speed and status if it reports within the window.',
    inputSchema: schema({ mmsi: str('9-digit MMSI'), seconds: num('Listening window, 10-180 (default 60)') }, ['mmsi']),
    run: async (o, a) => compact(await o.ship(String(a.mmsi), a.seconds ? Number(a.seconds) : 60)),
  },
  {
    name: 'oculon_robinhood',
    description: 'Robinhood Chain (id 4663) right now: chain activity, trending pools and pools created in the last hours, each with risk flags (thin liquidity, buys without sells, sudden dumps).',
    inputSchema: schema(),
    run: async (o) => compact(await o.robinhood()),
  },
  {
    name: 'oculon_robinhood_token',
    description: 'Risk read on a Robinhood Chain token: contract verification, top-10 holder concentration, holders, and pool behavior. Returns DANGER, CAUTION, OK or UNKNOWN with reasons.',
    inputSchema: schema({ address: str('Token address (0x...)') }, ['address']),
    run: async (o, a) => compact(await o.robinhoodToken(String(a.address))),
  },
  {
    name: 'oculon_robinhood_deployer',
    description: 'Robinhood Chain deployer reputation: from a token or deployer address, find every token that wallet launched (directly or through a launchpad) and how many are dead now. Flags serial launchers.',
    inputSchema: schema({ address: str('Token or deployer address (0x...)') }, ['address']),
    run: async (o, a) => compact(await o.robinhoodDeployer(String(a.address))),
  },
  {
    name: 'oculon_space_weather',
    description: 'Current space weather from NOAA SWPC: planetary K index, geomagnetic storm level (G1-G5) and the strongest solar flare of the last 7 days.',
    inputSchema: schema(),
    run: async (o) => compact(await o.spaceWeather()),
  },
  {
    name: 'oculon_air_quality',
    description: 'Latest PM2.5 air quality from monitoring stations near a place (OpenAQ), with the US EPA category.',
    inputSchema: schema({ place: str('Place name, e.g. "New Delhi"') }, ['place']),
    run: async (o, a) => compact(await o.airQuality(String(a.place))),
  },
  {
    name: 'oculon_url_check',
    description: 'Is a link dangerous? Checks Google Safe Browsing, URLhaus (abuse.ch), urlscan.io scan history, domain age and registrar (RDAP), and warning signs in the URL itself (brand names on other domains, punycode, risky TLDs). Returns a verdict (malicious, suspicious, no known threats), a 0-100 risk and the reasons.',
    inputSchema: schema({ url: str('The link or domain, e.g. "https://paypa1-login.top/verify"') }, ['url']),
    run: async (o, a) => compact(await o.urlCheck(String(a.url))),
  },
  {
    name: 'oculon_audit',
    description: 'Dependency audit for developers. Pass the text of a package.json or requirements.txt, or items like "npm:express@4.17.1 pypi:requests==2.19.0". For each package: known vulnerabilities with CVSS, deprecation, last release, versions behind, OpenSSF Scorecard and maintenance, license; plus a 0-100 risk. Source: deps.dev.',
    inputSchema: schema({ manifest: str('package.json or requirements.txt contents, or "npm:name@version" items'), max: num('Maximum packages to check (default 60, up to 150)') }, ['manifest']),
    run: async (o, a) => compact(await o.audit(String(a.manifest), a.max ? { max: Number(a.max) } : {})),
  },
  {
    name: 'oculon_fact_check',
    description: 'Fact check a claim, or the main claim of a news link. Finds published fact checks (Google Fact Check Tools: Snopes, AFP, PolitiFact, Full Fact and others) and current reporting, then gives a verdict (true, mostly true, mixed, misleading, false, unverified) with a confidence and a summary that cites the numbered sources.',
    inputSchema: schema({ claim: str('The claim, or a URL of an article') }, ['claim']),
    run: async (o, a) => compact(await o.factCheck(String(a.claim))),
  },
  {
    name: 'oculon_travel',
    description: 'Travel and place risk brief for the coming week: US State Department and UK FCDO advice, 7-day weather warnings (storms, heavy rain, gusts, heat, cold, UV), PM2.5 air quality, WHO disease outbreak news, GDACS disaster alerts, nearby earthquakes, satellite heat detections and confirmed internet outages. Returns a level (low, moderate, high, severe) with the reasons.',
    inputSchema: schema({ place: str('City, region or country, e.g. "Lisbon"') }, ['place']),
    run: async (o, a) => compact(await o.travel(String(a.place))),
  },
  {
    name: 'oculon_scam_check',
    description: 'Is this message a scam? Paste an SMS, email or chat message. Every link is checked (Safe Browsing, URLhaus, urlscan.io, domain age, look-alikes), the sender domain is compared with any brand it mentions, and known scam patterns are matched (parcel fees, account locked, one-time codes, gift cards or crypto, "hi mum" new number, prizes, job and investment promises). Returns likely scam, suspicious or no strong signs, a 0-100 risk, the reasons and what to do.',
    inputSchema: schema({ message: str('The full text of the message, including the sender line if there is one') }, ['message']),
    run: async (o, a) => compact(await o.scamCheck(String(a.message))),
  },
  {
    name: 'oculon_recall',
    description: 'Is this car or product recalled? Pass a 17-character VIN, "year make model" (e.g. "2018 Honda Accord"), or a product name ("stroller", "peanut butter"). Vehicles: NHTSA safety recalls with do-not-drive and park-outside warnings. Products: CPSC consumer recalls and FDA food, drug and device enforcement reports.',
    inputSchema: schema({ query: str('VIN, "year make model", or product name') }, ['query']),
    run: async (o, a) => compact(await o.recall(String(a.query))),
  },
  {
    name: 'oculon_email_security',
    description: 'Can someone send email that looks like it comes from this domain? Checks SPF, DMARC, DKIM, MTA-STS, TLS reporting, BIMI, CAA and DNSSEC from public DNS, and returns a verdict (spoofable, partly protected, protected), a 0-100 score and the fixes in order.',
    inputSchema: schema({ domain: str('Domain or email address, e.g. "example.com"') }, ['domain']),
    run: async (o, a) => compact(await o.emailSecurity(String(a.domain))),
  },
  {
    name: 'oculon_ip_check',
    description: 'Who runs this IP address, and is it known for abuse? Pass an IPv4 or IPv6 address, or a domain (its first address is checked). Returns network (ASN, owner, type), location, flags (Tor exit, proxy, hosting, internet scanner, known benign service), AbuseIPDB reports, GreyNoise scanner status, AlienVault OTX threat reports, VirusTotal engine verdicts, ThreatFox malware infrastructure, Spamhaus DROP listing and open ports, with a verdict (malicious, suspicious, no known abuse), a 0-100 risk and the reasons.',
    inputSchema: schema({ ip: str('IP address or domain, e.g. "185.220.101.1"') }, ['ip']),
    run: async (o, a) => compact(await o.ipCheck(String(a.ip))),
  },
  {
    name: 'oculon_hash_check',
    description: 'Is this file known malware, a known good file, or unknown? Pass an MD5, SHA-1 or SHA-256 hash. Checks CIRCL hashlookup (NIST NSRL and other known-software sets), MalwareBazaar, ThreatFox, AlienVault OTX and VirusTotal, and returns a verdict, the malware family when known, the reasons and what to do.',
    inputSchema: schema({ hash: str('MD5, SHA-1 or SHA-256 in hex') }, ['hash']),
    run: async (o, a) => compact(await o.hashCheck(String(a.hash))),
  },
  {
    name: 'oculon_ransomware',
    description: 'Ransomware leak-site claims collected by ransomware.live. Leave query empty for the newest claims, or pass a two-letter country code ("DE"), a sector ("Healthcare", "Manufacturing") or a company name or domain. Returns victims with group, country, sector and dates, plus counts by group, country and sector. These are claims by criminals and can be wrong.',
    inputSchema: schema({ query: str('Optional: country code, sector, company or domain') }, []),
    run: async (o, a) => compact(await o.ransomware(a.query ? String(a.query) : '')),
  },
  {
    name: 'oculon_company_lookup',
    description: 'Is this company or supplier real? Pass an EU VAT number (checked live in the European Commission VIES service: valid or not, registered name and address), a 20-character LEI, or a company name (Global LEI Index: legal name, registered address, status, registration number, ultimate parent). Useful before paying an invoice from a new supplier.',
    inputSchema: schema({ query: str('Company name, LEI, or EU VAT number such as "NL004495445B01"') }, ['query']),
    run: async (o, a) => compact(await o.companyCheck(String(a.query))),
  },
  {
    name: 'oculon_password_check',
    description: 'Has this password appeared in known data breaches (Have I Been Pwned Pwned Passwords)? Only the first 5 characters of its SHA-1 hash are sent; the match is done locally and the password is never stored. Pass the password, or "sha1:<40 hex>" if you already have the hash. Local only: this tool is not offered on the remote server.',
    inputSchema: schema({ password: str('The password, or "sha1:<hash>"') }, ['password']),
    run: async (o, a) => compact(await o.passwordCheck(String(a.password))),
  },
  {
    name: 'oculon_breaches',
    description: 'Data breaches from Have I Been Pwned: leave domain empty for the newest breaches, or pass a domain or company name for all of its breaches, with date, accounts affected and the kinds of data exposed.',
    inputSchema: schema({ domain: str('Optional: domain or company name, e.g. "adobe.com"') }, []),
    run: async (o, a) => compact(await o.breaches(a.domain ? String(a.domain) : '')),
  },
  {
    name: 'oculon_phone_check',
    description: 'Who is behind this phone number? Pass it in international format (+44 20 7946 0958), or a national number with country. Returns country, line type (mobile, landline, VoIP, premium rate), carrier and location when known, and warnings for premium-rate numbers, UK 070 personal numbers and the Caribbean "one ring" callback-scam area codes. Never looks up the owner.',
    inputSchema: schema({ number: str('Phone number'), country: str('ISO country code for a national number, e.g. "US"') }, ['number']),
    run: async (o, a) => compact(await o.phoneCheck(String(a.number), a.country ? { country: String(a.country) } : {})),
  },
  {
    name: 'oculon_satellites',
    description: 'Satellites from CelesTrak. Leave query empty for everything launched in the last 30 days, grouped by launch. Or pass a satellite name ("ISS", "starlink-1007") or NORAD catalog number for its orbit (perigee, apogee, period, inclination, regime), owner, launch date and status.',
    inputSchema: schema({ query: str('Optional: satellite name or NORAD number') }, []),
    run: async (o, a) => compact(await o.satellites(a.query ? String(a.query) : '')),
  },
  {
    name: 'oculon_papers',
    description: 'Research brief on a topic: the most cited papers of recent years, the newest relevant ones, papers per year (is the field growing?), PubMed counts for medical topics, and a short overview that cites the numbered papers. Sources: OpenAlex, PubMed, Semantic Scholar.',
    inputSchema: schema({ topic: str('Research topic, e.g. "solid-state battery"'), years: num('Look-back window in years for most cited (default 3)') }, ['topic']),
    run: async (o, a) => compact(await o.papers(String(a.topic), a.years ? { years: Number(a.years) } : {})),
  },
  {
    name: 'oculon_country',
    description: 'Country brief: GDP, growth, GDP per person, inflation, unemployment and population (World Bank), IMF growth and inflation outlook, head of state and government, capital, currency and its rate to the US dollar, US and UK travel advice, internet outages, disaster alerts and the latest headlines.',
    inputSchema: schema({ country: str('Country name or ISO code, e.g. "Argentina"') }, ['country']),
    run: async (o, a) => compact(await o.country(String(a.country))),
  },
  {
    name: 'oculon_airport',
    description: 'Is an airport running normally? Current METAR and TAF (flight category, wind, visibility, ceiling), FAA ground stops, delay programs and closures for US airports, and aircraft squawking an emergency within 150 km. Accepts IATA (JFK), ICAO (EGLL) or a name.',
    inputSchema: schema({ airport: str('IATA or ICAO code, or airport name') }, ['airport']),
    run: async (o, a) => compact(await o.airport(String(a.airport))),
  },
  {
    name: 'oculon_monitor',
    description: 'Create a monitor from a plain-language request, e.g. "tell me when there is an internet outage in Iran", "watch critical CVEs for nginx", "earthquakes above 6 near Tokyo", "news about OpenAI", "travel risk changes for Bangkok". It becomes a watch rule that is re-checked on a schedule and reports only changes, with evidence. Set dry_run to see the rule without saving it.',
    inputSchema: schema({ request: str('What to watch, in plain language'), dry_run: { type: 'boolean', description: 'Only show how the request would be read' } }, ['request']),
    run: async (o, a) => (a.dry_run ? o.monitorParse(String(a.request)) : o.monitor(String(a.request))),
  },
  {
    name: 'oculon_web_search',
    description: 'Search the web (Tavily, Exa fallback). Returns titles, URLs, snippets and dates.',
    inputSchema: schema({ query: str('Search query'), max: num('Max results (default 6)') }, ['query']),
    run: async (o, a) => {
      const r = await o.webSearch(String(a.query), a.max ? Number(a.max) : 6);
      return { results: r.data, source: r.prov.source, status: r.prov.status };
    },
  },
  {
    name: 'oculon_read_page',
    description: 'Fetch a web page and return its readable text (Jina Reader, Firecrawl fallback), capped at about 6000 characters.',
    inputSchema: schema({ url: str('http(s) URL') }, ['url']),
    run: async (o, a) => {
      const r = await o.readPage(String(a.url));
      return { text: r.data, source: r.prov.source, status: r.prov.status, ...(r.prov.note ? { note: r.prov.note } : {}) };
    },
  },
  {
    name: 'oculon_ask',
    description: 'Ask Oculon a question in plain language. An agent picks and calls Oculon tools (radar, dossiers, aircraft, satellites, on-chain, web) and answers with sources.',
    inputSchema: schema({ question: str('The question') }, ['question']),
    run: async (o, a) => o.ask(String(a.question)),
  },
  {
    name: 'oculon_case_new',
    description: 'Open a case file: a deeper OSINT investigation of a question (about 1-3 minutes). Returns an answer with confidence, sourced findings, a timeline, entities and open questions. Citations are verified against what the tools actually returned.',
    inputSchema: schema({ question: str('What to investigate') }, ['question']),
    run: async (o, a) => {
      const r = await o.caseInvestigate({ question: String(a.question) });
      return { id: r.case.id, report: r.case.report, markdown: r.case.markdown };
    },
  },
  {
    name: 'oculon_case_list',
    description: 'List case files with their confidence, number of findings and whether they are watched.',
    inputSchema: schema(),
    run: async (o) => (await o.caseList()).map((k) => ({ id: k.id, question: k.question, confidence: k.report?.confidence ?? null, findings: k.report?.findings.length ?? 0, runs: k.runs, watch: k.watch, updatedAt: k.updatedAt })),
  },
  {
    name: 'oculon_case_show',
    description: 'Show one case file in full.',
    inputSchema: schema({ id: num('Case id') }, ['id']),
    run: async (o, a) => o.caseGet(Number(a.id)),
  },
  {
    name: 'oculon_narratives',
    description: 'News narratives tracked across days (storylines such as a company crisis or an IPO), with stories per day and phase. Set run=true to first group the latest headlines.',
    inputSchema: schema({ run: { type: 'boolean', description: 'Group new headlines first (uses an LLM)' } }),
    run: async (o, a) => (a.run === true ? compact(await o.narrativesRun()) : (await o.narratives(14)).map((n) => ({ name: n.name, daily: n.daily, total: n.total, phase: n.phase, latest: n.latest.slice(0, 3) }))),
  },
  {
    name: 'oculon_health',
    description: 'Company early-warning score 0-100 from hiring momentum, new federal lawsuits, insider selling, news tone, GitHub shipping and the stock move, with every component explained and a 30-day history.',
    inputSchema: schema({ company: str('Company name') }, ['company']),
    run: async (o, a) => {
      const r = await o.health(String(a.company));
      return { result: r.result, signals: r.signals.filter((s) => s.module === 'health') };
    },
  },
  {
    name: 'oculon_impact',
    description: 'People exposed to current M6+ earthquakes and severe storms (Wikidata settlement populations within the affected radius, plus night-light change when enough nights have passed). Give a place to estimate exposure around it instead.',
    inputSchema: schema({ place: str('Optional place'), radius_km: num('Radius around the place (default 50)') }),
    run: async (o, a) => compact(await o.impact(a.place ? String(a.place) : undefined, a.radius_km ? Number(a.radius_km) : 50)),
  },
  {
    name: 'oculon_contradictions',
    description: 'Read several independent articles on a topic and list factual claims that conflict between them (numbers, dates, names, denials), each side with its source URL.',
    inputSchema: schema({ topic: str('Topic, e.g. "Anthropic IPO"') }, ['topic']),
    run: async (o, a) => compact(await o.contradictions(String(a.topic))),
  },
  {
    name: 'oculon_sanctions',
    description: 'Screen against the US OFAC sanctions (SDN) list: a wallet address (also checks whether it transacted directly with a listed address), a vessel IMO number, or the exact name of a company, person or vessel. Returns SANCTIONED, EXPOSED or CLEAR.',
    inputSchema: schema({ query: str('Wallet address, "IMO 1234567", or exact name') }, ['query']),
    run: async (o, a) => compact(await o.sanctions(String(a.query))),
  },
  {
    name: 'oculon_markets_crosscheck',
    description: 'Cross-check Polymarket against Kalshi and Manifold: an LLM confirms which markets ask exactly the same question, then gaps between venues are listed. A big gap means one crowd is wrong or knows something first.',
    inputSchema: schema({ min_gap_pp: num('Minimum gap in percentage points to flag (default 15)') }),
    run: async (o, a) => compact(await o.markets(a.min_gap_pp ? { minGapPp: Number(a.min_gap_pp) } : {})),
  },
  {
    name: 'oculon_launches',
    description: "Launch radar for a company: new Hugging Face models/datasets/Spaces, new iOS apps and app updates, new npm packages under its scope, and (with a domain) new hostnames, pages and repos.",
    inputSchema: schema({ company: str('Company name, e.g. OpenAI'), domain: str('Its domain, e.g. openai.com (optional)'), org: str('Org handle on GitHub/Hugging Face/npm (default: company)'), days: num('Look-back window (default 30)') }, ['company']),
    run: async (o, a) => compact(await o.launches(String(a.company), { ...(a.domain ? { domain: String(a.domain) } : {}), ...(a.org ? { org: String(a.org) } : {}), ...(a.days ? { days: Number(a.days) } : {}) })),
  },
  {
    name: 'oculon_rewind',
    description: 'Time machine: what Oculon would have seen on a past date. Wikipedia spikes measured against the weeks before, top Hacker News stories, strong earthquakes and that day\'s Guardian headlines, fused across sources.',
    inputSchema: schema({ date: str('YYYY-MM-DD, at least two days ago') }, ['date']),
    run: async (o, a) => compact(await o.rewind(String(a.date))),
  },
  {
    name: 'oculon_fence_add',
    description: 'Add a geofence around a place. Each check reports what is NEW inside it: military aircraft, military vessels, earthquakes, natural events.',
    inputSchema: schema({ name: str('Fence name'), place: str('Center place, e.g. "Strait of Hormuz"'), radius_km: num('Half-width in km (default 100)'), kinds: { type: 'array', items: { type: 'string', enum: ['air', 'sea', 'quake', 'events'] }, description: 'What to watch (default all)' } }, ['name', 'place']),
    run: async (o, a) => o.fenceAddAround(String(a.name), String(a.place), a.radius_km ? Number(a.radius_km) : 100, Array.isArray(a.kinds) ? a.kinds.map(String) : undefined),
  },
  {
    name: 'oculon_fence_list',
    description: 'List geofences with their boxes and what each watches.',
    inputSchema: schema(),
    run: (o) => o.fenceList().map((f) => ({ id: f.id, name: f.name, box: [f.south, f.west, f.north, f.east], kinds: f.kinds, lastRun: f.lastRun })),
  },
  {
    name: 'oculon_fence_check',
    description: 'Check every geofence now and report what is new inside each since the previous check.',
    inputSchema: schema(),
    run: async (o) => {
      const r = await o.fenceCheck();
      return { checks: r.checks.map((c) => ({ id: c.fence.id, name: c.fence.name, baseline: c.baseline, changes: c.changes, counts: c.counts })), signals: r.signals };
    },
  },
  {
    name: 'oculon_watch_list',
    description: 'List the watchlist: targets Oculon re-checks for changes (companies, domains, wallets, tokens, planes, topics, night lights, air quality).',
    inputSchema: schema(),
    run: (o) => o.watchList(),
  },
  {
    name: 'oculon_watch_add',
    description: `Add a watchlist target. Kinds: company, domain, plane, topic, lights (place), air (place), port (place, anchored-vessel queue), news (keyword), outage (country), cve (vendor or product), quake ("place|min magnitude"), hazard (country or storm name), url, package ("npm:name" or "pypi:name"), travel (place)${onchainEnabled() ? ', wallet, token (address or address@chain)' : ''}. For plain-language requests use oculon_monitor.`,
    inputSchema: schema({ kind: { type: 'string', enum: availableKinds() }, target: str('What to watch'), label: str('Optional display name') }, ['kind', 'target']),
    run: (o, a) => o.watchAdd(String(a.kind), String(a.target), a.label ? String(a.label) : undefined),
  },
  {
    name: 'oculon_watch_run',
    description: 'Re-check every watchlist target now and report only what changed since the previous check. The first check of a target records a baseline.',
    inputSchema: schema(),
    run: async (o) => {
      const r = await o.watchRun();
      return { runs: r.runs.map((x) => ({ id: x.item.id, kind: x.item.kind, target: x.item.target, baseline: x.baseline, changes: x.changes, ...(x.error ? { error: x.error } : {}) })), signals: r.signals };
    },
  },
  {
    name: 'oculon_brief',
    description: "Today's brief: the strongest signals of the last 24 hours and watchlist changes, summarized.",
    inputSchema: schema({ refresh: { type: 'boolean', description: 'Rewrite even if a brief exists for today' } }),
    run: (o, a) => o.brief({ refresh: a.refresh === true }),
  },
  {
    name: 'oculon_signals',
    description: 'Most recent signals produced by any Oculon module, with scores and evidence.',
    inputSchema: schema({ limit: num('Max signals (default 30)') }),
    run: (o, a) => o.signals(a.limit ? Number(a.limit) : 30),
  },
  {
    name: 'oculon_entity',
    description: 'Look up an entity in the Oculon graph and its neighbors. Ids look like "domain:openai.com", "org:nvidia", "aircraft:a835af", "company:falcon landing llc".',
    inputSchema: schema({ id: str('Entity id') }, ['id']),
    run: (o, a) => o.entity(String(a.id)),
  },
  {
    name: 'oculon_connect',
    description: 'How two things are connected in the Oculon graph: shortest path of typed edges between them (names or ids). Duplicates such as org:nvidia and company:nvidia are merged first.',
    inputSchema: schema({ a: str('First thing, e.g. "Nvidia"'), b: str('Second thing, e.g. "Jensen Huang"'), depth: num('Max hops (default 6)') }, ['a', 'b']),
    run: (o, a) => o.connect(String(a.a), String(a.b), a.depth ? Number(a.depth) : 6),
  },
  {
    name: 'oculon_social_pulse',
    description: 'What people are posting about a subject right now on X, Reddit, TikTok (paid Apify, small daily budget) and Bluesky: post counts per platform, pace over the last day when measurable, most engaged and latest posts with links.',
    inputSchema: schema({ query: str('Subject, e.g. "Nvidia"') }, ['query']),
    run: (o, a) => o.pulse(String(a.query)),
  },
  {
    name: 'oculon_podcast',
    description: 'Find recent podcast episodes about a subject and transcribe the newest English one (Deepgram, paid per minute with a daily budget): machine summary, topics, and timestamped passages that mention the subject.',
    inputSchema: schema({ subject: str('Subject, e.g. "Nvidia"'), pick: num('Episode index from the list (optional)') }, ['subject']),
    run: (o, a) => o.podcast(String(a.subject), a.pick !== undefined ? Number(a.pick) : undefined),
  },
  {
    name: 'oculon_listen',
    description: 'Transcribe a public audio or video FILE URL (mp3, mp4, wav...; not a YouTube page) with Deepgram and return a machine summary, topics and timestamped passages that mention the subject.',
    inputSchema: schema({ url: str('Direct media file URL'), subject: str('What to look for (optional)') }, ['url']),
    run: (o, a) => o.listen(String(a.url), a.subject ? String(a.subject) : ''),
  },
  {
    name: 'oculon_exposure',
    description: "A domain's internet exposure: resolves its main hosts and known subdomains, then lists open ports, software and known CVEs per IP from Shodan InternetDB (free). CDN edges are marked.",
    inputSchema: schema({ domain: str('Domain, e.g. example.com') }, ['domain']),
    run: (o, a) => o.exposure(String(a.domain)),
  },
  {
    name: 'oculon_dark_ships',
    description: 'Vessels that deliberately switched off AIS near a place (port, strait, sea) in the last days, from Global Fishing Watch: where they went dark and reappeared, for how long. Coverage is strongest for fishing and carrier vessels.',
    inputSchema: schema({ place: str('Sea area, strait or port'), days: num('Window in days (default 30)') }, ['place']),
    run: (o, a) => o.darkShips(String(a.place), a.days ? Number(a.days) : 30),
  },
  {
    name: 'oculon_vessel',
    description: 'Vessel identity from a name, MMSI or IMO (Global Fishing Watch registry data): flag history, type, owners, earlier names, first and last AIS transmission, OFAC sanctions check on the IMO.',
    inputSchema: schema({ query: str('Vessel name, MMSI or IMO') }, ['query']),
    run: (o, a) => o.vessel(String(a.query)),
  },
  {
    name: 'oculon_fires',
    description: 'Active fires and thermal hotspots near a place in the last 1-5 days from NASA FIRMS (VIIRS satellites): clusters with detection count and fire radiative power. Catches wildfires, industrial fires and strikes on infrastructure.',
    inputSchema: schema({ place: str('Place name'), days: num('1 to 5 (default 2)') }, ['place']),
    run: (o, a) => o.fires(String(a.place), a.days ? Number(a.days) : 2),
  },
  {
    name: 'oculon_cloud_outages',
    description: 'Current outages on major internet platforms: official status pages of GitHub, Cloudflare, OpenAI, Anthropic, Discord, Reddit, Vercel, npm and others, plus AWS, Azure and Google Cloud incidents.',
    inputSchema: schema({}),
    run: (o) => o.cloud(),
  },
  {
    name: 'oculon_bgp',
    description:
      'BGP routing. "world": global BGP hijacks and route leaks (Cloudflare Radar) with DDoS target countries. Two-letter country code: visible IPv4/IPv6 prefixes per hour and change versus the median (shutdowns and cable cuts show as drops), plus incidents involving it. AS number: visibility, prefixes, neighbours and incidents. IP address: announcing network, RPKI validity, abuse contact, location.',
    inputSchema: schema({ resource: str('"world", a country code like PK, an AS number like AS15169, or an IP address'), days: num('Window in days for incidents (default 2)') }),
    run: (o, a) => o.bgp(a.resource ? String(a.resource) : 'world', a.days ? Number(a.days) : 2),
  },
  {
    name: 'oculon_vulns',
    description: 'Vulnerabilities newly exploited in the wild (CISA KEV) with EPSS odds and due dates, new critical CVEs (NVD) and critical package advisories (GitHub), optionally for one vendor.',
    inputSchema: schema({ days: num('Window in days (default 7)'), vendor: str('Vendor or product filter, e.g. Microsoft, Fortinet') }),
    run: (o, a) => o.vulns({ ...(a.days ? { days: Number(a.days) } : {}), ...(a.vendor ? { vendor: String(a.vendor) } : {}) }),
  },
  {
    name: 'oculon_cve',
    description: 'One CVE in depth: CVSS, CWE, affected products, EPSS exploitation probability and 30-day trend, CISA KEV status, affected packages with fixed versions (OSV, GitHub).',
    inputSchema: schema({ id: str('CVE id, e.g. CVE-2021-44228') }, ['id']),
    run: (o, a) => o.cve(String(a.id)),
  },
  {
    name: 'oculon_package_vulns',
    description: 'Known vulnerabilities of a software package (OSV.dev), optionally for one version, flagged when exploited in the wild.',
    inputSchema: schema({ ecosystem: str('npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet...'), name: str('Package name'), version: str('Version (optional)') }, ['ecosystem', 'name']),
    run: (o, a) => o.packageVulns(String(a.ecosystem), String(a.name), a.version ? String(a.version) : undefined),
  },
  {
    name: 'oculon_regs',
    description: "US Federal Register: executive orders, final and proposed rules, notices and tomorrow's documents on public inspection, with effective dates and comment deadlines. Filter by text and agency.",
    inputSchema: schema({ query: str('Search text (optional)'), agency: str('Agency name or abbreviation, e.g. SEC, Commerce'), days: num('Window in days (default 7)') }),
    run: (o, a) => o.regs({ ...(a.query ? { query: String(a.query) } : {}), ...(a.agency ? { agency: String(a.agency) } : {}), ...(a.days ? { days: Number(a.days) } : {}) }),
  },
  {
    name: 'oculon_defi',
    description: 'DeFi risk radar (DefiLlama, alternative.me): protocol TVL crashes, stablecoin depegs and supply shocks, recent hacks, chain TVL moves, DEX volume and fee spikes, yield anomalies, crypto fear and greed.',
    inputSchema: schema(),
    run: (o) => o.defi(),
  },
  {
    name: 'oculon_protocol',
    description: 'One DeFi protocol in depth: TVL per chain, 1d-1y change, drawdown from its high, audits, oracles, hack history, funding rounds and DefiLlama warnings.',
    inputSchema: schema({ name: str('Protocol name or slug, e.g. aave') }, ['name']),
    run: (o, a) => o.protocol(String(a.name)),
  },
  {
    name: 'oculon_squawks',
    description: 'Aircraft squawking emergency transponder codes right now (adsb.lol): 7500 hijack, 7600 radio failure, 7700 general emergency, with position, registration and nearest airport.',
    inputSchema: schema(),
    run: (o) => o.squawks(),
  },
  {
    name: 'oculon_sec_search',
    description: 'SEC EDGAR full-text search across filings since 2001: which companies wrote a phrase (e.g. "cybersecurity incident", "going concern") in a window, with form, date and 8-K items.',
    inputSchema: schema({ query: str('Phrase or boolean query'), forms: str('Comma-separated forms, e.g. 8-K,10-K'), days: num('Window in days (default 30)') }, ['query']),
    run: (o, a) => o.filings(String(a.query), { ...(a.forms ? { forms: String(a.forms).split(',') } : {}), ...(a.days ? { days: Number(a.days) } : {}) }),
  },
  {
    name: 'oculon_sec_events',
    description: "A company's recent 8-K events decoded into plain English: material agreements, cybersecurity incidents, restructuring, restatements, CEO/CFO departures, bankruptcy.",
    inputSchema: schema({ company: str('Ticker or CIK'), days: num('Window in days (default 90)') }, ['company']),
    run: (o, a) => o.secEvents(String(a.company), a.days ? Number(a.days) : 90),
  },
  {
    name: 'oculon_blackout',
    description: 'Internet outages and shutdowns by country and network in the last days: Cloudflare Radar confirmed outages (with cause) and traffic anomalies, plus IODA outage scores per country.',
    inputSchema: schema({ days: num('Window in days (default 2, max 14)') }),
    run: (o, a) => o.blackout(a.days ? Number(a.days) : 2),
  },
  {
    name: 'oculon_hazards',
    description: 'Official orange and red disaster alerts from GDACS (UN/EU): earthquakes, cyclones, floods, volcanoes, droughts, wildfires, with severity and countries, plus tsunami bulletins and extreme US weather alerts.',
    inputSchema: schema({ days: num('Window in days (default 7)') }),
    // The bulletins hang off the result array and would be dropped by JSON, so they are returned beside it.
    run: async (o, a) => {
      const r = await o.hazards(a.days ? Number(a.days) : 7);
      return { ...r, result: { alerts: [...r.result], bulletins: r.result.bulletins ?? [] } };
    },
  },
  {
    name: 'oculon_calendar',
    description: 'Catalyst calendar for the next days: earnings (watched companies first, then the largest), key US macro releases, and high-volume prediction markets that close.',
    inputSchema: schema({ days: num('Window in days (default 14)') }),
    run: (o, a) => o.calendar(a.days ? Number(a.days) : 14),
  },
  {
    name: 'oculon_feedback_stats',
    description: 'Useful/Noise votes per module and how far each module alert bar has moved because of them.',
    inputSchema: schema({}),
    run: (o) => o.feedbackStats(),
  },
];

interface Request {
  jsonrpc: '2.0';
  id?: number | string | null;
  method: string;
  params?: Json;
}

/** Tools that change the shared watchlist, fences or plugins; not offered to anonymous remote clients. */
// Tools that change the shared watchlist, plus the password check: a password should never travel to a public server.
const REMOTE_HIDDEN = new Set(['oculon_watch_add', 'oculon_fence_add', 'oculon_watch_run', 'oculon_case_new', 'oculon_stamp_proofs', 'oculon_resolve_forecasts', 'oculon_auto_forecast', 'oculon_forecast', 'oculon_password_check']);

/** Tools this build offers: on-chain tools are left out unless OCULON_ONCHAIN=1. */
export function activeTools(): Tool[] {
  return onchainEnabled() ? TOOLS : TOOLS.filter((t) => !ONCHAIN_TOOLS.has(t.name));
}

export class McpServer {
  private oculon: Oculon | null = null;

  /**
   * `remote`: the server is reached over the internet by anyone (remote MCP). Tools that change what the whole
   * install watches are left out, and oculon_monitor only shows how a request would be read.
   */
  constructor(
    private readonly makeOculon: () => Oculon = () => new Oculon(),
    private readonly opts: { remote?: boolean } = {},
  ) {}

  private get o(): Oculon {
    return (this.oculon ??= this.makeOculon());
  }

  private pluginTools: Tool[] | null = null;

  /** Built-in tools plus one tool per installed plugin tool (`plugin_<plugin>_<tool>`), loaded once. */
  private async allTools(): Promise<Tool[]> {
    if (!this.pluginTools) {
      const { loadPlugins, pluginApi } = await import('./plugins.js');
      const { plugins } = await loadPlugins();
      this.pluginTools = plugins.flatMap((p) =>
        p.tools.map((t) => ({
          name: `plugin_${p.name}_${t.name}`.replace(/-/g, '_'),
          description: `[plugin ${p.name}] ${t.description}`,
          inputSchema: (t.inputSchema as Json) ?? schema(),
          run: (o: Oculon, a: Json) => t.run(pluginApi(o, p.name), a),
        })),
      );
    }
    const all = [...activeTools(), ...this.pluginTools];
    return this.opts.remote ? all.filter((t) => !REMOTE_HIDDEN.has(t.name)) : all;
  }

  /** Handle one JSON-RPC message; returns the response, or null for notifications. */
  async handle(msg: Request): Promise<Json | null> {
    const reply = (result: unknown) => ({ jsonrpc: '2.0', id: msg.id ?? null, result });
    const fail = (code: number, message: string) => ({ jsonrpc: '2.0', id: msg.id ?? null, error: { code, message } });
    const isNotification = msg.id === undefined || msg.id === null;

    switch (msg.method) {
      case 'initialize': {
        const asked = String(msg.params?.protocolVersion ?? '');
        return reply({
          protocolVersion: SUPPORTED.includes(asked) ? asked : SUPPORTED[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions:
            'Oculon is an OSINT engine. Every result includes provenance (LIVE/CACHED/UNAVAILABLE/ERROR per source). Report data as given; do not present ERROR or UNAVAILABLE sources as findings.',
        });
      }
      case 'ping':
        return reply({});
      case 'tools/list':
        return reply({ tools: (await this.allTools()).map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) });
      case 'tools/call': {
        const name = String(msg.params?.name ?? '');
        const tool = (await this.allTools()).find((t) => t.name === name);
        if (!tool) return fail(-32602, `unknown tool: ${name}`);
        const raw = msg.params?.arguments ?? {};
        if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return reply({ content: [{ type: 'text', text: 'Error: arguments must be a JSON object' }], isError: true });
        const bad = checkArgs(tool.inputSchema, raw as Json);
        if (bad) return reply({ content: [{ type: 'text', text: `Error: ${bad}` }], isError: true });
        try {
          const args = raw as Json;
          if (this.opts.remote && name === 'oculon_monitor') args.dry_run = true;
          const out = await tool.run(this.o, args);
          if (out && typeof out === 'object' && '__image' in out) {
            const { __image, meta } = out as { __image: string | null; meta: unknown };
            const content: Json[] = [{ type: 'text', text: JSON.stringify(meta) }];
            if (__image) content.unshift({ type: 'image', data: readFileSync(__image).toString('base64'), mimeType: 'image/png' });
            return reply({ content, isError: !__image });
          }
          return reply({ content: [{ type: 'text', text: JSON.stringify(out) }] });
        } catch (e) {
          return reply({ content: [{ type: 'text', text: `Error: ${(e as Error).message}` }], isError: true });
        }
      }
      default:
        if (isNotification) return null;
        return fail(-32601, `method not found: ${msg.method}`);
    }
  }

  close(): void {
    this.oculon?.close();
  }
}

/** Run on stdio. Logs go to stderr so stdout stays pure JSON-RPC. */
export function serveStdio(server = new McpServer()): void {
  const rl = createInterface({ input: process.stdin });
  const write = (m: Json) => process.stdout.write(`${JSON.stringify(m)}\n`);
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg: Request;
    try {
      msg = JSON.parse(line) as Request;
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
      return;
    }
    const res = await server.handle(msg);
    if (res) write(res);
  });
  rl.on('close', () => server.close());
}
