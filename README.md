# Oculon

**Open-source intelligence engine for the physical and digital world.** Oculon watches more than 50 public data sources (routing tables, exploit catalogs, transponders, satellites, ship trackers, registries and prediction markets), finds what is unusual, fuses observations about the same subject from independent sources into scored signals, and labels every result with where it came from and how fresh it is. An AI agent on top answers plain-language questions with sources.

[oculon.live](https://oculon.live) · [Documentation](https://oculon.live/docs) · [Privacy](https://oculon.live/privacy) · [Terms](https://oculon.live/terms)

[![CI](https://github.com/oculonlive/oculon/actions/workflows/ci.yml/badge.svg)](https://github.com/oculonlive/oculon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-00f0ff.svg)](LICENSE)
![Node 22.13+](https://img.shields.io/badge/node-%E2%89%A522.13-00f0ff.svg)
![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-00f0ff.svg)

It ships as a CLI, a TypeScript SDK, an MCP server for Claude and other agents (local, or remote at `https://mcp.oculon.live` with nothing to install), a web app and a Telegram bot, all over the same result objects. It has no runtime dependencies. About 20 sources work with no key; optional free-tier keys switch on the rest (see `.env.example`).

```sh
npx oculon radar
npx oculon ask "why is Nvidia in the news this week?"
```

## Highlights

- **Sourced by design.** Every answer names the sources it used and whether each one was live, cached or unavailable. Nothing is presented without provenance.
- **Cross-source signals.** When independent sources move on the same subject, Oculon fuses them into one scored signal with the evidence behind it, and storylines are tracked across days.
- **Measured, not claimed.** A time machine replays past days to calibrate the radar, a first-to-know check compares Oculon against media coverage, and forecasts are timestamped on Bitcoin so they cannot be edited later.
- **Built for agents.** 75 MCP tools, locally over stdio or remotely at `https://mcp.oculon.live`; the SDK and CLI return the same objects, and `--json` works on every command.
- **Everyday checks.** Is this message a scam? Is this link dangerous? Is this claim true? Is my car recalled? Can someone spoof my email domain? Are my dependencies safe? What should I know before I travel? Each answer names its sources, and any result can be shared as a link with a preview card.
- **Monitors in plain words.** "Tell me when there is an internet outage in Iran" becomes a rule that is re-checked on a schedule and reports only what changed, by email, in Telegram or in the app. Every visitor keeps their own monitors, with no account.
- **Everywhere people are.** A public Telegram bot ([@oculon_radar_bot](https://t.me/oculon_radar_bot)): forward it a suspicious message and it checks it. An OpenAPI spec at `/openapi.json` for ChatGPT Actions, n8n and Zapier.
- **Free to run.** Daily per-source budgets keep every free tier free, and the data lives in one local SQLite file.

## Contents

[What it does](#what-it-does) · [Install](#install) · [CLI](#cli) · [MCP server](#mcp-server) · [Remote MCP](#remote-mcp) · [SDK](#sdk) · [Web app](#dashboard-and-schedule) · [Telegram bot](#telegram-bot) · [Configuration](#configuration) · [Deploy](#deploy) · [How it works](#how-it-works) · [Limits](#limits) · [Development](#development)

## What it does

| Module | Command | What it does | Sources |
|---|---|---|---|
| Scam check | `oculon scam "<message>"` · Telegram: forward the message | Is this SMS, email or chat message a scam? Every link goes through the URL check, the sender is compared with any brand it names, and known scam patterns are matched in code (parcel fees, account locked, one-time codes, gift cards and crypto, "hi mum" new number asking for money, prizes, job and investment promises); a verdict, a 0-100 risk, the reasons and what to do | URL check sources, free-tier LLMs for the explanation |
| URL check | `oculon url <link>` | Is a link dangerous? A verdict (malicious, suspicious, no known threats), a 0-100 risk and the reasons: Safe Browsing and URLhaus matches, community tags on urlscan.io scans, domain age and registrar, and warning signs in the URL itself (a brand name on someone else's domain, punycode look-alikes, risky top-level domains, `@` tricks). Big platforms are not blamed for files their users upload | Google Safe Browsing, URLhaus (abuse.ch), urlscan.io, RDAP |
| Fact check | `oculon factcheck "<claim>"` or a news URL | Published fact checks about the claim (Snopes, AFP, PolitiFact, Full Fact and others) plus current reporting; an LLM weighs only that evidence and cites it by number, giving true, mostly true, mixed, misleading, false or unverified with a confidence. Without an LLM the published ratings decide | Google Fact Check Tools, Tavily or Exa, Jina Reader, free-tier LLMs |
| Audit | `oculon audit [package.json\|requirements.txt\|npm:name@ver ...]` | Dependency health for npm and PyPI: known vulnerabilities with CVSS, deprecation, years since the last release, major versions behind, OpenSSF Scorecard and its "Maintained" check, license; a 0-100 risk per package (dev dependencies weigh less) | deps.dev (Google Open Source Insights), OpenSSF Scorecard, OSV |
| Travel | `oculon travel <place>` | What a visitor should know for the coming week: US State Department level and UK FCDO advice, 7-day weather warnings (storms, heavy rain, strong gusts, heat, cold, UV), PM2.5, WHO disease outbreak news, orange and red disaster alerts, nearby strong earthquakes, satellite heat detections and confirmed internet outages; a level from low to severe | US State Department, UK FCDO, Open-Meteo, OpenAQ, WHO, GDACS, USGS, NASA FIRMS, Cloudflare Radar |
| Recall | `oculon recall <VIN\|"2018 Honda Accord"\|product>` | Is this car or product recalled? A VIN is decoded to make, model and year; vehicles get NHTSA safety recalls with do-not-drive and park-outside warnings; products get US consumer recalls and FDA food, drug and device enforcement reports from the last few years | NHTSA (vPIC and recalls), CPSC SaferProducts, openFDA |
| Email security | `oculon email <domain>` | Can someone send mail that looks like it comes from a domain? SPF (qualifier, DNS lookup count), DMARC (policy, coverage, reporting), DKIM on common selectors, MTA-STS, TLS reporting, BIMI, CAA and DNSSEC, a 0-100 score, a verdict (spoofable, partly protected, protected) and the fixes in order | Google Public DNS (DNS over HTTPS) |
| Papers | `oculon papers "<topic>"` | Research brief: the most cited papers of recent years among the most relevant, the newest relevant ones, papers per year (growing, steady or shrinking), PubMed counts for medical topics, and a short overview that cites the numbered papers | OpenAlex, PubMed, Semantic Scholar (optional key), free-tier LLMs |
| Country | `oculon country <name>` | One-page country brief: GDP, growth, GDP per person, inflation, unemployment and population, the IMF outlook for this year and next, head of state and government, capital, currency and its rate to the dollar, US and UK travel advice, internet outages, disaster alerts and the latest headlines | World Bank, IMF, Wikidata, open.er-api.com, US State Department, UK FCDO, Cloudflare Radar, GDACS, Guardian |
| Airport | `oculon airport <JFK\|EGLL\|name>` | Is an airport running normally? Current METAR and TAF (flight category, wind, visibility, ceiling), FAA ground stops, ground delay programs, delays and closures at US airports, and aircraft squawking an emergency within 150 km | aviationweather.gov (NOAA), FAA NAS status, adsb.lol, OurAirports |
| Share | web app · `/r/<id>` | Any everyday check can be shared as a link: the server runs the check, keeps a snapshot and serves it as a page with a preview card for X, Telegram, WhatsApp and Slack | Oculon |
| Personal monitors | web app · Telegram `/monitor` | Each visitor (a random id in a cookie, no account) or Telegram chat keeps up to 10 monitors of its own, written in plain language and re-checked about hourly; changes are kept as alerts and sent by email (after a confirmation link, with one-click unsubscribe) or to the Telegram chat | Resend (email), Meerkat |
| Monitor | `oculon monitor "<request>"` | Watch anything in plain language: "internet outages in Iran", "critical CVEs for nginx", "earthquakes above 6 near Tokyo", "news about OpenAI", "travel risk changes for Bangkok", "flood or cyclone alerts for the Philippines". The request becomes a watchlist rule; only changes are reported, with evidence, in the app, Telegram and the signal feed | free-tier LLMs (with a pattern fallback), Meerkat |
| Live | `oculon live` / `serve --live` | Listens to two real-time streams: English Wikipedia articles suddenly edited by several people (6+ human edits by 3+ editors in 15 minutes), and names or hashtags surging in English Bluesky posts against their own last hour (watched companies and topics get a lower bar) | Wikimedia EventStreams, Bluesky Jetstream |
| Calendar | `oculon calendar [days]` | Catalysts ahead: earnings (watched companies first, then the largest by revenue estimate), IPOs, key US macro releases (CPI, jobs, GDP, PCE, JOLTS...), rules taking effect and comment periods closing at market-moving agencies, and high-volume prediction markets that close; also added to the daily brief | Finnhub, FRED, Federal Register, Polymarket |
| Connect | `oculon connect <A> to <B>` / `resolve` | Entity resolution merges duplicates across kinds (`org:nvidia` = `company:nvidia` = `nvidia.com`), then finds the shortest chain of typed links between two things in the graph | Oculon graph |
| Sentinel | `oculon sentinel <place> [--compare date] [--radar]` | Sharp satellite view of a place at 10 m per pixel (least cloudy Sentinel-2 pass in the window), a before/after pair for any two dates, or Sentinel-1 radar that sees through clouds and at night | Copernicus Data Space (free account) |
| Fires | `oculon fires <place>` | Active fires and thermal hotspots near a place in the last 1-5 days from every satellite feed that is currently delivering (duplicates across satellites removed), grouped into clusters with fire radiative power; catches wildfires, industrial fires and strikes on infrastructure | NASA FIRMS (VIIRS NOAA-20/21, SNPP, MODIS; free key) |
| Blackout | `oculon blackout [days]` | Internet outages and shutdowns by country and network: outages Cloudflare confirmed (with cause, such as government-directed, power or cable cuts), automatic traffic anomalies, IODA's per-country outage scores, and the share of a country's address space still visible in global routing | Cloudflare Radar (free token), IODA, RIPEstat |
| BGP | `oculon bgp [world\|cc\|ASN\|IP]` | Worldwide BGP origin hijacks and route leaks (high-confidence hijacks between different organisations become signals), the countries most targeted by DDoS; for a country or network its routing visibility and incidents involving it; for an IP address the announcing network, RPKI validity, abuse contact and location | Cloudflare Radar, RIPEstat |
| Vulns | `oculon vulns` / `cve <id>` / `pkg <ecosystem> <name> [version]` | Vulnerabilities newly exploited in the wild with exploitation odds and federal deadlines, new critical CVEs and critical package advisories; one CVE in depth (CVSS, EPSS trend, affected packages and fixes); known vulnerabilities of a package version. `exposure` flags server CVEs that are exploited in the wild | CISA KEV, NVD, FIRST EPSS, OSV.dev, GitHub Advisory Database |
| Regs | `oculon regs [query] [--agency x]` | US executive orders, final and proposed rules and notices, plus tomorrow's documents on public inspection; effective dates and comment deadlines from market-moving agencies go on the catalyst calendar | Federal Register |
| Squawk | `oculon squawk` | Aircraft transmitting emergency transponder codes right now (7500 hijack, 7600 radio failure, 7700 emergency), ground tests and stale positions removed, with registration, type and nearest airport | adsb.lol, hexdb.io, OurAirports |
| Filings | `oculon filings "<phrase>"` / `edgar <ticker>` | Full-text search of every SEC filing for a phrase (e.g. "cybersecurity incident" in 8-Ks); a company's 8-K events decoded into plain English, with CEO/CFO departures read from the filing text | SEC EDGAR |
| Cloud | `oculon cloud` | Open incidents on the platforms the internet runs on: official status pages of GitHub, Cloudflare, OpenAI, Anthropic, Discord, Reddit, Vercel, npm and more, plus AWS, Azure and Google Cloud | Statuspage APIs, AWS Health, Azure and Google Cloud status |
| Hazards | `oculon hazards [days]` | Official orange and red disaster alerts (earthquakes, cyclones, floods, volcanoes, droughts, wildfires) with severity and affected countries, tsunami bulletins from the US warning centers, and extreme or severe US weather alerts | GDACS (UN / European Commission), tsunami.gov, NWS |
| Dark ships | `oculon darkships <place>` / `vessel <name\|MMSI\|IMO>` | Vessels that deliberately switched off AIS near a place, with where they went dark and reappeared; ship-to-ship encounters (possible transfers at sea), loitering, and the ports those vessels went to, each checked against OFAC by IMO; vessel identity with flag history, owners, earlier names, a year of gaps, encounters and port calls | Global Fishing Watch (free non-commercial token), OFAC |
| Listen | `oculon podcast <subject>` / `listen <media-url>` | Finds recent podcast episodes about a subject and transcribes the newest English one (or any audio/video file URL): machine summary, topics, and every passage that mentions the subject with its timestamp | iTunes podcast directory, Deepgram (pay per minute) |
| Exposure | `oculon exposure <domain>` | Resolves a domain's main hosts and known subdomains, then lists open ports, software and known CVEs per machine, the network that announces each IP (abuse contact, RPKI) and which CVEs are exploited in the wild; CDN edges are marked, and CVEs or exposed databases and remote access on direct machines become a signal | Google DNS, Shodan InternetDB (free), RIPEstat, CISA KEV |
| Social pulse | `oculon social <subject>` | Recent posts about a subject on X, Reddit, TikTok and Bluesky: count per platform, the most engaged and the newest posts with links, and Reddit's pace over the last six hours versus the day before; a sharp acceleration is a signal | Apify (X, Reddit, TikTok; pay per result), Bluesky |
| Feedback | Telegram buttons / `oculon feedback` | Every alert has Useful and Noise buttons; votes move that module's alert bar (from the third vote, capped at -10/+20 points) | your votes |
| Sanctions | `oculon sanctions <IMO\|name>` | Screens against the US OFAC SDN list and, for names, sanctions, PEP and wanted lists worldwide (OpenSanctions, free non-commercial key): vessel IMO numbers, exact names and aliases; for a confident name match, its owners, subsidiaries, directors and associates, sanctioned ones first. Runs automatically on every vessel seen over AIS | OFAC SDN, OpenSanctions |
| Narratives | `oculon narratives [run]` | Groups headlines into storylines that persist across days and flags new or fast-growing ones | Guardian, NYT, Hacker News, Oculon signals, free-tier LLMs |
| Calibration | `oculon calibrate` | Replays past days with the Time Machine, checks which radar items became news within three days, picks the signal threshold with the best F1 and per-source weights; the live radar uses them | Time Machine, Guardian |
| Company health | `oculon health <company>` | 0-100 early-warning score from hiring momentum, new lawsuits, insider selling, news tone, shipping and the stock move, each part explained; a sharp drop is a signal | Hound sources |
| Disaster impact | `oculon impact [place]` | People living within the affected radius of M6+ quakes and severe storms, plus night-light change once data covers the days after | USGS, NASA EONET, Wikidata, NASA VIIRS |
| Contradictions | `oculon contradictions <topic>` | Reads several outlets and lists factual claims that conflict, each side with its source | Tavily, GNews, Guardian, Jina, free-tier LLMs |
| Report | `oculon report` | A self-contained weekly HTML report; sent to Telegram on Mondays | everything above |
| Plugins | `oculon plugin list/run` | Local `.mjs` plugins add tools to the CLI and MCP server (see `examples/plugins/show-hn.mjs`) | your code |
| Case Files | `oculon case new "<question>"` | Deep investigations: an agent runs up to 10 tool steps, cross-checks sources and looks for contrary evidence, then writes a case file (answer, findings with confidence, timeline, entities, open questions). Citations are verified in code against what the tools returned; a finding needs two independent sources for "high". Watched cases are re-investigated daily and only new findings are reported | every tool below, free-tier LLMs |
| First to Know | `oculon scoops` | For each strong signal, finds when major media first covered the subject (oldest-first search from a week before) and records the lead time, positive or negative. An honest scoreboard of how often Oculon was ahead | Guardian, NYT, GNews |
| Lynx | `oculon markets` | Cross-checks Polymarket against Kalshi and Manifold; an LLM confirms each pair asks exactly the same question before gaps are reported | Polymarket, Kalshi, Manifold |
| Launch Radar | `oculon launches <company>` | New Hugging Face models/datasets/Spaces, new iOS apps and updates, new npm packages, plus (with a domain) new hostnames, pages and repos | Hugging Face, App Store, npm, Ferret sources |
| Time Machine | `oculon rewind <date>` | What Oculon would have seen on a past date: Wikipedia spikes against the weeks before, top Hacker News stories, strong earthquakes and that day's Guardian headlines, fused | Wikimedia, HN, USGS, Guardian |
| Geofences | `oculon fence add <name> <place>` | Boxes on the map, checked every scan for new military aircraft, military vessels, earthquakes and natural events; draw them on the dashboard map | adsb.lol, aisstream, USGS, NASA EONET |
| Octopus | `oculon ask "<question>"` | Tool-using AI agent: picks Oculon tools, searches and reads the web, answers with sources. Read-only. | Claude (optional, pay per use: Opus 5.5, Fable 5.2 for case files), then Groq, Gemini, Mistral, NVIDIA NIM, OpenRouter (free tiers, automatic fallback) |
| Owl | `oculon radar` | Global anomaly radar: Wikipedia readership spikes, Hacker News traction, prediction-market swings, trending coins, NYT top stories, earthquakes, natural events and space weather, fused across sources | Wikimedia, HN, Polymarket, CoinGecko, NYT, USGS, NASA EONET, NOAA SWPC |
| Hound | `oculon dossier <name> [--deep]` | Dossier on a company, person or project: profile and readership spike, stock quote, insider trades and insider sentiment, analyst ratings and their shift, peers, key financials, earnings surprises, decoded 8-K events, news from five outlets, web results, federal court dockets, job openings, UK registry, brand, prediction markets, repos, YouTube, Bluesky; FDA recalls and clinical trials for health and food companies; with `--deep` lobbying, federal contracts, visa filings and patents; one merged timeline | Wikipedia, Finnhub, SEC EDGAR, openFDA, ClinicalTrials.gov, GDELT, GNews, Guardian, NYT, Tavily, CourtListener, Adzuna, Companies House, Brandfetch, Polymarket, GitHub, YouTube, Bluesky |
| Cricket | `oculon hype <topic>` | Hype-cycle phase (DORMANT, EMERGING, RISING, PEAK, COOLING, STEADY) from 8 weeks of readers, developers, news, press, research, scholarly output and builders | Wikimedia, HN, GDELT, Guardian, arXiv, OpenAlex, GitHub |
| Ferret | `oculon footprint <domain>` | Pre-release footprints: hostnames new in Certificate Transparency logs or urlscan.io scans, newly archived pages, new public repos, Google Safe Browsing verdicts | crt.sh, CertSpotter, urlscan.io, Wayback Machine, GitHub, Safe Browsing |
| Meerkat | `oculon watch add/run/list/rm` | Watchlist: re-checks companies, domains, planes, topics, night lights, air quality, ports, news keywords, country outages, vendor CVEs, earthquakes near a place, disaster alerts, links, packages and travel risk, and reports only what changed since the last check | every module above |
| Falcon | `oculon plane <reg>` / `oculon mil` | One aircraft (owner, live position, nearest airport, moves between checks); worldwide military air traffic with notable roles (tanker, AWACS, ISR, bomber) and surges versus history | adsb.lol, OpenSky, hexdb.io, OurAirports |
| Condor | `oculon events` / `lights` / `image` / `space` / `air` | Natural events with severity; night-time lights of any place versus a baseline month to spot blackouts or surges; true-color satellite images; space weather (official NOAA alerts and scales, solar wind, 3-day forecast, solar flares, coronal mass ejections modelled to reach Earth, geomagnetic storms, close asteroid passes); PM2.5 air quality | NASA EONET, NASA GIBS (VIIRS, MODIS), NOAA SWPC, NASA DONKI and NeoWs, OpenAQ, Nominatim |
| Raven | `oculon forecast ...` | Forecasts on live Polymarket markets, resolved against real outcomes and scored (Brier) against the crowd price at forecast time | Polymarket |
| Tortoise | `oculon proof ...` | Tamper-evident proofs: forecasts hashed into a Merkle tree, timestamped on Bitcoin through OpenTimestamps, verified down to the block merkle root | OpenTimestamps, Blockstream |

## Install

Requires Node.js 22.13 or newer (it uses the built-in `node:sqlite`).

```sh
npm install -g oculon
oculon doctor
```

Data is stored in `~/.oculon` (set `OCULON_HOME` to change it).

## CLI

```sh
oculon tour                                   # what this install knows and what to try next
oculon calendar 7                             # earnings, macro releases, markets closing this week
oculon connect Nvidia to "Jensen Huang"       # shortest path in the entity graph
oculon resolve                                # merge duplicate entities
oculon live --minutes 30                      # Wikipedia + Bluesky surges in real time
oculon feedback                               # how Useful/Noise votes moved each module
oculon help calendar                          # help for one command
oculon gc                                     # drop old cached API responses, compact the database
oculon case new "Is the Nvidia board replacing its CEO, and who are the likely successors?"
oculon case watch 1                           # re-investigate daily, report new findings
oculon scoops check                           # lead time vs first media coverage
oculon markets                                # Polymarket vs Kalshi and Manifold
oculon launches OpenAI --domain openai.com    # what is about to ship
oculon rewind 2026-11-12                      # time machine
oculon fence add hormuz "Strait of Hormuz" --radius 150
oculon ships "Port of Rotterdam"              # live vessels (AIS)
oculon watch add company Nvidia               # watchlist: company domain plane topic lights air port
oculon watch run                              # report only what changed since last time
oculon brief                                  # today's brief
oculon quota                                  # today's API usage vs free-tier budgets
oculon ask "is there a geomagnetic storm right now?"
oculon radar                                  # what the world is suddenly watching
oculon dossier Nvidia                         # company / person dossier
oculon hype "ai agent"                        # hype phase
oculon footprint openai.com --days 30         # pre-release footprints
oculon plane N628TS                           # track an aircraft
oculon mil                                    # military air traffic
oculon events                                 # natural events
oculon lights "Gaza Strip"                    # night lights vs baseline
oculon image Kyoto --date 2026-11-15 --out kyoto.png
oculon space                                  # geomagnetic storms, solar flares
oculon air "New Delhi"                        # PM2.5 near a place
oculon search "query"                         # web search
oculon read https://example.com               # readable page text
oculon forecast <market-slug> --p 0.35 --why "reason"
oculon forecast auto | resolve | score | list
oculon proof stamp
oculon proof verify <forecast-id>
oculon signals                                # latest signals from every module
oculon entity org:nvidia                      # entity graph lookup
oculon serve --watch 15 --live --telegram     # dashboard on http://127.0.0.1:4747 + schedule, streams, bot
oculon mcp                                    # MCP server on stdio
oculon telegram                               # Telegram bot
```

Every command accepts `--json`.

## MCP server

Register Oculon with Claude Code:

```sh
claude mcp add oculon -- npx -y oculon mcp
```

Or with any MCP client that launches stdio servers:

```json
{ "mcpServers": { "oculon": { "command": "npx", "args": ["-y", "oculon", "mcp"] } } }
```

Every module is a tool (about 50, plus one per installed plugin tool; `tools/list` returns them with schemas). A few: `oculon_ask`, `oculon_radar`, `oculon_dossier`, `oculon_case_new`, `oculon_calendar`, `oculon_connect`, `oculon_markets_crosscheck`, `oculon_sanctions`, `oculon_health`, `oculon_narratives`, `oculon_ships`, `oculon_military_air`, `oculon_satellite_image` (returns the image), `oculon_forecast`, `oculon_verify_proof`, `oculon_watch_add`, `oculon_brief`, `oculon_signals`, `oculon_entity`.

## Remote MCP

Oculon also runs as a remote MCP server, so an agent can use every tool with nothing installed. The endpoint speaks Streamable HTTP (stateless JSON responses):

```
https://mcp.oculon.live
```

- **Claude Code**: `claude mcp add --transport http oculon https://mcp.oculon.live`
- **Claude** (web and desktop): Settings → Connectors → Add custom connector, and paste the URL.
- **Cursor**: `{ "mcpServers": { "oculon": { "url": "https://mcp.oculon.live" } } }` in `.cursor/mcp.json`
- **VS Code**: `{ "servers": { "oculon": { "type": "http", "url": "https://mcp.oculon.live" } } }` in `.vscode/mcp.json`
- Any other client that supports Streamable HTTP: the same URL.

Your own install serves the same endpoint at `/mcp` (for example `http://127.0.0.1:4747/mcp` while `oculon serve` runs). On a public install the remote server leaves out the tools that change what the whole install watches (watchlist, fences, forecasts), and `oculon_monitor` only shows how a request would be read.

The same checks are plain HTTP too: `https://app.oculon.live/openapi.json` describes them for ChatGPT Actions, n8n, Zapier and any OpenAPI client.

## SDK

```ts
import { Oculon } from 'oculon';

const o = new Oculon();
const radar = await o.radar();
const dossier = await o.dossier('Nvidia');
const lights = await o.nightLights('Kyiv');
const link = await o.urlCheck('paypa1-secure-login.top/verify');
const claim = await o.factCheck('The Great Wall of China is visible from space');
await o.monitor('Tell me when there is an internet outage in Iran');
const car = await o.recall('2018 Honda Accord');
const mail = await o.emailSecurity('example.com');
console.log(radar.signals, dossier.result.timeline, lights.result.verdict);
o.close();
```

Every CLI command has a method (`radar`, `dossier`, `caseInvestigate`, `calendar`, `connect`, `resolveEntities`, `feedback`, `markets`, `health`, `watchRun`, `brief`, `forecast`, `verifyProof`, `signals`, `entity`, ...). Module calls return `{ result, signals, provenance }`.

```ts
const live = await o.live({ onSignals: (s) => console.log(s) }); // Wikipedia + Bluesky listeners
// later: live.stop();
```

## Dashboard and schedule

`oculon serve` starts a local web server on `127.0.0.1:4747` with three pages: `/` is an overview page with live numbers and a console that runs a fixed set of read-only commands (bgp, vulns, hazards, cloud, squawk, blackout, regs, cve) and shows their real output, `/docs` renders this README plus `oculon help`, and `/app` is the dashboard. Behind a reverse proxy, a host starting with `app.` or `docs.` serves that page at its root. The dashboard has tabs for:

- **Overview**: live cards for exploits, space weather, cloud status, outages, disaster alerts, catalysts, narratives, forecasts, watchlist, cases and budgets. Drag to reorder, hide what you do not need.
- **Inbox**: every signal with read state, filters, Useful/Noise votes that move each module's alert bar, and a share card (PNG) for posting.
- **Signals, Map, Investigate, Cases, Watch, Forecasts, World, Calendar, Live and Graph**, plus **Timeline** (scrub through stored signals), **Sources** (which hosts answered and when, which key groups are set) and **Accuracy** (first-to-know lead times, radar calibration, forecast scoreboard).
- **Entity pages** for any company, domain, repo or market: signals, links, observations and sources in one place.

Press Ctrl+K anywhere to search entities or run a module (CVE ids, AS numbers, domains, dates and names are recognized). New signals arrive over a live stream without reloading, optional browser notifications flag scores of 75 and up, and the app installs as a PWA. Write actions only accept same-origin requests with a custom header.

`--watch 15` turns on the schedule (shared with the Telegram bot); `--live` adds the stream listeners; `--telegram` runs the bot in the same process:

| Every | Task |
|---|---|
| real time (`--live`) | Wikipedia edit surges, Bluesky term surges |
| 15 min (configurable) | radar, military air, natural events, space weather, geofences, disaster impact |
| 60 min | watchlist re-check |
| 6 h | resolve settled forecasts, First to Know check, market cross-check, narratives |
| daily | automatic forecasts and their Bitcoin timestamp, health of watched companies, watched cases (up to 3), cache cleanup, brief with the day's catalysts (from 07:00 local) |
| Mondays | weekly HTML report |

Free-tier quotas are protected by daily per-source budgets (`oculon quota`); when one is spent, Oculon serves the last cached result or labels the source unavailable instead of calling it.

## Telegram bot

Create a bot with @BotFather, then set:

```sh
TELEGRAM_BOT_TOKEN=...
TELEGRAM_ALLOWED_CHATS=123456789        # comma-separated; message the bot to learn your chat id
TELEGRAM_ALERT_MIN_SCORE=70
TELEGRAM_WATCH_MINUTES=15
```

Run `oculon telegram` (or `oculon serve --telegram`). Every module has a command (`/help` lists them), including `/ask`, `/case`, `/calendar`, `/connect Nvidia to Jensen Huang`, `/live`, `/brief`, `/report` and `/alerts on|off`. Alerts arrive with Useful and Noise buttons; `/feedback` shows how the votes moved each module's alert bar. Chats outside the allowlist are refused and cannot vote.

## Configuration

All optional, read from the environment or a `.env` file in the working directory:

| Variable | Effect |
|---|---|
| `OCULON_HOME` | Data folder (default `~/.oculon`) |
| `OCULON_DB` | Database path override |
| `OCULON_CONTACT` | Contact email, sent only to SEC EDGAR (which requires one); no other API receives it |
| `GITHUB_TOKEN` | Raises GitHub limits from 60 to 5000 requests/hour |
| LLM, search, news, markets, company, security, social and air keys | See `.env.example`; each is optional, all have free tiers. `oculon doctor` shows which groups are on |

API keys never appear in output: provenance URLs, errors and agent tool results are scrubbed of every key in the environment.

## Deploy

The web server runs anywhere Node 22.13+ or Docker runs. A server open to the internet must use public mode:

```sh
OCULON_ADMIN_TOKEN=<long random string> oculon serve --host 0.0.0.0 --public --watch 15 --live
```

In public mode visitors get the overview page, the docs, the legal pages and a read-only API. Writes, the dashboard, LLM-backed endpoints and anything personal (watchlist, cases, geofences, votes) stay closed, and every client is rate limited. The owner opens `/app`, signs in once with `OCULON_ADMIN_TOKEN` and gets the full app; the token is never stored in the browser. Serving beyond localhost without `--public` is refused.

Other deployment switches:

| Variable | Effect |
| --- | --- |
| `OCULON_OPEN=1` | Opens the whole app to every visitor: dashboard, writes and LLM-backed endpoints, with no sign-in and no rate limit. |
| `OCULON_DOMAIN=example.com` | Points app and docs links at `app.example.com` and `docs.example.com`, and redirects `/app` and `/docs` there. |
| `OCULON_EDGE_SECRET` | Shared secret with the Cloudflare Worker in `edge/`, which serves the two subdomains from the same server. |
| `OCULON_TELEGRAM=1` | Runs the Telegram bot inside `serve` (same as `--telegram`). |
| `OCULON_TELEGRAM_PUBLIC=1` | Anyone may use the bot's public commands (rate limited per chat); chats in `TELEGRAM_ALLOWED_CHATS` keep every command. |
| `RESEND_API_KEY`, `OCULON_MAIL_FROM` | Email alerts for personal monitors (default sender `Oculon <alerts@oculon.live>`; the domain must be verified in Resend). |
| `OCULON_PURGE_ONCHAIN=1` | Clears data left by the paused on-chain modules each time the server starts. |

The repository includes a `Dockerfile` and `railway.json`. Mount a persistent volume at `/data` (the image sets `OCULON_HOME=/data`), set your keys as environment variables, and point a domain at the service. Each deployment keeps its own database and its own daily budgets.

## How it works

- Provenance everywhere: each fetch is labeled `LIVE`, `CACHED`, `UNAVAILABLE` or `ERROR` with its URL and time. When a live fetch fails, stale cache is returned and labeled as stale.
- Polite by default: per-host throttling follows each provider's guidance (GDELT 1 request per 5 s, arXiv 1 per 3 s, Nominatim 1 per second), retries honor `Retry-After`.
- Entity graph: domains, repos, aircraft, companies, articles, markets and events become nodes with typed edges and observations over time, stored in SQLite.
- Explainable scores: every scoring rule is plain code with documented thresholds.

## Limits

- Free APIs rate-limit; GDELT and arXiv in particular answer 429 after heavy use. Affected sources are reported as errors and the rest of the result still returns.
- The Wayback Machine CDX API is often slow; Ferret caps it at 45 s.
- crt.sh can lag behind the CT logs by weeks.
- OpenTimestamps proofs stay PENDING until a calendar commits to Bitcoin, usually a few hours.
- Raven's automatic momentum rule is a hypothesis to be tested by its own track record, not a proven edge.
- Night-light analysis uses a gap-filled daily product that lags a few days; clouds and snow add noise, so only changes beyond -25% / +33% are reported.
- Military surge detection needs at least three earlier scans of a region.
- Owl fuses items by shared keywords, then (when an LLM key is set) asks the model to link items about the same event; every AI link carries the model's stated reason.
- The watchlist and geofences need two runs before they can report a change; the first run records a baseline.
- First to Know is deliberately strict: Wikipedia spikes usually follow the news, so most such signals score "media first". Lead time is most likely on footprint, chain and flight signals.
- Lynx only reports pairs an LLM confirms as the same question; exact matches across venues are rare, so an empty result is common and honest.
- AIS coverage depends on community receivers and is absent in some regions; empty windows say so.
- Sanctions screening uses exact matches on the OFAC SDN list only; it is not legal advice and does not cover other jurisdictions.
- Calibration measures "became news" by Guardian coverage, which under-counts niche tech stories; treat per-source weights as a mainstream-news lens.
- Disaster exposure sums Wikidata settlement populations (overlapping places can double count); it is an order-of-magnitude exposure estimate, not a casualty estimate.
- Live stream state is in memory: Bluesky surges need about 20 minutes of history after start, and a restart begins again. A Wikipedia edit surge often means an edit war or a breaking event; the signal links the page history so you can tell which.
- The calendar leaves out FOMC dates (FRED lists that series daily) and single sports games; earnings beyond watched companies are the 12 largest by revenue estimate.
- Entity resolution is rule-based and conservative (identical names, or a domain whose main label equals a company name of 4+ letters), so some duplicates stay separate. Connection paths only cover what Oculon has already stored.
- Paid services are optional and capped: Claude calls (ask, case files, brief, contradictions) and Apify runs count against daily budgets (`OCULON_QUOTA_ANTHROPIC`, default 150; `OCULON_QUOTA_APIFY`, default 40). High-volume background work (radar linking, market matching, narratives) always uses the free tiers.
- Transcription needs a direct media file (podcast enclosures work; YouTube pages do not). Deepgram's summary and topics are English-only and machine-written, and they include ads read in the episode; quotes come with timestamps so they can be checked. Transcriptions count against `OCULON_QUOTA_DEEPGRAM` (default 30 per day) and are stored, so reading one again is free.
- Blackout signals come only from outages Cloudflare confirmed or verified; IODA scores are shown for context and their scale is relative, not a percentage. Dark-ship data comes from Global Fishing Watch's gap model, which covers fishing and carrier vessels much better than tankers and cargo ships, and an AIS gap can also be poor reception.
- Exposure uses InternetDB, which reflects Shodan's last scan (days to weeks old) and knows nothing about machines behind a CDN.
- Social pulse samples are small (X returns about 10 posts per search on Apify's free plan) and X, TikTok and Bluesky are fetched by popularity, so pace is measured on Reddit only. Address labels come from a community dataset (MIT) and can be incomplete or stale.
- Plugins run with full Node permissions; install only code you trust.
- `oculon ask` answers are written by a free-tier LLM from tool results; they can still misread data, so check the cited sources.
- Respect each data provider's terms. OpenStreetMap, Nominatim and adsb.lol data are ODbL-licensed and require attribution.

## Development

```sh
npm install
npm test
npm run typecheck
npm run oculon -- radar     # run the CLI from source
npm run build
```

## Contributing and security

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Data from third-party sources remains subject to each provider's terms.
