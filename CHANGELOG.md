# Changelog

All notable changes are listed here. Versions follow [semantic versioning](https://semver.org).

## 0.1.5

Seven new checks over 19 new sources, in the CLI, SDK, MCP server, web app, Telegram bot and API.

- `oculon phone`: who is behind a number in a suspicious SMS or missed call. Country, line type (mobile, landline, VoIP, premium rate), carrier and location, with warnings for premium-rate numbers, UK 070 personal numbers and the Caribbean area codes named in "one ring" callback scams. Works offline from the calling code; Numverify (free key) adds carrier and line type. Never looks up the owner.
- `oculon password`: has a password leaked? Only the first 5 characters of its SHA-1 hash are sent (Have I Been Pwned, k-anonymity). In the web app the hash is made in the browser, so the server never sees the password. Not offered on the remote MCP server or in Telegram.
- `oculon breaches [domain]`: the newest data breaches, or every breach of one domain (Have I Been Pwned).
- `oculon company <name|LEI|EU VAT>`: is a supplier real? EU VAT numbers are checked live in VIES; names and LEIs come from the Global LEI Index with status, address and ultimate parent.
- `oculon ip <IP|domain>`: abuse reports (AbuseIPDB), internet scanners (GreyNoise), threat reports (AlienVault OTX), antivirus verdicts (VirusTotal), malware infrastructure (ThreatFox), Spamhaus DROP, Tor exits, network type (PeeringDB, IPinfo, ip-api.com) and open ports, with a verdict and risk.
- `oculon hash <md5|sha1|sha256>`: known malware or a known good file (CIRCL hashlookup with NIST NSRL, MalwareBazaar, ThreatFox, OTX, VirusTotal).
- `oculon ransomware [country|sector|name]`: ransomware leak-site claims from ransomware.live, without leak-site links.
- `oculon satellite [name|NORAD id]`: launches of the last 30 days, or one object's orbit, owner and status (CelesTrak).
- New optional keys: `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `IPINFO_TOKEN`, `VIRUSTOTAL_API_KEY`, `NUMVERIFY_API_KEY` (all free). Without them those sources are skipped and say how to turn them on.
- MCP: 83 tools locally, 74 on the remote server.

## 0.1.4

- MCP: tool arguments are checked against each tool's schema. A misspelled or unknown argument, a missing required one or a wrong type now returns a clear tool error naming the arguments the tool takes. Before, the scam check called with `text` instead of `message` answered "no strong signs".
- API: bad input returns 400 and a missing record 404 with a clear message, instead of 500 (for example `/api/cve?id=nope`, `/api/rewind?date=yesterday`, an unknown forecast or case).
- Entity graph: labels no longer pile on top of each other in dense clusters, stay inside the canvas, and nodes can be tapped on phones.
- Radar: Hacker News items without a points count are skipped instead of showing "undefined points".
- Faster: the prediction-market cross-check (about 80 s to about 25 s) and the contradiction finder read their sources in parallel.
- `oculon serve` explains a port that is already in use instead of crashing with a stack trace, and usage messages no longer repeat "usage:".
- The app header fits on one row on phones.

## 0.1.3

- New Oculon mark: favicon, app icons, link preview card and page headers.
- Oculon Analyst at `/ask`: questions are checked against live tools first and answered as a brief (bottom line, 0-100 confidence, findings with numbered sources, unknowns, what would change it), with a live trace of every source, cross-examination by two other models and one-click monitors. Models: Claude Haiku 5.5, Claude Opus 5.5 and GPT-6.2 Astra through OpenRouter.

## 0.1.2

- Forecast proofs can be checked without Oculon: `/api/proof?id=<id>` (forecast, canonical JSON, hash, Merkle path) and `/proof/<id>.ots` (a standard OpenTimestamps file).
- The docs show a live cross-source signal, keep the header above the page, land on the linked section and no longer scroll sideways on phones.
- Addresses stay clean: in-page links no longer add #section to the address bar.
- Install instructions show the full command and the npx option.

## 0.1.1

- Scam check: many more scam families are recognized: crypto giveaways asking for a wallet or recovery phrase, token promotion and fake volume offers, paid "services" pitched to token developers, early-access and signal groups, fake wallet support, platforms that charge a fee to withdraw, task jobs that ask for deposits, recovery services, sextortion, tech support and fake renewals, advance-fee loans, and toll or tax impersonation. Each family comes with its own advice.
- Opening the remote MCP URL in a browser shows a page with the URL, client setup and the tool list instead of redirecting to the docs.
- Docs links that jump to a section no longer leave the text hidden on phones.

## 0.1.0 · first npm release

- `oculon scam`: scam check for SMS, email and chat messages (links, sender, known patterns), also by forwarding a message to the Telegram bot.
- Personal monitors: every visitor and Telegram chat keeps its own monitors; changes arrive by email (Resend, confirmed and one-click unsubscribe) or in Telegram. The shared watchlist is now changed only by the owner.
- Public Telegram bot (`OCULON_TELEGRAM_PUBLIC=1`): public commands for everyone, rate limited per chat; groups get answers to commands only.
- `/openapi.json` for ChatGPT Actions, n8n and Zapier; the remote MCP server hides tools that change the shared watchlist.
- `oculon recall`: vehicle recalls by VIN or "year make model" (NHTSA) and product recalls (CPSC, FDA).
- `oculon email`: email spoofing protection of a domain (SPF, DMARC, DKIM, MTA-STS, DNSSEC) with a score and fixes.
- `oculon papers`: research briefs from OpenAlex and PubMed, with growth per year and a cited overview.
- `oculon country`: country briefs from the World Bank, IMF and Wikidata, plus travel advice, outages and headlines.
- `oculon airport`: airport weather (METAR, TAF), FAA delays and ground stops, nearby emergency squawks.
- Share links: any everyday check becomes `/r/<id>`, a snapshot page with a preview card; every page now has preview tags.
- Remote MCP over Streamable HTTP at `https://mcp.oculon.live` and at `/mcp` on every install.
- `oculon url`: link safety from Google Safe Browsing, URLhaus, urlscan.io history, domain age (RDAP) and URL warning signs.
- `oculon factcheck`: claims and news links checked against published fact checks and current reporting, with cited sources.
- `oculon audit`: dependency health for package.json, requirements.txt or package lists (deps.dev, OpenSSF Scorecard).
- `oculon travel`: travel risk brief from official advice, weather, air quality, outbreaks, disasters, earthquakes and outages.
- `oculon monitor`: monitors written in plain language, backed by eight new watchlist kinds (news, outage, cve, quake, hazard, url, package, travel).
- Every new check is also in the web app (Investigate, Watchlist), the Telegram bot and the MCP server (75 tools in all).
- On-chain features (Robinhood Chain pools, token and deployer checks; wallet and token checks; DeFi) are paused. Their code and tests stay in place; `OCULON_ONCHAIN=1` turns them back on.
- Public installs serve the dashboard at `app.<domain>` and the docs at `docs.<domain>` when `OCULON_DOMAIN` is set.

### Engine, measurement and surfaces from the first public release

#### Engine

- 42 modules over more than 50 public sources, each result with full provenance (live, cached, error, unavailable).
- Cross-source signals, storylines across days, entity resolution and a local evidence graph (SQLite).
- Daily per-source budgets that keep free tiers free, with cached fallbacks.

#### Measurement

- Time machine and radar calibration, first-to-know lead times against media coverage.
- Forecasts against prediction markets, hashed into Merkle trees and timestamped on Bitcoin through OpenTimestamps.

#### Surfaces

- CLI with `--json` on every command, TypeScript SDK, MCP server with 64 tools, Telegram bot with Useful/Noise feedback.
- Web app: overview page with a live console, docs, and a dashboard with Overview, Inbox, Timeline, Sources and Accuracy tabs, entity pages, Ctrl+K command palette, share cards, live updates and PWA install.
- Public mode for internet-facing installs: read-only API, rate limits and an owner sign-in.
