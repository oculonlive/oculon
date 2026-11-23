# Changelog

All notable changes are listed here. Versions follow [semantic versioning](https://semver.org).

## Unreleased

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

## 0.1.0 · first public release

### Engine

- 42 modules over more than 50 public sources, each result with full provenance (live, cached, error, unavailable).
- Cross-source signals, storylines across days, entity resolution and a local evidence graph (SQLite).
- Daily per-source budgets that keep free tiers free, with cached fallbacks.

### Measurement

- Time machine and radar calibration, first-to-know lead times against media coverage.
- Forecasts against prediction markets, hashed into Merkle trees and timestamped on Bitcoin through OpenTimestamps.

### Surfaces

- CLI with `--json` on every command, TypeScript SDK, MCP server with 64 tools, Telegram bot with Useful/Noise feedback.
- Web app: overview page with a live console, docs, and a dashboard with Overview, Inbox, Timeline, Sources and Accuracy tabs, entity pages, Ctrl+K command palette, share cards, live updates and PWA install.
- Public mode for internet-facing installs: read-only API, rate limits and an owner sign-in.
