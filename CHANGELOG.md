# Changelog

All notable changes are listed here. Versions follow [semantic versioning](https://semver.org).

## 0.1.0 · first public release

### Engine

- 42 modules over more than 50 public sources, each result with full provenance (live, cached, error, unavailable).
- Cross-source signals, storylines across days, entity resolution and a local evidence graph (SQLite).
- Daily per-source budgets that keep free tiers free, with cached fallbacks.

### Robinhood Chain (Heron)

- New and trending pools with risk flags: thin liquidity, buys without sells, sudden drops, valuation far above liquidity.
- Token checks (verification, holder concentration, pool behavior) and deployer memory, including launches through launchpad factories.

### Measurement

- Time machine and radar calibration, first-to-know lead times against media coverage.
- Forecasts against prediction markets, hashed into Merkle trees and timestamped on Bitcoin through OpenTimestamps.

### Surfaces

- CLI with `--json` on every command, TypeScript SDK, MCP server with 71 tools, Telegram bot with Useful/Noise feedback.
- Web app: overview page with a live console, docs, and a dashboard with Overview, Robinhood, Inbox, Timeline, Sources and Accuracy tabs, entity pages, Ctrl+K command palette, share cards, live updates and PWA install.
- Public mode for internet-facing installs: read-only API, rate limits and an owner sign-in.
