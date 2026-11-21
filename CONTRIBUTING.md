# Contributing to Oculon

Thanks for helping. Oculon is a small codebase with a few firm rules; reading them first saves a round of review.

## Ground rules

- **No runtime dependencies.** Everything ships on Node's standard library (`node:http`, `node:sqlite`, `fetch`). Dev dependencies are fine.
- **Every result carries provenance.** A module returns `{ module, input, generatedAt, result, signals, provenance }`, and each source it called is listed with its state (live, cached, error, unavailable).
- **Free tiers stay free.** New sources get a daily budget in `src/core/quota.ts` below their free limit, and repeated calls go through the cache.
- **No invented data.** If a source does not say something, Oculon does not say it either. Heuristics are labelled as heuristics.
- **English only** in code, output, docs and the web pages.

## Getting started

```sh
git clone https://github.com/oculonlive/oculon.git
cd oculon
npm install
npm test
npm run typecheck
npm run oculon -- radar        # run the CLI from source
npm run oculon -- serve        # web app on http://127.0.0.1:4747
```

Copy `.env.example` to `.env` and add only the keys you have. About 20 sources work with none.

## Adding a source or module

1. Put the HTTP calls in `src/sources/` and use the shared `Http` client from the context (it handles cache, host spacing and budgets).
2. Put the logic in `src/modules/`, returning a `ModuleResult` with signals only for things that are genuinely unusual.
3. Expose it on the SDK (`src/index.ts`), the CLI (`src/cli/main.ts`), and, if agents should call it, the MCP server (`src/mcp.ts`).
4. Add tests in `test/` with recorded or mocked responses. Tests never hit the network.
5. Document the command and its sources in the README table.

## Pull requests

- Keep each pull request to one change, with tests.
- `npm test` and `npm run typecheck` must pass; CI runs both on Node 22 and 24.
- Describe what changed and how you checked it.

## Reporting bugs

Open an issue with the command you ran, what you expected, what happened, and the output of `oculon doctor`. Remove any keys or personal data first. Security problems go through [SECURITY.md](SECURITY.md), not public issues.

By contributing you agree that your work is released under the [MIT License](LICENSE) and that you will follow the [Code of Conduct](CODE_OF_CONDUCT.md).
