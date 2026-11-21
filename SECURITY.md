# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an acknowledgement, and a fix or a plan, as soon as the report has been reviewed. Please give a reasonable time to fix the issue before disclosing it.

## Scope

In scope:

- The web server (`oculon serve`), especially public mode: anything that lets a visitor reach private endpoints, write data, run commands outside the console allowlist, or read the owner's watchlist, cases or keys.
- The MCP server, the Telegram bot's chat allowlist, and the CLI's handling of untrusted input.
- Leaks of API keys or personal data through output, logs or the web pages.

Out of scope:

- Problems in third-party data sources themselves.
- Rate limits or availability of the public demo at oculon.live.
- Plugins, which run with full Node permissions by design; install only plugins you trust.

## Supported versions

Security fixes go into the latest release.

## Design notes

- `oculon serve` listens on `127.0.0.1` by default. Serving beyond localhost requires `--public`, which exposes only a read-only API and rate limits each client.
- The dashboard in public mode requires `OCULON_ADMIN_TOKEN`; the browser keeps only a derived, HTTP-only cookie.
- Write endpoints require a custom header and a same-origin request.
- Key values are never returned by any endpoint; the Sources view shows key names only.
