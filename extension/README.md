# Oculon Shield

A Chrome and Edge extension (Manifest V3) that puts the free [Oculon](https://oculon.live) checks in your browser.

## What it does

- **Site guard.** When a tab opens a page, the extension checks its domain with the Oculon link check
  (`GET /api/url`: Safe Browsing, URLhaus, ScamSniffer and MetaMask blocklists, urlscan.io history, domain age,
  look-alike names).
  - **Dangerous** (verdict `malicious`, or `suspicious` with a risk score of 70 or more): the tab is sent to a
    full-page warning with the reasons. "Go back to safety" returns to the last safe page; "Continue anyway"
    allows that domain until the browser closes.
  - **Be careful** (verdict `suspicious`): a small banner in the corner of the page, which you can dismiss.
  - **No known threats**: nothing on the page. The toolbar badge shows a check mark.
  - Results are cached per domain for six hours in session storage. Well-known big sites (Google, GitHub,
    Wikipedia, major exchanges and so on), browser pages, `localhost`, local network names and private IP
    addresses are never sent.
- **Popup.** The verdict for the current site with its reasons, and a box to check any link, domain, wallet
  address or token contract. For a `0x` address you choose Token or Wallet and the chain (Robinhood Chain by
  default). Every result links to the full Oculon report with its sources.
- **Token pills.** On token pages of DexScreener, Uniswap (`/explore/tokens/...`), `robin.etherscan.io` and
  `robinhoodchain.blockscout.com`, a small pill in the corner shows the Oculon contract check (verdict and risk
  score). Click it for the reasons and the full report. Supported chains: Robinhood Chain, Ethereum, Base,
  BNB Chain, Arbitrum and Polygon; on other chains no pill appears.
- **Settings.** Turn the site guard and token pills on or off, change the API base URL (for a self-hosted
  Oculon server), and clear the allowed sites.

## Install

### Load unpacked (from source)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose this `extension` folder.

### From a release zip

1. Download `oculon-shield-<version>.zip` and unzip it to a folder you keep.
2. Follow the steps above and choose the unzipped folder.

To build the zip yourself: `node extension/build.cjs` writes `extension/dist/oculon-shield-<version>.zip`.

## Privacy

Oculon Shield sends only the domain, link, address or contract being checked, and only to the Oculon API
(`https://app.oculon.live` unless you change it). It never sends full page addresses from the site guard,
page content, your browsing history, cookies or any identifier. There is no analytics, no tracking and no
remote code: every script ships inside the extension. Verdicts are cached in the browser session and are
gone when the browser closes. The public API limits each client to a few checks per minute, so the
cache also keeps the extension well inside that limit.

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | Your settings, and the per-session cache of verdicts and allowed sites. |
| `webNavigation` | To see which domain a tab is opening, so it can be checked before you use the page. |
| `host_permissions`: `app.oculon.live`, `oculon.live` | To call the Oculon API. |
| Content script on all `http` and `https` pages | Only to draw the "be careful" banner. It reads nothing from the page. |
| Content script on DexScreener, Uniswap, `robin.etherscan.io`, `robinhoodchain.blockscout.com` (and `robinhood.blockscout.com`) | To read the token address from the page address (on DexScreener, from the token's explorer link) and show the token pill. |
| Optional host permission | Asked for only when you set a self-hosted API base URL, so the extension can reach that server. |

## API endpoints used

- `GET /api/url?url=<domain or link>`: site guard and link checks.
- `GET /api/contract?address=<0x...>&chain=<robinhood|eth|base|bsc|arbitrum|polygon>`: token pills and token checks.
- `GET /api/address?address=<address>[&network=robinhood]`: wallet checks.
- Full reports open at `/replay/<check id>`, the id each check returns.
