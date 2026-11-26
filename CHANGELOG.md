# Changelog

All notable changes are listed here. Versions follow [semantic versioning](https://semver.org).

## 0.4.0

API keys and fifteen new tools.

API keys
- One key for the REST API, the SDK, the CLI and the remote MCP server, made at console.oculon.live (or `/console` on any install) after a wallet signature. No email, no payment. A key is shown once and stored only as a SHA-256 hash; a wallet can have five.
- Free key: the everyday checks and public feeds, 200 calls a day. Holder key: every service, 5,000 calls a day, for a wallet holding 5,000,000 OCULON. The balance is read again every six hours; a wallet below the line keeps a working key on the free tier.
- Calls without a key from outside Oculon's own pages keep working on the free services, 50 a day per address (500 for the Oculon Shield extension). Oculon's own pages are not limited. The gate is on when `OCULON_API_KEYS=1` in public mode.
- `/api/key` shows a key's tier and what is left today; `/api/catalog` lists every endpoint and MCP tool with its tier. Responses carry `x-ratelimit-limit`, `x-ratelimit-remaining` and `x-oculon-tier`.
- SDK: `new OculonClient({ apiKey })` calls the hosted API. CLI: `oculon api <path> name=value` and `oculon api key`.

New tools
- Screenshot Check (`/screenshot`): a screenshot of a chat, SMS, email, ad or page is read by a free Gemini model, and the scam check judges the text and every link in it.
- I Got Scammed (`/rescue`): a checklist for the next 10 minutes, today and this week, for eleven situations, with official reporting links by country.
- Is It Down (`/down`): official status pages of about 30 services, plus a labelled one-location probe for services without one.
- Scam Inbox (`/inbox`): forward a suspicious email to check@oculon.live and the verdict comes back by email (Cloudflare Email Worker in `edge/inbox`).
- Discord Sentinel (`/discord`): a bot that removes malicious links, warns on suspicious ones, flags members imitating the staff, and answers `/check`.
- Brand Shield (`/brandshield`): domains imitating a brand, from lookalikes, new certificates, DNS and the URL check.
- Oculon Wire (`/today`): the strongest stored signals of the day as six lines, a card image and a ready post.
- Scam Trends (`/trends`): counts of what people checked this week. Nothing that was checked is shown; small groups are hidden.
- Live Wall (`/wall`): world signals on one live screen, with a kiosk mode.
- Spot the Scam (`/spot`): a daily game of eight links, real blocklisted phishing domains against real official pages.
- Terms Reader (`/terms-reader`): the clauses in terms or a contract worth reading twice, each quoted.
- Prove It (`/prove`): timestamp a file on Bitcoin with OpenTimestamps; only its hash leaves the browser.
- Security Checkup (`/checkup`): a five-minute score from A to F with the top fixes.
- Charity Check (`/charity`): US nonprofits by name or EIN from IRS data.
- Oculon Embed (`/embed`): a link checker any website can add with one script tag.

## 0.3.0

Rug Radar, Wallet Guard and the Oculon Shield browser extension.

- Rug Radar at `/rugradar` (JSON at `/api/rh/launches`): every new token on Robinhood Chain (Uniswap v2, v3, v4 and Pons pools) gets a quick read from its pool as it launches. Tokens that draw liquidity get the full check: verified source, the 10 largest wallets, every pool and the deployer's record. Liquidity is re-read for two days. A pool that held $3,000 or more and lost over 80% of it is marked RUGGED, and a launch that never drew liquidity is marked DEAD after a day. A ticker reused from an earlier launch is flagged as a copy. Danger and rug alerts for pools holding $5,000 or more go to a Telegram channel when `OCULON_RADAR_CHAT` is set. `OCULON_RUGRADAR=0` turns the scan off.
- Wallet Guard at `/guard`: the live approvals of a wallet on Robinhood Chain, Ethereum, Arbitrum, Polygon or Optimism, with risky spenders flagged. A connected wallet can revoke each one (`approve(spender, 0)` or `setApprovalForAll(spender, false)`), or every high-risk one in a row.
- Oculon Shield in `extension/` (Chrome and Edge, Manifest V3): a warning page before phishing and drainer sites, a banner on suspicious ones, a risk pill on token pages, and a toolbar check for any link, wallet or token. It only sends the domain or address being checked to the Oculon API.
- Fixed: approvals on Robinhood Chain were never found, because Blockscout pads log topics with nulls.
- Fixed: holder concentration on Robinhood Chain counted pools, the Uniswap v4 PoolManager, launchpad lockers and burn addresses as holders. EIP-7702 smart accounts still count as wallets.
- Fixed: Robinhood Chain explorer links now go to robinhoodchain.blockscout.com, since robinhood.blockscout.com returns 404.

## 0.2.0

Twenty-two new checks and seven new free sources: wallet safety, pages, files, apps and repos, and one report per target. Still no runtime dependency: the QR reader, the image decoders and the ZIP reader for Office files are written in Oculon itself.

Wallet safety
- `oculon approvals <wallet>` (`oculon_approvals`, `/api/approvals`): who can take tokens out of a wallet right now. Every ERC-20 and NFT approval it signed is re-read on chain, so revoked and used-up ones drop out. Known routers and marketplaces are named; plain wallets, unverified contracts and unknown contracts with unlimited access are flagged. Fake approval events from spam tokens are filtered. Ethereum, Arbitrum and Polygon.
- `oculon contract <token>` (`oculon_contract_risk`): what the owner can still do: mint, blacklist, pause trading, change taxes, limit wallets, change balances, upgrade the code, self-destruct. Read from verified source (Sourcify, Etherscan) or from the selectors in the bytecode, plus owner, proxy admin and implementation, holder concentration, locked liquidity and the main pool. Large established tokens (stablecoins, wrapped assets) are capped at "caution" with a note, since those powers are part of their design. Ethereum, Base, BNB Chain, Arbitrum and Polygon.
- `oculon signature <request>` (`oculon_signature_check`, web app paste): what a signature request really allows before you sign it: ERC-2612 and DAI permits, Permit2 allowances and transfers, Seaport orders that give assets away, approve and setApprovalForAll calldata, multicall bundles, unknown functions, raw eth_sign hashes and messages asking for a seed phrase.
- `oculon poisoning <wallet>` (`oculon_address_poisoning`): lookalike addresses planted in a wallet's history, zero-value transfers it never signed, fake USDT and USDC, and whether funds already went to a lookalike.
- `oculon trace <address>` (`oculon_trace_funds`): where money went, hop by hop, priced in USD, until an exchange, a mixer, a bridge, a contract or a sanctioned address, with transaction hashes for a report.
- `oculon site <link>` (`oculon_site_check`): is this page a wallet drainer or phishing? Receiver addresses written into scripts, permit and Permit2 requests, token-balance APIs, known drainer kits, seed phrase and login forms on the wrong domain, Telegram bot tokens and Discord webhooks, lookalikes of known apps.
- `oculon tx <hash>` (`oculon_tx_explain`): what happened in a transaction, in plain words, and whether tokens were taken with an earlier approval. Spam tokens faking transfers are recognized.
- `oculon creator <token>` (`oculon_token_creator`): who made a token, what else they deployed, how much of it is dead, and who funded them.
- Monitors: `approvals` (new approvals on a wallet) and `contract` (owner changes, code upgrades, liquidity pulls, holder concentration) can be set in plain words, e.g. "watch for a rug pull on 0x...".

Files and repos
- `oculon photo <image>` (`oculon_image_check`): made by AI, edited, or a camera photo? C2PA Content Credentials, IPTC source type, generator settings and prompts (Stable Diffusion, ComfyUI, NovelAI, InvokeAI, Midjourney), EXIF camera and editing software.
- `oculon qr <image>` (`oculon_qr_check`): reads the QR code in a photo or screenshot and checks where it leads: links, crypto payment codes, SEPA payment codes, Wi-Fi, SMS and phone codes.
- `oculon repo <owner/name>` (`oculon_repo_check`): is a GitHub repo safe to run? Install hooks, VS Code tasks that run on folder open, code that downloads and runs code, wallet and browser password theft, webhooks, obfuscation, hidden code, committed programs, account age and bought stars.
- `oculon eml <file>` (`oculon_email_file`): a whole email checked at once: headers, message, links and every attachment.
- `oculon apk <file>` (`oculon_apk_check`): is an Android app safe to install? Permissions banking trojans use, accessibility and SMS abuse, the signer, known malware. The binary manifest is parsed in Oculon.
- `oculon job "<message>"` (`oculon_job_check`): job scam patterns, links, the sender and any repo in the message.
- `oculon where <photo>` (`oculon_photo_location`): where and when a photo was taken, the place, and the weather and daylight at that hour.
- `oculon archive <link>` (`oculon_archive`): save a page as evidence in the Wayback Machine, with its hash.
- `oculon invite <link>` (`oculon_invite_check`): what is behind a Telegram or Discord invite, and whether it poses as a brand or project.
- The document check now reads Word, Excel and PowerPoint files: VBA and Excel 4.0 macros, remote templates, DDE fields, embedded objects, ActiveX, hidden sheets, author and last editor, and the IBANs in the text.

Reports
- `oculon check <domain|0x address>` (`oculon_domain_report`, `oculon_wallet_report`): every relevant check on one page, kept as one check with a replay log and a PDF (`--pdf report.pdf`).

New sources (all free)
- Crypto phishing blocklists in every link check: ScamSniffer (about 358,000 drainer and phishing domains) and MetaMask's eth-phishing-detect list, stored locally and refreshed daily.
- Cloudflare URL Scanner in the site check: the page is also opened in a real browser, so drainer code that loads later, JavaScript redirects and the rendered page are read, and Cloudflare's verdict is added.
- Alchemy: poisoning and the fund trace now run on Base and BNB Chain, prices for tokens DexScreener does not know, NFT spam flags in approvals, and a fallback RPC.
- Blockscout: approvals, poisoning, trace and the token creator on Optimism and Robinhood Chain. The Robinhood Chain address check works again (the shared Blockscout API now needs a key).
- Hybrid Analysis sandbox verdicts in the hash, APK and email attachment checks. Chainabuse victims' reports in the address and site checks. The logged-in Wayback Machine for the archive check.
- `oculon stocktoken [TSLA|0x...]` (`oculon_stock_token`): Robinhood Stock Tokens from Robinhood's official API: contract, live price, sessions, supply, dividends and splits, and fake copies of a ticker.
- Fixed: "seen before" compared checks of the same address on different chains.

Everywhere
- Telegram bot: `/approvals`, `/contract`, `/sig`, `/poison`, `/trace`, `/repo`, `/check`, `/site`, `/tx`, `/creator`, `/job`, `/invite`, `/archive`, `/stock`, and files: a photo for its QR code, an image as a file for the AI and edit check (or with /where for its place and time), a PDF or Office file for the document check, an .eml email and an .apk app.
- Web app: new Investigate options for all of the above, with file upload and paste boxes.
- MCP: 111 tools locally (118 with on-chain on), 109 on the remote server.

## 0.1.7

A document check, and every check is now kept: replay it, download it as a PDF, see what changed since last time. Results show up as cards inside Claude and ChatGPT.

- `oculon doc <file>` (also an upload in the web app and `oculon_doc_check` over MCP): was this invoice, bank statement or payment screenshot edited? It reads the file itself: the programs that made and saved it (online PDF editors, image editors, word processors), creation vs modification date, how many times it was saved, the same font embedded twice, white boxes over text, annotations, digital signatures, and dangerous parts (JavaScript, launch actions, embedded files). Every IBAN in the text is checked. Screenshots and scanned PDFs are read with a free AI vision model (OpenRouter or Gemini) when a key is set, and the result says when an image was sent to one.
- Replay log: every check gets an id. `/replay/<id>`, `oculon replay <id>` and `oculon_replay` list every source it called, in order, with status, time and notes. Checks are kept for 90 days.
- PDF report: `/report/<id>.pdf` and `oculon replay <id> --pdf report.pdf` turn one check into a report to send on, with the verdict, reasons, what to do, history and every source called. Written by Oculon's own PDF writer, so still no runtime dependency.
- Seen before: checking the same thing again says when it was last checked and what changed (verdict, risk, new and gone reasons). Shown in the web app, the API, MCP and the CLI.
- Source status: `/status`, `/api/status`, `oculon status` and `oculon_status` show which sources are up, slow, degraded or down over the last day, measured from real calls.
- Automatic fallback: a source that fails three times in a row is skipped for five minutes, and the cached answer or a mirror is used instead. DNS lookups fall back from Google to Cloudflare and Bitcoin lookups from mempool.space to Blockstream; the result says which host answered.
- Verdict cards: check tools return `structuredContent` and a UI resource (`ui://oculon/verdict.html` for MCP Apps hosts, a Skybridge template for ChatGPT apps), so chat apps that render them show the verdict, risk, reasons, sources and links to the replay log and PDF.
- Brief mode: every MCP tool takes `brief: true` for a short answer (verdict, risk, top reasons, sources, check id) with far fewer tokens.
- `/llms.txt` and `/llms-full.txt`: every tool explained for AI agents, generated from the live tool list.
- Web app: the Investigate tab now offers the document check, IBAN, email headers (with a text box for the raw headers), lookalike domains, crypto address and honeypot checks, and every check shows its replay log and PDF report.
- Fixed: raw email headers over 10 KB were refused by the web app.
- MCP: 91 tools locally (98 with on-chain on), 89 on the remote server.

## 0.1.6

Five new checks that need no API key, OCULON utility, and Robinhood Chain back on the live site.

- `oculon iban <IBAN> [--country NL]`: is this IBAN valid before you pay? Country, length, ISO 13616 check digits and bank code, fully offline, with a warning when the account is in another country than the supplier.
- `oculon headers < headers.txt`: paste the raw headers of a suspicious email and get the SPF, DKIM and DMARC results, the delivery path, the origin IP and country, and spoofing signs (a Reply-To elsewhere, a display name posing as an address, an envelope sender from another domain).
- `oculon lookalike <domain>`: lookalike domains of a brand that exist in DNS (typos, swapped letters, homoglyphs, extra words, other endings), with mail servers, plus certificates issued in the last 90 days for names containing the brand.
- `oculon honeypot <token> [--chain eth|bsc|base]`: can this token be sold? A buy and sell simulation and recent holders' sells (honeypot.is): taxes, holders who could not sell, unpublished or upgradeable contracts.
- `oculon address <address>`: a crypto address before you send funds: chain from the format, US OFAC sanctions, balance, transactions and labels (mempool.space, Blockscout, Solana RPC). Wallets with an EIP-7702 delegation are not mistaken for contracts.
- OCULON utility at `/utility`, read straight from Robinhood Chain: burn 1,500,000 for a deep investigation published as a public page, burn 2,000,000 for a 30-day live safety badge on a token (`/badge/<token>.svg`), or sign in with a wallet holding 3,500,000 for up to 30 personal monitors checked every 15 minutes. Each burn counts once and only the burning wallet can use it. Wallet signatures are checked with keccak256 and secp256k1 written in `src/core/evm.ts`, so there is still no runtime dependency.
- `/thetoken` shows every burn with its time, amount and transaction, read live from the chain.
- Robinhood Chain, wallet and token checks and DeFi are on again at oculon.live (`OCULON_ONCHAIN=1`); the docs describe them. MCP: 88 tools locally (95 with on-chain on), 86 on the remote server.

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
