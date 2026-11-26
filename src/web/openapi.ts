/** OpenAPI 3.1 description of the public read API, for ChatGPT Actions, n8n, Zapier and other tools. */
import { SERVER_INFO } from '../mcp.js';

type P = { name: string; desc: string; example: string; required?: boolean };
const E: [string, string, string, P[]][] = [
  ['/api/scam', 'scamCheck', 'Is this SMS, email or chat message a scam? Checks its links, sender and known scam patterns.', [{ name: 'message', desc: 'The full message text', example: 'USPS: your package is on hold, pay $1.99 at usps-help.top', required: true }]],
  ['/api/url', 'urlCheck', 'Is a link dangerous? Safe Browsing, URLhaus, urlscan.io history, domain age and look-alike checks.', [{ name: 'url', desc: 'Link or domain', example: 'paypa1-secure-login.top/verify', required: true }]],
  ['/api/factcheck', 'factCheck', 'Fact check a claim or a news link against published fact checks and current reporting.', [{ name: 'claim', desc: 'Claim text or article URL', example: 'The Great Wall of China is visible from space', required: true }]],
  ['/api/recall', 'recall', 'Vehicle recalls by VIN or "year make model", or product recalls by name (NHTSA, CPSC, FDA).', [{ name: 'q', desc: 'VIN, vehicle or product', example: '2018 Honda Accord', required: true }]],
  ['/api/emailsec', 'emailSecurity', 'Can someone spoof email from this domain? SPF, DMARC, DKIM, MTA-STS, DNSSEC, with fixes.', [{ name: 'domain', desc: 'Domain', example: 'example.com', required: true }]],
  ['/api/phone', 'phoneCheck', 'Who is calling? Country, line type, carrier, premium-rate and callback-scam warnings for a phone number.', [{ name: 'number', desc: 'Phone number in international format', example: '+1 876 555 0100', required: true }, { name: 'country', desc: 'ISO country code for a national number', example: 'US' }]],
  ['/api/company', 'companyCheck', 'Is this supplier real? EU VAT number (VIES), LEI or company name (GLEIF): status, address, ultimate parent.', [{ name: 'q', desc: 'Company name, LEI or EU VAT number', example: 'NL004495445B01', required: true }]],
  ['/api/breaches', 'dataBreaches', 'Newest data breaches in Have I Been Pwned, or every breach of one domain.', [{ name: 'domain', desc: 'Domain or company (optional)', example: 'adobe.com' }]],
  ['/api/ip', 'ipCheck', 'Who runs this IP, and is it known for abuse? AbuseIPDB, GreyNoise, OTX, VirusTotal, ThreatFox, Spamhaus DROP, Tor, open ports.', [{ name: 'ip', desc: 'IP address or domain', example: '185.220.101.1', required: true }]],
  ['/api/hash', 'hashCheck', 'Is this file known malware or a known good file? MD5, SHA-1 or SHA-256.', [{ name: 'hash', desc: 'File hash in hex', example: '094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d', required: true }]],
  ['/api/ransomware', 'ransomwareClaims', 'Ransomware leak-site claims: newest, or by country code, sector, company or domain.', [{ name: 'q', desc: 'Country code, sector, company or domain (optional)', example: 'Healthcare' }]],
  ['/api/prove', 'proveStatus', "Look up a Bitcoin timestamp (OpenTimestamps) by a file's SHA-256: pending, or confirmed in block N at time T. Submit new ones with POST /api/prove from oculon.live/prove.", [{ name: 'hash', desc: 'SHA-256 of the file (hex)', example: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', required: true }]],
  ['/api/terms', 'termsRead', 'Flag the clauses in terms of service or a contract worth reading twice (auto-renewal, arbitration, data sharing, penalties...), each quoted verbatim. URL form; POST {text} for pasted text.', [{ name: 'url', desc: 'URL of the terms page', example: 'https://www.spotify.com/us/legal/end-user-agreement/', required: true }]],
  ['/api/down', 'downStatus', 'Is it down? Official status pages of popular services (components with problems, open incidents), plus a labelled one-location probe for services without a status feed. Problems first.', [{ name: 'service', desc: 'Optional service id, name or domain', example: 'github' }]],
  ['/api/charity', 'charityCheck', 'Check a US-registered nonprofit by name or EIN: IRS registration, 501(c) subsection, latest filings with revenue, expenses and assets, and warnings.', [{ name: 'q', desc: 'Charity name or EIN', example: 'red cross', required: true }, { name: 'ein', desc: 'EIN of the match to open', example: '53-0196605' }]],
  ['/api/brandshield', 'brandShield', "Domains imitating a brand: lookalikes, new certificates naming the brand, DNS, and the URL check on the top live ones, ranked with reasons.", [{ name: 'domain', desc: "The brand's own domain", example: 'example.com', required: true }]],
  ['/api/wire', 'wireToday', 'Oculon Wire: the strongest stored signals of the last 24 hours, at most six, one per desk (internet, air and sea, hazards, cyber, markets, space), each with its sources and time, plus a ready X post. Image: /wire/today.png.', [{ name: 'date', desc: 'Optional UTC day, YYYY-MM-DD', example: '2026-11-26' }]],
  ['/api/trends', 'scamTrends', 'Scam Trends: counts of the checks people ran in the last 7 days (by kind, verdict, scam pattern, impersonated brand, top-level domain) against the week before. Counts only; groups under 3 are hidden.', [{ name: 'days', desc: 'Window in days, 1-30', example: '7' }]],
  ['/api/rescue', 'rescuePlan', 'I got scammed: a merged checklist (next 10 minutes, today, this week) for one or more situations, and official reporting links for a country. Without parameters it returns the catalog.', [{ name: 'situation', desc: 'Comma-separated: link, password, code, seed, signed, card, bank, crypto, remote, id, takeover', example: 'seed,signed' }, { name: 'country', desc: 'US, GB, CA, AU, NZ, IE, FR, NL, ES, SG, EU or OTHER', example: 'GB' }]],
  ['/api/spot', 'spotTheScam', "Spot the Scam: the day's 8 defanged links (real blocklisted phishing domains and real official sign-in pages), with answers and explanations. The same round for everyone on a UTC date.", [{ name: 'date', desc: 'Optional UTC day, YYYY-MM-DD', example: '2026-11-27' }]],
  ['/api/iban', 'ibanCheck', 'Check an IBAN offline: country, length, check digits, bank code, and whether the account is in the supplier\'s country.', [{ name: 'iban', desc: 'IBAN', example: 'DE89 3704 0044 0532 0130 00', required: true }, { name: 'country', desc: 'Supplier ISO country code', example: 'NL' }]],
  ['/api/lookalike', 'lookalikes', 'Lookalike domains of a brand that exist in DNS, and new certificates naming the brand.', [{ name: 'domain', desc: 'The real domain', example: 'example.com', required: true }]],
  ['/api/honeypot', 'honeypotCheck', 'Can this token be sold? Buy and sell simulation with taxes (Ethereum, BNB Chain, Base).', [{ name: 'address', desc: 'Token contract address', example: '0x6982508145454Ce325dDbE47a25d4ec3d2311933', required: true }, { name: 'chain', desc: 'eth, bsc or base', example: 'eth' }]],
  ['/api/address', 'addressCheck', 'Crypto address check without keys: chain, OFAC sanctions, balance and activity.', [{ name: 'address', desc: 'Crypto address', example: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', required: true }, { name: 'network', desc: '"robinhood" for Robinhood Chain 0x addresses', example: 'robinhood' }]],
  ['/api/approvals', 'approvalsCheck', 'Who can take tokens out of this wallet: active ERC-20 and NFT approvals, re-read on chain, risky spenders flagged.', [{ name: 'address', desc: 'Wallet address', example: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045', required: true }, { name: 'chain', desc: 'eth, arbitrum or polygon', example: 'eth' }]],
  ['/api/contract', 'contractRisk', 'What the owner of a token contract can still do: mint, blacklist, taxes, upgrades; owner, holders and liquidity.', [{ name: 'address', desc: 'Token contract address', example: '0x6982508145454Ce325dDbE47a25d4ec3d2311933', required: true }, { name: 'chain', desc: 'eth, base, bsc, arbitrum or polygon', example: 'eth' }]],
  ['/api/poisoning', 'poisoningCheck', 'Lookalike addresses, zero-value transfers and fake tokens planted in a wallet history.', [{ name: 'address', desc: 'Wallet address', example: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045', required: true }, { name: 'chain', desc: 'eth, arbitrum or polygon', example: 'eth' }]],
  ['/api/trace', 'traceFunds', 'Follow funds out of an address hop by hop until exchanges, mixers, bridges or sanctioned addresses.', [{ name: 'address', desc: 'Wallet address', example: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045', required: true }, { name: 'chain', desc: 'eth, arbitrum or polygon', example: 'eth' }, { name: 'hops', desc: 'Hops to follow, 1-4', example: '3' }]],
  ['/api/repo', 'repoCheck', 'Is this GitHub repo safe to run? Install hooks, remote code, wallet and browser theft, obfuscation, fake stars.', [{ name: 'repo', desc: 'owner/name or github.com link', example: 'expressjs/express', required: true }]],
  ['/api/report/domain', 'domainReport', 'Full report on a domain: link check, email protection, exposure, lookalikes, company.', [{ name: 'domain', desc: 'Domain', example: 'example.com', required: true }]],
  ['/api/report/wallet', 'walletReport', 'Full report on a wallet (address, approvals, poisoning, fund trace) or a token (contract risk, sell simulation).', [{ name: 'address', desc: 'Wallet address', example: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045', required: true }, { name: 'chain', desc: 'eth, arbitrum, polygon, base or bsc', example: 'eth' }]],
  ['/api/site', 'siteCheck', 'Open a page and look for wallet drainer code and phishing forms, brand copies and Telegram exfiltration.', [{ name: 'url', desc: 'Page link', example: 'https://example.com', required: true }]],
  ['/api/tx', 'explainTx', 'Explain a transaction: function, transfers, approvals, tokens taken with an earlier approval.', [{ name: 'hash', desc: 'Transaction hash', example: '0xe8701d00f5a33788ab823bb8c32a3863395083914c43c2d97fd50dc33e65ceb5', required: true }, { name: 'chain', desc: 'eth, base, arbitrum, bsc or polygon (found automatically)', example: 'eth' }]],
  ['/api/creator', 'creatorCheck', 'Who created a token and how many of their other tokens are dead.', [{ name: 'address', desc: 'Token contract address', example: '0x6982508145454Ce325dDbE47a25d4ec3d2311933', required: true }, { name: 'chain', desc: 'eth, arbitrum or polygon', example: 'eth' }]],
  ['/api/archive', 'archivePage', 'Save a page in the Wayback Machine as evidence, with its hash and status.', [{ name: 'url', desc: 'Page link', example: 'https://example.com', required: true }]],
  ['/api/invite', 'inviteCheck', 'What is behind a Telegram or Discord invite: members, age, verified badge, scam labels, impersonation.', [{ name: 'link', desc: 'Invite link', example: 'https://t.me/durov', required: true }]],
  ['/api/stocktoken', 'stockToken', 'Robinhood Stock Tokens: official contract, live price, corporate actions; or whether an address is a fake one.', [{ name: 'q', desc: 'Ticker, token address, or empty', example: 'TSLA' }]],
  ['/api/check', 'getCheck', 'An earlier check by its id (returned as check.id by every check): verdict, every source call in order, what changed since the check before it, and the full result.', [{ name: 'id', desc: 'Check id', example: 'qQcUfNGmZgrcQ9kD', required: true }]],
  ['/api/status', 'sourceStatus', 'Which sources are up, slow, degraded or down, from real calls: success rate, median time, last error.', [{ name: 'hours', desc: 'Window in hours (default 24, max 48)', example: '24' }]],
  ['/api/satellites', 'satellites', 'Satellites launched in the last 30 days, or one object\'s orbit, owner and status.', [{ name: 'q', desc: 'Satellite name or NORAD number (optional)', example: '25544' }]],
  ['/api/travel', 'travelRisk', 'Travel risk for the coming week: official advice, weather, air, outbreaks, disasters, quakes, outages.', [{ name: 'place', desc: 'City or country', example: 'Lisbon', required: true }]],
  ['/api/airport', 'airportStatus', 'Airport weather (METAR, TAF), FAA delays and ground stops, nearby emergency squawks.', [{ name: 'code', desc: 'IATA or ICAO code, or name', example: 'JFK', required: true }]],
  ['/api/country', 'countryBrief', 'Country brief: economy, IMF outlook, leaders, currency, travel advice, outages, headlines.', [{ name: 'name', desc: 'Country name or ISO code', example: 'Argentina', required: true }]],
  ['/api/papers', 'researchPapers', 'Research brief: most cited and newest papers on a topic, growth per year, a cited overview.', [{ name: 'topic', desc: 'Research topic', example: 'solid-state battery', required: true }]],
  ['/api/audit', 'dependencyAudit', 'Dependency health: vulnerabilities, deprecation, staleness, OpenSSF Scorecard.', [{ name: 'packages', desc: 'Space-separated npm:name@version or pypi:name==version items', example: 'npm:lodash@4.17.15 pypi:requests==2.19.0', required: true }]],
  ['/api/cve', 'cve', 'One CVE in depth: severity, exploitation odds, exploited-in-the-wild status, fixes.', [{ name: 'id', desc: 'CVE id', example: 'CVE-2024-3400', required: true }]],
  ['/api/vulns', 'exploitedVulnerabilities', 'Vulnerabilities newly exploited in the wild, new critical CVEs and package advisories.', [{ name: 'days', desc: 'Look-back window (1-30)', example: '7' }, { name: 'vendor', desc: 'Vendor or product filter', example: 'Microsoft' }]],
  ['/api/hazards', 'disasterAlerts', 'Official orange and red disaster alerts worldwide, tsunami bulletins and severe US weather.', []],
  ['/api/blackout', 'internetOutages', 'Internet outages and shutdowns by country and network.', []],
  ['/api/cloud', 'cloudOutages', 'Open incidents on AWS, Azure, Google Cloud, GitHub, Cloudflare, OpenAI and more.', []],
  ['/api/bgp', 'bgpRouting', 'BGP hijacks and route leaks worldwide, or routing of a country, network or IP.', [{ name: 'q', desc: 'world, a country code, ASN or IP', example: 'world' }]],
  ['/api/air', 'airQuality', 'PM2.5 air quality near a place.', [{ name: 'place', desc: 'Place', example: 'New Delhi', required: true }]],
  ['/api/space', 'spaceWeather', 'Geomagnetic storms, solar flares and coronal mass ejections.', []],
  ['/api/radar', 'radar', 'What the world is suddenly paying attention to, fused across sources.', []],
  ['/api/signals', 'signals', 'Latest scored signals from every module.', [{ name: 'limit', desc: 'How many (max 200)', example: '20' }]],
];

export function openApiSpec(serverUrl: string): Record<string, unknown> {
  const paths: Record<string, unknown> = {};
  for (const [path, op, summary, params] of E) {
    paths[path] = {
      get: {
        operationId: op,
        summary,
        parameters: params.map((p) => ({ name: p.name, in: 'query', required: Boolean(p.required), description: p.desc, schema: { type: 'string' }, example: p.example })),
        responses: {
          '200': { description: 'Result with provenance (which sources answered, live or cached).', content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
          '400': { description: 'Missing or invalid parameter.' },
        },
      },
    };
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'Oculon API',
      version: SERVER_INFO.version,
      description: 'Open-source intelligence checks with sources on every answer: scam messages, links, claims, recalls, email domains, travel risk, airports, countries, research papers, dependencies, vulnerabilities, outages and disasters. Free, no key. MCP clients can use https://mcp.oculon.live instead.',
      license: { name: 'MIT', url: 'https://github.com/oculonlive/oculon/blob/main/LICENSE' },
    },
    servers: [{ url: serverUrl }],
    paths,
  };
}
