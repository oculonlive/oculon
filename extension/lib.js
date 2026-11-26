// Shared helpers for the service worker, popup, options and warning pages.
// Only the domain, link, address or contract being checked is ever sent, and only to the Oculon API.

export const DEFAULTS = {
  siteGuard: true,
  tokenPills: true,
  apiBase: 'https://app.oculon.live',
};

export const SITE_TTL = 6 * 3600_000; // site verdicts are cached for six hours
export const TOKEN_TTL = 30 * 60_000; // token verdicts for thirty minutes

// Chains the /api/contract endpoint accepts (documented: eth, base, bsc, arbitrum, polygon; robinhood tested live).
export const CHAINS = [
  { key: 'robinhood', label: 'Robinhood Chain' },
  { key: 'eth', label: 'Ethereum' },
  { key: 'base', label: 'Base' },
  { key: 'bsc', label: 'BNB Chain' },
  { key: 'arbitrum', label: 'Arbitrum' },
  { key: 'polygon', label: 'Polygon' },
];

export async function getSettings() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  return { ...DEFAULTS, ...s, apiBase: cleanBase(s.apiBase) };
}

export function cleanBase(b) {
  const v = String(b || '').trim().replace(/\/+$/, '');
  return /^https?:\/\/[^\s/]+$/i.test(v) ? v : DEFAULTS.apiBase;
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function apiGet(path, params) {
  const { apiBase } = await getSettings();
  const qs = new URLSearchParams(params).toString();
  let res;
  try {
    res = await fetch(`${apiBase}${path}?${qs}`, { credentials: 'omit', cache: 'no-store', headers: { accept: 'application/json' } });
  } catch {
    throw new ApiError('Oculon could not be reached. Check your connection.', 0);
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* not JSON */
  }
  if (!res.ok) {
    const msg = res.status === 429 ? 'Too many checks in a minute. Try again shortly.' : (body && body.error) || `Oculon answered ${res.status}`;
    throw new ApiError(msg, res.status);
  }
  return body;
}

const PRIVATE_V4 = /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;

// Big, well-known domains (and their subdomains) are not sent for checking.
export const SKIP_DOMAINS = [
  'google.com', 'google.co.uk', 'youtube.com', 'gmail.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
  'x.com', 'twitter.com', 'linkedin.com', 'reddit.com', 'wikipedia.org', 'wikimedia.org', 'github.com',
  'githubusercontent.com', 'gitlab.com', 'stackoverflow.com', 'microsoft.com', 'live.com', 'office.com',
  'bing.com', 'apple.com', 'icloud.com', 'amazon.com', 'netflix.com', 'yahoo.com', 'duckduckgo.com',
  'cloudflare.com', 'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai', 'telegram.org', 'discord.com',
  'twitch.tv', 'spotify.com', 'paypal.com', 'ebay.com', 'zoom.us', 'dropbox.com', 'notion.so', 'medium.com',
  'robinhood.com', 'coinbase.com', 'binance.com', 'kraken.com', 'metamask.io', 'uniswap.org', 'dexscreener.com',
  'etherscan.io', 'blockscout.com', 'coingecko.com', 'coinmarketcap.com', 'oculon.live',
];

/** The hostname to check for a URL, or null when it should be skipped. */
export function checkableHost(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const h = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!h || !h.includes('.')) return null; // localhost, intranet names
  if (/\.(local|localhost|internal|lan|home|arpa|test|invalid)$/.test(h)) return null;
  if (/^\[/.test(h) || h.includes(':')) return null; // IPv6 literals
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) && PRIVATE_V4.test(h)) return null;
  if (SKIP_DOMAINS.some((d) => h === d || h.endsWith(`.${d}`))) return null;
  return h;
}

/** What kind of thing the user typed. */
export function classify(input) {
  const v = String(input || '').trim();
  if (!v) return null;
  if (/^0x[0-9a-fA-F]{40}$/.test(v)) return { kind: 'evm', value: v };
  if (/^0x[0-9a-fA-F]{64}$/.test(v)) return { kind: 'txhash', value: v };
  // Bitcoin, Solana, Tron, Litecoin and other non-EVM addresses go to the address check.
  if (/^(bc1|tb1|ltc1)[0-9a-z]{20,90}$/i.test(v) || /^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(v) || /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(v) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v)) {
    return { kind: 'address', value: v };
  }
  if (/\s/.test(v)) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) || /^[^/\s]+\.[a-z]{2,}([/:?#].*)?$/i.test(v)) return { kind: 'url', value: v };
  return null;
}

/** Turns an API response into one shape the UI can show. level: ok | warn | danger */
export function fromUrlCheck(r) {
  const x = (r && r.result) || {};
  const risk = Number(x.risk) || 0;
  const level = x.verdict === 'malicious' ? 'danger' : x.verdict === 'suspicious' ? (risk >= 70 ? 'danger' : 'warn') : 'ok';
  return { kind: 'url', subject: x.domain || x.host || r.input, verdict: x.verdict || 'unknown', level, score: risk, reasons: list(x.reasons), check: checkOf(r) };
}

export function fromContract(r) {
  const x = (r && r.result) || {};
  const level = x.verdict === 'dangerous contract' || x.verdict === 'risky contract' ? 'danger' : x.verdict === 'caution' ? 'warn' : 'ok';
  const name = [x.name, x.symbol ? `(${x.symbol})` : ''].filter(Boolean).join(' ');
  return { kind: 'contract', subject: name || x.address || r.input, chain: x.chain || null, verdict: x.verdict || 'unknown', level, score: Number(x.risk) || 0, reasons: list(x.reasons).concat(list(x.notes)), advice: browserAdvice(x.advice), check: checkOf(r) };
}

export function fromAddress(r) {
  const x = (r && r.result) || {};
  const reasons = [];
  if (x.sanctioned) reasons.push(`on the OFAC sanctions list${x.sanctionHits && x.sanctionHits.length ? `: ${x.sanctionHits.join(', ')}` : ''}`);
  for (const w of list(x.warnings)) reasons.push(w);
  const rep = x.reports || {};
  if (rep.count) reasons.push(`${rep.count} public report${rep.count === 1 ? '' : 's'} on Chainabuse${rep.categories && rep.categories.length ? ` (${rep.categories.join(', ')})` : ''}${rep.trusted ? `, ${rep.trusted} from trusted reporters` : ', none from trusted reporters'}`);
  if (x.activity && x.activity.label) reasons.push(`labelled ${x.activity.label}`);
  // Follows the address check itself: its warnings and sanctions decide, and only trusted reports add caution.
  const level = x.sanctioned ? 'danger' : list(x.warnings).length || rep.trusted ? 'warn' : 'ok';
  const verdict = x.sanctioned ? 'sanctioned' : level === 'warn' ? 'reports or warnings found' : 'nothing alarming found';
  return { kind: 'address', subject: x.address || r.input, chain: x.network || x.format || null, verdict, level, score: null, reasons, advice: browserAdvice(x.advice), check: checkOf(r) };
}

const list = (a) => (Array.isArray(a) ? a.filter((s) => typeof s === 'string' && s.trim()) : []);
// Advice lines that name a CLI command ("oculon honeypot <address>") are for the terminal, not the browser.
const browserAdvice = (a) => list(a).filter((s) => !/\boculon [a-z]+ </i.test(s));
const checkOf = (r) => (r && r.check && typeof r.check.replay === 'string' ? { id: r.check.id, replay: r.check.replay } : null);

/** Link to the full report page for a check, on the configured server. */
export async function reportUrl(check) {
  if (!check || !/^\/replay\/[A-Za-z0-9_-]+$/.test(check.replay)) return null;
  const { apiBase } = await getSettings();
  return `${apiBase}${check.replay}`;
}

export async function checkInput(input, opts = {}) {
  const c = classify(input);
  if (!c) throw new ApiError('Enter a link, a domain, a wallet address or a token contract.', 400);
  if (c.kind === 'txhash') throw new ApiError('That looks like a transaction hash. Paste a link, domain, wallet or token contract instead.', 400);
  if (c.kind === 'url') return fromUrlCheck(await apiGet('/api/url', { url: c.value }));
  if (c.kind === 'address') return fromAddress(await apiGet('/api/address', { address: c.value }));
  const chain = opts.chain || 'robinhood';
  if (opts.as === 'wallet') return fromAddress(await apiGet('/api/address', chain === 'robinhood' ? { address: c.value, network: 'robinhood' } : { address: c.value }));
  return fromContract(await apiGet('/api/contract', { address: c.value, chain }));
}

export const LEVEL_TEXT = { ok: 'No known threats', warn: 'Be careful', danger: 'Dangerous', unknown: 'Not checked' };
