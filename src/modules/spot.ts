/**
 * Spot the Scam: a daily round of 8 links, the same for everyone on a given UTC date. The scams are real,
 * recently listed crypto phishing domains from the ScamSniffer blocklist (the project's phishing feed, newest
 * first); the legitimate ones come from a fixed list of official sign-in and brand pages written below. Every
 * explanation is worked out from the address by code. If the feed cannot be read, no round is built: scams are
 * never invented. A built round is stored, so a date's round does not change when the feed refreshes.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { ensurePhishLists } from '../sources/phishlists.js';
import { apexOf, urlHeuristics } from './urlcheck.js';

export interface SpotItem {
  n: number;
  /** Defanged address for display: hxxps:// and [.] so it cannot be opened by accident. */
  display: string;
  answer: 'scam' | 'legit';
  brand: string | null;
  signs: string[];
  explanation: string;
  source: string;
  /** Only for legitimate items: the real address, safe to open. */
  url?: string;
}

export interface SpotRound {
  date: string;
  available: boolean;
  reason: string | null;
  items: SpotItem[];
  scams: number;
  legit: number;
  builtAt: string | null;
  share: string;
  note: string;
}

/** Official sign-in and brand pages (addresses opened and checked when this list was written, 2026-11-26). */
export const OFFICIAL: { brand: string; url: string; note?: string }[] = [
  { brand: 'Google', url: 'https://accounts.google.com/' },
  { brand: 'Microsoft', url: 'https://login.microsoftonline.com/', note: 'microsoftonline.com is the domain Microsoft uses for work and school sign-in.' },
  { brand: 'Microsoft', url: 'https://m365.cloud.microsoft/', note: '.microsoft is a brand top-level domain that only Microsoft can register under; Office links now land here.' },
  { brand: 'Microsoft', url: 'https://login.live.com/', note: 'live.com is Microsoft\'s domain for personal account sign-in.' },
  { brand: 'Apple', url: 'https://appleid.apple.com/' },
  { brand: 'Apple', url: 'https://www.icloud.com/', note: 'icloud.com is Apple\'s own domain for iCloud.' },
  { brand: 'Amazon', url: 'https://www.amazon.com/' },
  { brand: 'Netflix', url: 'https://www.netflix.com/login' },
  { brand: 'Instagram', url: 'https://www.instagram.com/accounts/login/' },
  { brand: 'LinkedIn', url: 'https://www.linkedin.com/login' },
  { brand: 'GitHub', url: 'https://github.com/login' },
  { brand: 'Coinbase', url: 'https://login.coinbase.com/' },
  { brand: 'Binance', url: 'https://accounts.binance.com/en/login' },
  { brand: 'Kraken', url: 'https://www.kraken.com/sign-in' },
  { brand: 'MetaMask', url: 'https://metamask.io/' },
  { brand: 'Uniswap', url: 'https://app.uniswap.org/' },
  { brand: 'OpenSea', url: 'https://opensea.io/' },
  { brand: 'Dropbox', url: 'https://www.dropbox.com/login' },
  { brand: 'Discord', url: 'https://discord.com/login' },
  { brand: 'Telegram', url: 'https://web.telegram.org/' },
  { brand: 'Chase', url: 'https://secure.chase.com/', note: 'The word "secure" is a subdomain Chase itself runs; the registrable domain is chase.com.' },
  { brand: 'Wells Fargo', url: 'https://connect.secure.wellsfargo.com/auth/login/present', note: 'A long chain of subdomains is fine when it ends in the real domain, here wellsfargo.com.' },
  { brand: 'Bank of America', url: 'https://www.bankofamerica.com/' },
  { brand: 'USPS', url: 'https://www.usps.com/' },
  { brand: 'FedEx', url: 'https://www.fedex.com/' },
  { brand: 'Steam', url: 'https://store.steampowered.com/login/', note: 'Valve runs Steam on steampowered.com and steamcommunity.com; fakes often use "steamcommunity" look-alikes.' },
  { brand: 'Ledger', url: 'https://www.ledger.com/' },
  { brand: 'Trezor', url: 'https://trezor.io/' },
  { brand: 'X', url: 'https://x.com/i/flow/login' },
  { brand: 'DocuSign', url: 'https://www.docusign.com/' },
  { brand: 'Adobe', url: 'https://account.adobe.com/' },
  { brand: 'HSBC', url: 'https://www.hsbc.com/' },
  { brand: 'Wise', url: 'https://wise.com/login' },
  { brand: 'Safe', url: 'https://app.safe.global/', note: '.global is an ordinary top-level domain; safe.global is the Safe wallet\'s own domain.' },
  { brand: 'Phantom', url: 'https://phantom.com/' },
  { brand: 'OKX', url: 'https://www.okx.com/account/login' },
  { brand: 'Bybit', url: 'https://www.bybit.com/login' },
];

/** Names phishers copy, matched against the labels of a scam domain. */
const LURE_BRANDS = ['metamask', 'uniswap', 'opensea', 'pancakeswap', 'phantom', 'coinbase', 'binance', 'kraken', 'ledger', 'trezor', 'arbitrum', 'optimism', 'zksync', 'layerzero', 'eigenlayer', 'ethena', 'jupiter', 'raydium', 'magiceden', 'lido', 'aave', 'curve', 'sushiswap', '1inch', 'okx', 'bybit', 'kucoin', 'trustwallet', 'rabby', 'starknet', 'celestia', 'polymarket', 'hyperliquid', 'pumpfun', 'blast', 'scroll', 'linea', 'zora', 'base', 'solana', 'ethereum', 'bitcoin', 'tether', 'circle', 'usdc', 'walletconnect', 'safe', 'gnosis', 'chainlink', 'aptos', 'sui', 'ton', 'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'discord', 'telegram', 'steam', 'twitter', 'blur', 'pudgypenguins', 'doodles', 'azuki', 'apecoin', 'yuga', 'otherside', 'firelight', 'elysium', 'sei', 'monad', 'berachain', 'movement', 'hyperlane', 'wormhole', 'jito', 'pyth', 'kamino', 'drift', 'morpho', 'pendle', 'gmx', 'dydx', 'compound', 'maker', 'sky', 'ens'];
const LURE_WORDS = ['claim', 'airdrop', 'reward', 'rewards', 'vote', 'votes', 'voting', 'bonus', 'giveaway', 'verify', 'connect', 'mint', 'drop', 'migrate', 'migration', 'sync', 'validate', 'recover', 'unlock', 'gift', 'presale', 'whitelist', 'refund', 'stake', 'staking', 'points', 'eligibility', 'eligible', 'checker', 'portal', 'dapp', 'support', 'secure', 'wallet', 'proposal', 'snapshot', 'event', 'redeem', 'restore', 'fix', 'rectify', 'bridge', 'allocation', 'governance', 'boost', 'hub', 'swap', 'earn', 'launch'];
const FREE_HOSTS = ['pages.dev', 'vercel.app', 'netlify.app', 'github.io', 'web.app', 'firebaseapp.com', 'workers.dev', 'gitbook.io', 'webflow.io', 'glitch.me', 'replit.app', 'onrender.com', 'wixsite.com', 'weebly.com', 'blogspot.com', 'framer.website', 'framer.app', 'herokuapp.com', 'surge.sh', 'fleek.co', 'ipfs.io', 'square.site', 'godaddysites.com', 'webcindario.com', 'azurewebsites.net', 'r2.dev', 'deno.dev'];

const OFFICIAL_APEX = new Set(OFFICIAL.map((o) => apexOf(new URL(o.url).hostname)));
const SOURCE = 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json';
const POOL = 3000;
const SIZE = 8;

export const defang = (url: string) => url.replace(/^http(s?):\/\//i, 'hxxp$1://').replace(/\./g, '[.]');

function lev(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length]!;
}

/** Why a blocklisted domain looks like a scam, read from the address alone. */
export function scamSigns(domain: string): { signs: string[]; brand: string | null } {
  const host = domain.toLowerCase();
  const signs: string[] = [];
  const free = FREE_HOSTS.find((f) => host.endsWith(`.${f}`));
  if (free) signs.push(`it is hosted on ${free}, a free site builder anyone can use, not on the project's own domain`);
  const own = free ? host.slice(0, -free.length - 1) : host.split('.').slice(0, -1).join('.');
  const tokens = own.split(/[.-]/).filter(Boolean);
  let brand: string | null = null;
  for (const b of LURE_BRANDS) {
    if (tokens.includes(b) || (b.length >= 6 && own.replace(/[.-]/g, '').includes(b))) { brand = b; signs.push(`it uses the name "${b}" but is not on ${b}'s own domain`); break; }
  }
  if (!brand) {
    for (const t of tokens) {
      if (t.length < 5) continue;
      const b = LURE_BRANDS.find((x) => x.length >= 5 && x !== t && lev(t, x) <= (x.length >= 8 ? 2 : 1));
      if (b) { brand = b; signs.push(`"${t}" is a look-alike of "${b}", a letter or two different`); break; }
    }
  }
  const lure = tokens.flatMap((t) => LURE_WORDS.filter((w) => t === w || (w.length >= 4 && t.startsWith(w) && /^\d*$/.test(t.slice(w.length)))));
  if (lure.length) signs.push(`it uses the bait word${lure.length > 1 ? 's' : ''} ${[...new Set(lure)].slice(0, 3).map((w) => `"${w}"`).join(', ')}`);
  if (/\d/.test(tokens.join('')) && tokens.some((t) => /[a-z]\d+$|^\d+$/.test(t))) signs.push('numbers are tacked onto the name, a sign of many copies of the same fake');
  for (const h of urlHeuristics(new URL(`https://${host}/`))) {
    if (/^mentions "/.test(h) && brand) continue;
    signs.push(h);
  }
  return { signs: [...new Set(signs)], brand };
}

export function legitSigns(o: { brand: string; url: string; note?: string }): string[] {
  const host = new URL(o.url).hostname;
  const apex = apexOf(host);
  const out = [`the registrable domain is ${apex}, ${o.brand}'s own domain${host !== apex && host !== `www.${apex}` ? `; "${host.slice(0, -apex.length - 1)}" is a subdomain it controls` : ''}`];
  if (o.url.startsWith('https://')) out.push('it uses https, though that alone proves nothing: most phishing sites do too');
  if (o.note) out.push(o.note);
  return out;
}

/** Deterministic random numbers from a date string (FNV-1a hash into mulberry32). */
export function seeded(seed: string): () => number {
  let h = 2166136261;
  for (const c of seed) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); }
  let a = h >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(rnd: () => number, xs: T[], n: number): T[] => {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j]!, a[i]!]; }
  return a.slice(0, n);
};

/** Build the round for a date from a pool of blocklisted domains, newest first. Pure. */
export function buildRound(date: string, pool: string[]): SpotItem[] {
  const rnd = seeded(`spot:${date}`);
  const seen = new Set<string>();
  const usable = [...new Set(pool.map((d) => d.trim().toLowerCase()))]
    .filter((d) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) && d.length <= 60 && !OFFICIAL_APEX.has(apexOf(d)))
    // One domain per campaign: numbered copies (1-proposal-x, 2-proposal-x) count once.
    .filter((d) => { const k = d.replace(/\d+/g, '#'); if (seen.has(k)) return false; seen.add(k); return true; });
  const nScam = 3 + Math.floor(rnd() * 3);
  // Prefer domains whose address shows at least one sign, so the explanation teaches something.
  const withSigns = usable.filter((d) => scamSigns(d).signs.length);
  // At most two scams on the same parent domain (pages.dev hosts many), so a round shows several tricks.
  const per = new Map<string, number>();
  const scams = pick(rnd, withSigns.length >= nScam ? withSigns : usable, Infinity)
    .filter((d) => { const a = apexOf(d); const n = per.get(a) ?? 0; if (n >= 2) return false; per.set(a, n + 1); return true; })
    .slice(0, nScam);
  if (scams.length < nScam) return [];
  const legit = pick(rnd, OFFICIAL, SIZE - nScam);
  const items: Omit<SpotItem, 'n'>[] = [
    ...scams.map((d) => {
      const { signs, brand } = scamSigns(d);
      const all = [...signs, 'it is on the ScamSniffer blocklist of crypto phishing and wallet-drainer sites'];
      return { display: defang(`https://${d}/`), answer: 'scam' as const, brand, signs: all, explanation: signs.length ? `Scam: ${signs.slice(0, 2).join("; ")}.` : 'Scam: nothing in the address gives it away; only a blocklist or your own bookmark would have caught it.', source: 'ScamSniffer blocklist' };
    }),
    ...legit.map((o) => ({ display: defang(o.url), answer: 'legit' as const, brand: o.brand, signs: legitSigns(o), explanation: `Legit: ${legitSigns(o)[0]}.`, source: 'Oculon official list', url: o.url })),
  ];
  return pick(rnd, items, items.length).map((it, i) => ({ n: i + 1, ...it }));
}

const todayUtc = (ctx: Ctx) => ctx.now().toISOString().slice(0, 10);

export async function spotRound(ctx: Ctx, date?: string): Promise<ModuleResult<SpotRound>> {
  const today = todayUtc(ctx);
  const d = date?.trim() || today;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || Number.isNaN(Date.parse(`${d}T00:00:00Z`)) || new Date(`${d}T00:00:00Z`).toISOString().slice(0, 10) !== d) throw new Error('date must be YYYY-MM-DD');
  if (d > today) throw new Error('that round is not out yet');
  const key = `derived:spot:round:${d}`;
  const share = `Spot the Scam ${d}`;
  const base = { date: d, share, note: 'Scam links are shown defanged (hxxps, [.]) and are never clickable. Do not type them into a browser.' };
  const cached = ctx.store.cacheGet(key);
  if (cached) {
    const items = JSON.parse(cached.body) as SpotItem[];
    return wrap(ctx, { ...base, available: true, reason: null, items, scams: items.filter((i) => i.answer === 'scam').length, legit: items.filter((i) => i.answer === 'legit').length, builtAt: new Date(cached.fetchedAt).toISOString() }, [{ source: 'spot-round', url: SOURCE, status: 'CACHED', fetchedAt: new Date(cached.fetchedAt).toISOString(), note: 'stored round for this date' }]);
  }
  let prov: Provenance[] = [];
  let pool: string[] = [];
  try {
    prov = await ensurePhishLists(ctx);
    pool = (ctx.store.db.prepare("SELECT domain FROM phish_domains WHERE source = 'scamsniffer' ORDER BY rowid LIMIT ?").all(POOL) as { domain: string }[]).map((r) => r.domain);
  } catch (e) {
    prov.push({ source: 'scamsniffer', url: SOURCE, status: 'ERROR', fetchedAt: ctx.now().toISOString(), note: (e as Error).message });
  }
  const items = pool.length ? buildRound(d, pool) : [];
  if (!items.length) {
    return wrap(ctx, { ...base, available: false, reason: 'The phishing feed could not be read, so no round was built today. Oculon does not make up scam links; try again later.', items: [], scams: 0, legit: 0, builtAt: null }, prov);
  }
  ctx.store.cachePut(key, JSON.stringify(items), ctx.now().getTime());
  return wrap(ctx, { ...base, available: true, reason: null, items, scams: items.filter((i) => i.answer === 'scam').length, legit: items.filter((i) => i.answer === 'legit').length, builtAt: ctx.now().toISOString() }, prov);
}

function wrap(ctx: Ctx, r: SpotRound, provenance: Provenance[]): ModuleResult<SpotRound> {
  return { module: 'spot', input: r.date, generatedAt: ctx.now().toISOString(), result: r, signals: [], provenance };
}
