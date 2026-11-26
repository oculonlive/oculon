/**
 * Site check: open a page the way a visitor would and look for what phishing pages and wallet drainers do.
 *   Drainers: wallet connection code next to signature requests that hand over assets (permits, Permit2,
 *     setApprovalForAll, unlimited approve, Seaport orders, eth_sign), a receiver address written into the
 *     script, token-balance APIs used to rank what to take first, and heavy obfuscation.
 *   Phishing: a login, card or seed-phrase form on a domain that is not the brand the page shows, forms that send
 *     to another domain, and Telegram bot tokens or Discord webhooks in the code (phishing kits send what people
 *     type there).
 *   Reputation: the link check (Safe Browsing, URLhaus, urlscan.io, domain age) of the final address after
 *     redirects, and lookalikes of well known apps and brands.
 *   Browser: when a Cloudflare URL Scanner token is set, the page is also opened in a real browser on Cloudflare's
 *     side, so scripts that load later, redirects done in JavaScript and the rendered page are read too, and
 *     Cloudflare's own verdict is added. Victims' reports on the domain come from Chainabuse.
 * The page is fetched here with a normal browser User-Agent; scripts are read here, never run here.
 */
import type { Ctx } from '../core/context.js';
import { publicUrl } from '../core/safeurl.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { apexOf, urlCheck } from './urlcheck.js';
import { browserScan, type BrowserScan } from '../sources/cfurlscan.js';
import { chainabuse, type AbuseReports } from '../sources/chainabuse.js';

export interface SiteReport {
  url: string;
  finalUrl: string;
  domain: string;
  title: string | null;
  verdict: 'wallet drainer' | 'phishing page' | 'suspicious' | 'no known risk found';
  risk: number;
  drainer: string[];
  phishing: string[];
  reputation: { verdict: string; risk: number; ageDays: number | null; reasons: string[] } | null;
  forms: { action: string; password: boolean; seed: boolean; card: boolean; external: boolean }[];
  scripts: { read: number; external: string[] };
  /** The page opened in a real browser (Cloudflare URL Scanner), when configured. */
  browser: { malicious: boolean; categories: string[]; report: string; finalUrl: string | null; domains: number; scripts: number } | null;
  /** Scam reports on the domain filed by victims (Chainabuse). */
  reports: AbuseReports | null;
  exfil: string[];
  reasons: string[];
  advice: string[];
}

/** Brands and apps people are phished for, with the domains that really belong to them. */
const BRANDS: Record<string, string[]> = {
  uniswap: ['uniswap.org'], opensea: ['opensea.io'], pancakeswap: ['pancakeswap.finance'], metamask: ['metamask.io'], blur: ['blur.io'],
  lido: ['lido.fi'], aave: ['aave.com'], curve: ['curve.fi', 'curve.finance'], jupiter: ['jup.ag'], raydium: ['raydium.io'], 'pump.fun': ['pump.fun'],
  'magic eden': ['magiceden.io'], arbitrum: ['arbitrum.io', 'arbitrum.foundation'], layerzero: ['layerzero.network'], zksync: ['zksync.io'],
  eigenlayer: ['eigenlayer.xyz'], etherscan: ['etherscan.io'], coinbase: ['coinbase.com'], binance: ['binance.com'], phantom: ['phantom.app', 'phantom.com'],
  rabby: ['rabby.io'], ledger: ['ledger.com'], trezor: ['trezor.io'], 'revoke.cash': ['revoke.cash'], kraken: ['kraken.com'], bybit: ['bybit.com'], okx: ['okx.com'],
  paypal: ['paypal.com'], apple: ['apple.com', 'icloud.com'], microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'], google: ['google.com'],
  amazon: ['amazon.com'], netflix: ['netflix.com'], facebook: ['facebook.com'], instagram: ['instagram.com'], whatsapp: ['whatsapp.com'], telegram: ['telegram.org', 't.me'],
  dhl: ['dhl.com'], fedex: ['fedex.com'], usps: ['usps.com'], steam: ['steampowered.com', 'steamcommunity.com'], discord: ['discord.com'], docusign: ['docusign.com', 'docusign.net'],
};

const DRAIN: [RegExp, string, number][] = [
  [/\b(receiver|recipient|drainTo|walletReceiver|receiveAddress)\s*[:=]\s*["'`]0x[0-9a-fA-F]{40}["'`]/, 'a receiver address is written into the script: where taken assets go', 35],
  [/0x000000000022d473030f116ddee9f6b43ac78ba3/i, 'asks for Uniswap Permit2 signatures, which can hand over many tokens at once', 10],
  [/\bPermitBatch\b|\bPermitSingle\b|primaryType["']?\s*:\s*["']Permit["']/, 'builds permit signatures in the page', 10],
  [/a22cb465|setApprovalForAll/, 'asks to approve all NFTs of a collection (setApprovalForAll)', 5],
  [/0x095ea7b3[\s\S]{0,400}f{40,}|approve\([^)]{0,120}(MaxUint256|MAX_UINT|maxUint|0xf{20,}|115792089237316195423570985008687907853269984665640564039457584007913129639935)/i, 'asks for unlimited token approvals', 10],
  [/0x00000000000000adc04c56bf30ac9d3c0aaf14dc|0x0000000000000068f116a894984e2db1123eb395|OrderComponents/i, 'builds Seaport marketplace orders (a common way to take NFTs for nothing)', 5],
  [/["']eth_sign["']/, 'uses eth_sign, which signs a blind hash', 5],
  [/getWalletTokenBalances|ankr_getAccountBalance|getTokenBalances|alchemy_getTokenBalances|api\.debank|covalenthq|\/balances_v2\//i, 'reads the visitor\'s token balances to pick what to take first', 15],
  [/signAllTransactions/, 'asks Solana wallets to sign all transactions at once', 5],
  [/wallet_switchEthereumChain[\s\S]{0,2000}wallet_switchEthereumChain/, 'switches the wallet through several chains in a row', 5],
  [/\bdrainer\b|inferno.?drainer|angel.?drainer|pink.?drainer|ms.?drainer|venom.?drainer/i, 'names a known drainer kit', 40],
];
/** Markers a normal app does not have; generic wallet-library strings alone never make a drainer verdict. */
const STRONG = /receiver address is written|known drainer kit|token balances to pick/;
const CONNECTS = /window\.ethereum|ethereum\.request|walletconnect|web3modal|@reown|wagmi|rainbowkit|solana\.connect|window\.solana|phantom\.solana/i;

const edits = (a: string, b: string) => {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)] as number[]);
  for (let j = 1; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length]![b.length]!;
};

const attr = (tag: string, name: string) => new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)?.slice(1).find((x) => x !== undefined) ?? null;

export async function siteCheck(ctx: Ctx, input: string, opts: { browser?: boolean } = {}): Promise<ModuleResult<SiteReport>> {
  const u = publicUrl(input);
  const provenance: Provenance[] = [];
  // The browser scan runs on Cloudflare while the page and its scripts are read here.
  const scanning = opts.browser === false ? Promise.resolve({ data: null as BrowserScan | null, prov: null as Provenance | null }) : browserScan(ctx, u.href).catch(() => ({ data: null as BrowserScan | null, prov: null as Provenance | null }));
  const page = await ctx.http.getPage(u.href, { source: 'site', timeoutMs: 25_000 });
  provenance.push(page.prov);
  if (!page.data) throw new Error(`the page did not open (${page.prov.note ?? page.prov.status})`);
  const finalUrl = page.data.finalUrl;
  const fu = publicUrl(finalUrl);
  const domain = apexOf(fu.hostname);
  const scan = await scanning;
  if (scan.prov) provenance.push(scan.prov);
  // The rendered page (after scripts ran) shows forms and text that the raw HTML may only build later.
  const html = page.data.body.toString('utf8') + (scan.data?.dom ? `\n${scan.data.dom}` : '');
  const lower = html.toLowerCase();
  const title = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(html)?.[1]?.trim() ?? /property=["']og:site_name["'][^>]*content=["']([^"']{1,100})/i.exec(html)?.[1] ?? null;
  const drainer: [string, number][] = [], phishing: [string, number][] = [], exfil: string[] = [];

  // Scripts: inline ones and up to 12 external files, read as text.
  const inline = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]!).join('\n');
  const srcs = [...new Set([...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].map((m) => { try { return new URL(m[1]!, finalUrl).href; } catch { return null; } }).filter((x): x is string => Boolean(x && /^https?:/.test(x))))];
  const external = srcs.filter((s) => apexOf(new URL(s).hostname) !== domain).map((s) => new URL(s).hostname);
  let js = inline, read = 0;
  // Scripts the browser loaded that the raw page did not name (loaded by other scripts).
  for (const extra of (scan.data?.scripts ?? []).filter((x) => !srcs.includes(x)).slice(0, 8)) srcs.push(extra);
  const pick = srcs.filter((s) => !/googletagmanager|google-analytics|gstatic|cloudflareinsights|recaptcha|hotjar|clarity\.ms|facebook\.net|cdn\.jsdelivr\.net\/npm\/(bootstrap|jquery)/i.test(s)).slice(0, 20);
  for (let i = 0; i < pick.length; i += 4) {
    const got = await Promise.all(pick.slice(i, i + 4).map((s) => ctx.http.getPage(s, { source: 'site-script', timeoutMs: 15_000, maxBytes: 1_500_000 })));
    for (const g of got) if (g.data && g.data.status < 400) { js += '\n' + g.data.body.toString('utf8'); read++; }
  }

  // Drainer patterns, which only matter when the page also connects wallets.
  const connects = CONNECTS.test(js) || CONNECTS.test(html);
  if (connects) for (const [re, what, w] of DRAIN) if (re.test(js)) drainer.push([what, w]);
  const obf = (js.match(/_0x[0-9a-f]{4,6}/g) ?? []).length;
  if (obf > 200) (connects ? drainer : phishing).push([`the scripts are heavily obfuscated (${obf} _0x names)`, connects ? 15 : 10]);
  if (connects && drainer.length && /\bclaim\b|airdrop|eligib|reward|mint now|free mint/i.test(html + title)) drainer.push(['wraps the signature requests in an airdrop or claim page', 10]);

  // Where typed data goes.
  for (const m of js.matchAll(/api\.telegram\.org\/bot(\d{6,12}):[\w-]{30,}/g)) exfil.push(`Telegram bot ${m[1]}`);
  for (const m of js.matchAll(/discord(?:app)?\.com\/api\/webhooks\/(\d+)/g)) exfil.push(`Discord webhook ${m[1]}`);
  if (exfil.length) phishing.push([`sends data to ${[...new Set(exfil)].slice(0, 3).join(', ')} from the page: how phishing kits collect what people type`, 45]);

  // Forms.
  const forms: SiteReport['forms'] = [];
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const tag = m[1]!, body = m[2]!;
    const action = attr(tag, 'action') ?? '';
    let target = domain;
    try { target = action ? apexOf(new URL(action, finalUrl).hostname) : domain; } catch {}
    const password = /type\s*=\s*["']?password/i.test(body);
    const seed = /seed|mnemonic|recovery phrase|secret phrase|private key|12 words|24 words|word\s*#?\s*1\b/i.test(body);
    const card = /cc-number|card.?number|cvv|cvc|expir/i.test(body);
    forms.push({ action: action.slice(0, 160), password, seed, card, external: target !== domain });
    if (target !== domain && (password || card || seed)) phishing.push([`a ${seed ? 'seed phrase' : password ? 'login' : 'card'} form sends to another domain (${target})`, 35]);
  }
  const seedText = /enter (your )?(12|24)[- ]word|import (your )?(wallet|seed)|recovery phrase|secret recovery|validate (your )?wallet|sync (your )?wallet|rectify|wallet ?connect.{0,40}manually/i.test(lower);
  if (seedText && (forms.some((f) => f.seed) || /<textarea/i.test(html))) phishing.push(['asks visitors to type a wallet seed phrase or private key: no real app ever does', 70]);

  // Brand on the page vs the domain it is on.
  const pageText = `${title ?? ''} ${(/<h1[^>]*>([\s\S]{0,200}?)<\/h1>/i.exec(html)?.[1] ?? '').replace(/<[^>]+>/g, '')}`.toLowerCase();
  const label = domain.split('.')[0]!;
  for (const [brand, own] of Object.entries(BRANDS)) {
    const owns = own.some((d) => domain === d || domain.endsWith(`.${d}`));
    if (owns) continue;
    const key = brand.replace(/[^a-z]/g, '');
    const near = key.length >= 5 && label !== key && edits(label.replace(/[^a-z]/g, ''), key) <= 2;
    if (near) phishing.push([`the domain ${domain} looks like ${own[0]} (${brand})`, 35]);
    else if ((label === key || new RegExp(`\\b${brand.replace('.', '\\.')}\\b`, 'i').test(pageText)) && (forms.some((f) => f.password || f.seed || f.card) || (connects && drainer.length))) phishing.push([`the page presents itself as ${brand} but is not on ${own[0]}`, 30]);
  }

  if (scan.data?.malicious) phishing.push([`Cloudflare's browser scan marks it malicious${scan.data.categories.length ? ` (${scan.data.categories.join(', ')})` : ''}`, 60]);
  let reports: AbuseReports | null = null;
  try { const ca = await chainabuse(ctx, 'domain', domain); if (ca.prov) provenance.push(ca.prov); reports = ca.data; } catch {}
  if (reports?.count) phishing.push([`${reports.count} scam report${reports.count > 1 ? 's' : ''} about ${domain} filed by victims on Chainabuse${reports.categories.length ? ` (${reports.categories.join(', ')})` : ''}`, reports.trusted || reports.count >= 3 ? 40 : 15]);
  // Reputation of the final address.
  let reputation: SiteReport['reputation'] = null;
  try {
    const r = await urlCheck(ctx, finalUrl);
    provenance.push(...r.provenance.slice(0, 5));
    reputation = { verdict: r.result.verdict, risk: r.result.risk, ageDays: r.result.domainInfo?.ageDays ?? null, reasons: r.result.reasons.slice(0, 6) };
  } catch {}
  if (apexOf(u.hostname) !== domain) phishing.push([`the link redirects to another domain (${apexOf(u.hostname)} -> ${domain})`, 10]);

  // The official domain of a known brand or app is not phishing it, and its wallet code is the real app's.
  const official = Object.entries(BRANDS).find(([, own]) => own.some((d) => domain === d || domain.endsWith(`.${d}`)))?.[0] ?? null;
  const notes: string[] = [];
  if (official) { notes.push(`${domain} is the official domain of ${official}.`); drainer.splice(0, drainer.length, ...drainer.filter(([r]) => STRONG.test(r))); }
  const sum = (xs: [string, number][]) => xs.reduce((s, [, w]) => s + w, 0);
  const strong = drainer.some(([r]) => STRONG.test(r));
  const dRisk = strong ? sum(drainer) : Math.min(25, sum(drainer)), pRisk = sum(phishing);
  const young = reputation?.ageDays !== null && reputation?.ageDays !== undefined && reputation.ageDays < 30;
  const risk = Math.min(100, Math.max(dRisk, pRisk, reputation?.risk ?? 0) + (young && (dRisk || pRisk) ? 15 : 0));
  const verdict: SiteReport['verdict'] = dRisk >= 50 || (dRisk >= 35 && young) ? 'wallet drainer' : pRisk >= 50 || reputation?.verdict === 'malicious' ? 'phishing page' : risk >= 30 ? 'suspicious' : 'no known risk found';
  const reasons = [...(strong || pRisk ? drainer : []), ...phishing].sort((a, b) => b[1] - a[1]).map(([r]) => r);
  if (!strong && !pRisk && drainer.length) notes.push(`The page connects wallets and its code mentions ${drainer.map(([r]) => r.replace(/^(asks for|asks to|asks|builds|uses|reads|switches) /, '')).slice(0, 3).join('; ')}. Wallet libraries contain these for every app, so alone they are not a warning.`);
  reasons.push(...notes);
  if (reputation) reasons.push(...reputation.reasons.slice(0, 3));
  if (!connects && verdict === 'no known risk found') reasons.push('the page does not connect to crypto wallets');
  const advice = verdict === 'wallet drainer'
    ? ['Do not connect a wallet or sign anything on this site.', 'If you already signed, revoke approvals now (oculon approvals <wallet>) and move what is left to a new wallet.']
    : verdict === 'phishing page' ? ['Do not type anything on this page. Go to the real site by typing its address yourself.', 'If you entered a password, change it now and turn on two-factor sign-in.']
      : ['Nothing alarming in the page and its scripts. Still type addresses yourself instead of following links from messages.'];
  const now = ctx.now().toISOString();
  const signals: Signal[] = risk >= 70 ? [{ id: signalId('site', domain), module: 'site', title: `${domain}: ${verdict}`, score: risk, entity: `domain:${domain}`, evidence: reasons.slice(0, 4).map((t) => ({ source: 'oculon-site', text: t, url: finalUrl })), createdAt: now }] : [];
  return {
    module: 'site', input: u.href, generatedAt: now,
    result: { url: u.href, finalUrl, domain, title, verdict, risk, drainer: drainer.map(([r]) => r), phishing: phishing.map(([r]) => r), reputation, forms: forms.slice(0, 10), scripts: { read, external: [...new Set(external)].slice(0, 15) }, browser: scan.data ? { malicious: scan.data.malicious, categories: scan.data.categories, report: scan.data.report, finalUrl: scan.data.finalUrl, domains: scan.data.domains.length, scripts: scan.data.scripts.length } : null, reports, exfil: [...new Set(exfil)], reasons, advice },
    signals, provenance,
  };
}
