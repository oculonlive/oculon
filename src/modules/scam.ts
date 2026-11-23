/**
 * Scam message check: paste a text, email or chat message and get a verdict with the reasons.
 *   Every link in it goes through the URL check (Safe Browsing, URLhaus, urlscan.io, domain age, look-alikes).
 *   The sender's email domain, when present, gets its age and its email protection.
 *   Known scam patterns are matched in plain code: urgency, account locked, parcel fees, prizes, refunds,
 *   one-time codes, gift cards and crypto payments, job and investment promises, impersonated brands.
 *   An LLM, when configured, adds a short explanation; the verdict itself comes from the evidence above.
 */
import type { Ctx } from '../core/context.js';
import { complete } from '../core/llm.js';
import { clamp } from '../core/stats.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { apexOf, urlCheck, type UrlCheck } from './urlcheck.js';

export type ScamVerdict = 'likely scam' | 'suspicious' | 'no strong signs';

export interface ScamCheck {
  verdict: ScamVerdict;
  risk: number;
  reasons: string[];
  patterns: { name: string; evidence: string }[];
  links: { url: string; verdict: UrlCheck['verdict']; risk: number; reasons: string[] }[];
  sender: { email: string; domain: string; freeMail: boolean } | null;
  phones: string[];
  advice: string[];
  explanation: string | null;
}

const PATTERNS: { name: string; weight: number; re: RegExp }[] = [
  { name: 'urgency or threat', weight: 15, re: /\b(urgent|immediately|within (24|48) hours|final (notice|warning)|last chance|act now|expires? today|will be (suspended|closed|deleted|blocked)|legal action|arrest warrant)\b/i },
  { name: 'account locked or verify your account', weight: 20, re: /\b(account (has been |is )?(suspended|locked|limited|restricted|on hold|compromised)|verify your (account|identity|details)|unusual (sign[- ]?in|activity)|confirm your (password|details|information))\b/i },
  { name: 'parcel or delivery fee', weight: 25, re: /\b(parcel|package|delivery|shipment)\b[\s\S]{0,80}\b(fee|pay|held|on hold|failed|unpaid|customs|redeliver|re-?schedule)\b/i },
  { name: 'prize, lottery or giveaway', weight: 25, re: /\b(you('ve| have)? won|winner|lottery|jackpot|claim your (prize|reward|gift)|selected to receive|free (iphone|gift)|giveaway|airdrop|you (were|have been|are|got) (selected|chosen|picked)|(selected|chosen|picked) as (the|a|one of)|lucky (winner|recipient|one))\b/i },
  { name: 'asks for your crypto wallet or recovery phrase', weight: 35, re: /\b(seed phrase|recovery phrase|secret (recovery )?phrase|private key|1[2-8][- ]word|connect your wallet|(validate|verify|sync|rectify) your wallet)\b|\b(send|share|give|drop|reply with|dm|tell)\b(?: me)?[\s\S]{0,25}\b(sol|solana|eth|ethereum|btc|bitcoin|usdt|bnb|trx|crypto|wallet|metamask|phantom|trust ?wallet)\s+(wallet\s+)?(address|addy|wallet)\b/i },
  { name: 'refund or tax rebate', weight: 20, re: /\b(refund|rebate|overpaid|reimbursement|compensation)\b[\s\S]{0,60}\b(claim|click|eligible|pending|approved)\b/i },
  { name: 'asks for a one-time code or password', weight: 40, re: /\b(otp|one[- ]time (code|password)|verification code|security code|6-digit code|pin)\b[\s\S]{0,60}\b(send|share|reply|tell|give|forward)\b|\b(send|share|reply with|tell me|give me|forward)\b[\s\S]{0,40}\b(otp|code|password|pin)\b/i },
  { name: 'gift card or crypto payment', weight: 30, re: /\b(gift ?cards?|itunes card|google play card|steam card|pay (in|with|via) (bitcoin|btc|usdt|crypto)|bitcoin atm|wallet address)\b/i },
  { name: 'job offer that pays too easily', weight: 20, re: /\b(work from home|part[- ]time job|earn \$?\d+[\s\S]{0,15}(per|a) (day|hour)|daily (salary|income)|like (videos|posts) (and|to) earn|task[- ]based)\b/i },
  { name: 'guaranteed investment returns', weight: 25, re: /\b(guaranteed (profit|return)s?|double your (money|investment)|\d{2,3}% (return|profit)|risk[- ]free investment|trading (signal|mentor)|recover your (lost )?(funds|crypto))\b/i },
  { name: 'a "new number" or a request for secrecy', weight: 25, re: /\b(this is my new number|my new number|lost my phone|phone (is )?broken|don't tell (anyone|dad|mom|mum)|keep (this|it) (between us|confidential|secret|quiet))\b/i },
  { name: 'asks you to send money', weight: 20, re: /\b(send|transfer|wire|lend|pay)\b(?: me)?[\s\S]{0,25}(\$|€|£|usd|eur|gbp)\s?\d|\b(send|transfer|wire|lend)\b(?: me)? (some )?(money|cash|funds)\b/i },
  { name: 'crypto promotion or fake volume offer', weight: 35, re: /\b(promot(e|ion|ing) (your|ur|the) (project|token|coin|community|launch)|(massive|organic|real|huge) (volume|holders|buyers|traction)|volume bots?|diamond holders|increase (your |ur )?(project'?s? )?(market ?cap|mc|holders|volume)|(trend(ing)?) on (dextools|dexscreener|coingecko|cmc|birdeye|pump\.?fun|twitter|x)|(cmc|coingecko|coinmarketcap|cg|cex) listings?|fast[- ]track listing|kol (campaign|marketing|promotion)s?|shill(ing)? (campaign|service|team)|raid (team|service)s?|call channels?|promote on all chains|pump (your|ur) (chart|token|coin))\b/i },
  { name: 'unsolicited paid service for your token', weight: 30, re: /\b(how to buy (guide|video|tutorial)|(logo|banner|website|video|meme|sticker|animation)s? for (your|ur) (token|project|coin|memecoin))\b|\b(yo|hey|hi|hello|dear|gm) dev\b[\s\S]{0,220}\b(dm|d m|telegram|details|\$\s?\d+)|\bfor (your|ur) (token|project|coin|memecoin)\b[\s\S]{0,160}(\$\s?\d+|\d+\s?(usdt|usd|sol|eth|bnb)\b|check my (last |previous |past )?work)/i },
  { name: 'exclusive early-access or signals pitch', weight: 25, re: /\b(right circle|inner circle|private (group|circle|channel|community)|vip (group|channel|signals?|access)|alpha (group|channel|calls?|chat)|position(ing|ed)? (early|smart)|get in early|before (it|they) (pumps?|moons?|trends?|explodes?)|first wave|next \d{2,4}x|\d{2,4}x (gems?|coins?|potential|returns?)|insider (info|calls|tips|access)|(trading|crypto|forex) signals?|pump (group|signals?))\b/i },
  { name: 'hype or fear of missing out', weight: 10, re: /\b(don'?t miss (out|this)|before it'?s too late|limited (spots|slots|seats)|only \d+ (spots|slots|seats) left|access matters|timing matters|being early|early (access|entry|birds?)|to the moon|life[- ]changing (money|opportunity)|financial freedom|passive income)\b/i },
  { name: 'fake support or wallet "validation"', weight: 35, re: /\b(i('m| am) (from|with) (the )?(support|admin|help ?desk|security|compliance) team|(binance|coinbase|metamask|trust ?wallet|phantom|kraken|ledger|okx|bybit|kucoin) (support|team|security|admin)|wallet (validation|synchroni[sz]ation|sync|migration|rectification|whitelisting)|(claim|unlock|release) your (airdrop|tokens|funds|rewards)|dapp (link|portal|connect))\b/i },
  { name: 'investment platform that needs a fee to withdraw', weight: 35, re: /\b((withdrawal|unlock|release|clearance|verification|upgrade) (fee|tax|deposit)|pay (the |a |an )?(tax|fee|deposit) (to|before|in order to) (withdraw|release|unlock)|(liquidity|usdt|cloud|defi) mining|mining pool|arbitrage (bot|platform|trading)|my (uncle|aunt|mentor|teacher|cousin) (works|taught|showed|is an analyst)|(trading|investment) platform\b[\s\S]{0,60}\b(profit|returns?|deposit|withdraw))\b/i },
  { name: 'task job that asks for a deposit', weight: 30, re: /\b((optimi[sz]ation|rating|review|data|order) tasks?|complete (\d+ )?tasks (a|per) day|(recharge|top[- ]?up|deposit) (to|before|in order to) (unlock|continue|complete|withdraw)|commission (per|for each|on every) (task|order|review)|negative balance)\b/i },
  { name: 'funds recovery offer', weight: 35, re: /\b((funds?|crypto|scam|asset) recovery (service|expert|agent|team|company)|recovery (expert|agent|specialist|hacker)|ethical hacker|hire a hacker|we (can )?(help )?(get|bring) (your |the )?(money|funds|crypto) back)\b/i },
  { name: 'blackmail or sextortion', weight: 45, re: /\b(i (have )?(recorded|hacked|filmed) (you|your)|(webcam|camera) (recording|footage)|intimate (video|photos?|pictures)|send (it|this|the (video|photos?)) to (all )?your (contacts|friends|family|colleagues)|(or|otherwise) (i will|i'll) (send|share|publish|release|leak))\b/i },
  { name: 'tech support or fake subscription renewal', weight: 30, re: /\b(your (computer|pc|device|phone|mac) (is|has been) (infected|hacked|compromised|locked)|(call|contact) (microsoft|apple|windows|norton|mcafee) support|(norton|mcafee|geek squad|amazon prime|paypal)\b[\s\S]{0,50}\b(renew(al|ed)?|subscription|charged|invoice|order)\b[\s\S]{0,80}\b(call|cancel|dispute|refund)|toll[- ]free)\b/i },
  { name: 'loan that wants a fee first', weight: 30, re: /\b((instant|guaranteed|pre[- ]?approved) loan|loan (has been |is )?approved|no credit check|(processing|insurance|activation|registration) fee\b[\s\S]{0,40}\bloan|loan\b[\s\S]{0,40}\b(processing|insurance|activation|registration) fee)\b/i },
  { name: 'government, toll or tax impersonation', weight: 25, re: /\b(irs|hmrc|social security (number|administration)|ssn (has been |is )?(suspended|compromised|blocked)|tax (office|department|authority) [\s\S]{0,40}(owe|unpaid|refund)|toll (charges?|payment|violation|balance)|unpaid (toll|tax|fine|ticket)|outstanding (toll|fine|penalty|balance)[\s\S]{0,40}(pay|avoid))\b/i },
  { name: 'wrong-number or cold friendly opener', weight: 10, re: /^\s*((hi|hello|hey)[\s,!.]*)?(is this|are you) [A-Z][a-z]+\b|\b(sorry,? (wrong number|i (must have )?(texted|messaged) the wrong (person|number))|remember me\?)/i },
  { name: 'moves you to a private chat', weight: 10, re: /\b(check (my|the|your) (dm|d m|inbox|pm)|in (the |my )?d ?m\b|dm me|pm me|message me on (whatsapp|telegram|signal)|add me on (whatsapp|telegram|signal|wechat|line)|contact (me|us) on (whatsapp|telegram))\b/i },
  { name: 'link shortener or tracking link', weight: 10, re: /\b(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|tiny\.cc)\//i },
];

const BRANDS = /\b(paypal|apple|amazon|netflix|microsoft|google|facebook|instagram|whatsapp|dhl|fedex|ups|usps|royal mail|irs|hmrc|bank|visa|mastercard|binance|coinbase|metamask)\b/i;
const FREE_MAIL = /^(gmail|googlemail|yahoo|outlook|hotmail|live|aol|icloud|proton|protonmail|gmx|mail|yandex|zoho)\.[a-z.]+$/i;

/** Links, sender address and phone numbers found in a message. */
export function extractParts(text: string): { urls: string[]; sender: string | null; emails: string[]; phones: string[] } {
  const urls = new Set<string>();
  for (const m of text.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/gi)) urls.add(m[0].replace(/[.,;:!?]+$/, ''));
  // Bare domains such as "paypal-verify.top/login" (common in SMS), skipping e-mail addresses.
  for (const m of text.matchAll(/(?<![@\w/.-])((?:[a-z0-9-]+\.)+(?:com|net|org|info|top|xyz|site|online|shop|live|link|click|io|co|me|app|club|vip|icu|cc|ly|gd|at|us|uk|ru|cn|tk|ml|ga|cf)(?:\/[^\s<>"')\]]*)?)/gi)) {
    if (![...urls].some((u) => u.includes(m[1]!))) urls.add(m[1]!.replace(/[.,;:!?]+$/, ''));
  }
  const emails = [...new Set([...text.matchAll(/[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi)].map((m) => m[0].toLowerCase()))];
  const from = /^(?:from|sender|reply-to)\s*:\s*.*?([\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+)/im.exec(text)?.[1]?.toLowerCase() ?? null;
  const phones = [...new Set([...text.matchAll(/(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)/g)].map((m) => m[0].replace(/[^\d+]/g, '')).filter((p) => p.replace(/\D/g, '').length >= 8 && p.replace(/\D/g, '').length <= 15))];
  return { urls: [...urls].slice(0, 8), sender: from ?? emails[0] ?? null, emails, phones };
}

export async function scamCheck(ctx: Ctx, text: string): Promise<ModuleResult<ScamCheck>> {
  const msg = text.trim().slice(0, 6000);
  if (msg.length < 8) throw new Error('paste the message you received');
  const parts = extractParts(msg);
  const provenance: Provenance[] = [];
  const links: ScamCheck['links'] = [];
  for (const u of parts.urls.slice(0, 5)) {
    try {
      const r = await urlCheck(ctx, u);
      provenance.push(...r.provenance);
      links.push({ url: r.result.url, verdict: r.result.verdict, risk: r.result.risk, reasons: r.result.reasons.slice(0, 3) });
    } catch {
      // not a checkable link
    }
  }
  const patterns = PATTERNS.flatMap((p) => { const m = p.re.exec(msg); return m ? [{ name: p.name, evidence: m[0].slice(0, 80), weight: p.weight }] : []; });
  const senderDomain = parts.sender ? parts.sender.split('@')[1]! : null;
  const sender = parts.sender && senderDomain ? { email: parts.sender, domain: senderDomain, freeMail: FREE_MAIL.test(senderDomain) } : null;

  const reasons: string[] = [];
  let risk = 0;
  const bad = links.filter((l) => l.verdict === 'malicious');
  const sus = links.filter((l) => l.verdict === 'suspicious');
  if (bad.length) { risk = Math.max(risk, 90); reasons.push(`${bad.length} link${bad.length === 1 ? ' is' : 's are'} known to be malicious: ${bad.map((l) => new URL(l.url).hostname).join(', ')}`); }
  if (sus.length) { risk += 35; reasons.push(`${sus.length} link${sus.length === 1 ? ' looks' : 's look'} suspicious: ${sus.map((l) => `${new URL(l.url).hostname} (${l.reasons[0] ?? 'warning signs'})`).join('; ')}`); }
  for (const p of patterns) { risk += p.weight; reasons.push(`${p.name}: "${p.evidence}"`); }
  // "Hi mum, new number, send money" is one of the most common scams: the pair counts more than its parts.
  if (patterns.some((p) => /new number/.test(p.name)) && patterns.some((p) => /send money/.test(p.name))) { risk += 20; reasons.push('a new number asking for money is the "hi mum" family-impersonation scam'); }
  // Several crypto scam signs in one message weigh more than each alone.
  const cryptoHits = patterns.filter((p) => /crypto|token|early-access|fake support|withdraw/.test(p.name)).length;
  if (cryptoHits >= 2) { risk += 15; reasons.push('several crypto scam signs appear together'); }
  // A giveaway that wants your wallet is the crypto "you were selected" scam.
  if (patterns.some((p) => /giveaway/.test(p.name)) && patterns.some((p) => /crypto wallet/.test(p.name))) { risk += 20; reasons.push('a giveaway that asks for your wallet is a common crypto scam'); }
  const brand = BRANDS.exec(msg)?.[1];
  if (brand && sender && (sender.freeMail || !senderDomain!.includes(brand.toLowerCase().replace(/\s+/g, '')))) { risk += 25; reasons.push(`mentions ${brand} but the sender is ${sender.email}`); }
  if (brand && links.length && links.every((l) => !apexOf(new URL(l.url).hostname).includes(brand.toLowerCase().replace(/\s+/g, '')))) { risk += 15; reasons.push(`mentions ${brand} but its links go elsewhere`); }
  risk = clamp(Math.round(risk), 0, 100);
  const verdict: ScamVerdict = bad.length || risk >= 60 ? 'likely scam' : risk >= 30 ? 'suspicious' : 'no strong signs';

  const advice: string[] = [];
  if (verdict !== 'no strong signs') {
    advice.push('Do not click the links or reply. Open the company\'s app or type its address yourself.');
    if (patterns.some((p) => /code|password/.test(p.name))) advice.push('Never share a one-time code: no real company asks for it.');
    if (patterns.some((p) => /gift card|crypto payment/.test(p.name))) advice.push('Requests for gift cards or crypto are almost always fraud.');
    if (patterns.some((p) => /crypto wallet/.test(p.name))) advice.push('Never share a recovery phrase or private key, and ignore "giveaways" that ask for your wallet: they lead to drained wallets or fake fees.');
    if (patterns.some((p) => /promotion|paid service|early-access/.test(p.name))) advice.push('Unsolicited offers to promote a token, sell you "volume" or let you into an early group are spam or paid pump schemes. Do not pay upfront.');
    if (patterns.some((p) => /fee to withdraw|task job/.test(p.name))) advice.push('If a platform or job wants a fee or deposit before you can withdraw, stop paying: the money will not come back.');
    if (patterns.some((p) => /recovery/.test(p.name))) advice.push('"Recovery" services that contact you after a loss are a second scam.');
    if (patterns.some((p) => /blackmail/.test(p.name))) advice.push('Do not pay or reply. These threats are usually sent in bulk with a password from an old data leak. Change that password and report the message.');
    if (patterns.some((p) => /tech support|subscription/.test(p.name))) advice.push('Do not call numbers in the message. Check your account on the company\'s own site.');
    if (patterns.some((p) => /new number/.test(p.name))) advice.push('Call the person on the number you already have before sending anything.');
    advice.push('Report it: forward phishing SMS to 7726 (US, UK) and report emails to the impersonated company.');
  } else advice.push('No warning signs were found, which is not proof it is safe. If it asks for money or codes, check with the sender another way.');

  let explanation: string | null = null;
  if (verdict !== 'no strong signs' || links.length) {
    try {
      const x = await complete('You explain to an ordinary person, in 2-3 short sentences, why a message is or is not likely a scam, using only the findings given. No new claims.', `Message:\n${msg.slice(0, 1500)}\n\nFindings (verdict ${verdict}):\n${reasons.join('\n') || 'none'}`, { maxTokens: 160, temperature: 0.2 });
      explanation = x.text.slice(0, 600) || null;
    } catch {
      // no LLM configured
    }
  }
  return { module: 'scam', input: msg.slice(0, 120), generatedAt: ctx.now().toISOString(), result: { verdict, risk, reasons, patterns: patterns.map(({ name, evidence }) => ({ name, evidence })), links, sender, phones: parts.phones, advice, explanation }, signals: [], provenance };
}
