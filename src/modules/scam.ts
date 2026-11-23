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
