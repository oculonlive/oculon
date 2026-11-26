/**
 * Terms reader: paste terms of service, a privacy policy, a subscription, rental or employment contract (or give
 * its URL) and get the clauses worth reading twice. Detection is rule-based, in code: every finding quotes the
 * exact sentence it matched and carries a severity. An LLM, when configured, adds a short plain-English summary
 * that may only refer to the quoted findings; everything works without one.
 */
import type { Ctx } from '../core/context.js';
import { complete } from '../core/llm.js';
import { publicUrl } from '../core/safeurl.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export type Severity = 'high' | 'medium' | 'low';

export type TermsCategory =
  | 'auto-renewal' | 'cancellation' | 'arbitration' | 'data-sharing' | 'sensitive-data' | 'content-licence'
  | 'unilateral-changes' | 'termination' | 'liability' | 'penalties' | 'jurisdiction' | 'data-retention';

export interface TermsFinding {
  n: number;
  category: TermsCategory;
  label: string;
  severity: Severity;
  why: string;
  /** The sentence from the input, verbatim (cut with "..." only when longer than 900 characters). */
  quote: string;
  /** Character offset of the sentence in the analysed text. */
  offset: number;
}

export interface TermsReport {
  source: 'text' | 'url';
  url: string | null;
  title: string | null;
  chars: number;
  truncated: boolean;
  rating: 'many red flags' | 'some red flags' | 'few red flags' | 'nothing flagged';
  counts: { high: number; medium: number; low: number };
  categories: { category: TermsCategory; label: string; count: number; top: Severity }[];
  findings: TermsFinding[];
  summary: string | null;
  summaryBy: string | null;
  notes: string[];
}

export const MAX_TERMS_CHARS = 60_000;

/** A rule matches a sentence with `re`, unless `unless` also matches (for example a right that is yours, not the company's). */
interface Rule { re: RegExp; severity: Severity; why: string; unless?: RegExp }

/** Sentences that give you, not the company, the right to cancel or end the contract. */
const YOURS = /^\W*(you|users?|customers?|subscribers?|members?|the (customer|user|subscriber|member|tenant|employee|buyer)) (may(?! not)|can(?!not|'t|’t| not)|are (free|entitled) to|have the right to)\b/i;
const CATS: { category: TermsCategory; label: string; rules: Rule[] }[] = [
  { category: 'auto-renewal', label: 'Automatic renewal', rules: [
    { re: /\b(automatic(ally)?[- ]renew(s|ed|al)?|auto[- ]?renew(s|al|ed)?|renews? automatically|will (be )?(automatically )?renew(ed)?|continuous (subscription|billing))\b/i, severity: 'medium', why: 'the plan renews and charges again unless you cancel in time' },
    { re: /\b(recurring (charge|payment|billing|fee)s?|charged? (each|every) (month|year|billing (period|cycle))|until (you )?cancel(l?ed)?|continues? indefinitely)\b/i, severity: 'medium', why: 'you are charged repeatedly until you cancel' },
    { re: /\bfree trial\b[\s\S]{0,160}\b(charg|bill|convert|paid (plan|subscription))/i, severity: 'medium', why: 'a free trial turns into a paid plan' },
  ] },
  { category: 'cancellation', label: 'Cancellation fees or hard cancellation', rules: [
    { re: /\b(cancell?ation (fee|charge|penalt(y|ies))|fee (for|to) cancel)\b/i, severity: 'high', why: 'cancelling costs money' },
    { re: /\b(non[- ]?refundable|no refunds?|not (be )?(eligible for a )?refund(ed|able)?|refunds? (will|shall) not be (given|issued|provided))\b/i, severity: 'medium', why: 'money already paid is not returned' },
    { re: /\b(may not|cannot|can ?not|can't) (be )?cancel(l?ed)?\b|\bcancel(lation)?\b[\s\S]{0,80}\b(in writing|by (post|mail|letter|registered mail|phone|telephone)|(\d+|thirty|sixty|ninety) days'? (prior |advance |written )*notice)\b/i, severity: 'medium', why: 'cancelling is restricted or needs a slow, formal step' },
    { re: /\b(remaining|outstanding|rest of the) (balance|term|contract|payments?)\b[\s\S]{0,60}\b(due|payable|charged)\b/i, severity: 'high', why: 'leaving early can make the rest of the contract payable' },
  ] },
  { category: 'arbitration', label: 'Forced arbitration or class action waiver', rules: [
    { re: /\b(binding (individual )?arbitration|mandatory arbitration|(shall|will|must) be (resolved|settled|decided) (exclusively )?(by|through|in) (final and binding )?arbitration|submit(ted)? to (binding )?arbitration)\b/i, severity: 'high', why: 'disputes go to a private arbitrator instead of a court' },
    { re: /\b(class[- ]action waiver|waive (any |your )?(right|ability) to (participate in |bring |join )?(a |any )?class|(not|no) (bring|participate in|join) (a |any )?class (action|arbitration)|class(-wide)? (or|and) (collective|representative) (action|proceeding)s?\b[\s\S]{0,40}\b(not|waive))/i, severity: 'high', why: 'you give up joining a class action' },
    { re: /\b(waive|waiving|waiver of) (any |your )?(right to )?(a )?(trial by )?jury( trial)?\b/i, severity: 'high', why: 'you give up a jury trial' },
    { re: /\bon an individual basis\b|\bindividual (capacity|claims?) only\b/i, severity: 'medium', why: 'claims can only be brought one person at a time' },
  ] },
  { category: 'data-sharing', label: 'Selling or sharing personal data', rules: [
    { re: /\b(sell|sold|selling|sale of|rent|monetiz(e|ing)) (your |the )?(personal )?(data|information|info)\b|\bdata brokers?\b/i, severity: 'high', why: 'your personal data may be sold' },
    { re: /\b(share|disclose|provide|transfer|make available)\b[\s\S]{0,100}\b(with|to) (our |selected |trusted |certain )?(third[- ]part(y|ies)|advertis(ers|ing partners)|marketing partners|business partners|partners|affiliates|sponsors)\b/i, severity: 'medium', why: 'your data goes to other companies' },
    { re: /\b(targeted|interest[- ]based|personali[sz]ed|behaviou?ral|cross[- ]context(ual)? behaviou?ral) advertis(ing|ements?)\b/i, severity: 'medium', why: 'your activity is used to target ads' },
  ] },
  { category: 'sensitive-data', label: 'Location, biometric or contacts collection', rules: [
    { re: /\b(biometric|face ?print|facial (geometry|recognition|scan)|voice ?print|fingerprints?|retina|iris scan)\b/i, severity: 'high', why: 'biometric data cannot be changed if it leaks' },
    { re: /\b(precise (geo)?location|gps (location|data)|geolocation|location (data|information|history)|background location)\b/i, severity: 'medium', why: 'where you are is collected' },
    { re: /\b(your )?(contacts?( list)?|address book|phone ?book|call (log|history)|sms (messages|log))\b[\s\S]{0,40}\b(access|collect|upload|read|import|sync)|\b(access|collect|upload|read|import|sync)\w*\b[\s\S]{0,40}\b(your )?(contacts?( list)?|address book|phone ?book|call (log|history))\b/i, severity: 'medium', why: 'your contacts or call history are read' },
  ] },
  { category: 'content-licence', label: 'Broad licence to your content', rules: [
    { re: /\b(perpetual|irrevocable)\b[\s\S]{0,120}\b(licen[cs]e|right)/i, severity: 'high', why: 'the licence to what you post never ends and cannot be withdrawn' },
    { re: /\b(worldwide|royalty[- ]free|sub[- ]?licen[cs]able|transferable)\b[\s\S]{0,120}\blicen[cs]e\b[\s\S]{0,160}\b(content|submissions?|posts?|uploads?|materials?|photos?|videos?)\b|\blicen[cs]e\b[\s\S]{0,60}\b(to )?(use|reproduce|modify|adapt|publish|distribute|create derivative works)\b[\s\S]{0,160}\b(your |user )(content|submissions?|posts?|uploads?|materials?)\b/i, severity: 'medium', why: 'the company may use, change and pass on what you upload' },
    { re: /\b(waive|waiver of) (any |all )?(moral rights|rights of (publicity|attribution))\b/i, severity: 'medium', why: 'you give up being credited or controlling use of your name or likeness' },
  ] },
  { category: 'unilateral-changes', label: 'Terms can change without your consent', rules: [
    { re: /\b(may|can|reserve the right to|will) (at any time )?(change|modify|amend|update|revise|alter)\b[\s\S]{0,80}\b(terms|agreement|polic(y|ies)|prices?|fees?|conditions)\b[\s\S]{0,120}\b(at any time|without (prior )?notice|sole discretion|from time to time)\b|\b(at any time|without (prior )?notice|sole discretion)\b[\s\S]{0,60}\b(change|modify|amend|update|revise)\b[\s\S]{0,60}\b(terms|agreement|polic(y|ies)|prices?|fees?)\b/i, severity: 'medium', why: 'the company can change the deal on its own' },
    { re: /\b(continued|continuing) (use|access)\b[\s\S]{0,120}\b(constitutes?|means|signifies|deemed|indicates)\b[\s\S]{0,40}\b(accept|agree|consent)/i, severity: 'medium', why: 'simply keeping on using the service counts as agreeing to new terms' },
  ] },
  { category: 'termination', label: 'Termination without notice', rules: [
    { re: /\b(terminate|suspend|close|disable|delete|deactivate|cancel)\b[\s\S]{0,100}\b(at any time|without (prior |advance )?(notice|warning)|for any (or no )?reason|(in|at) (our|its) (sole|absolute) discretion|with or without cause)\b|\b(at any time|without (prior )?notice|for any (or no )?reason|(in|at) (our|its) (sole|absolute) discretion)\b[\s\S]{0,60}\b(terminate|suspend|close|disable|deactivate)\b/i, severity: 'high', why: 'your account or contract can be ended without warning', unless: YOURS },
    { re: /\b(forfeit|lose|loss of)\b[\s\S]{0,60}\b(balance|credits?|funds|points|rewards|purchases|content)\b[\s\S]{0,80}\b(terminat|suspen|clos)/i, severity: 'high', why: 'you may lose money or purchases when the account is closed' },
  ] },
  { category: 'liability', label: 'Liability and warranty waivers', rules: [
    { re: /\b["“]?as is["”]?\b[\s\S]{0,40}\b(as available|without warrant|basis)|\b(disclaims?|exclude[sd]?) (any and )?all (warranties|liability)|\bwithout (any )?warrant(y|ies) of any kind\b/i, severity: 'medium', why: 'no promise that the service works or is fit for purpose' },
    { re: /\b(in no event|under no circumstances)\b[\s\S]{0,120}\b(liable|responsible|liability)\b|\b(not|no|won’t|won't|will not) (be )?(liable|responsible) for (any|the following) ?(indirect|incidental|consequential|special|punitive|loss|damages?)/i, severity: 'medium', why: 'the company refuses responsibility for losses it causes' },
    { re: /\b(aggregate|total|maximum|entire) liability\b[\s\S]{0,140}\b(shall not exceed|will not exceed|limited to|not to exceed|capped at)\b/i, severity: 'medium', why: 'what you can recover is capped, often at a small amount' },
    { re: /\b(you(’ll|'ll)? (agree to |shall |will |must )?(indemnify|defend and indemnify|hold (us )?harmless))\b|\bindemnify\b[\s\S]{0,60}\b(us|company|landlord|employer|our)\b/i, severity: 'medium', why: 'you may have to pay the company\'s legal costs' },
  ] },
  { category: 'penalties', label: 'Early termination penalties and non-compete', rules: [
    { re: /\b(non[- ]?compet(e|ition)|not (to )?(compete|engage in (any )?competing)|covenant not to compete|restrictive covenants?)\b/i, severity: 'high', why: 'limits where you can work after you leave' },
    { re: /\b(non[- ]?solicit(ation)?|not (to )?solicit)\b/i, severity: 'medium', why: 'limits contacting clients or colleagues after you leave' },
    { re: /\b(early (termination|exit|cancell?ation) (fee|charge|penalty|payment)|break (fee|clause|charge)|liquidated damages|penalty (of|equal to)|re-?letting fee|lease[- ]break)\b/i, severity: 'high', why: 'ending early costs a fixed penalty' },
    { re: /\b(forfeit|retain|keep|withhold)\b[\s\S]{0,40}\b(security )?deposit\b|\b(repay|reimburse|pay back)\b[\s\S]{0,60}\b(training|relocation|signing|sign-on|recruitment) (costs?|fees?|bonus|expenses)\b/i, severity: 'medium', why: 'leaving can cost your deposit or money paid to you' },
  ] },
  { category: 'jurisdiction', label: 'Disputes handled far away', rules: [
    { re: /\b(exclusive(ly)? (jurisdiction|venue)|(courts?|venue) (located )?(in|of) [A-Z][\w .,'-]{2,60}\b[\s\S]{0,40}\b(exclusive|sole))\b|\bsubmit to the (exclusive |personal )*jurisdiction\b/i, severity: 'medium', why: 'you may have to go to court in the company\'s chosen place; check whether it is far from you' },
    { re: /\b(governed by|construed in accordance with|subject to) the laws? of\b|\blaws? (will|shall) govern\b/i, severity: 'low', why: 'another country\'s or state\'s law may apply; check where that is' },
  ] },
  { category: 'data-retention', label: 'Data kept after deletion', rules: [
    { re: /\b(retain|keep|store|preserve|continue to (use|store|hold))\b[\s\S]{0,140}\b(after|even after|following|beyond|once) (you )?(delet|clos|terminat|cancel|request(ed)? (deletion|erasure)|the (end|termination))/i, severity: 'medium', why: 'your data is kept after you delete it or leave' },
    { re: /\b(backup|archived?|residual|cached) (copies|data|information)\b[\s\S]{0,100}\b(remain|retain|persist|may (still )?exist|kept)\b|\b(data|information|content|records)\b[\s\S]{0,80}\b(for as long as (necessary|needed|we (deem|consider))|indefinitely)\b/i, severity: 'medium', why: 'there is no clear end to how long your data is kept' },
  ] },
];

const ENT: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '-', mdash: '-', hellip: '...', lsquo: "'", rsquo: "'", ldquo: '"', rdquo: '"', copy: '(c)', reg: '(R)', trade: '(TM)', sect: '§' };

/** Visible text of an HTML page: scripts, styles and navigation chrome removed, blocks on their own lines. */
export function htmlToText(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript|svg|template|iframe|head)\b[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<(nav|footer)\b[\s\S]*?<\/\1\s*>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/?(p|div|li|ul|ol|h[1-6]|tr|table|section|article|header|blockquote|dd|dt|pre)\b[^>]*>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
      if (e[0] === '#') { const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1)); return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ' '; }
      return ENT[e.toLowerCase()] ?? m;
    })
    .replace(/[ \t ]+/g, ' ')
    .replace(/ *\n[ \n]*/g, '\n')
    .trim();
}

/** Sentences with their offsets in `text`; each one is an exact substring of the input. */
export function sentences(text: string): { s: string; at: number }[] {
  const out: { s: string; at: number }[] = [];
  const re = /[^\n]+/g;
  for (const line of text.matchAll(re)) {
    const l = line[0], base = line.index!;
    // Split after . ! ? or ; followed by space and a capital, a quote, a bracket or a number.
    let start = 0;
    for (const m of l.matchAll(/(?<!\b(?:e\.g|i\.e|etc|Inc|Ltd|Co|No|Mr|Mrs|Ms|Dr|St|vs|U\.S|a\.m|p\.m))[.!?;](?=\s+["'“(\[A-Z0-9])/g)) {
      const end = m.index! + 1;
      push(l.slice(start, end), base + start);
      start = end;
    }
    push(l.slice(start), base + start);
  }
  function push(raw: string, at: number) {
    const lead = raw.length - raw.trimStart().length;
    const s = raw.trim();
    if (s.length >= 12) out.push({ s, at: at + lead });
  }
  return out;
}

/** Rule-based clause detection. Pure: no network, no LLM. */
export function findClauses(text: string): TermsFinding[] {
  const found: TermsFinding[] = [];
  const perCat = new Map<TermsCategory, number>();
  for (const { s, at } of sentences(text)) {
    // Section headings ("Class action waiver") name a topic but are not a clause; the sentences below them are.
    if (s.length < 120 && !/[.!?;:,)"”]$/.test(s) && s.split(/\s+/).length < 14 && !/\b(we|you|shall|will|may|must)\b/i.test(s)) continue;
    for (const c of CATS) {
      const hits = c.rules.filter((r) => r.re.test(s) && !r.unless?.test(s));
      if (!hits.length) continue;
      if ((perCat.get(c.category) ?? 0) >= 6) continue;
      const top = hits.find((h) => h.severity === 'high') ?? hits.find((h) => h.severity === 'medium') ?? hits[0]!;
      perCat.set(c.category, (perCat.get(c.category) ?? 0) + 1);
      found.push({ n: 0, category: c.category, label: c.label, severity: top.severity, why: top.why, quote: s.length > 900 ? `${s.slice(0, 900)}...` : s, offset: at });
    }
  }
  const rank = { high: 0, medium: 1, low: 2 };
  found.sort((a, b) => rank[a.severity] - rank[b.severity] || a.offset - b.offset);
  return found.slice(0, 60).map((f, i) => ({ ...f, n: i + 1 }));
}

async function fetchTerms(ctx: Ctx, input: string, provenance: Provenance[], notes: string[]): Promise<{ text: string; url: string; title: string | null }> {
  const u = publicUrl(input);
  const page = await ctx.http.getPage(u.href, { source: 'terms-fetch', timeoutMs: 25_000, maxBytes: 4_000_000 });
  provenance.push(page.prov);
  if (!page.data) throw new Error(`the page did not open (${page.prov.note ?? page.prov.status})`);
  const final = publicUrl(page.data.finalUrl);
  if (page.data.status >= 400) throw new Error(`the page answered HTTP ${page.data.status}`);
  const type = (page.data.headers['content-type'] ?? '').toLowerCase();
  if (/pdf/.test(type) || page.data.body.subarray(0, 5).toString('latin1') === '%PDF-') throw new Error('that link is a PDF; open it, copy the text and paste it here');
  const body = page.data.body.toString('utf8');
  const isHtml = /html|xml/.test(type) || /^\s*<(!doctype|html|head|body)/i.test(body);
  if (!isHtml && type && !/text\//.test(type)) throw new Error(`that link is not a web page (${type.split(';')[0]})`);
  const rawTitle = isHtml ? /<title[^>]*>([^<]{1,200})<\/title>/i.exec(body)?.[1] : undefined;
  const title = rawTitle ? htmlToText(rawTitle) || null : null;
  const text = isHtml ? htmlToText(body) : body.replace(/\r\n?/g, '\n');
  if (text.length < 200) notes.push('Very little text was found on the page; it may be built by scripts. If so, copy the terms and paste them instead.');
  return { text, url: final.href, title };
}

export async function termsRead(ctx: Ctx, input: { text?: string; url?: string }): Promise<ModuleResult<TermsReport>> {
  const provenance: Provenance[] = [];
  const notes: string[] = [];
  let text: string, url: string | null = null, title: string | null = null;
  const source: TermsReport['source'] = input.text?.trim() ? 'text' : 'url';
  if (source === 'text') text = input.text!.replace(/\r\n?/g, '\n');
  else if (input.url?.trim()) ({ text, url, title } = await fetchTerms(ctx, input.url, provenance, notes));
  else throw new Error('paste the terms or give the link to them');
  const truncated = text.length > MAX_TERMS_CHARS;
  if (truncated) { text = text.slice(0, MAX_TERMS_CHARS); notes.push(`Only the first ${MAX_TERMS_CHARS.toLocaleString('en-US')} characters were read.`); }
  if (text.trim().length < 40) throw new Error('that is too short to be terms or a contract');

  const findings = findClauses(text);
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  const categories = CATS.flatMap((c) => {
    const fs = findings.filter((f) => f.category === c.category);
    return fs.length ? [{ category: c.category, label: c.label, count: fs.length, top: (fs.some((f) => f.severity === 'high') ? 'high' : fs.some((f) => f.severity === 'medium') ? 'medium' : 'low') as Severity }] : [];
  });
  const highCats = categories.filter((c) => c.top === 'high').length;
  const rating: TermsReport['rating'] = highCats >= 3 ? 'many red flags' : highCats >= 1 || categories.length >= 4 ? 'some red flags' : findings.length ? 'few red flags' : 'nothing flagged';
  notes.push(findings.length
    ? 'Findings are matched by fixed rules and quote the text as written. Read each quoted sentence in context; local law may make some clauses unenforceable.'
    : 'No clause matched the rules. That is not proof the terms are fair: read anything about money, cancelling and your data yourself.');

  let summary: string | null = null, summaryBy: string | null = null;
  if (findings.length) {
    try {
      const list = findings.slice(0, 25).map((f) => `[${f.n}] (${f.severity}, ${f.label}) "${f.quote.slice(0, 400)}"`).join('\n');
      const r = await complete(
        'You summarize contract clauses for an ordinary reader in plain English. Use only the numbered findings given; cite them like [1]. Do not add clauses, facts, legal advice or claims that are not in the quotes. 3 to 5 short sentences, no lists, no emoji.',
        `Document: ${title ?? url ?? 'pasted text'}\nRating: ${rating}\n\nFindings:\n${list}`,
        { maxTokens: 260, temperature: 0.2 },
      );
      const t = r.text.trim();
      // Keep the summary only when every finding it cites exists.
      const cited = [...t.matchAll(/\[(\d+)\]/g)].map((m) => Number(m[1]));
      if (t && cited.every((n) => n >= 1 && n <= findings.length)) { summary = t.slice(0, 1200); summaryBy = r.model; }
    } catch {
      // no LLM configured: the findings stand on their own
    }
  }
  return {
    module: 'terms', input: (url ?? text.slice(0, 120)).slice(0, 200), generatedAt: ctx.now().toISOString(),
    result: { source, url, title, chars: text.length, truncated, rating, counts, categories, findings, summary, summaryBy, notes },
    signals: [], provenance,
  };
}
