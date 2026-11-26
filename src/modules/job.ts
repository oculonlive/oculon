/**
 * Job offer check: paste the message from a "recruiter" and see whether it follows the patterns of job scams.
 *   Patterns, matched in plain code: fees before you start, "tasks" you pay to unlock (like, rate, review,
 *   boost orders), pay that does not fit the work, contact only through WhatsApp or Telegram, hired without an
 *   interview, early requests for ID or bank details, check-cashing and reimbursement tricks, and coding "test
 *   tasks" that ask you to run a repository.
 *   Links and the sender go through the scam check; a GitHub repo in the message goes through the repo check.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { scamCheck } from './scam.js';
import { repoCheck } from './repo.js';

export interface JobReport {
  verdict: 'job scam' | 'likely scam' | 'suspicious' | 'no known risk found';
  risk: number;
  patterns: { name: string; evidence: string }[];
  links: { url: string; verdict: string; risk: number }[];
  sender: string | null;
  repo: { repo: string; verdict: string; risk: number; findings: string[] } | null;
  reasons: string[];
  advice: string[];
}

const PATTERNS: [string, RegExp, number][] = [
  ['asks for a fee before you start', /\b((registration|training|onboarding|equipment|starter kit|processing|visa|background check|activation|membership)\s+fees?|pay (a |the )?(small |one[- ]time )?(fee|deposit)|deposit (to|before you|in order to) (start|unlock|activate|begin))\b/i, 40],
  ['paid "tasks" you have to unlock (like, rate, review or boost orders)', /\b((like|rate|review|subscribe|follow|boost|optimi[sz]e|submit)\s.{0,30}\b(videos?|apps?|products?|hotels?|orders?|tasks?|listings?)\b.{0,80}\b(commission|earn|paid|\$)|complete \d+ (tasks|orders)|prepaid tasks?|task (set|package|combo)|commission per (task|order)|recharge|top[- ]?up (your )?(account|balance))/i, 40],
  ['pay or deposits in crypto', /\b(usdt|trc-?20|erc-?20 wallet|binance pay|crypto (wallet|deposit)|send (bitcoin|btc|eth|usdt))\b/i, 20],
  ['pay that does not fit the work', /(\$|usd|€|£)\s?\d{3,5}\s?(\+\s?)?(per|\/|a)\s?(day|daily)|earn (up to )?(\$|usd|€|£)\s?\d{3,}[^.]{0,30}(day|daily|week)|daily (income|salary|pay|profit)/i, 20],
  ['contact only through WhatsApp or Telegram', /\b(whatsapp|telegram|signal|wa\.me|t\.me)\b.{0,60}\b(contact|text|message|add|reach|chat|interview|hr|manager)\b|\b(contact|text|message|add|reach)\b.{0,40}\b(whatsapp|telegram)\b/i, 15],
  ['hired without an interview', /\b(no interview( needed| required)?|you('ve| have) been (selected|hired|shortlisted|approved)|congratulations.{0,60}(selected|position|role|hired))\b/i, 20],
  ['asks for ID or bank details early', /\b(send|provide|share|upload)\b.{0,50}\b(passport|id card|national id|ssn|social security|bank (details|account|statement)|driver'?s? licen[sc]e|card number)\b/i, 25],
  ['check cashing or buy-and-reimburse trick', /\b(deposit|cash) (a |the )?(check|cheque)|send (the )?(rest|remaining|difference|balance) back|buy (gift cards|equipment|supplies).{0,60}(reimburs|refund|pay you back)/i, 40],
  ['a coding "test task" that asks you to run a project', /\b(clone|download|run|install|set up|npm install|yarn)\b.{0,50}\b(repo|repository|project|codebase|test task|assignment|take[- ]home)\b/i, 15],
  ['vague company and role', /\b(online (assistant|job|work)|data entry|simple (tasks|job|work)|part[- ]time.{0,30}(from home|online)|no experience (needed|required))\b/i, 10],
];

export async function jobCheck(ctx: Ctx, text: string): Promise<ModuleResult<JobReport>> {
  const msg = text.trim();
  if (msg.length < 20) throw new Error('paste the whole job message or email (at least a sentence)');
  if (msg.length > 30_000) throw new Error('the message is too long (max 30,000 characters)');
  const provenance: Provenance[] = [];
  const signals: Signal[] = [];
  const patterns: JobReport['patterns'] = [];
  const reasons: [string, number][] = [];
  for (const [name, re, w] of PATTERNS) {
    const m = re.exec(msg);
    if (m) { patterns.push({ name, evidence: m[0].slice(0, 120) }); reasons.push([name, w]); }
  }

  const s = await scamCheck(ctx, msg);
  provenance.push(...s.provenance.slice(0, 8));
  signals.push(...s.signals);
  const links = s.result.links.map((l) => ({ url: l.url, verdict: l.verdict, risk: l.risk }));
  for (const l of s.result.links.filter((x) => x.risk >= 40).slice(0, 3)) reasons.push([`link ${l.url.slice(0, 80)}: ${l.verdict}${l.reasons[0] ? ` (${l.reasons[0]})` : ''}`, l.verdict === 'malicious' ? 40 : 15]);
  const sender = s.result.sender?.email ?? null;
  if (s.result.sender?.freeMail && /\b(recruit|hiring|hr|talent|company|inc|ltd|llc|corp)\b/i.test(msg)) reasons.push([`a company recruiter writing from a free mailbox (${s.result.sender.domain})`, 15]);

  let repo: JobReport['repo'] = null;
  const gh = /https?:\/\/(?:www\.)?github\.com\/[\w.-]+\/[\w.-]+/i.exec(msg)?.[0];
  if (gh) {
    try {
      const r = await repoCheck(ctx, gh);
      provenance.push(...r.provenance.slice(0, 3));
      signals.push(...r.signals);
      repo = { repo: r.result.repo, verdict: r.result.verdict, risk: r.result.risk, findings: r.result.reasons.slice(0, 5) };
      if (r.result.verdict === 'malicious code found') reasons.unshift([`the repo in the message (${r.result.repo}) contains malicious code: ${r.result.reasons[0] ?? ''}`, 70]);
      else if (r.result.verdict === 'suspicious') reasons.push([`the repo in the message (${r.result.repo}) looks suspicious`, 25]);
    } catch (e) { reasons.push([`the GitHub link could not be checked (${(e as Error).message.slice(0, 60)})`, 0]); }
  }

  const risk = Math.min(100, reasons.reduce((a, [, w]) => a + w, 0));
  const verdict: JobReport['verdict'] = risk >= 70 ? 'job scam' : risk >= 45 ? 'likely scam' : risk >= 20 ? 'suspicious' : 'no known risk found';
  const advice = risk >= 45
    ? ['Do not pay anything, do not send ID or bank details, and do not run code they send.', 'Real employers never charge you to start, and never pay you through "tasks" you top up yourself.', 'Look the company up yourself and contact it through its official website to ask whether the offer is real.']
    : ['Look the company and the recruiter up yourself (official site, LinkedIn) before you share documents.', 'Run any code from a test task in a throwaway virtual machine, never on a machine with a wallet.'];
  return { module: 'job', input: msg.slice(0, 200), generatedAt: ctx.now().toISOString(), signals, provenance, result: { verdict, risk, patterns, links, sender, repo, reasons: reasons.sort((a, b) => b[1] - a[1]).map(([r]) => r), advice } };
}
