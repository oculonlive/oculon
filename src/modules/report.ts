/**
 * Full reports: several checks on one target, run together and summed up on one page (and one PDF).
 *   domainReport: link check of the site, email protection (SPF, DKIM, DMARC), what the domain exposes to the
 *     internet (open ports, known CVEs), lookalike domains, and the company behind the name (GLEIF).
 *   walletReport: address check (sanctions, activity), active approvals, address poisoning, where the funds
 *     went, and for token contracts the contract risk and a sell simulation.
 * Each part keeps its own verdict and sources; a part that fails is listed as not checked, never guessed.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { toneOf, verdictOf, type Tone } from '../core/verdict.js';
import { chainCan, codeAt, evmChain, isAddr } from '../sources/evm.js';
import { urlCheck } from './urlcheck.js';
import { emailSecurity } from './emailsec.js';
import { exposure } from './exposure.js';
import { lookalikes } from './lookalike.js';
import { companyCheck } from './company.js';
import { addressCheck } from './address.js';
import { approvalsCheck } from './approvals.js';
import { poisoningCheck } from './poisoning.js';
import { traceFunds } from './trace.js';
import { contractRisk } from './contract.js';
import { honeypotCheck } from './honeypot.js';

export interface ReportPart { part: string; verdict: string | null; tone: Tone; risk: number | null; points: string[]; error: string | null }

export interface FullReport {
  target: string;
  kind: 'domain' | 'wallet' | 'token';
  verdict: string;
  risk: number;
  parts: ReportPart[];
  reasons: string[];
  advice: string[];
}

type Job = [string, () => Promise<ModuleResult<unknown>>];

async function runAll(jobs: Job[], provenance: Provenance[], signals: Signal[]): Promise<{ parts: ReportPart[]; results: Record<string, unknown> }> {
  const settled = await Promise.allSettled(jobs.map(([, f]) => f()));
  const parts: ReportPart[] = [], results: Record<string, unknown> = {};
  settled.forEach((s, i) => {
    const part = jobs[i]![0];
    if (s.status === 'fulfilled') {
      const v = verdictOf(s.value);
      provenance.push(...s.value.provenance.slice(0, 6));
      signals.push(...s.value.signals);
      results[part] = s.value.result;
      // Only a result's own "risk" counts here: some modules report a "score" where higher is better.
      const own = (s.value.result as { risk?: unknown } | null)?.risk;
      const risk = typeof own === 'number' ? Math.round(own) : null;
      parts.push({ part, verdict: v.verdict, tone: risk === null && v.risk !== null ? toneOf(v.verdict, null) : v.tone, risk, points: v.points.slice(0, 5), error: null });
    } else parts.push({ part, verdict: null, tone: 'info', risk: null, points: [], error: String((s.reason as Error)?.message ?? s.reason).slice(0, 160) });
  });
  return { parts, results };
}

function sum(parts: ReportPart[]): { verdict: string; risk: number; reasons: string[] } {
  const bad = parts.filter((p) => p.tone === 'bad'), warn = parts.filter((p) => p.tone === 'warn');
  const risk = Math.min(100, Math.max(0, ...parts.map((p) => p.risk ?? (p.tone === 'bad' ? 80 : p.tone === 'warn' ? 40 : 0))));
  const verdict = bad.length ? `high risk: ${bad.map((p) => p.part).join(', ')}` : warn.length ? `check: ${warn.map((p) => p.part).join(', ')}` : 'no major risks found';
  const reasons = [...bad, ...warn].map((p) => `${p.part}: ${p.verdict ?? 'flagged'}${p.points[0] ? ` (${p.points[0]})` : ''}`);
  const failed = parts.filter((p) => p.error);
  if (failed.length) reasons.push(`not checked: ${failed.map((p) => p.part).join(', ')}`);
  return { verdict, risk, reasons };
}

export async function domainReport(ctx: Ctx, input: string): Promise<ModuleResult<FullReport>> {
  const domain = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[/?#]/)[0]!;
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) throw new Error('give a domain, e.g. example.com');
  const provenance: Provenance[] = [], signals: Signal[] = [];
  const brand = domain.split('.').slice(-2)[0]!;
  const { parts } = await runAll([
    ['link check', () => urlCheck(ctx, `https://${domain}`)],
    ['email protection', () => emailSecurity(ctx, domain)],
    ['internet exposure', () => exposure(ctx, domain)],
    ['lookalike domains', () => lookalikes(ctx, domain)],
    ['company', () => companyCheck(ctx, brand)],
  ], provenance, signals);
  // A company match by name alone is a hint, and lookalikes say how much the brand is copied, not whether this
  // domain is bad: neither raises the risk.
  for (const p of parts.filter((x) => x.part === 'company' || x.part === 'lookalike domains')) { p.tone = 'info'; p.risk = null; }
  const { verdict, risk, reasons } = sum(parts);
  const advice = risk >= 70
    ? ['Do not log in, pay or reply through this domain until the flagged parts are explained.']
    : ['Keep the PDF of this report with the check id: it lists every source and its answer.'];
  return { module: 'report', input: domain, generatedAt: ctx.now().toISOString(), result: { target: domain, kind: 'domain', verdict, risk, parts, reasons, advice }, signals, provenance };
}

export async function walletReport(ctx: Ctx, input: string, opts: { chain?: string } = {}): Promise<ModuleResult<FullReport>> {
  const address = input.trim().toLowerCase();
  if (!isAddr(address)) throw new Error('give an EVM address: 0x followed by 40 hex characters');
  const c = evmChain(opts.chain);
  const code = await codeAt(ctx, c, address);
  const isContract = Boolean(code && code !== '0x' && !/^0xef0100/i.test(code));
  const provenance: Provenance[] = [], signals: Signal[] = [];
  const chain = c.key;
  const jobs: Job[] = isContract
    ? [
      ['contract risk', () => contractRisk(ctx, address, { chain })],
      ...(['eth', 'bsc', 'base'].includes(chain) ? [['sell simulation', () => honeypotCheck(ctx, address, { chain })] as Job] : []),
      ['address', () => addressCheck(ctx, address, chain === 'robinhood' ? { network: 'robinhood' } : {})],
    ]
    : [
      ['address', () => addressCheck(ctx, address, chain === 'robinhood' ? { network: 'robinhood' } : {})],
      ...(chainCan(c, 'logs') ? [['approvals', () => approvalsCheck(ctx, address, { chain })] as Job] : []),
      ...(chainCan(c, 'transfers') ? [
        ['address poisoning', () => poisoningCheck(ctx, address, { chain })] as Job,
        ['where funds went', () => traceFunds(ctx, address, { chain, hops: 2, width: 3 })] as Job,
      ] : []),
    ];
  const { parts } = await runAll(jobs, provenance, signals);
  // Where funds went describes the past, not this wallet's safety, unless it reached a sanctioned address.
  const tr = parts.find((p) => p.part === 'where funds went');
  if (tr && !/sanction/.test(tr.verdict ?? '')) { tr.tone = 'info'; tr.risk = null; }
  const { verdict, risk, reasons } = sum(parts);
  if (!isContract && !chainCan(c, 'logs')) reasons.push(`${c.label}: approvals need event logs that no free source covers here`);
  if (!isContract && !chainCan(c, 'transfers')) reasons.push(`${c.label}: poisoning and fund trace need transaction history that no configured source covers`);
  const advice = isContract
    ? risk >= 70 ? ['Do not buy this token.'] : ['Owner powers and liquidity can change; check again before a large trade.']
    : risk >= 70 ? ['Revoke flagged approvals and move funds to a new wallet if you did not sign them.'] : ['Nothing urgent. Revoke approvals you no longer use.'];
  return { module: 'report', input: address, generatedAt: ctx.now().toISOString(), result: { target: address, kind: isContract ? 'token' : 'wallet', verdict, risk, parts, reasons, advice }, signals, provenance };
}
