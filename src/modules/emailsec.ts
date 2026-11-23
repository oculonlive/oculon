/**
 * Email security of a domain: can someone send mail that looks like it comes from it?
 * Reads public DNS over HTTPS (Google Public DNS, no key): MX, SPF, DMARC, common DKIM selectors, MTA-STS,
 * TLS reporting, BIMI, CAA and DNSSEC. Gives a 0-100 score, a plain verdict and the fixes, most important first.
 */
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import type { ModuleResult, Provenance, Sourced } from '../core/types.js';

export type SpoofVerdict = 'spoofable' | 'partly protected' | 'protected';

export interface EmailSecurity {
  domain: string;
  verdict: SpoofVerdict;
  score: number;
  receivesMail: boolean;
  mx: string[];
  spf: { record: string | null; all: string | null; lookups: number; problems: string[] };
  dmarc: { record: string | null; policy: string | null; subdomainPolicy: string | null; pct: number | null; reports: boolean; problems: string[] };
  dkim: { selectorsFound: string[]; checked: string[] };
  mtaSts: { record: string | null; mode: string | null };
  tlsRpt: boolean;
  bimi: boolean;
  caa: string[];
  dnssec: boolean;
  fixes: string[];
}

interface DohAnswer { name: string; type: number; data: string }
interface Doh { Status: number; AD?: boolean; Answer?: DohAnswer[] }

const unquote = (s: string) => s.replace(/^"|"$/g, '').replace(/"\s*"/g, '');

async function doh(ctx: Ctx, name: string, type: string): Promise<Sourced<Doh>> {
  return ctx.http.get<Doh>(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}&do=1`, { source: 'google-dns', ttlSec: 1800, keep: (d: Doh) => ({ Status: d.Status, AD: d.AD, Answer: (d.Answer ?? []).map((a) => ({ name: a.name, type: a.type, data: a.data })) }) });
}

const txts = (r: Sourced<Doh>) => (r.data?.Answer ?? []).filter((a) => a.type === 16).map((a) => unquote(a.data));

/** SPF details: the "all" qualifier, DNS lookups used (limit 10) and problems. */
export function analyzeSpf(records: string[]): EmailSecurity['spf'] {
  const spf = records.filter((r) => /^v=spf1\b/i.test(r));
  const problems: string[] = [];
  if (!spf.length) return { record: null, all: null, lookups: 0, problems: ['no SPF record'] };
  if (spf.length > 1) problems.push(`${spf.length} SPF records (receivers treat this as an error; merge them into one)`);
  const rec = spf[0]!;
  const all = /([+~?-]?)all\b/i.exec(rec);
  const q = all ? (all[1] || '+') : null;
  const lookups = (rec.match(/\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)/gi) ?? []).length;
  if (lookups > 10) problems.push(`${lookups} DNS lookups, over the limit of 10 (SPF fails for everyone)`);
  if (q === '+') problems.push('"+all" lets any server on the internet send as this domain');
  if (q === '?') problems.push('"?all" is neutral: it does not tell receivers to reject anything');
  if (!all && !/redirect=/i.test(rec)) problems.push('no "all" at the end, so unlisted servers are not rejected');
  if (/\bptr\b/i.test(rec)) problems.push('"ptr" is deprecated and slow');
  return { record: rec, all: q === '-' ? '-all (fail)' : q === '~' ? '~all (soft fail)' : q === '?' ? '?all (neutral)' : q === '+' ? '+all (pass everything)' : null, lookups, problems };
}

/** DMARC details: policy, subdomain policy, percentage, reporting and problems. */
export function analyzeDmarc(records: string[]): EmailSecurity['dmarc'] {
  const rec = records.find((r) => /^v=DMARC1\b/i.test(r)) ?? null;
  if (!rec) return { record: null, policy: null, subdomainPolicy: null, pct: null, reports: false, problems: ['no DMARC record, so receivers have no instruction for mail that fails SPF and DKIM'] };
  const tag = (t: string) => new RegExp(`(?:^|;)\\s*${t}\\s*=\\s*([^;]+)`, 'i').exec(rec)?.[1]?.trim().toLowerCase() ?? null;
  const policy = tag('p');
  const sp = tag('sp');
  const pct = tag('pct') ? Number(tag('pct')) : null;
  const reports = Boolean(tag('rua'));
  const problems: string[] = [];
  if (!policy) problems.push('the DMARC record has no "p=" policy');
  if (policy === 'none') problems.push('DMARC policy is "none": spoofed mail is still delivered (monitoring only)');
  if (pct !== null && pct < 100) problems.push(`the policy applies to only ${pct}% of failing mail`);
  if (sp === 'none' && policy !== 'none') problems.push('subdomains have policy "none", so look-alike subdomains can be spoofed');
  if (!reports) problems.push('no "rua=" address, so you never see who sends mail as you');
  return { record: rec, policy, subdomainPolicy: sp, pct, reports, problems };
}

const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'cf2024-1', 'resend', 'amazonses', 'default', 'k1', 'k2', 's1', 's2', 'dkim', 'mail', 'smtp', 'mandrill', 'mxvault', 'zoho', 'protonmail', 'fm1', 'cm'];

export async function emailSecurity(ctx: Ctx, input: string): Promise<ModuleResult<EmailSecurity>> {
  const domain = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^[^@]*@/, '').replace(/\/.*$/, '').replace(/\.$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new Error(`not a domain: ${input}`);
  const provenance: Provenance[] = [];
  const [mx, txt, dm, sts, rpt, bimi, caa, soa] = await Promise.all([
    doh(ctx, domain, 'MX'),
    doh(ctx, domain, 'TXT'),
    doh(ctx, `_dmarc.${domain}`, 'TXT'),
    doh(ctx, `_mta-sts.${domain}`, 'TXT'),
    doh(ctx, `_smtp._tls.${domain}`, 'TXT'),
    doh(ctx, `default._bimi.${domain}`, 'TXT'),
    doh(ctx, domain, 'CAA'),
    doh(ctx, domain, 'SOA'),
  ]);
  provenance.push(mx.prov);
  if (!soa.data || (soa.data.Status === 3 && !(mx.data?.Answer?.length))) throw new Error(`domain not found: ${domain}`);
  // A real key is "v=DKIM1" or a long "p=" value at that exact name; a CNAME counts when it points at a DKIM host.
  // Wildcard records (a domain answering every name with its SPF or DMARC text) do not count.
  const dkimR = await Promise.all(DKIM_SELECTORS.map((s) => doh(ctx, `${s}._domainkey.${domain}`, 'TXT').then((r) => {
    const own = (r.data?.Answer ?? []).filter((a) => a.name.replace(/\.$/, '').toLowerCase() === `${s}._domainkey.${domain}`);
    const key = own.filter((a) => a.type === 16).map((a) => unquote(a.data)).some((t) => /\bv=DKIM1\b/i.test(t) || /(^|;)\s*p=[A-Za-z0-9+/]{40,}/.test(t));
    const alias = own.some((a) => a.type === 5 && /dkim|domainkey/i.test(a.data));
    return { s, ok: key || alias };
  })));
  provenance.push({ ...mx.prov, url: 'https://dns.google/resolve', note: `${8 + DKIM_SELECTORS.length} DNS queries` });

  const mxHosts = (mx.data?.Answer ?? []).filter((a) => a.type === 15).map((a) => a.data.split(/\s+/)[1]?.replace(/\.$/, '') ?? '').filter(Boolean);
  const nullMx = mxHosts.length === 1 && mxHosts[0] === '';
  const receivesMail = mxHosts.length > 0 && !nullMx;
  const spf = analyzeSpf(txts(txt));
  const dmarc = analyzeDmarc(txts(dm));
  const stsRec = txts(sts).find((t) => /^v=STSv1/i.test(t)) ?? null;
  let stsMode: string | null = null;
  if (stsRec) {
    const pol = await ctx.http.get<string>(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { source: 'mta-sts', as: 'text', ttlSec: 6 * 3600, retries: 0, timeoutMs: 8000 });
    stsMode = /mode:\s*(\w+)/i.exec(pol.data ?? '')?.[1]?.toLowerCase() ?? null;
  }
  const dkimFound = dkimR.filter((d) => d.ok).map((d) => d.s);
  const caaList = (caa.data?.Answer ?? []).filter((a) => a.type === 257).map((a) => a.data);
  const dnssec = Boolean(soa.data?.AD);

  // Score: DMARC enforcement matters most, then SPF, then the hardening extras.
  let score = 0;
  score += dmarc.policy === 'reject' ? 40 : dmarc.policy === 'quarantine' ? 30 : dmarc.policy === 'none' ? 8 : 0;
  if (dmarc.pct !== null && dmarc.pct < 100 && score > 8) score -= 8;
  if (dmarc.reports) score += 5;
  score += spf.record ? (spf.all?.startsWith('-') ? 25 : spf.all?.startsWith('~') ? 20 : 8) : 0;
  if (spf.problems.some((p) => /DNS lookups|SPF records/.test(p))) score -= 10;
  score += dkimFound.length ? 10 : 0;
  score += stsMode === 'enforce' ? 7 : stsMode ? 3 : 0;
  score += txts(rpt).some((t) => /^v=TLSRPTv1/i.test(t)) ? 3 : 0;
  score += dnssec ? 7 : 0;
  score += caaList.length ? 3 : 0;
  score = clamp(score, 0, 100);
  // A domain that sends no mail is protected by "v=spf1 -all" plus DMARC reject; say so plainly.
  const verdict: SpoofVerdict = (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') && (dmarc.pct ?? 100) === 100 && spf.record && !spf.problems.some((p) => /\+all|limit of 10|SPF records/.test(p))
    ? (dmarc.policy === 'reject' ? 'protected' : 'partly protected')
    : 'spoofable';

  const fixes: string[] = [];
  if (!dmarc.record) fixes.push(`Add a DMARC record: TXT _dmarc.${domain} "v=DMARC1; p=none; rua=mailto:dmarc@${domain}", watch the reports for two weeks, then move to p=quarantine and p=reject.`);
  else if (dmarc.policy === 'none') fixes.push('Move DMARC from p=none to p=quarantine, then p=reject, once the reports show all your real senders pass.');
  else if (dmarc.policy === 'quarantine') fixes.push('Move DMARC from p=quarantine to p=reject for full protection.');
  if (dmarc.record && !dmarc.reports) fixes.push(`Add rua=mailto:dmarc@${domain} to the DMARC record to receive reports.`);
  if (!spf.record) fixes.push(receivesMail ? `Add an SPF record listing your mail senders, ending in -all or ~all.` : `This domain sends no mail: publish TXT "v=spf1 -all" so nobody can use it.`);
  for (const p of spf.problems) if (!/^no SPF/.test(p)) fixes.push(`SPF: ${p}.`);
  if (!dkimFound.length && receivesMail) fixes.push('Turn on DKIM signing with your mail provider (no common DKIM selector was found; a custom selector may exist).');
  if (!stsMode && receivesMail) fixes.push('Add MTA-STS so other servers only deliver your mail over verified TLS.');
  if (!dnssec) fixes.push('Turn on DNSSEC at your DNS provider so these records cannot be forged in transit.');
  if (!caaList.length) fixes.push('Add CAA records naming the certificate authorities you use.');

  return {
    module: 'emailsec',
    input: domain,
    generatedAt: ctx.now().toISOString(),
    result: { domain, verdict, score, receivesMail, mx: mxHosts, spf, dmarc, dkim: { selectorsFound: dkimFound, checked: DKIM_SELECTORS }, mtaSts: { record: stsRec, mode: stsMode }, tlsRpt: txts(rpt).some((t) => /^v=TLSRPTv1/i.test(t)), bimi: txts(bimi).some((t) => /^v=BIMI1/i.test(t)), caa: caaList, dnssec, fixes },
    signals: [],
    provenance,
  };
}
