/**
 * Email header analysis. Paste the raw headers of a message ("Show original" in Gmail, "View source" elsewhere)
 * and get what the receiving server decided about SPF, DKIM and DMARC, the path the message took, the
 * server that first handed it over, and the classic spoofing tells: a From address that differs from the
 * envelope sender, a Reply-To that sends answers elsewhere, a display name dressed up as an address.
 * Parsing is offline; only the origin IP is looked up (ip-api.com, keyless) to say where it came from.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { ipApi, isPublicIp } from '../sources/threatintel.js';

export interface Hop { from: string | null; by: string | null; ip: string | null; date: string | null }
export interface HeaderReport {
  from: { name: string | null; address: string | null; domain: string | null };
  replyTo: string | null;
  returnPath: string | null;
  subject: string | null;
  date: string | null;
  messageIdDomain: string | null;
  auth: { spf: string | null; dkim: string | null; dmarc: string | null; dkimDomain: string | null };
  hops: Hop[];
  origin: { ip: string | null; country: string | null; isp: string | null; hosting: boolean | null };
  verdict: 'looks genuine' | 'suspicious' | 'likely spoofed';
  risk: number;
  flags: string[];
  advice: string[];
}

/** Unfold continuation lines and split into [name, value] pairs, in order. */
export function parseHeaders(raw: string): [string, string][] {
  const text = raw.replace(/\r\n/g, '\n').split(/\n\n/)[0]!.replace(/\n[ \t]+/g, ' ');
  const out: [string, string][] = [];
  for (const line of text.split('\n')) {
    const m = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(line);
    if (m) out.push([m[1]!.toLowerCase(), m[2]!.trim()]);
  }
  return out;
}

const domainOf = (addr: string | null) => (addr ? /@([^>\s]+)/.exec(addr)?.[1]?.toLowerCase().replace(/[>.]+$/, '') ?? null : null);
const addrIn = (v: string | undefined) => (v ? (/<([^>]+)>/.exec(v)?.[1] ?? /[^\s<>"]+@[^\s<>"]+/.exec(v)?.[0] ?? null) : null);
/** The registrable part, good enough for comparing sender domains (mail.example.com ~ example.com). */
const base = (d: string | null) => (d ? d.split('.').slice(-2).join('.') : null);

export function analyzeHeaders(raw: string): Omit<HeaderReport, 'origin'> & { originIp: string | null } {
  const h = parseHeaders(raw);
  const get = (n: string) => h.find(([k]) => k === n)?.[1];
  const all = (n: string) => h.filter(([k]) => k === n).map(([, v]) => v);
  const fromRaw = get('from') ?? '';
  const fromAddr = addrIn(fromRaw);
  const fromName = fromRaw.includes('<') ? fromRaw.slice(0, fromRaw.indexOf('<')).replace(/"/g, '').trim() || null : null;
  const replyTo = addrIn(get('reply-to'));
  const returnPath = addrIn(get('return-path'));
  const ar = all('authentication-results').join('; ') + '; ' + all('arc-authentication-results').join('; ');
  const res = (k: string) => new RegExp(`\\b${k}=([a-z]+)`, 'i').exec(ar)?.[1]?.toLowerCase() ?? null;
  const rspf = /^(pass|fail|softfail|neutral|none|temperror|permerror)\b/i.exec(get('received-spf') ?? '')?.[1]?.toLowerCase() ?? null;
  const auth = { spf: res('spf') ?? rspf, dkim: res('dkim'), dmarc: res('dmarc'), dkimDomain: /header\.d=([^\s;]+)/i.exec(ar)?.[1]?.toLowerCase() ?? /\bd=([^\s;]+)/.exec(get('dkim-signature') ?? '')?.[1]?.toLowerCase() ?? null };
  const hops: Hop[] = all('received').map((v) => ({
    from: /\bfrom\s+([^\s(;]+)/i.exec(v)?.[1] ?? null,
    by: /\bby\s+([^\s(;]+)/i.exec(v)?.[1] ?? null,
    ip: /\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{3,})\]/i.exec(v)?.[1] ?? /\((?:[^)]*?)(\d{1,3}(?:\.\d{1,3}){3})(?:[^)]*)\)/.exec(v)?.[1] ?? null,
    date: v.includes(';') ? v.slice(v.lastIndexOf(';') + 1).trim() || null : null,
  }));
  // Received headers are newest first: the last public IP is the server that first handed the message in.
  const originIp = [...hops].reverse().map((x) => x.ip).find((ip) => ip && isPublicIp(ip)) ?? null;
  const fromDomain = domainOf(fromAddr);
  const flags: string[] = [];
  let risk = 0;
  if (auth.dmarc === 'fail') { flags.push('DMARC failed: the sending domain says this message is not from it'); risk += 45; }
  if (auth.spf === 'fail') { flags.push('SPF failed: the sending server is not allowed to send for this domain'); risk += 25; }
  else if (auth.spf === 'softfail') { flags.push('SPF soft fail: the sending server is not on the domain\'s list'); risk += 12; }
  if (auth.dkim === 'fail') { flags.push('DKIM signature failed: the message may have been altered'); risk += 20; }
  if (!auth.dkim || auth.dkim === 'none') { flags.push('no DKIM signature'); risk += 6; }
  if (auth.dkimDomain && fromDomain && base(auth.dkimDomain) !== base(fromDomain)) { flags.push(`signed by ${auth.dkimDomain}, not by ${fromDomain}`); risk += 10; }
  const rpDomain = domainOf(returnPath);
  if (rpDomain && fromDomain && base(rpDomain) !== base(fromDomain)) { flags.push(`envelope sender ${rpDomain} differs from the From domain ${fromDomain}`); risk += 10; }
  const rtDomain = domainOf(replyTo);
  if (rtDomain && fromDomain && base(rtDomain) !== base(fromDomain)) { flags.push(`replies go to ${replyTo}, not to the sender`); risk += 20; }
  if (fromName && /@/.test(fromName) && domainOf(fromName) !== fromDomain) { flags.push(`the display name shows an address (${fromName}) that is not the real sender`); risk += 25; }
  if (fromDomain && /^(gmail|outlook|hotmail|yahoo|proton|icloud)\./.test(fromDomain) && fromName && /\b(bank|support|security|billing|paypal|microsoft|apple|amazon|invoice|account)\b/i.test(fromName)) { flags.push(`"${fromName}" sent from a free ${fromDomain} mailbox`); risk += 20; }
  risk = Math.min(100, risk);
  const verdict = risk >= 50 ? 'likely spoofed' : risk >= 20 ? 'suspicious' : 'looks genuine';
  const advice = verdict === 'looks genuine'
    ? ['The authentication checks passed. That proves which domain sent it, not that the domain is honest: check the domain itself before acting.']
    : ['Do not click links, open attachments or pay anything from this message.', 'Contact the sender through an address or phone number you already have, not one in this email.'];
  return {
    from: { name: fromName, address: fromAddr, domain: fromDomain }, replyTo, returnPath, subject: get('subject') ?? null, date: get('date') ?? null,
    messageIdDomain: domainOf(get('message-id') ?? null), auth, hops, originIp, verdict, risk, flags, advice,
  };
}

export async function headerCheck(ctx: Ctx, raw: string): Promise<ModuleResult<HeaderReport>> {
  if (!raw || !/^(received|from|return-path|delivered-to|authentication-results|dkim-signature|message-id|arc-|x-)/im.test(raw)) {
    throw new Error('give the raw email headers: in Gmail open the message, choose "Show original" and copy everything above the body');
  }
  const a = analyzeHeaders(raw.slice(0, 200_000));
  const provenance: Provenance[] = [{ source: 'email-headers', url: 'https://www.rfc-editor.org/rfc/rfc8601', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: `${a.hops.length} Received hops parsed offline` }];
  let origin: HeaderReport['origin'] = { ip: a.originIp, country: null, isp: null, hosting: null };
  if (a.originIp) {
    const g = await ipApi(ctx, a.originIp);
    provenance.push(g.prov);
    if (g.data) origin = { ip: a.originIp, country: g.data.country ?? null, isp: g.data.isp ?? null, hosting: g.data.hosting ?? null };
  }
  const { originIp: _o, ...rest } = a;
  return { module: 'headers', input: `${a.from.address ?? 'unknown sender'}${a.subject ? ` · ${a.subject.slice(0, 80)}` : ''}`, generatedAt: ctx.now().toISOString(), result: { ...rest, origin }, signals: [], provenance };
}
