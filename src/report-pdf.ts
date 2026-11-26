/**
 * One check as a PDF report to send on (to a bank, a team, the police): what was checked, the verdict and why,
 * what changed since earlier checks, what to do, and every source called with its answer. Built from the stored
 * check only, so the file always matches what Oculon returned.
 */
import { renderPdf, TONE_RGB, type Block } from './core/pdf.js';
import type { CheckRecord } from './modules/checks.js';

type Any = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const KIND_LABEL: Record<string, string> = {
  scam: 'Message scam check', url: 'Link check', iban: 'IBAN check', headers: 'Email header check', lookalike: 'Lookalike domains', honeypot: 'Token sell check',
  address: 'Crypto address check', phone: 'Phone number check', ip: 'IP address check', hash: 'File hash check', emailsec: 'Email security of a domain',
  company: 'Company check', token: 'Token check', rhtoken: 'Robinhood Chain token check', wallet: 'Wallet check', sanctions: 'Sanctions screening',
  factcheck: 'Fact check', recall: 'Recall check', travel: 'Travel risk', cve: 'Vulnerability', exposure: 'Exposure of a domain', doc: 'Document check',
  approvals: 'Wallet approvals', contract: 'Token contract risk', signature: 'Signature request', poisoning: 'Address poisoning', trace: 'Fund trace',
  image: 'Image authenticity', qr: 'QR code check', repo: 'GitHub repository check', domainreport: 'Domain report', walletreport: 'Wallet and token report',
  site: 'Site check (drainer and phishing)', tx: 'Transaction explained', creator: 'Token creator record', eml: 'Email file check', apk: 'Android app check', job: 'Job offer check', where: 'Photo location and time', archive: 'Page saved as evidence', invite: 'Invite link check', stocktoken: 'Robinhood Stock Token check',
};

const when = (iso: string) => `${iso.slice(0, 16).replace('T', ' ')} UTC`;

/** Short "key: value" lines from a result object, for the details section. Long lists and objects are skipped. */
function details(result: unknown): [string, string][] {
  const x = ((result as Any)?.result ?? result) as Any;
  if (!x || typeof x !== 'object') return [];
  const rows: [string, string][] = [];
  for (const [k, v] of Object.entries(x)) {
    if (['verdict', 'risk', 'reasons', 'flags', 'warnings', 'points', 'advice', 'notes', 'input'].includes(k)) continue;
    if (typeof v === 'string' && v && v.length < 300) rows.push([k, v]);
    else if (typeof v === 'number' || typeof v === 'boolean') rows.push([k, String(v)]);
    else if (Array.isArray(v) && v.length && v.every((i) => typeof i === 'string')) rows.push([k, v.slice(0, 8).join(', ')]);
    else if (v && typeof v === 'object' && !Array.isArray(v)) {
      const flat = Object.entries(v as Any).filter(([, y]) => typeof y === 'string' || typeof y === 'number').slice(0, 6);
      if (flat.length) rows.push([k, flat.map(([a, b]) => `${a}: ${b}`).join('; ')]);
    }
    if (rows.length >= 14) break;
  }
  return rows;
}

function listOf(result: unknown, key: string): string[] {
  const x = ((result as Any)?.result ?? result) as Any;
  const v = x?.[key];
  return Array.isArray(v) ? v.filter((i) => typeof i === 'string').slice(0, 10) : [];
}

export function reportPdf(c: CheckRecord, history: { id: string; at: string; verdict: string | null; risk: number | null }[] = [], baseUrl?: string): Buffer {
  const v = c.verdict;
  const blocks: Block[] = [{ t: 'title', text: `${KIND_LABEL[c.kind] ?? c.kind}: ${c.label}` }];
  blocks.push({ t: 'kv', rows: [['Checked', when(c.createdAt)], ['Check id', c.id], ['Took', `${(c.durationMs / 1000).toFixed(1)} s, ${c.calls.length} source call${c.calls.length === 1 ? '' : 's'}`]] });
  blocks.push({ t: 'bar', label: 'VERDICT', text: `${(v.verdict ?? 'result').toUpperCase()}${v.risk !== null ? `   risk ${v.risk}/100` : ''}`, color: TONE_RGB[v.tone]! });
  if (v.points.length) blocks.push({ t: 'h', text: 'Why' }, { t: 'bullets', items: v.points });
  if (c.seenBefore) {
    blocks.push({ t: 'h', text: 'Seen before' }, { t: 'p', text: `Last checked ${when(c.seenBefore.at)} (verdict then: ${c.seenBefore.verdict ?? 'none'}).` });
    blocks.push(c.seenBefore.changes.length ? { t: 'bullets', items: c.seenBefore.changes } : { t: 'p', text: 'Nothing changed since then.' });
  }
  const advice = listOf(c.result, 'advice');
  if (advice.length) blocks.push({ t: 'h', text: 'What to do' }, { t: 'bullets', items: advice });
  const notes = listOf(c.result, 'notes');
  if (notes.length) blocks.push({ t: 'h', text: 'Notes' }, { t: 'bullets', items: notes, color: [0.42, 0.47, 0.49] });
  const d = details(c.result);
  if (d.length) blocks.push({ t: 'h', text: 'Details' }, { t: 'kv', rows: d });
  if (history.length > 1) {
    blocks.push({ t: 'h', text: 'History of this target' }, { t: 'table', head: ['When', 'Verdict', 'Risk'], widths: [170, 250, 75], rows: history.map((h) => [when(h.at), h.verdict ?? '-', h.risk === null ? '-' : String(h.risk)]) });
  }
  blocks.push({ t: 'h', text: 'Sources called' });
  blocks.push({ t: 'p', text: `${v.sources.live} live, ${v.sources.cached} from cache, ${v.sources.failed} failed or not available (for example, no key set). A failed or unavailable source is not a finding.`, size: 9.5 });
  if (c.calls.length) {
    blocks.push({ t: 'table', head: ['Time (UTC)', 'Source', 'Host', 'Status', 'ms'], widths: [70, 130, 150, 95, 50], rows: c.calls.slice(0, 120).map((k) => [k.at.slice(11, 19), k.source, k.via ? `${k.host} (mirror)` : k.host, k.note && k.status !== 'LIVE' ? `${k.status}: ${k.note}`.slice(0, 60) : k.status, String(k.ms)]) });
    if (c.calls.length > 120) blocks.push({ t: 'p', text: `${c.calls.length - 120} more calls are in the replay log.`, size: 9 });
  } else blocks.push({ t: 'p', text: 'No network calls: this check ran on the input alone.', size: 9.5 });
  if (baseUrl) {
    blocks.push({ t: 'h', text: 'Online' }, { t: 'link', text: `${baseUrl}/replay/${c.id}`, url: `${baseUrl}/replay/${c.id}` });
  }
  blocks.push({ t: 'gap', h: 10 }, { t: 'p', text: 'Oculon is free, open-source software (MIT). This report shows what public sources said at the time of the check. It is not legal, financial or security advice, and a clean result is not a guarantee.', size: 8.5, color: [0.42, 0.47, 0.49] });
  return renderPdf(blocks, `Oculon report ${c.id} · ${when(c.createdAt)}`);
}
