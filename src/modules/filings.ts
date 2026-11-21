/**
 * Filings: what companies are telling the SEC.
 *   filings(): EDGAR full-text search across every filer (efts.sec.gov, the index behind sec.gov/edgar/search),
 *     e.g. every 8-K mentioning "cybersecurity incident" in the last 30 days.
 *   recentEvents(): one company's recent 8-Ks with the item codes decoded into plain English. High-impact items
 *     (bankruptcy, cybersecurity incident, restatement, delisting, CEO/CFO departure) become signals.
 * Needs OCULON_CONTACT (SEC requires contact details in the User-Agent). Requests stay sequential and few,
 * far under SEC's 10 requests/second fair-access limit.
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { Evidence, ModuleResult, Provenance, Signal } from '../core/types.js';
import { companies, filingText, fullTextSearch, matchCompany, recentFilings, type Company, type Filing, type FullTextHit } from '../sources/sec.js';

/** Form 8-K items (SEC General Instructions B) with an impact weight 0-100 for signals. */
export const EIGHT_K_ITEMS: Record<string, { title: string; impact: number }> = {
  '1.01': { title: 'Entered a material definitive agreement', impact: 35 },
  '1.02': { title: 'Terminated a material definitive agreement', impact: 50 },
  '1.03': { title: 'Bankruptcy or receivership', impact: 95 },
  '1.04': { title: 'Mine safety: shutdown or pattern of violations', impact: 55 },
  '1.05': { title: 'Material cybersecurity incident', impact: 85 },
  '2.01': { title: 'Completed an acquisition or disposition of assets', impact: 45 },
  '2.02': { title: 'Results of operations (earnings release)', impact: 15 },
  '2.03': { title: 'New direct financial obligation (debt or off-balance-sheet arrangement)', impact: 30 },
  '2.04': { title: 'Triggering event accelerated a financial obligation (e.g. debt default)', impact: 70 },
  '2.05': { title: 'Exit or disposal costs (restructuring, layoffs, closures)', impact: 60 },
  '2.06': { title: 'Material impairment', impact: 60 },
  '3.01': { title: 'Delisting notice or failure to meet a listing standard', impact: 75 },
  '3.02': { title: 'Unregistered sale of equity securities', impact: 30 },
  '3.03': { title: 'Material modification to rights of security holders', impact: 45 },
  '4.01': { title: 'Changed certifying accountant (auditor change)', impact: 60 },
  '4.02': { title: 'Non-reliance on previously issued financial statements (restatement)', impact: 85 },
  '5.01': { title: 'Change in control of the company', impact: 70 },
  '5.02': { title: 'Director or officer departure, election or appointment; compensation', impact: 40 },
  '5.03': { title: 'Amended articles or bylaws; fiscal year change', impact: 15 },
  '5.04': { title: 'Temporary suspension of trading under employee benefit plans', impact: 25 },
  '5.05': { title: 'Amended or waived code of ethics', impact: 35 },
  '5.06': { title: 'Change in shell company status', impact: 40 },
  '5.07': { title: 'Shareholder vote results', impact: 10 },
  '5.08': { title: 'Shareholder director nominations', impact: 15 },
  '6.01': { title: 'ABS informational and computational material', impact: 5 },
  '6.02': { title: 'Change of ABS servicer or trustee', impact: 15 },
  '6.03': { title: 'Change in ABS credit enhancement', impact: 20 },
  '6.04': { title: 'Failure to make a required ABS distribution', impact: 60 },
  '6.05': { title: 'Securities Act updating disclosure (ABS)', impact: 10 },
  '7.01': { title: 'Regulation FD disclosure', impact: 10 },
  '8.01': { title: 'Other events', impact: 15 },
  '9.01': { title: 'Financial statements and exhibits', impact: 0 },
};

/** Items that raise a signal on their own. 5.02 only does when the CEO or CFO is leaving. */
export const HIGH_IMPACT_ITEMS = new Set(['1.03', '1.05', '2.04', '3.01', '4.02', '5.01', '6.04']);

export const decodeItem = (code: string): string => EIGHT_K_ITEMS[code]?.title ?? `Item ${code}`;

export interface DecodedItem {
  code: string;
  title: string;
  impact: number;
}

export interface CorporateEvent {
  date: string;
  form: string;
  items: DecodedItem[];
  url: string;
  /** For item 5.02: which top officer the filing says is leaving, read from the filing text. */
  officerDeparture: 'CEO' | 'CFO' | 'CEO and CFO' | null;
  /** Highest item impact, raised to 80 for a CEO/CFO departure. */
  impact: number;
  summary: string;
}

export interface RecentEvents {
  company: Company | null;
  days: number;
  events: CorporateEvent[];
}

const OFFICER = { CEO: /chief executive officer|\bCEO\b/i, CFO: /chief financial officer|principal financial officer|\bCFO\b/i };
const LEAVING = /\b(resign\w*|retire\w*|depart\w*|step(?:s|ped)? down|terminat\w*|separat\w*|will (?:leave|cease)|no longer serve|transition(?:ing)? (?:out|from))\b/i;

/** Which of CEO/CFO a 5.02 text says is leaving (a sentence naming the role and a departure verb). */
export function officerLeaving(text: string): CorporateEvent['officerDeparture'] {
  const sentences = text.split(/(?<=[.;])\s+/).filter((s) => LEAVING.test(s));
  const ceo = sentences.some((s) => OFFICER.CEO.test(s));
  const cfo = sentences.some((s) => OFFICER.CFO.test(s));
  return ceo && cfo ? 'CEO and CFO' : ceo ? 'CEO' : cfo ? 'CFO' : null;
}

/**
 * Turn submissions-feed filings into decoded 8-K events (newest first as given). Reads the text of up to
 * `read502` item-5.02 filings to tell a CEO/CFO departure from a routine board change.
 */
export async function decodeEvents(ctx: Ctx, list: Filing[], o: { since: number; read502?: number; provenance?: Provenance[] }): Promise<CorporateEvent[]> {
  let reads = o.read502 ?? 3;
  const events: CorporateEvent[] = [];
  for (const x of list.filter((f) => /^8-K/.test(f.form) && Date.parse(f.date) >= o.since)) {
    const items = (x.items ?? []).map((code) => ({ code, title: decodeItem(code), impact: EIGHT_K_ITEMS[code]?.impact ?? 10 }));
    let officerDeparture: CorporateEvent['officerDeparture'] = null;
    if (items.some((i) => i.code === '5.02') && reads > 0) {
      reads--;
      const t = await filingText(ctx, x.url);
      o.provenance?.push(t.prov);
      if (t.data) officerDeparture = officerLeaving(t.data);
    }
    const impact = Math.max(0, ...items.map((i) => i.impact), officerDeparture ? 80 : 0);
    const shown = items.filter((i) => i.code !== '9.01' && !(i.code === '5.02' && officerDeparture));
    const summary = [officerDeparture ? `${officerDeparture} departure` : '', ...shown.map((i) => i.title)].filter(Boolean).join('; ') || x.description;
    events.push({ date: x.date, form: x.form, items, url: x.url, officerDeparture, impact, summary });
  }
  return events;
}

/** Evidence lines for an event's high-impact items; empty when nothing in it is high impact. */
export function eventEvidence(e: CorporateEvent): Evidence[] {
  return [
    ...e.items.filter((i) => HIGH_IMPACT_ITEMS.has(i.code)).map((i) => ({ source: 'sec-edgar', text: `${e.form} item ${i.code}: ${i.title}`, url: e.url, value: i.impact })),
    ...(e.officerDeparture ? [{ source: 'sec-edgar', text: `${e.form} item 5.02: ${e.officerDeparture} departure`, url: e.url, value: 80 }] : []),
  ];
}

async function resolveCompany(ctx: Ctx, tickerOrCik: string | number, provenance: Provenance[]): Promise<Company | null> {
  const raw = String(tickerOrCik).trim();
  if (/^\d{1,10}$/.test(raw)) return { cik: Number(raw), ticker: '', name: `CIK ${Number(raw)}` };
  const list = await companies(ctx);
  provenance.push(list.prov);
  return list.data ? matchCompany(list.data, raw) : null;
}

export interface EventOptions {
  days?: number;
  /** Read the text of up to this many 5.02 filings to see whether the CEO or CFO is leaving. Default 3. */
  read502?: number;
}

export async function recentEvents(ctx: Ctx, tickerOrCik: string | number, opts: EventOptions = {}): Promise<ModuleResult<RecentEvents>> {
  const days = opts.days ?? 90;
  const now = ctx.now();
  const nowIso = now.toISOString();
  const provenance: Provenance[] = [];
  const company = await resolveCompany(ctx, tickerOrCik, provenance);
  const base = { module: 'filings', input: String(tickerOrCik), generatedAt: nowIso };
  if (!company) return { ...base, result: { company: null, days, events: [] }, signals: [], provenance };

  const f = await recentFilings(ctx, company.cik, 300);
  provenance.push(f.prov);
  const events = await decodeEvents(ctx, f.data ?? [], { since: now.getTime() - days * DAY_MS, read502: opts.read502 ?? 3, provenance });

  const signals: Signal[] = [];
  const id = ctx.graph.upsert('company', company.name, { cik: company.cik, ...(company.ticker ? { ticker: company.ticker } : {}) });
  for (const e of events) {
    const evidence = eventEvidence(e);
    if (!evidence.length) continue;
    const ageDays = (now.getTime() - Date.parse(`${e.date}T00:00:00Z`)) / DAY_MS;
    signals.push({
      id: signalId('filings', String(company.cik), e.url),
      module: 'filings',
      title: `${company.ticker || company.name}: ${e.summary} (${e.form}, ${e.date})`,
      // Fresh filings score higher; a 90-day-old one is context, not news.
      score: clamp(Math.round(e.impact - Math.min(30, ageDays / 3)), 0, 100),
      entity: id,
      evidence,
      createdAt: nowIso,
    });
  }
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { ...base, result: { company, days, events }, signals, provenance };
}

export interface FilingsOptions {
  /** Form types, e.g. ['8-K']. Default: all forms. */
  forms?: string[];
  /** Look-back window in days. Default 30. */
  days?: number;
  /** Limit to one company by CIK. */
  cik?: number;
}

export interface FilingsResult {
  query: string;
  from: string;
  to: string;
  forms: string[];
  total: number;
  totalIsLowerBound: boolean;
  hits: (FullTextHit & { itemTitles: string[] })[];
  topCompanies: { name: string; docs: number }[];
}

/** A multi-word query without quotes or operators is searched as an exact phrase. */
export function phraseQuery(q: string): string {
  const t = q.trim();
  if (/["()]|\b(AND|OR|NOT)\b/.test(t) || !/\s/.test(t)) return t;
  return `"${t}"`;
}

export async function filings(ctx: Ctx, query: string, opts: FilingsOptions = {}): Promise<ModuleResult<FilingsResult>> {
  const days = opts.days ?? 30;
  const now = ctx.now();
  const to = now.toISOString().slice(0, 10);
  const from = new Date(now.getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const q = phraseQuery(query);
  const forms = opts.forms ?? [];
  const r = await fullTextSearch(ctx, q, { forms, from, to, ...(opts.cik ? { cik: opts.cik } : {}) });
  const d = r.data;
  return {
    module: 'filings',
    input: query,
    generatedAt: now.toISOString(),
    result: {
      query: q,
      from,
      to,
      forms,
      total: d?.total ?? 0,
      totalIsLowerBound: d?.totalIsLowerBound ?? false,
      hits: (d?.hits ?? []).map((h) => ({ ...h, itemTitles: h.items.filter((c) => c !== '9.01').map(decodeItem) })),
      topCompanies: d?.topCompanies ?? [],
    },
    signals: [],
    provenance: [r.prov],
  };
}
