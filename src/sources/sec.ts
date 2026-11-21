import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface Company {
  cik: number;
  ticker: string;
  name: string;
}

export interface Filing {
  form: string;
  date: string;
  description: string;
  url: string;
  /** 8-K item codes such as 1.05 or 5.02, from the submissions feed. */
  items?: string[];
  accession?: string;
}

/** SEC requires a User-Agent with contact details; without OCULON_CONTACT we do not call it at all. */
function contactMissing(url: string): Sourced<never> {
  return {
    data: null,
    prov: { source: 'sec-edgar', url, status: 'UNAVAILABLE', fetchedAt: new Date().toISOString(), note: 'set OCULON_CONTACT in .env to enable SEC EDGAR' },
  };
}

const hasContact = () => Boolean(process.env.OCULON_CONTACT?.trim());

export async function companies(ctx: Ctx): Promise<Sourced<Company[]>> {
  const url = 'https://www.sec.gov/files/company_tickers.json';
  if (!hasContact()) return contactMissing(url);
  const r = await ctx.http.get<Record<string, { cik_str: number; ticker: string; title: string }>>(url, { source: 'sec-edgar', ttlSec: 7 * 86_400 });
  return { data: r.data ? Object.values(r.data).map((c) => ({ cik: c.cik_str, ticker: c.ticker, name: c.title })) : null, prov: r.prov };
}

/** Exact ticker match first, then the shortest company name that contains the query as a word. */
export function matchCompany(list: Company[], query: string): Company | null {
  const q = query.trim().toLowerCase();
  const byTicker = list.find((c) => c.ticker.toLowerCase() === q);
  if (byTicker) return byTicker;
  const re = new RegExp(`\\b${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
  return list.filter((c) => re.test(c.name)).sort((a, b) => a.name.length - b.name.length)[0] ?? null;
}

const archiveUrl = (cik: number | string, accession: string, doc: string) => `https://www.sec.gov/Archives/edgar/data/${Number(cik)}/${accession.replace(/-/g, '')}/${doc}`;

export async function recentFilings(ctx: Ctx, cik: number, max = 40): Promise<Sourced<Filing[]>> {
  const url = `https://data.sec.gov/submissions/CIK${String(cik).padStart(10, '0')}.json`;
  if (!hasContact()) return contactMissing(url);
  const r = await ctx.http.get<{ filings?: { recent?: Record<string, string[]> } }>(url, { source: 'sec-edgar', ttlSec: 1800 });
  const rec = r.data?.filings?.recent;
  if (!rec) return { data: null, prov: r.prov };
  const n = Math.min(max, rec.form?.length ?? 0);
  const data = Array.from({ length: n }, (_, i): Filing => {
    const acc = rec.accessionNumber?.[i] ?? '';
    const items = rec.items?.[i]
      ?.split(',')
      .map((x) => x.trim())
      .filter(Boolean);
    return {
      form: rec.form?.[i] ?? '',
      date: rec.filingDate?.[i] ?? '',
      description: rec.primaryDocDescription?.[i] || rec.form?.[i] || '',
      url: archiveUrl(cik, acc, rec.primaryDocument?.[i] ?? ''),
      ...(items?.length ? { items } : {}),
      ...(acc ? { accession: acc } : {}),
    };
  });
  return { data, prov: r.prov };
}

export interface FullTextHit {
  company: string;
  ticker: string | null;
  cik: number;
  form: string;
  filed: string;
  /** The document type that matched, e.g. 8-K or EX-99.1. */
  fileType: string;
  items: string[];
  location: string | null;
  accession: string;
  url: string;
  /** EDGAR filing index page. */
  indexUrl: string;
}

export interface FullTextResult {
  total: number;
  /** True when SEC caps the count (relation "gte"). */
  totalIsLowerBound: boolean;
  /** One entry per filing (exhibits of the same filing are merged), newest first. */
  hits: FullTextHit[];
  /** Companies with the most matching documents, from SEC's own aggregation. */
  topCompanies: { name: string; docs: number }[];
}

export interface FullTextOptions {
  /** e.g. ['8-K'] or ['10-K', '10-Q']. */
  forms?: string[];
  /** YYYY-MM-DD. */
  from?: string;
  to?: string;
  /** Limit to one company. */
  cik?: number;
  /** Offset for paging (SEC returns 100 documents per page). */
  offset?: number;
}

interface EftsSource {
  ciks?: string[];
  display_names?: string[];
  form?: string;
  root_forms?: string[];
  file_date?: string;
  file_type?: string;
  items?: string[];
  biz_locations?: string[];
  adsh?: string;
}

/** "Examplecorp Inc.  (EXC)  (CIK 0000000001)" -> name and ticker. */
export function parseDisplayName(s: string): { name: string; ticker: string | null } {
  const m = s.match(/^(.*?)\s+(?:\(([A-Z0-9.\-, ]+)\)\s+)?\(CIK \d+\)\s*$/);
  if (!m) return { name: s.trim(), ticker: null };
  return { name: m[1]!.trim(), ticker: m[2]?.split(',')[0]?.trim() || null };
}

/** EDGAR full-text search (2001 onward); the same index that powers sec.gov/edgar/search. Phrases need double quotes. */
export async function fullTextSearch(ctx: Ctx, q: string, o: FullTextOptions = {}): Promise<Sourced<FullTextResult>> {
  const params = [`q=${enc(q)}`];
  if (o.from || o.to) params.push('dateRange=custom', ...(o.from ? [`startdt=${o.from}`] : []), ...(o.to ? [`enddt=${o.to}`] : []));
  if (o.forms?.length) params.push(`forms=${enc(o.forms.join(','))}`);
  if (o.cik) params.push(`ciks=${String(o.cik).padStart(10, '0')}`);
  if (o.offset) params.push(`from=${o.offset}`);
  const url = `https://efts.sec.gov/LATEST/search-index?${params.join('&')}`;
  if (!hasContact()) return contactMissing(url);
  const r = await ctx.http.get<FullTextResult>(url, {
    source: 'sec-edgar',
    ttlSec: 3600,
    // Raw pages are ~60 KB; keep only what we show.
    keep: (d: { hits?: { total?: { value?: number; relation?: string }; hits?: { _id: string; _source: EftsSource }[] }; aggregations?: { entity_filter?: { buckets?: { key: string; doc_count: number }[] } } }): FullTextResult => {
      const byAcc = new Map<string, FullTextHit>();
      for (const h of d.hits?.hits ?? []) {
        const s = h._source;
        const acc = s.adsh ?? h._id.split(':')[0] ?? '';
        if (!acc || byAcc.has(acc)) continue;
        const cik = Number(s.ciks?.[0] ?? 0);
        const doc = h._id.split(':')[1] ?? '';
        const dn = parseDisplayName(s.display_names?.[0] ?? '');
        byAcc.set(acc, {
          company: dn.name,
          ticker: dn.ticker,
          cik,
          form: s.form ?? s.root_forms?.[0] ?? '',
          filed: s.file_date ?? '',
          fileType: s.file_type ?? '',
          items: s.items ?? [],
          location: s.biz_locations?.[0] ?? null,
          accession: acc,
          url: archiveUrl(cik, acc, doc),
          indexUrl: `https://www.sec.gov/Archives/edgar/data/${cik}/${acc.replace(/-/g, '')}/${acc}-index.htm`,
        });
      }
      return {
        total: d.hits?.total?.value ?? 0,
        totalIsLowerBound: d.hits?.total?.relation === 'gte',
        hits: [...byAcc.values()].sort((a, b) => b.filed.localeCompare(a.filed)),
        topCompanies: (d.aggregations?.entity_filter?.buckets ?? []).slice(0, 10).map((b) => ({ name: parseDisplayName(b.key).name, docs: b.doc_count })),
      };
    },
  });
  return { data: r.data, prov: r.prov };
}

/** Plain text of one filing document (HTML stripped), capped in size; used to read 8-K item 5.02 details. */
export async function filingText(ctx: Ctx, url: string, maxChars = 20_000): Promise<Sourced<string>> {
  if (!hasContact()) return contactMissing(url);
  const r = await ctx.http.get<string>(url, { source: 'sec-edgar', ttlSec: 30 * 86_400, as: 'text', timeoutMs: 20_000 });
  if (!r.data) return { data: null, prov: r.prov };
  const text = r.data
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;|&#160;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#8217;|&rsquo;/g, "'")
    .replace(/&#\d+;|&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return { data: text.slice(0, maxChars), prov: r.prov };
}
