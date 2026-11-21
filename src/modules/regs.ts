/**
 * US regulation radar (Federal Register API, no key):
 *   documents: final rules, proposed rules, presidential documents (executive orders, proclamations, memoranda,
 *     determinations) and notices, with agencies, effective dates and comment deadlines.
 *   public inspection: documents on file to be published in the next issue, the earliest official warning.
 *   agencies: resolves agency names ("Securities and Exchange Commission", "SEC") to Federal Register slugs.
 * Executive orders and significant final rules from the last 2 days, and presidential documents on public
 * inspection, become signals. `upcomingRegDates` feeds effective dates and comment deadlines to a calendar.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';

const FR = 'https://www.federalregister.gov/api/v1';
const DAY = 86_400_000;
const SOURCE = 'federal-register';

export type RegType = 'rule' | 'proposed' | 'presidential' | 'notice';
const TYPE_CODE: Record<RegType, string> = { rule: 'RULE', proposed: 'PRORULE', presidential: 'PRESDOCU', notice: 'NOTICE' };
const TYPE_NAME: Record<RegType, string> = { rule: 'Rule', proposed: 'Proposed Rule', presidential: 'Presidential Document', notice: 'Notice' };

const FIELDS = ['title', 'type', 'subtype', 'abstract', 'action', 'document_number', 'html_url', 'publication_date', 'effective_on', 'comments_close_on', 'agencies', 'significant', 'executive_order_number', 'signing_date', 'docket_ids', 'regulation_id_numbers'];
const fieldQs = FIELDS.map((f) => `fields[]=${f}`).join('&');

export interface RegDoc {
  documentNumber: string;
  title: string;
  type: string;
  subtype: string | null;
  action: string | null;
  agencies: string[];
  publicationDate: string;
  effectiveOn: string | null;
  commentsCloseOn: string | null;
  significant: boolean;
  executiveOrder: string | null;
  signingDate: string | null;
  abstract: string;
  dockets: string[];
  rins: string[];
  url: string;
}

export interface InspectionDoc {
  documentNumber: string;
  title: string;
  type: string;
  agencies: string[];
  filingType: string;
  filedAt: string;
  publicationDate: string;
  url: string;
  pdfUrl: string;
}

interface RawDoc {
  title?: string;
  type?: string;
  subtype?: string | null;
  abstract?: string | null;
  action?: string | null;
  document_number: string;
  html_url: string;
  publication_date: string;
  effective_on?: string | null;
  comments_close_on?: string | null;
  agencies?: { name?: string; raw_name?: string; slug?: string }[];
  significant?: boolean | null;
  executive_order_number?: string | number | null;
  signing_date?: string | null;
  docket_ids?: string[];
  regulation_id_numbers?: string[];
}

interface RawInspection {
  document_number: string;
  title?: string;
  type?: string;
  agency_names?: string[];
  agencies?: { name?: string; slug?: string }[];
  filing_type?: string;
  filed_at?: string;
  publication_date?: string;
  html_url: string;
  pdf_url?: string;
}

const agencyNames = (a?: { name?: string; raw_name?: string }[]) => [...new Set((a ?? []).map((x) => x.name ?? x.raw_name ?? '').filter(Boolean))];

const toDoc = (d: RawDoc): RegDoc => ({
  documentNumber: d.document_number,
  title: (d.title ?? '').replace(/\s+/g, ' ').trim(),
  type: d.type ?? '',
  subtype: d.subtype ?? null,
  action: d.action ?? null,
  agencies: agencyNames(d.agencies),
  publicationDate: d.publication_date,
  effectiveOn: d.effective_on ?? null,
  commentsCloseOn: d.comments_close_on ?? null,
  significant: d.significant === true,
  executiveOrder: d.executive_order_number != null && d.executive_order_number !== '' ? String(d.executive_order_number) : null,
  signingDate: d.signing_date ?? null,
  abstract: (d.abstract ?? '').replace(/\s+/g, ' ').trim().slice(0, 400),
  dockets: d.docket_ids ?? [],
  rins: d.regulation_id_numbers ?? [],
  url: d.html_url,
});

const isoDay = (t: number) => new Date(t).toISOString().slice(0, 10);

interface AgencyRef { name: string; short: string; slug: string }

/** All Federal Register agencies (about 470), cached for a week. */
export async function frAgencies(ctx: Ctx): Promise<Sourced<AgencyRef[]>> {
  return ctx.http.get<AgencyRef[]>(`${FR}/agencies`, { source: SOURCE, ttlSec: 7 * 86_400, timeoutMs: 30_000, keep: (d: { name?: string; short_name?: string | null; slug?: string }[]) => (Array.isArray(d) ? d.map((a) => ({ name: a.name ?? '', short: a.short_name ?? '', slug: a.slug ?? '' })) : []) });
}

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

/** Resolve an agency name, short name or slug to its Federal Register slug. */
export async function resolveAgency(ctx: Ctx, agency: string): Promise<{ slug: string; name: string; prov: Provenance }> {
  const r = await frAgencies(ctx);
  const q = norm(agency);
  const list = r.data ?? [];
  const hit =
    list.find((a) => a.slug === agency.trim().toLowerCase()) ??
    list.find((a) => norm(a.short) === q) ??
    list.find((a) => norm(a.name) === q) ??
    // "Department of Homeland Security" is listed as "Homeland Security Department".
    list.find((a) => { const words = q.split(' ').filter((w) => !['of', 'the', 'and', 'for', 'us', 'u', 's'].includes(w)); return words.length > 0 && words.every((w) => norm(a.name).split(' ').includes(w)); });
  return { slug: hit?.slug ?? agency.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-'), name: hit?.name ?? agency, prov: r.prov };
}

async function searchDocs(ctx: Ctx, cond: string, perPage: number, ttlSec: number): Promise<Sourced<RegDoc[]>> {
  const r = await ctx.http.get<RawDoc[]>(`${FR}/documents.json?per_page=${perPage}&order=newest&${cond}&${fieldQs}`, { source: SOURCE, ttlSec, timeoutMs: 30_000, keep: (d: { results?: RawDoc[] }) => d.results ?? [] });
  return { data: r.data ? r.data.map(toDoc) : null, prov: r.prov };
}

/** Documents on public inspection now (to be published in the next issue or two). */
export async function publicInspection(ctx: Ctx): Promise<Sourced<InspectionDoc[]>> {
  const r = await ctx.http.get<InspectionDoc[]>(`${FR}/public-inspection-documents/current.json`, {
    source: SOURCE,
    ttlSec: 1800,
    timeoutMs: 30_000,
    keep: (d: { results?: RawInspection[] }) =>
      (d.results ?? []).map((x) => ({ documentNumber: x.document_number, title: (x.title ?? '').replace(/\s+/g, ' ').trim(), type: x.type ?? '', agencies: x.agency_names?.length ? x.agency_names : agencyNames(x.agencies), filingType: x.filing_type ?? '', filedAt: x.filed_at ?? '', publicationDate: x.publication_date ?? '', url: x.html_url, pdfUrl: x.pdf_url ?? '' })),
  });
  return r;
}

export interface RegsResult {
  window: { from: string; to: string };
  query: string | null;
  agency: string | null;
  types: RegType[];
  documents: RegDoc[];
  executiveOrders: RegDoc[];
  publicInspection: InspectionDoc[];
}

/**
 * Recent Federal Register documents. Notices are numerous (hundreds a day), so they are only included by default
 * when a query or agency narrows the search; pass `types` to choose explicitly.
 */
export async function regs(ctx: Ctx, opts: { query?: string; days?: number; agency?: string; types?: RegType[] } = {}): Promise<ModuleResult<RegsResult>> {
  const now = ctx.now();
  const days = Math.max(1, Math.min(opts.days ?? 7, 365));
  const fromT = now.getTime() - days * DAY;
  const query = opts.query?.trim() || null;
  const provenance: Provenance[] = [];
  let agencySlug: string | null = null;
  let agencyName: string | null = null;
  if (opts.agency?.trim()) {
    const a = await resolveAgency(ctx, opts.agency);
    provenance.push(a.prov);
    agencySlug = a.slug;
    agencyName = a.name;
  }
  const types: RegType[] = opts.types?.length ? [...new Set(opts.types)] : query || agencySlug ? ['rule', 'proposed', 'presidential', 'notice'] : ['rule', 'proposed', 'presidential'];

  const base = [`conditions[publication_date][gte]=${isoDay(fromT)}`, query ? `conditions[term]=${encodeURIComponent(query)}` : '', agencySlug ? `conditions[agencies][]=${encodeURIComponent(agencySlug)}` : ''].filter(Boolean).join('&');
  const main = types.filter((t) => t !== 'notice');
  const documents: RegDoc[] = [];
  if (main.length) {
    const r = await searchDocs(ctx, `${base}&${main.map((t) => `conditions[type][]=${TYPE_CODE[t]}`).join('&')}`, 100, 1800);
    provenance.push(r.prov);
    documents.push(...(r.data ?? []));
  }
  if (types.includes('notice')) {
    const r = await searchDocs(ctx, `${base}&conditions[type][]=NOTICE`, 50, 1800);
    provenance.push(r.prov);
    documents.push(...(r.data ?? []));
  }
  documents.sort((a, b) => b.publicationDate.localeCompare(a.publicationDate) || b.documentNumber.localeCompare(a.documentNumber));

  // Executive orders get their own query so they are never crowded out of the window by other documents.
  const eo = await searchDocs(ctx, `conditions[publication_date][gte]=${isoDay(fromT)}&conditions[presidential_document_type][]=executive_order${query ? `&conditions[term]=${encodeURIComponent(query)}` : ''}`, 50, 1800);
  provenance.push(eo.prov);
  const executiveOrders = eo.data ?? [];

  const pi = await publicInspection(ctx);
  provenance.push(pi.prov);
  const wantNames = new Set(types.map((t) => TYPE_NAME[t]));
  const q = query?.toLowerCase();
  const an = agencyName ? norm(agencyName) : null;
  const inspection = (pi.data ?? []).filter((d) => wantNames.has(d.type) && (!q || d.title.toLowerCase().includes(q)) && (!an || d.agencies.some((x) => norm(x) === an)));

  const recent = isoDay(now.getTime() - 2 * DAY);
  const signals: Signal[] = [];
  for (const d of executiveOrders.filter((x) => x.publicationDate >= recent).slice(0, 5)) {
    signals.push({ id: signalId('regs', d.documentNumber), module: 'regs', title: `Executive Order${d.executiveOrder ? ` ${d.executiveOrder}` : ''}: ${d.title}`, score: 74, entity: 'Executive Office of the President', evidence: [{ source: SOURCE, text: `Published ${d.publicationDate}${d.signingDate ? `, signed ${d.signingDate}` : ''}`, url: d.url }], createdAt: now.toISOString() });
  }
  for (const d of documents.filter((x) => x.type === 'Rule' && x.significant && /final rule/i.test(x.action ?? 'final rule') && !/correct/i.test(x.action ?? '') && x.publicationDate >= recent).slice(0, 5)) {
    signals.push({ id: signalId('regs', d.documentNumber), module: 'regs', title: `Significant final rule: ${d.title}`, score: 64, ...(d.agencies[0] ? { entity: d.agencies[0] } : {}), evidence: [{ source: SOURCE, text: `${d.agencies.join(', ')}; published ${d.publicationDate}${d.effectiveOn ? `, effective ${d.effectiveOn}` : ''}${d.abstract ? `: ${d.abstract.slice(0, 200)}` : ''}`, url: d.url }], createdAt: now.toISOString() });
  }
  for (const d of inspection.filter((x) => x.type === 'Presidential Document').slice(0, 3)) {
    signals.push({ id: signalId('regs', 'pi', d.documentNumber), module: 'regs', title: `Presidential document on public inspection: ${d.title}`, score: 70, entity: 'Executive Office of the President', evidence: [{ source: SOURCE, text: `Filed ${d.filedAt.slice(0, 16).replace('T', ' ')}, to be published ${d.publicationDate}`, url: d.url }], createdAt: now.toISOString() });
  }
  for (const s of signals) ctx.graph.saveSignal(s);

  return {
    module: 'regs',
    input: [query, agencyName, `last ${days}d`].filter(Boolean).join(', '),
    generatedAt: now.toISOString(),
    result: { window: { from: new Date(fromT).toISOString(), to: now.toISOString() }, query, agency: agencySlug, types, documents, executiveOrders, publicInspection: inspection },
    signals,
    provenance,
  };
}

export interface RegDate {
  date: string;
  title: string;
  kind: 'effective' | 'comments-close';
  url: string;
  agency: string;
}

/** Final rules taking effect and proposed-rule comment periods closing in the next `days` days, for a catalyst calendar. */
export async function upcomingRegDates(ctx: Ctx, days = 30): Promise<RegDate[]> {
  const now = ctx.now().getTime();
  const from = isoDay(now);
  const to = isoDay(now + Math.max(1, Math.min(days, 365)) * DAY);
  const [eff, com] = await Promise.all([
    searchDocs(ctx, `conditions[effective_date][gte]=${from}&conditions[effective_date][lte]=${to}&conditions[type][]=RULE`, 100, 6 * 3600),
    searchDocs(ctx, `conditions[comment_date][gte]=${from}&conditions[comment_date][lte]=${to}&conditions[type][]=PRORULE`, 100, 6 * 3600),
  ]);
  const out: RegDate[] = [];
  for (const d of eff.data ?? []) if (d.effectiveOn && d.effectiveOn >= from && d.effectiveOn <= to) out.push({ date: d.effectiveOn, title: d.title, kind: 'effective', url: d.url, agency: d.agencies[0] ?? '' });
  for (const d of com.data ?? []) if (d.commentsCloseOn && d.commentsCloseOn >= from && d.commentsCloseOn <= to) out.push({ date: d.commentsCloseOn, title: d.title, kind: 'comments-close', url: d.url, agency: d.agencies[0] ?? '' });
  return out.sort((a, b) => a.date.localeCompare(b.date) || a.title.localeCompare(b.title));
}
