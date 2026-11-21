/**
 * Regulated-product trails (no keys):
 *   openFDA enforcement reports: drug, device and food recalls by recalling firm (api.fda.gov; 1,000 requests/day
 *     per IP without a key, 240/minute).
 *   ClinicalTrials.gov v2: trials a company sponsors or collaborates on, counted by status, plus recent terminations.
 */
import { DAY_MS, enc, type Ctx } from '../core/context.js';
import type { Provenance, Sourced } from '../core/types.js';

export type RecallCategory = 'drug' | 'device' | 'food';

export interface Recall {
  category: RecallCategory;
  recallNumber: string;
  firm: string;
  /** Class I: reasonable probability of serious harm or death. Class II: temporary or reversible harm. Class III: unlikely to cause harm. */
  classification: string;
  status: string;
  product: string;
  reason: string;
  quantity: string;
  distribution: string;
  /** Dates as YYYY-MM-DD. */
  initiated: string;
  reported: string;
  voluntary: string;
  url: string;
}

export interface FirmRecalls {
  firm: string;
  /** All enforcement reports matching the firm name, per category (openFDA total). */
  totals: Record<RecallCategory, number>;
  /** Newest first, up to 10 per category. */
  recent: Recall[];
  /** Class I recalls reported within the window. */
  newClassI: Recall[];
}

const isoDay = (s: string | undefined) => (s && /^\d{8}$/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}` : (s ?? ''));
const compact = (s: string | undefined, n: number) => (s ?? '').replace(/\s+/g, ' ').trim().slice(0, n);

/** openFDA phrase search; quotes and other syntax characters in the name are dropped. */
const firmTerm = (firm: string) => `"${firm.replace(/["\\:()[\]{}+]/g, ' ').replace(/\s+/g, ' ').trim()}"`;

interface EnforcementRow {
  recall_number?: string;
  recalling_firm?: string;
  classification?: string;
  status?: string;
  product_description?: string;
  reason_for_recall?: string;
  product_quantity?: string;
  distribution_pattern?: string;
  recall_initiation_date?: string;
  report_date?: string;
  voluntary_mandated?: string;
}

export async function enforcement(ctx: Ctx, category: RecallCategory, firm: string, limit = 10): Promise<Sourced<{ total: number; recalls: Recall[] }>> {
  const url = `https://api.fda.gov/${category}/enforcement.json?search=recalling_firm:${enc(firmTerm(firm))}&sort=report_date:desc&limit=${limit}`;
  const r = await ctx.http.get<{ total: number; recalls: Recall[] }>(url, {
    source: 'openfda',
    ttlSec: 12 * 3600,
    keep: (d: { meta?: { results?: { total?: number } }; results?: EnforcementRow[] }) => ({
      total: d.meta?.results?.total ?? d.results?.length ?? 0,
      recalls: (d.results ?? []).map(
        (x): Recall => ({
          category,
          recallNumber: x.recall_number ?? '',
          firm: x.recalling_firm ?? '',
          classification: x.classification ?? '',
          status: x.status ?? '',
          product: compact(x.product_description, 240),
          reason: compact(x.reason_for_recall, 300),
          quantity: compact(x.product_quantity, 80),
          distribution: compact(x.distribution_pattern, 160),
          initiated: isoDay(x.recall_initiation_date),
          reported: isoDay(x.report_date),
          voluntary: x.voluntary_mandated ?? '',
          // The openFDA record itself; FDA's enforcement-report site has no stable per-recall link.
          url: `https://api.fda.gov/${category}/enforcement.json?search=recall_number:${enc(`"${x.recall_number ?? ''}"`)}`,
        }),
      ),
    }),
  });
  // openFDA answers 404 "No matches found" when nothing matches; that is an empty result, not an outage.
  if (!r.data && r.prov.note === 'HTTP 404') return { data: { total: 0, recalls: [] }, prov: r.prov };
  return r;
}

/** Drug, device and food recalls for a firm. Each recall must name the firm (all query words), to drop look-alike firms. */
export async function recalls(ctx: Ctx, firm: string, opts: { days?: number; match?: (recallingFirm: string) => boolean } = {}): Promise<{ data: FirmRecalls | null; provenance: Provenance[] }> {
  const days = opts.days ?? 90;
  const cats: RecallCategory[] = ['drug', 'device', 'food'];
  const rs = await Promise.all(cats.map((c) => enforcement(ctx, c, firm)));
  const provenance = rs.map((r) => r.prov);
  if (rs.every((r) => !r.data)) return { data: null, provenance };
  const words = firm.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 1);
  const match = opts.match ?? ((f: string) => words.every((w) => new RegExp(`\\b${w}\\b`).test(f.toLowerCase())));
  const totals = { drug: 0, device: 0, food: 0 } as Record<RecallCategory, number>;
  const recent: Recall[] = [];
  cats.forEach((c, i) => {
    const d = rs[i]!.data;
    if (!d) return;
    const mine = d.recalls.filter((x) => match(x.firm));
    // The total counts every firm the phrase matched; only report it when the sample is all this firm.
    totals[c] = mine.length === d.recalls.length ? d.total : mine.length;
    recent.push(...mine);
  });
  recent.sort((a, b) => b.reported.localeCompare(a.reported));
  const since = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  return { data: { firm, totals, recent, newClassI: recent.filter((x) => x.classification === 'Class I' && x.reported >= since) }, provenance };
}

export interface Trial {
  nctId: string;
  title: string;
  status: string;
  phases: string[];
  leadSponsor: string;
  conditions: string[];
  enrollment: number | null;
  whyStopped: string | null;
  completionDate: string | null;
  lastUpdate: string | null;
  url: string;
}

export interface SponsorTrials {
  sponsor: string;
  counts: { recruiting: number; active: number; completed: number; terminated: number };
  /** Terminated trials with a completion (stop) date inside the window, newest first. */
  recentlyTerminated: Trial[];
}

interface CtStudy {
  protocolSection?: {
    identificationModule?: { nctId?: string; briefTitle?: string };
    statusModule?: { overallStatus?: string; whyStopped?: string; completionDateStruct?: { date?: string }; lastUpdatePostDateStruct?: { date?: string } };
    sponsorCollaboratorsModule?: { leadSponsor?: { name?: string } };
    conditionsModule?: { conditions?: string[] };
    designModule?: { phases?: string[]; enrollmentInfo?: { count?: number } };
  };
}

const CT = 'https://clinicaltrials.gov/api/v2/studies';
const CT_FIELDS = 'NCTId,BriefTitle,OverallStatus,Phase,WhyStopped,CompletionDate,LastUpdatePostDate,LeadSponsorName,Condition,EnrollmentCount';

const toTrial = (s: CtStudy): Trial => {
  const p = s.protocolSection ?? {};
  const id = p.identificationModule?.nctId ?? '';
  return {
    nctId: id,
    title: p.identificationModule?.briefTitle ?? '',
    status: p.statusModule?.overallStatus ?? '',
    phases: p.designModule?.phases ?? [],
    leadSponsor: p.sponsorCollaboratorsModule?.leadSponsor?.name ?? '',
    conditions: (p.conditionsModule?.conditions ?? []).slice(0, 4),
    enrollment: p.designModule?.enrollmentInfo?.count ?? null,
    whyStopped: p.statusModule?.whyStopped ?? null,
    completionDate: p.statusModule?.completionDateStruct?.date ?? null,
    lastUpdate: p.statusModule?.lastUpdatePostDateStruct?.date ?? null,
    url: `https://clinicaltrials.gov/study/${id}`,
  };
};

async function ctCount(ctx: Ctx, sponsor: string, status: string): Promise<Sourced<number>> {
  const r = await ctx.http.get<{ totalCount?: number }>(`${CT}?query.spons=${enc(sponsor)}&filter.overallStatus=${status}&pageSize=1&countTotal=true&fields=NCTId`, {
    source: 'clinicaltrials',
    ttlSec: 24 * 3600,
    keep: (d: { totalCount?: number }) => ({ totalCount: d.totalCount ?? 0 }),
  });
  return { data: r.data ? (r.data.totalCount ?? 0) : null, prov: r.prov };
}

/** Trials where the company is lead sponsor or collaborator (ClinicalTrials.gov query.spons). */
export async function sponsorTrials(ctx: Ctx, sponsor: string, days = 180): Promise<{ data: SponsorTrials | null; provenance: Provenance[] }> {
  const [rec, act, done, term] = await Promise.all([
    ctCount(ctx, sponsor, 'RECRUITING'),
    ctCount(ctx, sponsor, 'ACTIVE_NOT_RECRUITING'),
    ctCount(ctx, sponsor, 'COMPLETED'),
    ctx.http.get<{ totalCount?: number; studies?: CtStudy[] }>(`${CT}?query.spons=${enc(sponsor)}&filter.overallStatus=TERMINATED&pageSize=20&countTotal=true&sort=CompletionDate:desc&fields=${CT_FIELDS}`, {
      source: 'clinicaltrials',
      ttlSec: 12 * 3600,
    }),
  ]);
  const provenance = [rec.prov, act.prov, done.prov, term.prov];
  if (rec.data === null && act.data === null && done.data === null && !term.data) return { data: null, provenance };
  const today = ctx.now().toISOString().slice(0, 10);
  const since = new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  // CompletionDate may be "2026-10" (month only); compare as strings, which still orders correctly.
  const recentlyTerminated = (term.data?.studies ?? []).map(toTrial).filter((t) => t.completionDate && t.completionDate >= since.slice(0, t.completionDate.length) && t.completionDate <= today);
  return {
    data: {
      sponsor,
      counts: { recruiting: rec.data ?? 0, active: act.data ?? 0, completed: done.data ?? 0, terminated: term.data?.totalCount ?? 0 },
      recentlyTerminated,
    },
    provenance,
  };
}

export const isPhase3 = (t: Trial) => t.phases.includes('PHASE3');
