/**
 * Recall check: is this car or product recalled?
 *   Vehicles: a 17-character VIN (decoded with NHTSA vPIC) or "year make model", checked against NHTSA safety
 *     recalls, with "park it" and "park outside" warnings.
 *   Products: US consumer product recalls (CPSC SaferProducts) and FDA food, drug and device enforcement reports.
 * No keys needed.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';

export interface RecallItem {
  source: 'NHTSA' | 'CPSC' | 'FDA';
  id: string;
  date: string | null;
  title: string;
  hazard: string;
  remedy: string;
  url: string;
  /** Vehicle recalls: the owner is told not to drive it, or to park it outside. */
  parkIt?: boolean;
  parkOutside?: boolean;
  component?: string;
  /** FDA: Class I is the most serious. */
  classification?: string;
}

export interface RecallResult {
  query: string;
  kind: 'vehicle' | 'product';
  vehicle: { make: string; model: string; year: number; vin: string | null } | null;
  recalls: RecallItem[];
  note: string | null;
}

const VIN_RE = /^[A-HJ-NPR-Z0-9]{17}$/i;
const nhtsaDate = (d: string | undefined) => { const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(d ?? ''); return m ? `${m[3]}-${m[2]}-${m[1]}` : d ?? null; };
const clip = (s: string | undefined, n = 400) => (s ?? '').replace(/\s+/g, ' ').trim().slice(0, n);

/** "2018 Honda Accord", "Honda Accord 2018" → year, make, model. */
export function parseVehicle(q: string): { year: number; make: string; model: string } | null {
  const words = q.trim().split(/\s+/);
  const yi = words.findIndex((w) => /^(19[5-9]\d|20[0-4]\d)$/.test(w));
  if (yi < 0) return null;
  const rest = words.filter((_, i) => i !== yi);
  if (rest.length < 2) return null;
  return { year: Number(words[yi]), make: rest[0]!, model: rest.slice(1).join(' ') };
}

async function decodeVin(ctx: Ctx, vin: string): Promise<Sourced<{ make: string; model: string; year: number }>> {
  const r = await ctx.http.get<{ Make?: string; Model?: string; ModelYear?: string; ErrorCode?: string }>(`https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/${encodeURIComponent(vin)}?format=json`, { source: 'nhtsa-vpic', ttlSec: 30 * 86_400, keep: (d: { Results?: { Make?: string; Model?: string; ModelYear?: string; ErrorCode?: string }[] }) => d.Results?.[0] ?? {} });
  const d = r.data;
  return { data: d?.Make && d.Model && d.ModelYear ? { make: d.Make, model: d.Model, year: Number(d.ModelYear) } : null, prov: r.prov };
}

interface NhtsaRecall { NHTSACampaignNumber?: string; ReportReceivedDate?: string; Component?: string; Summary?: string; Consequence?: string; Remedy?: string; parkIt?: boolean; parkOutSide?: boolean; Manufacturer?: string }

async function vehicleRecalls(ctx: Ctx, make: string, model: string, year: number): Promise<Sourced<RecallItem[]>> {
  const r = await ctx.http.get<NhtsaRecall[]>(`https://api.nhtsa.gov/recalls/recallsByVehicle?make=${encodeURIComponent(make)}&model=${encodeURIComponent(model)}&modelYear=${year}`, { source: 'nhtsa', ttlSec: 12 * 3600, keep: (d: { results?: NhtsaRecall[] }) => d.results ?? [] });
  return {
    data: r.data?.map((x) => ({
      source: 'NHTSA' as const,
      id: x.NHTSACampaignNumber ?? '',
      date: nhtsaDate(x.ReportReceivedDate),
      title: `${x.Component ?? 'Recall'}`.replace(/:/g, ' › '),
      hazard: clip(x.Consequence || x.Summary),
      remedy: clip(x.Remedy, 300),
      url: `https://www.nhtsa.gov/recalls?nhtsaId=${encodeURIComponent(x.NHTSACampaignNumber ?? '')}`,
      parkIt: Boolean(x.parkIt),
      parkOutside: Boolean(x.parkOutSide),
      component: x.Component ?? '',
    })).sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '')) ?? null,
    prov: r.prov,
  };
}

interface CpscRecall { RecallNumber?: string; RecallDate?: string; Title?: string; URL?: string; Hazards?: { Name?: string }[]; Remedies?: { Name?: string }[] }

async function consumerRecalls(ctx: Ctx, q: string): Promise<Sourced<RecallItem[]>> {
  const since = new Date(ctx.now().getTime() - 5 * 365 * 86_400_000).toISOString().slice(0, 10);
  const r = await ctx.http.get<CpscRecall[]>(`https://www.saferproducts.gov/RestWebServices/Recall?format=json&ProductName=${encodeURIComponent(q)}&RecallDateStart=${since}`, {
    source: 'cpsc',
    ttlSec: 12 * 3600,
    timeoutMs: 30_000,
    keep: (d: CpscRecall[]) => (Array.isArray(d) ? d.slice(0, 40).map((x) => ({ RecallNumber: x.RecallNumber, RecallDate: x.RecallDate, Title: x.Title, URL: x.URL, Hazards: (x.Hazards ?? []).slice(0, 1), Remedies: (x.Remedies ?? []).slice(0, 1) })) : []),
  });
  return {
    data: r.data?.map((x) => ({ source: 'CPSC' as const, id: x.RecallNumber ?? '', date: x.RecallDate?.slice(0, 10) ?? null, title: clip(x.Title, 200), hazard: clip(x.Hazards?.[0]?.Name), remedy: clip(x.Remedies?.[0]?.Name, 300), url: x.URL ?? 'https://www.cpsc.gov/Recalls' })).sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '')) ?? null,
    prov: r.prov,
  };
}

interface FdaEnf { recall_number?: string; report_date?: string; product_description?: string; reason_for_recall?: string; classification?: string; recalling_firm?: string; status?: string }

async function fdaRecalls(ctx: Ctx, q: string): Promise<{ data: RecallItem[]; prov: Provenance[] }> {
  const term = q.replace(/["\\]/g, '').trim();
  const words = term.split(/\s+/).filter((w) => w.length > 1).slice(0, 4);
  const search = words.map((w) => `product_description:${encodeURIComponent(w)}`).join('+AND+');
  const out: RecallItem[] = [];
  const prov: Provenance[] = [];
  for (const cat of ['food', 'drug', 'device'] as const) {
    const r = await ctx.http.get<FdaEnf[]>(`https://api.fda.gov/${cat}/enforcement.json?search=${search}+AND+report_date:[${new Date(ctx.now().getTime() - 3 * 365 * 86_400_000).toISOString().slice(0, 10).replace(/-/g, '')}+TO+${ctx.now().toISOString().slice(0, 10).replace(/-/g, '')}]&sort=report_date:desc&limit=8`, {
      source: 'openfda',
      ttlSec: 12 * 3600,
      keep: (d: { results?: FdaEnf[] }) => d.results ?? [],
    });
    prov.push(r.prov);
    for (const x of r.data ?? []) {
      const d = x.report_date ?? '';
      out.push({ source: 'FDA', id: x.recall_number ?? '', date: d.length === 8 ? `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6)}` : null, title: clip(`${cat}: ${x.product_description ?? ''}`, 200), hazard: clip(x.reason_for_recall), remedy: `${x.recalling_firm ?? 'The firm'} recall, ${x.status ?? 'status unknown'}`.toLowerCase().replace(/^./, (c) => c.toUpperCase()), url: `https://www.accessdata.fda.gov/scripts/ires/index.cfm?Product=${encodeURIComponent(x.recall_number ?? '')}`, classification: x.classification ?? '' });
    }
  }
  return { data: out.sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '')), prov };
}

/** Recalls for a VIN, "year make model", or a product name. */
export async function recall(ctx: Ctx, input: string): Promise<ModuleResult<RecallResult>> {
  const q = input.trim();
  if (!q) throw new Error('missing VIN, vehicle or product');
  const provenance: Provenance[] = [];
  let vehicle: RecallResult['vehicle'] = null;
  let recalls: RecallItem[] = [];
  let note: string | null = null;

  if (VIN_RE.test(q)) {
    const v = await decodeVin(ctx, q.toUpperCase());
    provenance.push(v.prov);
    if (!v.data) throw new Error(`could not decode VIN ${q}`);
    vehicle = { ...v.data, vin: q.toUpperCase() };
  } else {
    const p = parseVehicle(q);
    if (p) vehicle = { ...p, vin: null };
  }
  if (vehicle) {
    const r = await vehicleRecalls(ctx, vehicle.make, vehicle.model, vehicle.year);
    provenance.push(r.prov);
    recalls = r.data ?? [];
    note = vehicle.vin
      ? 'These recalls cover the model year; whether this exact car was already repaired is on nhtsa.gov/recalls with the VIN or at a dealer.'
      : 'Recalls for the model year. Check your exact car with its VIN.';
  } else {
    const [c, f] = await Promise.all([consumerRecalls(ctx, q), fdaRecalls(ctx, q)]);
    provenance.push(c.prov, ...f.prov);
    recalls = [...(c.data ?? []), ...f.data].sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '')).slice(0, 30);
    note = 'US recalls (CPSC and FDA) from the last few years. Match the brand, model and lot number on your product before acting.';
  }

  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = [];
  const parked = recalls.filter((r) => r.parkIt || r.parkOutside);
  if (vehicle && parked.length) {
    const s: Signal = {
      id: signalId('recall', `${vehicle.year} ${vehicle.make} ${vehicle.model}`, parked.map((r) => r.id).join(',')),
      module: 'recall',
      title: `${vehicle.year} ${vehicle.make} ${vehicle.model}: ${parked[0]!.parkIt ? 'do not drive' : 'park outside'} recall`,
      score: 70,
      evidence: parked.slice(0, 3).map((r) => ({ source: 'nhtsa', text: `${r.id}: ${r.component}`, url: r.url })),
      createdAt: nowIso,
    };
    ctx.graph.saveSignal(s);
    signals.push(s);
  }
  return { module: 'recall', input: q, generatedAt: nowIso, result: { query: q, kind: vehicle ? 'vehicle' : 'product', vehicle, recalls, note }, signals, provenance };
}
