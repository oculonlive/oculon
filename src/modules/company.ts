/**
 * Company identity check, useful before paying an invoice or signing with a new supplier.
 *   EU VAT number (e.g. "NL004495445B01"): checked live with the European Commission VIES service.
 *   LEI (20 characters) or a company name: the Global LEI Index (GLEIF), with registered address, status,
 *     registration authority and ultimate parent.
 * Both keyless.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export interface LeiRecord {
  lei: string;
  name: string;
  otherNames: string[];
  status: string | null;
  registration: string | null;
  jurisdiction: string | null;
  legalForm: string | null;
  registeredAs: string | null;
  address: string | null;
  headquarters: string | null;
  country: string | null;
  created: string | null;
  lastUpdate: string | null;
  nextRenewal: string | null;
  parent: { lei: string; name: string } | null;
  url: string;
}

export interface VatCheck { country: string; number: string; valid: boolean; name: string | null; address: string | null; checkedAt: string }

export interface CompanyCheck {
  query: string;
  kind: 'vat' | 'lei' | 'name';
  vat: VatCheck | null;
  records: LeiRecord[];
  warnings: string[];
  note: string;
}

const VAT_RE = /^(AT|BE|BG|CY|CZ|DE|DK|EE|EL|GR|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK|XI)([0-9A-Z+*]{2,12})$/;
const LEI_RE = /^[A-Z0-9]{18}[0-9]{2}$/;

export function parseVat(q: string): { country: string; number: string } | null {
  const s = q.toUpperCase().replace(/[\s.\-]/g, '');
  const m = VAT_RE.exec(s);
  if (!m || !/\d/.test(m[2]!)) return null;
  return { country: m[1] === 'GR' ? 'EL' : m[1]!, number: m[2]! };
}

interface GleifAddr { addressLines?: string[]; city?: string; region?: string; country?: string; postalCode?: string }
interface GleifRec { id?: string; attributes?: { lei?: string; entity?: { legalName?: { name?: string }; otherNames?: { name?: string }[]; legalAddress?: GleifAddr; headquartersAddress?: GleifAddr; jurisdiction?: string; legalForm?: { id?: string; other?: string }; registeredAs?: string; status?: string; creationDate?: string }; registration?: { status?: string; lastUpdateDate?: string; nextRenewalDate?: string } } }

const addr = (a?: GleifAddr) => (a ? [...(a.addressLines ?? []), [a.postalCode, a.city].filter(Boolean).join(' '), a.region, a.country].filter((x) => x && String(x).trim()).join(', ') : null) || null;

function toRecord(x: GleifRec): LeiRecord | null {
  const a = x.attributes;
  const lei = a?.lei ?? x.id;
  if (!a || !lei) return null;
  const e = a.entity ?? {};
  return {
    lei,
    name: e.legalName?.name ?? lei,
    otherNames: (e.otherNames ?? []).map((n) => n.name ?? '').filter(Boolean).slice(0, 4),
    status: e.status ?? null,
    registration: a.registration?.status ?? null,
    jurisdiction: e.jurisdiction ?? null,
    // Only a written-out form; the bare ISO 20275 code (e.g. "6QQB") means nothing to a reader.
    legalForm: e.legalForm?.other || null,
    registeredAs: e.registeredAs ?? null,
    address: addr(e.legalAddress),
    headquarters: addr(e.headquartersAddress),
    country: e.legalAddress?.country ?? null,
    created: e.creationDate?.slice(0, 10) ?? null,
    lastUpdate: a.registration?.lastUpdateDate?.slice(0, 10) ?? null,
    nextRenewal: a.registration?.nextRenewalDate?.slice(0, 10) ?? null,
    parent: null,
    url: `https://search.gleif.org/#/record/${lei}`,
  };
}

const slimRec = (d: { data?: GleifRec | GleifRec[] }) => {
  const one = (x: GleifRec): GleifRec => ({ id: x.id, attributes: { lei: x.attributes?.lei, entity: x.attributes?.entity ? { legalName: x.attributes.entity.legalName, otherNames: x.attributes.entity.otherNames?.slice(0, 4), legalAddress: x.attributes.entity.legalAddress, headquartersAddress: x.attributes.entity.headquartersAddress, jurisdiction: x.attributes.entity.jurisdiction, legalForm: x.attributes.entity.legalForm, registeredAs: x.attributes.entity.registeredAs, status: x.attributes.entity.status, creationDate: x.attributes.entity.creationDate } : undefined, registration: x.attributes?.registration ? { status: x.attributes.registration.status, lastUpdateDate: x.attributes.registration.lastUpdateDate, nextRenewalDate: x.attributes.registration.nextRenewalDate } : undefined } });
  return { data: Array.isArray(d.data) ? d.data.map(one) : d.data ? one(d.data) : undefined };
};

/** The closest names first: exact, then "starts with", then active and issued records, then shorter names. */
export function rankByName(recs: LeiRecord[], q: string): LeiRecord[] {
  const n = (s: string) => s.toLowerCase().replace(/[.,]/g, '').trim();
  const t = n(q);
  // "Siemens Aktiengesellschaft" is the company itself; "Siemens Energy Ltd" is a subsidiary.
  const FORM = /^(ag|aktiengesellschaft|se|inc|incorporated|corp|corporation|co|company|ltd|limited|plc|llc|lp|gmbh|sa|sas|sarl|spa|srl|nv|bv|as|asa|ab|oy|oyj|kk|pte ltd|pty ltd|holdings?|group)$/;
  const score = (r: LeiRecord) => {
    const names = [r.name, ...r.otherNames].map(n);
    const rest = names.filter((x) => x.startsWith(`${t} `)).map((x) => x.slice(t.length + 1));
    return (names.includes(t) ? 8 : rest.some((x) => FORM.test(x)) ? 7 : rest.length ? 4 : names.some((x) => x.includes(t)) ? 2 : 0) + (r.status === 'ACTIVE' ? 1 : 0) + (r.registration === 'ISSUED' ? 1 : 0);
  };
  return [...recs].sort((a, b) => score(b) - score(a) || a.name.length - b.name.length);
}

async function vies(ctx: Ctx, country: string, number: string): Promise<{ data: VatCheck | null; prov: Provenance }> {
  const first = await viesOnce(ctx, country, number);
  // VIES often answers "too many requests to this country right now"; one short retry usually works.
  if (first.data || !/CONCURRENT|SERVICE_UNAVAILABLE|TIMEOUT/.test(first.prov.note ?? '')) return first;
  if (first.prov.status !== 'CACHED') await new Promise((r) => setTimeout(r, 2000));
  return viesOnce(ctx, country, number, true);
}

async function viesOnce(ctx: Ctx, country: string, number: string, fresh = false): Promise<{ data: VatCheck | null; prov: Provenance }> {
  const r = await ctx.http.get<{ isValid?: boolean; name?: string; address?: string; userError?: string; requestDate?: string }>(`https://ec.europa.eu/taxation_customs/vies/rest-api/ms/${country}/vat/${encodeURIComponent(number)}`, { source: 'vies', ttlSec: fresh ? 0 : 24 * 3600, timeoutMs: 25_000, retries: 1 });
  const d = r.data;
  if (!d) return { data: null, prov: r.prov };
  if (typeof d.isValid !== 'boolean' || (d.userError && !/^(VALID|INVALID)$/.test(d.userError))) return { data: null, prov: { ...r.prov, status: 'ERROR', note: `VIES: ${d.userError ?? 'no answer'} (the national VAT service may be down; try later)` } };
  const clean = (s?: string) => (s && s.trim() && s.trim() !== '---' ? s.replace(/\s*\n\s*/g, ', ').trim() : null);
  return { data: { country, number, valid: d.isValid, name: clean(d.name), address: clean(d.address), checkedAt: d.requestDate ?? new Date().toISOString() }, prov: r.prov };
}

export async function companyCheck(ctx: Ctx, input: string): Promise<ModuleResult<CompanyCheck>> {
  const q = input.trim();
  if (q.length < 2) throw new Error('missing company name, LEI or EU VAT number');
  const provenance: Provenance[] = [];
  const warnings: string[] = [];
  const vatIn = parseVat(q);
  const leiIn = LEI_RE.test(q.toUpperCase()) ? q.toUpperCase() : null;
  let vat: VatCheck | null = null;
  let records: LeiRecord[] = [];
  const base = 'https://api.gleif.org/api/v1/lei-records';

  if (vatIn && !leiIn) {
    const v = await vies(ctx, vatIn.country, vatIn.number);
    provenance.push(v.prov);
    if (!v.data) throw new Error(`could not check that VAT number right now: ${v.prov.note ?? v.prov.status}`);
    vat = v.data;
    if (!vat.valid) warnings.push(`VAT number ${vat.country}${vat.number} is not valid in VIES. Do not pay an invoice that quotes it until the supplier explains.`);
    else if (!vat.name) warnings.push(`The VAT number is valid, but ${vat.country === 'DE' ? 'Germany' : 'this country'} does not publish the holder's name through VIES; confirm the name with the supplier.`);
    if (vat.valid && vat.name) {
      const g = await ctx.http.get<{ data?: GleifRec[] }>(`${base}?filter%5Bfulltext%5D=${encodeURIComponent(vat.name.slice(0, 80))}&filter%5Bentity.legalAddress.country%5D=${vat.country === 'EL' ? 'GR' : vat.country === 'XI' ? 'GB' : vat.country}&page%5Bsize%5D=3`, { source: 'gleif', ttlSec: 24 * 3600, keep: slimRec });
      provenance.push(g.prov);
      records = (g.data?.data ?? []).map(toRecord).filter((x): x is LeiRecord => x !== null);
    }
  } else if (leiIn) {
    const g = await ctx.http.get<{ data?: GleifRec }>(`${base}/${leiIn}`, { source: 'gleif', ttlSec: 24 * 3600, keep: slimRec });
    provenance.push(g.prov);
    const rec = g.data?.data ? toRecord(g.data.data) : null;
    if (!rec) throw new Error(`no such LEI: ${leiIn}`);
    records = [rec];
  } else {
    const g = await ctx.http.get<{ data?: GleifRec[] }>(`${base}?filter%5Bfulltext%5D=${encodeURIComponent(q.slice(0, 120))}&filter%5Bentity.category%5D=GENERAL&page%5Bsize%5D=30`, { source: 'gleif', ttlSec: 24 * 3600, keep: slimRec });
    provenance.push(g.prov);
    if (!g.data) throw new Error(`GLEIF is not answering right now (${g.prov.note ?? g.prov.status})`);
    records = rankByName((g.data.data ?? []).map(toRecord).filter((x): x is LeiRecord => x !== null), q).slice(0, 8);
  }

  let top = records[0];
  if (top) {
    const p = await ctx.http.get<{ data?: GleifRec }>(`${base}/${top.lei}/ultimate-parent`, { source: 'gleif', ttlSec: 7 * 86_400, retries: 0, keep: slimRec });
    if (p.data?.data) {
      const pr = toRecord(p.data.data);
      provenance.push(p.prov);
      if (pr && pr.lei !== top.lei) {
        const plain = (s: string) => s.toLowerCase().replace(/[.,]/g, '').trim();
        // A name search for "Siemens" that lands on a subsidiary shows the group's parent first.
        if (!leiIn && !vatIn && plain(pr.name).startsWith(plain(q))) {
          records = [pr, ...records.filter((r) => r.lei !== pr.lei)].slice(0, 8);
          top = pr;
        } else top.parent = { lei: pr.lei, name: pr.name };
      }
    }
    if (top.status === 'INACTIVE') warnings.push(`${top.name} is marked INACTIVE in the LEI register (dissolved or merged).`);
    if (top.registration === 'LAPSED') warnings.push(`The LEI of ${top.name} has lapsed: its details were not renewed${top.nextRenewal ? ` since ${top.nextRenewal}` : ''} and may be out of date.`);
    if (top.registration === 'RETIRED' || top.registration === 'ANNULLED') warnings.push(`The LEI of ${top.name} is ${top.registration.toLowerCase()}.`);
  }
  if (!records.length && !vat) warnings.push('No company with that name in the LEI register. Many small firms have no LEI, so this alone is not a warning sign.');

  return {
    module: 'company',
    input: q,
    generatedAt: ctx.now().toISOString(),
    result: { query: q, kind: vatIn && !leiIn ? 'vat' : leiIn ? 'lei' : 'name', vat, records, warnings, note: 'An LEI is a global ID that companies trading in financial markets must hold. Not having one is normal for small firms.' },
    signals: [],
    provenance,
  };
}
