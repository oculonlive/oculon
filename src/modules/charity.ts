/**
 * Charity check for US-registered nonprofits, from IRS data published by ProPublica's Nonprofit Explorer (no key).
 *   Search by name or look up an EIN: name, city and state, NTEE category, tax-exempt subsection.
 *   For the chosen organisation: ruling year, subsection, deductibility, and the latest filings with revenue,
 *   expenses and assets as the IRS extracts report them.
 * Warnings come from the data only: no filings in three years, a revocation if the record shows one, and a search
 * result whose name is very close to a well-known charity but carries a different EIN.
 * Charities registered outside the United States are not covered.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';

const API = 'https://projects.propublica.org/nonprofits/api/v2';
const SITE = 'https://projects.propublica.org/nonprofits/organizations';
export const COVERAGE = 'US-registered nonprofits only: IRS Business Master File and Form 990 data via ProPublica Nonprofit Explorer. Charities registered in other countries are not covered.';

/** NTEE major groups (National Center for Charitable Statistics). */
const NTEE: Record<string, string> = {
  A: 'Arts, Culture and Humanities', B: 'Education', C: 'Environment', D: 'Animal-Related', E: 'Health Care', F: 'Mental Health and Crisis Intervention',
  G: 'Diseases, Disorders and Medical Disciplines', H: 'Medical Research', I: 'Crime and Legal-Related', J: 'Employment', K: 'Food, Agriculture and Nutrition',
  L: 'Housing and Shelter', M: 'Public Safety, Disaster Preparedness and Relief', N: 'Recreation and Sports', O: 'Youth Development', P: 'Human Services',
  Q: 'International, Foreign Affairs and National Security', R: 'Civil Rights, Social Action and Advocacy', S: 'Community Improvement and Capacity Building',
  T: 'Philanthropy, Voluntarism and Grantmaking Foundations', U: 'Science and Technology', V: 'Social Science', W: 'Public and Societal Benefit',
  X: 'Religion-Related', Y: 'Mutual and Membership Benefit', Z: 'Unknown',
};

/** IRS Business Master File deductibility codes. */
const DEDUCTIBILITY: Record<number, string> = { 1: 'contributions are deductible', 2: 'contributions are not deductible', 4: 'contributions are deductible by treaty (foreign organisation)' };
const FORMS: Record<number, string> = { 0: '990', 1: '990-EZ', 2: '990-PF' };

/**
 * Well-known US charities and their EINs, each checked against Nonprofit Explorer (November 2026): the national
 * organisation's record, its city and the size of its latest filing.
 * Used only to flag a search result whose name is very close to one of these but has another EIN.
 */
export const WELL_KNOWN: { name: string; ein: string; aliases?: string[] }[] = [
  { name: 'American National Red Cross', ein: '530196605', aliases: ['American Red Cross', 'Red Cross'] },
  { name: 'St Jude Childrens Research Hospital', ein: '620646012', aliases: ['St Jude'] },
  { name: 'Feeding America', ein: '363673599' },
  { name: 'Salvation Army National Corp', ein: '222406433', aliases: ['Salvation Army'] },
  { name: 'United Way Worldwide', ein: '131635294' },
  { name: 'Medecins Sans Frontieres USA', ein: '133433452', aliases: ['Doctors Without Borders'] },
  { name: 'Habitat for Humanity International', ein: '911914868' },
  { name: 'World Wildlife Fund', ein: '521693387' },
  { name: 'Save the Children Federation', ein: '060726487', aliases: ['Save the Children'] },
  { name: 'Direct Relief', ein: '951831116' },
  { name: 'Make-A-Wish Foundation of America', ein: '860481941', aliases: ['Make A Wish'] },
  { name: 'Wounded Warrior Project', ein: '202370934' },
  { name: 'Goodwill Industries International', ein: '530196517' },
  { name: 'American Heart Association', ein: '135613797' },
  { name: 'Natural Resources Defense Council', ein: '132654926' },
  { name: 'Oxfam America', ein: '237069110' },
  { name: 'International Rescue Committee', ein: '135660870' },
  { name: 'World Vision', ein: '951922279' },
  { name: 'Planned Parenthood Federation of America', ein: '131644147' },
  { name: 'Wikimedia Foundation', ein: '200049703' },
  { name: 'Mozilla Foundation', ein: '200097189' },
  { name: 'GiveDirectly', ein: '271661997' },
  { name: 'Electronic Frontier Foundation', ein: '043091431' },
];

export interface CharityMatch { name: string; ein: string; city: string | null; state: string | null; ntee: { code: string; category: string } | null; subsection: string | null; url: string }
export interface CharityFiling { year: number | null; taxPeriod: string | null; form: string; revenue: number | null; expenses: number | null; assets: number | null; liabilities: number | null; pdf: string | null }
export interface CharityOrg {
  name: string; ein: string; address: string | null; city: string | null; state: string | null; zip: string | null;
  rulingYear: number | null; subsection: string | null; deductibility: string | null; ntee: { code: string; category: string } | null;
  latestTaxPeriod: string | null; url: string;
}
export interface CharityReport {
  query: string;
  kind: 'ein' | 'name';
  coverage: string;
  totalMatches: number;
  matches: CharityMatch[];
  organization: CharityOrg | null;
  /** Why this organisation is the one shown: the EIN given, the well-known charity the name points to, or the top search result. */
  selectedBy: 'ein' | 'well-known name' | 'top search result' | null;
  filings: CharityFiling[];
  filingsWithoutData: { year: number | null; form: string; pdf: string | null }[];
  programmeSpending: { share: number | null; note: string };
  warnings: string[];
  advice: string[];
}

export const fmtEin = (ein: string | number) => { const s = String(ein).replace(/\D/g, '').padStart(9, '0'); return `${s.slice(0, 2)}-${s.slice(2)}`; };
const rawEin = (ein: string | number) => String(ein).replace(/\D/g, '').padStart(9, '0');
const subsectionLabel = (n: unknown) => (typeof n === 'number' && n > 0 ? `501(c)(${n})` : null);
function nteeOf(code: unknown): CharityMatch['ntee'] {
  if (typeof code !== 'string' || !code.trim()) return null;
  const c = code.trim().toUpperCase();
  return { code: c, category: NTEE[c[0]!] ?? 'Unknown' };
}
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/** Lowercase words without punctuation and legal suffixes, for comparing names. */
export function normName(s: string): string {
  return s.toLowerCase().replace(/&/g, ' and ').replace(/[^a-z0-9 ]+/g, ' ').replace(/\b(inc|incorporated|corp|corporation|co|ltd|llc|the|of|usa|us|org|fund|foundation)\b/g, ' ').replace(/\s+/g, ' ').trim();
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0]!; prev[0] = i;
    for (let j = 1; j <= b.length; j++) { const t = prev[j]!; prev[j] = Math.min(prev[j]! + 1, prev[j - 1]! + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1)); diag = t; }
  }
  return prev[b.length]!;
}

/** The well-known charity a name imitates, when it is very close to one but the EIN differs. */
export function imitates(name: string, ein: string): { name: string; ein: string } | null {
  const n = normName(name);
  if (n.length < 5) return null;
  for (const w of WELL_KNOWN) {
    if (w.ein === rawEin(ein)) continue;
    for (const alt of [w.name, ...(w.aliases ?? [])]) {
      const k = normName(alt);
      if (k.length < 5) continue;
      const d = levenshtein(n, k);
      if (n === k || d <= Math.max(1, Math.floor(k.length / 10))) return { name: w.name, ein: fmtEin(w.ein) };
    }
  }
  return null;
}

/** Programme spending share, only when the filing itself carries a programme expense figure next to total expenses. */
export function programmeShare(f: Record<string, unknown>): number | null {
  const total = num(f.totfuncexpns);
  if (!total || total <= 0) return null;
  const key = Object.keys(f).find((k) => /^(totprgm|prgm|program).*exp/i.test(k) && num(f[k]) !== null);
  const prog = key ? num(f[key]) : null;
  return prog !== null && prog >= 0 && prog <= total ? Math.round((prog / total) * 1000) / 10 : null;
}

interface SearchOrg { ein: number; name: string; city?: string | null; state?: string | null; ntee_code?: string | null; subseccd?: number | null }
interface SearchAnswer { total_results?: number; organizations?: SearchOrg[] }
interface OrgAnswer { organization?: Record<string, unknown>; filings_with_data?: Record<string, unknown>[]; filings_without_data?: Record<string, unknown>[] }

const DAY = 86_400_000;

export async function charityCheck(ctx: Ctx, input: string, opts: { ein?: string } = {}): Promise<ModuleResult<CharityReport>> {
  const q = input?.trim() ?? '';
  if (!q && !opts.ein) throw new Error('give a charity name or a US EIN, for example "red cross" or 53-0196605');
  if (q.length > 120) throw new Error('give a shorter name (at most 120 characters)');
  const provenance: Provenance[] = [];
  const isEin = /^\d{2}-?\d{7}$/.test(q);
  const kind: CharityReport['kind'] = isEin ? 'ein' : 'name';
  let matches: CharityMatch[] = [];
  let totalMatches = 0;

  if (!isEin && q) {
    const url = `${API}/search.json?q=${encodeURIComponent(q)}`;
    const r = await ctx.http.get<SearchAnswer>(url, { source: 'propublica', ttlSec: 24 * 3600, timeoutMs: 20_000, keep: (d: SearchAnswer) => ({ total_results: d.total_results, organizations: (d.organizations ?? []).slice(0, 25).map((o) => ({ ein: o.ein, name: o.name, city: o.city, state: o.state, ntee_code: o.ntee_code, subseccd: o.subseccd })) }) });
    // ProPublica answers a search with no results as HTTP 404.
    if (r.prov.status === 'UNAVAILABLE' && r.prov.note === 'HTTP 404') provenance.push({ ...r.prov, status: 'LIVE', note: 'no matching organisations' });
    else provenance.push(r.prov);
    totalMatches = r.data?.total_results ?? 0;
    matches = (r.data?.organizations ?? []).slice(0, 10).map((o) => ({ name: o.name, ein: fmtEin(o.ein), city: o.city ?? null, state: o.state ?? null, ntee: nteeOf(o.ntee_code), subsection: subsectionLabel(o.subseccd), url: `${SITE}/${rawEin(o.ein)}` }));
    if (!r.data && provenance[0]!.status !== 'LIVE') {
      return done(ctx, q, kind, { totalMatches: 0, matches: [], organization: null, selectedBy: null, filings: [], filingsWithoutData: [], programmeSpending: { share: null, note: 'not available: the search did not answer' }, warnings: [`ProPublica Nonprofit Explorer did not answer (${r.prov.note ?? r.prov.status}); nothing was checked`], advice: ['Try again in a few minutes.'] }, provenance);
    }
  }

  // A search for a well-known charity by name opens that charity's own record, even when the search ranks a
  // smaller organisation with the same name first.
  const famous = !isEin && !opts.ein && q ? imitates(q, '000000000') : null;
  const chosen = opts.ein ? rawEin(opts.ein) : isEin ? rawEin(q) : famous ? rawEin(famous.ein) : matches[0] ? rawEin(matches[0].ein) : null;
  const warnings: string[] = [];
  let organization: CharityOrg | null = null;
  let filings: CharityFiling[] = [];
  let filingsWithoutData: CharityReport['filingsWithoutData'] = [];
  let programmeSpending: CharityReport['programmeSpending'] = { share: null, note: 'not available' };

  const close = new Map<string, CharityMatch[]>();
  for (const m of matches) {
    const imit = imitates(m.name, m.ein);
    if (imit) close.set(`${imit.name} (EIN ${imit.ein})`, [...(close.get(`${imit.name} (EIN ${imit.ein})`) ?? []), m]);
  }
  for (const [famousName, list] of close) {
    const shown = list.slice(0, 3).map((m) => `"${m.name}" (EIN ${m.ein}, ${[m.city, m.state].filter(Boolean).join(', ') || 'location unknown'})`).join(', ');
    warnings.push(`${list.length === 1 ? 'one search result has' : `${list.length} search results have`} a name very close to ${famousName} but a different EIN: ${shown}${list.length > 3 ? ` and ${list.length - 3} more` : ''}. These may be local chapters or affiliates, or organisations using a similar name. Check the EIN before giving.`);
  }

  if (chosen) {
    const url = `${API}/organizations/${chosen}.json`;
    const r = await ctx.http.get<OrgAnswer>(url, { source: 'propublica', ttlSec: 24 * 3600, timeoutMs: 20_000, keep: (d: OrgAnswer) => ({ organization: d.organization, filings_with_data: (d.filings_with_data ?? []).slice(0, 12), filings_without_data: (d.filings_without_data ?? []).slice(0, 12) }) });
    provenance.push(r.prov);
    const o = r.data?.organization;
    // An unknown EIN comes back as "Unknown Organization" with every field empty.
    const known = o && typeof o.name === 'string' && !(o.name === 'Unknown Organization' && o.city == null && o.subsection_code == null);
    if (!r.data) warnings.push(`the organisation record did not load (${r.prov.note ?? r.prov.status}); filings were not checked`);
    else if (!known) warnings.push(`no US nonprofit with EIN ${fmtEin(chosen)} is in the IRS data`);
    else {
      const ruling = typeof o.ruling_date === 'string' ? Number(o.ruling_date.slice(0, 4)) || null : null;
      organization = {
        name: String(o.name), ein: fmtEin(chosen), address: (o.address as string) ?? null, city: (o.city as string) ?? null, state: (o.state as string) ?? null, zip: (o.zipcode as string) ?? null,
        rulingYear: ruling, subsection: subsectionLabel(o.subsection_code), deductibility: DEDUCTIBILITY[o.deductibility_code as number] ?? null, ntee: nteeOf(o.ntee_code),
        latestTaxPeriod: typeof o.tax_period === 'string' ? o.tax_period.slice(0, 7) : null, url: `${SITE}/${chosen}`,
      };
      const withData = r.data.filings_with_data ?? [];
      filings = withData.slice(0, 6).map((f) => ({
        year: num(f.tax_prd_yr), taxPeriod: typeof f.tax_prd === 'number' ? `${String(f.tax_prd).slice(0, 4)}-${String(f.tax_prd).slice(4, 6)}` : null,
        form: FORMS[f.formtype as number] ?? 'unknown', revenue: num(f.totrevenue), expenses: num(f.totfuncexpns) ?? num(f.totexpns), assets: num(f.totassetsend),liabilities: num(f.totliabend),
        pdf: typeof f.pdf_url === 'string' ? f.pdf_url : null,
      }));
      filingsWithoutData = (r.data.filings_without_data ?? []).slice(0, 6).map((f) => ({ year: num(f.tax_prd_yr), form: typeof f.formtype_str === 'string' ? f.formtype_str : FORMS[f.formtype as number] ?? 'unknown', pdf: typeof f.pdf_url === 'string' ? f.pdf_url : null }));
      const share = withData[0] ? programmeShare(withData[0]) : null;
      programmeSpending = share !== null
        ? { share, note: `${share}% of total expenses went to programmes in the latest filing with data` }
        : { share: null, note: 'not available: the IRS extract for the latest filing does not split expenses into programmes, management and fundraising. The full Form 990 (Part IX) has it; see the filing PDF.' };

      const years = [...withData, ...(r.data.filings_without_data ?? [])].map((f) => num(f.tax_prd_yr)).filter((y): y is number => y !== null);
      const latest = years.length ? Math.max(...years) : null;
      const thisYear = ctx.now().getUTCFullYear();
      if (latest === null) warnings.push('no Form 990 filings are on record. Small charities (gross receipts usually under $50,000) file only the 990-N e-Postcard, which this data does not include.');
      else if (thisYear - latest > 3) warnings.push(`no filings in the last 3 years: the latest is for tax year ${latest}. An organisation that stops filing for three years loses its exemption automatically.`);
      // Revocation shows up as a field in some records; flag it only when the data says so.
      const revKey = Object.keys(o).find((k) => /revo/i.test(k) && o[k] != null && o[k] !== false && o[k] !== '' && o[k] !== 0);
      if (revKey) warnings.push(`the record shows a revocation (${revKey}: ${String(o[revKey]).slice(0, 40)}): donations may not be tax-deductible`);
      if (organization.subsection && organization.subsection !== '501(c)(3)') warnings.push(`it is a ${organization.subsection} organisation, not a 501(c)(3) charity: gifts to it are usually not tax-deductible as charitable contributions`);
      if (o.deductibility_code === 2) warnings.push('the IRS record says contributions to it are not deductible');
      const updated = typeof o.updated_at === 'string' ? Date.parse(o.updated_at) : NaN;
      if (Number.isFinite(updated) && ctx.now().getTime() - updated > 400 * DAY) warnings.push('the record was not refreshed in over a year: check the IRS Tax Exempt Organization Search for its current status');
    }
  }

  const advice = [
    'Give through the charity\'s own website, reached by typing its address, not through a link in a message or a caller who contacts you first.',
    'Match the EIN on the donation page or receipt with the one shown here.',
    'For current exemption status, the IRS Tax Exempt Organization Search (apps.irs.gov/app/eos) is the official source.',
  ];
  if (!isEin && organization && !matches.some((m) => m.ein === organization!.ein)) {
    matches.unshift({ name: organization.name, ein: organization.ein, city: organization.city, state: organization.state, ntee: organization.ntee, subsection: organization.subsection, url: organization.url });
  }
  if (!matches.length && !organization && !isEin) warnings.push('no US-registered nonprofit matches that name. Charities registered in other countries are not covered here.');
  return done(ctx, q || fmtEin(chosen ?? ''), kind, { totalMatches: isEin ? (organization ? 1 : 0) : totalMatches, matches: isEin && organization ? [{ name: organization.name, ein: organization.ein, city: organization.city, state: organization.state, ntee: organization.ntee, subsection: organization.subsection, url: organization.url }] : matches, organization, selectedBy: !organization ? null : opts.ein || isEin ? 'ein' : famous && rawEin(famous.ein) === rawEin(organization.ein) ? 'well-known name' : 'top search result', filings, filingsWithoutData, programmeSpending, warnings, advice }, provenance);
}

function done(ctx: Ctx, query: string, kind: CharityReport['kind'], r: Omit<CharityReport, 'query' | 'kind' | 'coverage'>, provenance: Provenance[]): ModuleResult<CharityReport> {
  return { module: 'charity', input: query, generatedAt: ctx.now().toISOString(), result: { query, kind, coverage: COVERAGE, ...r }, signals: [], provenance };
}
