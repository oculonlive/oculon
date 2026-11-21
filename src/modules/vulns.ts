/**
 * Vulnerabilities (no keys; GITHUB_TOKEN optional for a higher GitHub rate limit):
 *   CISA Known Exploited Vulnerabilities catalog: what attackers are exploiting right now, with ransomware use and
 *     federal remediation due dates. `kevSet` lets other modules flag exposed CVEs that are actively exploited.
 *   NVD CVE API 2.0: CVSS, CWE, affected products (CPE) and references; also newly published critical CVEs.
 *   FIRST EPSS: probability of exploitation in the next 30 days, with a 30-day trend.
 *   OSV.dev: affected open-source packages and fixed versions; package queries.
 *   GitHub Advisory Database: reviewed advisories with vulnerable version ranges; new critical advisories.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';
import { postJson } from '../sources/press.js';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const DAY = 86_400_000;

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  cwes: string[];
}

export interface KevCatalog {
  version: string;
  released: string;
  count: number;
  vulnerabilities: KevEntry[];
}

/** The CISA KEV catalog, slimmed (no long required-action text) and cached for 6 hours. */
export async function kevCatalog(ctx: Ctx): Promise<Sourced<KevCatalog>> {
  return ctx.http.get<KevCatalog>(KEV_URL, {
    source: 'cisa-kev',
    ttlSec: 6 * 3600,
    timeoutMs: 60_000,
    keep: (d: { catalogVersion?: string; dateReleased?: string; count?: number; vulnerabilities?: Record<string, unknown>[] }): KevCatalog => ({
      version: String(d.catalogVersion ?? ''),
      released: String(d.dateReleased ?? ''),
      count: Number(d.count ?? d.vulnerabilities?.length ?? 0),
      vulnerabilities: (d.vulnerabilities ?? []).map((v) => ({
        cveID: String(v.cveID ?? '').toUpperCase(),
        vendorProject: String(v.vendorProject ?? ''),
        product: String(v.product ?? ''),
        vulnerabilityName: String(v.vulnerabilityName ?? ''),
        dateAdded: String(v.dateAdded ?? ''),
        shortDescription: String(v.shortDescription ?? '').slice(0, 300),
        dueDate: String(v.dueDate ?? ''),
        knownRansomwareCampaignUse: String(v.knownRansomwareCampaignUse ?? 'Unknown'),
        cwes: Array.isArray(v.cwes) ? (v.cwes as string[]) : [],
      })),
    }),
  });
}

/** Upper-case CVE ids in the KEV catalog (empty set if the catalog is unavailable). */
export async function kevSet(ctx: Ctx): Promise<Set<string>> {
  const r = await kevCatalog(ctx);
  return new Set((r.data?.vulnerabilities ?? []).map((v) => v.cveID.toUpperCase()));
}

export interface Epss {
  score: number;
  percentile: number;
  date: string;
  /** Change in score over the returned time series (about 30 days); null without history. */
  change30d: number | null;
}

interface EpssRow { cve: string; epss: string; percentile: string; date: string; 'time-series'?: { epss: string; date: string }[] }

/** EPSS scores for up to 100 CVEs per request. */
export async function epssScores(ctx: Ctx, ids: string[], series = false): Promise<{ data: Map<string, Epss>; prov: Provenance[] }> {
  const out = new Map<string, Epss>();
  const prov: Provenance[] = [];
  const uniq = [...new Set(ids.map((i) => i.toUpperCase()))];
  for (let i = 0; i < uniq.length; i += 50) {
    const batch = uniq.slice(i, i + 50);
    const r = await ctx.http.get<{ data?: EpssRow[] }>(`https://api.first.org/data/v1/epss?cve=${batch.join(',')}${series ? '&scope=time-series' : ''}`, { source: 'epss', ttlSec: 12 * 3600 });
    prov.push(r.prov);
    for (const row of r.data?.data ?? []) {
      const score = Number(row.epss);
      const ts = row['time-series'] ?? [];
      const oldest = ts.length ? Number(ts[ts.length - 1]!.epss) : NaN;
      out.set(row.cve.toUpperCase(), { score, percentile: Number(row.percentile), date: row.date, change30d: Number.isFinite(oldest) ? Math.round((score - oldest) * 1e5) / 1e5 : null });
    }
  }
  return { data: out, prov };
}

function ghHeaders(): Record<string, string> {
  const t = key('GITHUB_TOKEN');
  return { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', ...(t ? { authorization: `Bearer ${t}` } : {}) };
}

interface GhAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  html_url: string;
  summary: string;
  severity: string;
  published_at: string;
  withdrawn_at?: string | null;
  cvss?: { score?: number | null } | null;
  vulnerabilities?: { package?: { ecosystem?: string; name?: string }; vulnerable_version_range?: string | null; first_patched_version?: string | null }[];
}

export interface Advisory {
  id: string;
  cve: string | null;
  summary: string;
  severity: string;
  cvss: number | null;
  published: string;
  packages: { ecosystem: string; name: string; vulnerable: string; patched: string | null }[];
  url: string;
}

const slimGh = (list: unknown): Advisory[] =>
  (Array.isArray(list) ? (list as GhAdvisory[]) : [])
    .filter((a) => !a.withdrawn_at)
    .map((a) => ({
      id: a.ghsa_id,
      cve: a.cve_id ?? null,
      summary: (a.summary ?? '').slice(0, 200),
      severity: a.severity ?? 'unknown',
      cvss: a.cvss?.score ?? null,
      published: a.published_at,
      packages: (a.vulnerabilities ?? []).slice(0, 12).map((v) => ({ ecosystem: v.package?.ecosystem ?? '', name: v.package?.name ?? '', vulnerable: v.vulnerable_version_range ?? '', patched: v.first_patched_version ?? null })),
      url: a.html_url,
    }));

export interface RecentCve {
  id: string;
  published: string;
  cvss: number | null;
  description: string;
  url: string;
}

export interface VulnsResult {
  window: { from: string; to: string };
  vendor: string | null;
  catalog: { version: string; released: string; count: number } | null;
  kev: (KevEntry & { epss: number | null; daysToDue: number | null })[];
  /** Newly published CVEs rated CRITICAL by NVD (window capped at 30 days). */
  criticalCves: RecentCve[];
  /** Newly published GitHub-reviewed critical advisories (open-source supply chain). */
  advisories: Advisory[];
}

const isoDay = (d: Date) => d.toISOString().slice(0, 10);
const nvdDate = (d: Date) => d.toISOString().slice(0, 23);

/** Newly added KEV entries (and fresh critical CVEs and advisories) in the last `days`, optionally for one vendor or product. */
export async function vulns(ctx: Ctx, opts: { days?: number; vendor?: string } = {}): Promise<ModuleResult<VulnsResult>> {
  const now = ctx.now();
  const days = Math.max(1, Math.min(opts.days ?? 7, 365));
  const from = new Date(now.getTime() - days * DAY);
  const vendor = opts.vendor?.trim() || null;
  const vq = vendor?.toLowerCase();
  const provenance: Provenance[] = [];

  const cat = await kevCatalog(ctx);
  provenance.push(cat.prov);
  const kevAll = (cat.data?.vulnerabilities ?? [])
    .filter((v) => v.dateAdded >= isoDay(from))
    .filter((v) => !vq || `${v.vendorProject} ${v.product} ${v.vulnerabilityName}`.toLowerCase().includes(vq))
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || a.cveID.localeCompare(b.cveID));

  const ep = kevAll.length ? await epssScores(ctx, kevAll.slice(0, 100).map((v) => v.cveID)) : { data: new Map<string, Epss>(), prov: [] };
  provenance.push(...ep.prov);
  const kev = kevAll.map((v) => ({
    ...v,
    epss: ep.data.get(v.cveID)?.score ?? null,
    daysToDue: v.dueDate ? Math.ceil((Date.parse(`${v.dueDate}T23:59:59Z`) - now.getTime()) / DAY) : null,
  }));

  // NVD: publication window may not exceed 120 days; keep it to 30 to stay within the keyless rate limit.
  const nvdFrom = new Date(now.getTime() - Math.min(days, 30) * DAY);
  const nvd = await ctx.http.get<{ vulnerabilities?: { cve: NvdCve }[] }>(
    `${NVD}?pubStartDate=${nvdDate(nvdFrom)}&pubEndDate=${nvdDate(now)}&cvssV3Severity=CRITICAL&resultsPerPage=200${vendor ? `&keywordSearch=${encodeURIComponent(vendor)}` : ''}`,
    { source: 'nvd', ttlSec: 3 * 3600, timeoutMs: 60_000, keep: (d: { vulnerabilities?: { cve: NvdCve }[] }) => ({ vulnerabilities: (d.vulnerabilities ?? []).map((v) => ({ cve: { id: v.cve.id, published: v.cve.published, descriptions: v.cve.descriptions?.filter((x) => x.lang === 'en').map((x) => ({ lang: x.lang, value: x.value.slice(0, 300) })), metrics: { cvssMetricV31: v.cve.metrics?.cvssMetricV31?.slice(0, 1) } } })) }) },
  );
  provenance.push(nvd.prov);
  const criticalCves: RecentCve[] = (nvd.data?.vulnerabilities ?? [])
    .map(({ cve: c }) => ({ id: c.id, published: c.published, cvss: c.metrics?.cvssMetricV31?.[0]?.cvssData.baseScore ?? null, description: (c.descriptions?.find((x) => x.lang === 'en')?.value ?? '').slice(0, 300), url: `https://nvd.nist.gov/vuln/detail/${c.id}` }))
    .sort((a, b) => b.published.localeCompare(a.published));

  const gh = await ctx.http.get<Advisory[]>(`https://api.github.com/advisories?type=reviewed&severity=critical&per_page=100&sort=published&direction=desc&published=${encodeURIComponent(`>=${isoDay(from)}`)}`, { source: 'github-advisories', ttlSec: 3 * 3600, headers: ghHeaders(), keep: slimGh });
  provenance.push(gh.prov);
  const advisories = (gh.data ?? []).filter((a) => !vq || `${a.summary} ${a.packages.map((p) => p.name).join(' ')}`.toLowerCase().includes(vq));

  const signals: Signal[] = [];
  for (const v of kev.slice(0, 10)) {
    const ransomware = v.knownRansomwareCampaignUse.toLowerCase() === 'known';
    const dueSoon = v.daysToDue !== null && v.daysToDue <= 7;
    const score = Math.min(95, 68 + (ransomware ? 14 : 0) + (dueSoon ? 8 : 0) + (v.epss !== null && v.epss >= 0.5 ? 5 : 0));
    signals.push({
      id: signalId('vulns', 'kev', v.cveID),
      module: 'vulns',
      title: `Actively exploited: ${v.cveID} ${v.vendorProject} ${v.product}${ransomware ? ' (used by ransomware)' : ''}`,
      score,
      entity: v.vendorProject,
      evidence: [{ source: 'cisa-kev', text: `Added to CISA KEV ${v.dateAdded}, federal due date ${v.dueDate}${v.epss !== null ? `, EPSS ${v.epss.toFixed(3)}` : ''}: ${v.shortDescription.slice(0, 200)}`, url: `https://nvd.nist.gov/vuln/detail/${v.cveID}` }],
      createdAt: now.toISOString(),
    });
  }
  for (const a of advisories.filter((x) => now.getTime() - Date.parse(x.published) <= 2 * DAY).slice(0, 3)) {
    const pkg = a.packages[0];
    signals.push({
      id: signalId('vulns', 'ghsa', a.id),
      module: 'vulns',
      title: `Critical open-source advisory: ${a.summary}`,
      score: 58,
      ...(pkg?.name ? { entity: pkg.name } : {}),
      evidence: [{ source: 'github-advisories', text: `${a.id}${a.cve ? ` / ${a.cve}` : ''}${pkg ? `, ${pkg.ecosystem} ${pkg.name} ${pkg.vulnerable}${pkg.patched ? `, fixed in ${pkg.patched}` : ', no fix yet'}` : ''}`, url: a.url }],
      createdAt: now.toISOString(),
    });
  }
  for (const s of signals) ctx.graph.saveSignal(s);

  return {
    module: 'vulns',
    input: vendor ? `${vendor}, last ${days}d` : `last ${days}d`,
    generatedAt: now.toISOString(),
    result: { window: { from: from.toISOString(), to: now.toISOString() }, vendor, catalog: cat.data ? { version: cat.data.version, released: cat.data.released, count: cat.data.count } : null, kev, criticalCves, advisories },
    signals,
    provenance,
  };
}

interface NvdCve {
  id: string;
  published: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: Record<string, { source?: string; type?: string; cvssData: { baseScore: number; baseSeverity?: string; vectorString: string; version: string } }[] | undefined>;
  weaknesses?: { description: { lang: string; value: string }[] }[];
  configurations?: { nodes: { cpeMatch: { vulnerable: boolean; criteria: string }[] }[] }[];
  references?: { url: string; tags?: string[] }[];
}

export interface CveDetail {
  id: string;
  description: string;
  published: string | null;
  lastModified: string | null;
  status: string | null;
  cvss: { version: string; score: number; severity: string; vector: string } | null;
  cwes: string[];
  /** Vendor:product pairs from NVD CPE configurations (vulnerable only). */
  products: string[];
  references: { url: string; tags: string[] }[];
  kev: KevEntry | null;
  epss: Epss | null;
  packages: { ecosystem: string; name: string; fixed: string[]; source: 'osv' | 'github' }[];
  advisories: Advisory[];
  aliases: string[];
}

export const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

/** One CVE in depth: NVD, EPSS (with trend), KEV membership, OSV affected packages and GitHub advisories. */
export async function cve(ctx: Ctx, id: string): Promise<ModuleResult<CveDetail>> {
  const now = ctx.now();
  const cid = id.trim().toUpperCase();
  if (!CVE_RE.test(cid)) throw new Error(`not a CVE id: ${id} (expected CVE-YYYY-NNNN)`);
  const provenance: Provenance[] = [];

  const nvd = await ctx.http.get<{ vulnerabilities?: { cve: NvdCve }[] }>(`${NVD}?cveId=${cid}`, {
    source: 'nvd',
    ttlSec: 24 * 3600,
    timeoutMs: 60_000,
    keep: (d: { vulnerabilities?: { cve: NvdCve }[] }) => ({ vulnerabilities: (d.vulnerabilities ?? []).map((v) => ({ cve: { ...v.cve, references: v.cve.references?.slice(0, 25).map((r) => ({ url: r.url, tags: r.tags })), configurations: v.cve.configurations?.slice(0, 20) } })) }),
  });
  provenance.push(nvd.prov);
  const c = nvd.data?.vulnerabilities?.[0]?.cve;
  const metric = c ? (['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as const).map((k) => c.metrics?.[k]?.find((m) => m.type === 'Primary') ?? c.metrics?.[k]?.[0]).find(Boolean) : undefined;
  const products = new Set<string>();
  for (const conf of c?.configurations ?? []) for (const n of conf.nodes) for (const m of n.cpeMatch) if (m.vulnerable) { const p = m.criteria.split(':'); if (p[3] && p[4]) products.add(`${p[3]}:${p[4]}`); }

  const [ep, kevs] = await Promise.all([epssScores(ctx, [cid], true), kevCatalog(ctx)]);
  provenance.push(...ep.prov, kevs.prov);
  const kev = kevs.data?.vulnerabilities.find((v) => v.cveID === cid) ?? null;

  const osv = await ctx.http.get<{ aliases?: string[]; affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type: string; events: Record<string, string>[] }[] }[] }>(`https://api.osv.dev/v1/vulns/${cid}`, {
    source: 'osv',
    ttlSec: 12 * 3600,
    keep: (d: { aliases?: string[]; affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type: string; events: Record<string, string>[] }[] }[] }) => ({ aliases: d.aliases, affected: (d.affected ?? []).filter((a) => a.package?.name).slice(0, 40).map((a) => ({ package: { ecosystem: a.package!.ecosystem, name: a.package!.name }, ranges: a.ranges?.filter((r) => r.type !== 'GIT').map((r) => ({ type: r.type, events: r.events.filter((e) => 'fixed' in e) })) })) }),
  });
  provenance.push(osv.prov);

  const gh = await ctx.http.get<Advisory[]>(`https://api.github.com/advisories?cve_id=${cid}`, { source: 'github-advisories', ttlSec: 12 * 3600, headers: ghHeaders(), keep: slimGh });
  provenance.push(gh.prov);
  const advisories = gh.data ?? [];

  const packages: CveDetail['packages'] = [];
  const seen = new Set<string>();
  for (const a of osv.data?.affected ?? []) {
    const k = `${a.package?.ecosystem}:${a.package?.name}`.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    packages.push({ ecosystem: a.package?.ecosystem ?? '', name: a.package?.name ?? '', fixed: [...new Set((a.ranges ?? []).flatMap((r) => r.events.map((e) => e.fixed!).filter(Boolean)))], source: 'osv' });
  }
  for (const a of advisories)
    for (const p of a.packages) {
      const k = `${p.ecosystem}:${p.name}`.toLowerCase();
      if (seen.has(k)) continue;
      seen.add(k);
      packages.push({ ecosystem: p.ecosystem, name: p.name, fixed: p.patched ? [p.patched] : [], source: 'github' });
    }

  const epss = ep.data.get(cid) ?? null;
  const detail: CveDetail = {
    id: cid,
    description: c?.descriptions?.find((d) => d.lang === 'en')?.value ?? kev?.shortDescription ?? '',
    published: c?.published ?? null,
    lastModified: c?.lastModified ?? null,
    status: c?.vulnStatus ?? null,
    cvss: metric ? { version: metric.cvssData.version, score: metric.cvssData.baseScore, severity: metric.cvssData.baseSeverity ?? '', vector: metric.cvssData.vectorString } : null,
    cwes: [...new Set((c?.weaknesses ?? []).flatMap((w) => w.description.map((d) => d.value)).filter((v) => /^CWE-\d+$/.test(v)))],
    products: [...products].slice(0, 30),
    references: (c?.references ?? []).slice(0, 15).map((r) => ({ url: r.url, tags: r.tags ?? [] })),
    kev,
    epss,
    packages,
    advisories,
    aliases: [...new Set([...(osv.data?.aliases ?? []), ...advisories.map((a) => a.id)])],
  };

  const signals: Signal[] = [];
  const url = `https://nvd.nist.gov/vuln/detail/${cid}`;
  if (kev) {
    signals.push({ id: signalId('vulns', 'kev', cid), module: 'vulns', title: `Actively exploited: ${cid} ${kev.vendorProject} ${kev.product}`, score: kev.knownRansomwareCampaignUse.toLowerCase() === 'known' ? 82 : 72, entity: kev.vendorProject, evidence: [{ source: 'cisa-kev', text: `In CISA KEV since ${kev.dateAdded}, due ${kev.dueDate}, ransomware use: ${kev.knownRansomwareCampaignUse}`, url }], createdAt: now.toISOString() });
  }
  if (epss && epss.change30d !== null && epss.change30d >= 0.2) {
    signals.push({ id: signalId('vulns', 'epss-jump', cid, epss.date), module: 'vulns', title: `Exploitation likelihood rising: ${cid} EPSS ${epss.score.toFixed(3)}`, score: 64, evidence: [{ source: 'epss', text: `EPSS up ${epss.change30d.toFixed(3)} over about 30 days (percentile ${epss.percentile.toFixed(3)})`, url: `https://api.first.org/data/v1/epss?cve=${cid}` }], createdAt: now.toISOString() });
  }
  for (const s of signals) ctx.graph.saveSignal(s);

  return { module: 'vulns', input: cid, generatedAt: now.toISOString(), result: detail, signals, provenance };
}

export interface PackageVuln {
  id: string;
  aliases: string[];
  summary: string;
  severity: string;
  published: string;
  modified: string;
  fixed: string[];
  exploited: boolean;
  url: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  modified?: string;
  withdrawn?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { events: Record<string, string>[] }[] }[];
}

/** Known vulnerabilities of one open-source package (optionally one version) from OSV.dev, flagged when exploited (KEV). */
export async function packageVulns(ctx: Ctx, ecosystem: string, name: string, version?: string): Promise<ModuleResult<{ ecosystem: string; name: string; version: string | null; vulns: PackageVuln[] }>> {
  const now = ctx.now();
  const provenance: Provenance[] = [];
  const all: OsvVuln[] = [];
  let pageToken: string | undefined;
  for (let page = 0; page < 3; page++) {
    const body = { package: { name, ecosystem }, ...(version ? { version } : {}), ...(pageToken ? { page_token: pageToken } : {}) };
    const r = await postJson<{ vulns?: OsvVuln[]; next_page_token?: string }>(ctx, 'https://api.osv.dev/v1/query', body, {}, 'osv', 6 * 3600);
    provenance.push(r.prov);
    all.push(...(r.data?.vulns ?? []));
    pageToken = r.data?.next_page_token;
    if (!pageToken) break;
  }
  const kev = await kevSet(ctx);
  const lname = name.toLowerCase();
  const list: PackageVuln[] = all
    .filter((v) => !v.withdrawn)
    .map((v) => {
      const aliases = (v.aliases ?? []).filter((a) => a !== v.id);
      const ids = [v.id, ...aliases].map((x) => x.toUpperCase());
      const mine = (v.affected ?? []).filter((a) => a.package?.name?.toLowerCase() === lname);
      return {
        id: v.id,
        aliases,
        summary: (v.summary ?? v.details ?? '').slice(0, 200),
        severity: v.database_specific?.severity ?? v.severity?.[0]?.score ?? 'unknown',
        published: v.published ?? '',
        modified: v.modified ?? '',
        fixed: [...new Set(mine.flatMap((a) => (a.ranges ?? []).flatMap((r) => r.events.map((e) => e.fixed!).filter(Boolean))))],
        exploited: ids.some((x) => kev.has(x)),
        url: `https://osv.dev/vulnerability/${v.id}`,
      };
    })
    .sort((a, b) => Number(b.exploited) - Number(a.exploited) || b.published.localeCompare(a.published));

  const signals: Signal[] = list
    .filter((v) => v.exploited)
    .slice(0, 5)
    .map((v) => ({
      id: signalId('vulns', 'pkg', ecosystem, name, version ?? '', v.id),
      module: 'vulns',
      title: `${ecosystem} ${name}${version ? ` ${version}` : ''} has an actively exploited vulnerability: ${v.aliases.find((a) => CVE_RE.test(a)) ?? v.id}`,
      score: version ? 76 : 66,
      entity: name,
      evidence: [{ source: 'osv', text: `${v.summary}${v.fixed.length ? `; fixed in ${v.fixed.join(', ')}` : ''}; listed in CISA KEV`, url: v.url }],
      createdAt: now.toISOString(),
    }));
  for (const s of signals) ctx.graph.saveSignal(s);

  return { module: 'vulns', input: `${ecosystem}/${name}${version ? `@${version}` : ''}`, generatedAt: now.toISOString(), result: { ecosystem, name, version: version ?? null, vulns: list }, signals, provenance };
}
