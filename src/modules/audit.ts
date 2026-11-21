/**
 * Dependency audit: health and supply-chain risk of every package in a manifest.
 *   deps.dev (Google Open Source Insights, no key): versions, release dates, deprecation, licenses,
 *     known advisories (OSV / GitHub), and the source project with its OpenSSF Scorecard and stars.
 * Accepts package.json (npm), requirements.txt (PyPI), or a list such as "npm:express@4.17.1 pypi:requests".
 * Every flag is plain: vulnerable, deprecated, no release in 2 years, behind the latest major, weak or
 * unmaintained per Scorecard, missing or strong-copyleft license.
 */
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';

const DD = 'https://api.deps.dev/v3';
const DAY = 86_400_000;
const SOURCE = 'deps.dev';

export type Ecosystem = 'npm' | 'pypi' | 'go' | 'cargo' | 'maven' | 'nuget';
const SYSTEM: Record<Ecosystem, string> = { npm: 'NPM', pypi: 'PYPI', go: 'GO', cargo: 'CARGO', maven: 'MAVEN', nuget: 'NUGET' };

export interface Dependency { ecosystem: Ecosystem; name: string; spec: string | null; dev: boolean }

export interface PackageAudit {
  ecosystem: Ecosystem;
  name: string;
  spec: string | null;
  version: string | null;
  latest: string | null;
  latestReleased: string | null;
  dev: boolean;
  licenses: string[];
  deprecated: string | null;
  advisories: { id: string; title: string; cvss: number | null; aliases: string[]; url: string }[];
  /** All known advisories for this version (details are fetched for the first 8). */
  advisoryCount: number;
  project: { id: string; stars: number | null; scorecard: number | null; maintained: number | null; url: string } | null;
  flags: string[];
  /** 0 (fine) to 100 (fix now). */
  risk: number;
}

export interface AuditResult {
  manifest: string;
  packages: PackageAudit[];
  summary: { total: number; checked: number; vulnerable: number; advisories: number; deprecated: number; stale: number; weakScorecard: number; risky: number };
  skipped: string[];
}

/** Parses package.json, requirements.txt or "eco:name@version" lists into dependencies. */
export function parseManifest(text: string): { kind: string; deps: Dependency[] } {
  const t = text.trim();
  if (t.startsWith('{')) {
    const j = JSON.parse(t) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string> };
    const deps: Dependency[] = [];
    for (const [name, spec] of Object.entries({ ...j.dependencies, ...j.optionalDependencies })) deps.push({ ecosystem: 'npm', name, spec: String(spec), dev: false });
    for (const [name, spec] of Object.entries(j.devDependencies ?? {})) if (!deps.some((d) => d.name === name)) deps.push({ ecosystem: 'npm', name, spec: String(spec), dev: true });
    return { kind: 'package.json', deps };
  }
  const tokens = t.split(/[\s,]+/).filter(Boolean);
  if (tokens.length && tokens.every((x) => /^(npm|pypi|go|cargo|maven|nuget):/i.test(x))) {
    return {
      kind: 'list',
      deps: tokens.map((x) => {
        const [eco, rest] = [x.slice(0, x.indexOf(':')).toLowerCase() as Ecosystem, x.slice(x.indexOf(':') + 1)];
        // "requests==2.19.0" (pip style) or "express@4.17.1"; a leading "@" is an npm scope, not a version.
        const pin = /^(.+?)(==|~=|>=)(.+)$/.exec(rest);
        if (pin) return { ecosystem: eco, name: eco === 'pypi' ? pin[1]!.toLowerCase() : pin[1]!, spec: `${pin[2]}${pin[3]}`, dev: false };
        const at = rest.lastIndexOf('@');
        return at > 0 ? { ecosystem: eco, name: rest.slice(0, at), spec: rest.slice(at + 1), dev: false } : { ecosystem: eco, name: eco === 'pypi' ? rest.toLowerCase() : rest, spec: null, dev: false };
      }),
    };
  }
  // requirements.txt: "name==1.2.3", "name>=1.0", "name[extra]~=2.0", comments and options ignored.
  const deps: Dependency[] = [];
  for (const raw of t.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line || line.startsWith('-')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:(==|===|~=|>=|<=|>|<|!=)\s*([^;,\s]+))?/.exec(line);
    if (m) deps.push({ ecosystem: 'pypi', name: m[1]!.toLowerCase(), spec: m[4] ? `${m[3]}${m[4]}` : null, dev: false });
  }
  if (!deps.length) throw new Error('could not read the manifest: expected package.json, requirements.txt or "npm:name@version" items');
  return { kind: 'requirements.txt', deps };
}

interface DdVersion { versionKey: { version: string }; publishedAt?: string; isDefault?: boolean; isDeprecated?: boolean; deprecatedReason?: string }

const cmp = (a: string, b: string) => {
  const pa = a.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  const pb = b.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    return String(x).localeCompare(String(y));
  }
  return 0;
};
const major = (v: string) => Number(/^\D*(\d+)/.exec(v)?.[1] ?? NaN);
const isPre = (v: string) => /-|a\d|b\d|rc|dev|alpha|beta/i.test(v);

/** The version a spec most likely installs: an exact pin, else the highest release in the same major (or the default). */
export function resolveVersion(spec: string | null, versions: string[], fallback: string | null): string | null {
  if (!spec) return fallback;
  const s = spec.trim();
  const exact = s.replace(/^(==|===|v)/, '');
  if (versions.includes(exact)) return exact;
  const base = /(\d+(?:\.\d+){0,2})/.exec(s)?.[1];
  if (!base) return fallback;
  const releases = versions.filter((v) => !isPre(v));
  if (/^\^|^~=|^~|^>=|^>/.test(s)) {
    const sameMajor = releases.filter((v) => major(v) === major(base) && cmp(v, base) >= 0).sort(cmp);
    if (s.startsWith('>')) return releases.filter((v) => cmp(v, base) >= 0).sort(cmp).at(-1) ?? fallback;
    return sameMajor.at(-1) ?? fallback;
  }
  return releases.filter((v) => cmp(v, base) <= 0).sort(cmp).at(-1) ?? fallback;
}

const COPYLEFT = /^(A?GPL|SSPL|EUPL|OSL)/i;

async function auditOne(ctx: Ctx, d: Dependency, prov: Provenance[]): Promise<PackageAudit | string> {
  const sys = SYSTEM[d.ecosystem];
  const pkgPath = `${DD}/systems/${sys}/packages/${encodeURIComponent(d.name)}`;
  const pkg = await ctx.http.get<DdVersion[]>(pkgPath, { source: SOURCE, ttlSec: 12 * 3600, keep: (x: { versions?: DdVersion[] }) => (x.versions ?? []).map((v) => ({ versionKey: { version: v.versionKey.version }, publishedAt: v.publishedAt, isDefault: v.isDefault, isDeprecated: v.isDeprecated, deprecatedReason: v.deprecatedReason })) });
  prov.push(pkg.prov);
  if (!pkg.data?.length) return `${d.ecosystem}:${d.name} (not found on deps.dev)`;
  const all = pkg.data;
  const def = all.find((v) => v.isDefault) ?? [...all].sort((a, b) => cmp(a.versionKey.version, b.versionKey.version)).at(-1)!;
  const latest = def.versionKey.version;
  const version = resolveVersion(d.spec, all.map((v) => v.versionKey.version), latest);
  const vr = version
    ? await ctx.http.get<{ licenses?: string[]; isDeprecated?: boolean; deprecatedReason?: string; advisoryKeys?: { id: string }[]; relatedProjects?: { projectKey: { id: string }; relationType: string }[] }>(`${pkgPath}/versions/${encodeURIComponent(version)}`, { source: SOURCE, ttlSec: 12 * 3600 })
    : null;
  if (vr) prov.push(vr.prov);
  const v = vr?.data ?? null;

  const advisories: PackageAudit['advisories'] = [];
  for (const a of (v?.advisoryKeys ?? []).slice(0, 8)) {
    const ar = await ctx.http.get<{ title?: string; cvss3Score?: number; aliases?: string[]; url?: string }>(`${DD}/advisories/${encodeURIComponent(a.id)}`, { source: SOURCE, ttlSec: 24 * 3600 });
    prov.push(ar.prov);
    advisories.push({ id: a.id, title: ar.data?.title ?? a.id, cvss: ar.data?.cvss3Score ?? null, aliases: ar.data?.aliases ?? [], url: ar.data?.url ?? `https://osv.dev/vulnerability/${a.id}` });
  }
  const extraAdvisories = Math.max(0, (v?.advisoryKeys?.length ?? 0) - advisories.length);

  const projId = v?.relatedProjects?.find((p) => p.relationType === 'SOURCE_REPO')?.projectKey.id ?? v?.relatedProjects?.[0]?.projectKey.id;
  let project: PackageAudit['project'] = null;
  if (projId) {
    const pr = await ctx.http.get<{ starsCount?: number; scorecard?: { overallScore?: number; checks?: { name: string; score: number }[] } }>(`${DD}/projects/${encodeURIComponent(projId)}`, {
      source: SOURCE,
      ttlSec: 24 * 3600,
      keep: (x: { starsCount?: number; scorecard?: { overallScore?: number; checks?: { name: string; score: number }[] } }) => ({ starsCount: x.starsCount, scorecard: x.scorecard ? { overallScore: x.scorecard.overallScore, checks: (x.scorecard.checks ?? []).map((c) => ({ name: c.name, score: c.score })) } : undefined }),
    });
    prov.push(pr.prov);
    if (pr.data) project = { id: projId, stars: pr.data.starsCount ?? null, scorecard: pr.data.scorecard?.overallScore ?? null, maintained: pr.data.scorecard?.checks?.find((c) => c.name === 'Maintained')?.score ?? null, url: `https://${projId}` };
  }

  const flags: string[] = [];
  let risk = 0;
  if (advisories.length) {
    const worst = Math.max(0, ...advisories.map((a) => a.cvss ?? 0));
    risk += worst >= 9 ? 70 : worst >= 7 ? 55 : 40;
    flags.push(`${advisories.length + extraAdvisories} known vulnerabilit${advisories.length + extraAdvisories === 1 ? 'y' : 'ies'}${worst ? ` (worst CVSS ${worst})` : ''}`);
  }
  const deprecated = v?.isDeprecated ? v.deprecatedReason || 'deprecated' : def.isDeprecated ? def.deprecatedReason || 'deprecated' : null;
  if (deprecated) { risk += 30; flags.push(`deprecated: ${deprecated.slice(0, 120)}`); }
  const lastRelease = def.publishedAt ?? null;
  const ageDays = lastRelease ? (ctx.now().getTime() - Date.parse(lastRelease)) / DAY : null;
  if (ageDays != null && ageDays > 730) { risk += 20; flags.push(`no release in ${Math.floor(ageDays / 365)} years`); }
  if (version && latest && major(version) < major(latest)) { risk += 10; flags.push(`${major(latest) - major(version)} major version${major(latest) - major(version) === 1 ? '' : 's'} behind (latest ${latest})`); }
  if (project?.scorecard != null && project.scorecard < 4) { risk += 15; flags.push(`weak OpenSSF Scorecard (${project.scorecard}/10)`); }
  if (project?.maintained === 0) { risk += 15; flags.push('Scorecard says not actively maintained'); }
  const licenses = v?.licenses ?? [];
  if (!licenses.length || licenses.every((l) => /^non-standard$/i.test(l))) { risk += 5; flags.push('no declared license'); }
  else if (licenses.some((l) => COPYLEFT.test(l))) flags.push(`strong copyleft license (${licenses.join(', ')})`);
  if (d.dev) risk = Math.round(risk * 0.6);

  return { ecosystem: d.ecosystem, name: d.name, spec: d.spec, version, latest, latestReleased: lastRelease, dev: d.dev, licenses, deprecated, advisories, advisoryCount: advisories.length + extraAdvisories, project, flags, risk: clamp(risk, 0, 100) };
}

/** Audits up to `max` packages from a manifest (package.json, requirements.txt, or "npm:name@ver" items). */
export async function audit(ctx: Ctx, manifestText: string, opts: { max?: number } = {}): Promise<ModuleResult<AuditResult>> {
  const { kind, deps } = parseManifest(manifestText);
  const max = Math.max(1, Math.min(opts.max ?? 60, 150));
  const todo = deps.slice(0, max);
  const provenance: Provenance[] = [];
  const packages: PackageAudit[] = [];
  const skipped: string[] = deps.slice(max).map((d) => `${d.ecosystem}:${d.name} (over the ${max}-package limit)`);
  // A small pool keeps deps.dev happy and still finishes a typical manifest in seconds.
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(6, todo.length) }, async () => {
      while (next < todo.length) {
        const d = todo[next++]!;
        try {
          const r = await auditOne(ctx, d, provenance);
          if (typeof r === 'string') skipped.push(r);
          else packages.push(r);
        } catch (e) {
          skipped.push(`${d.ecosystem}:${d.name} (${(e as Error).message})`);
        }
      }
    }),
  );
  packages.sort((a, b) => b.risk - a.risk || a.name.localeCompare(b.name));
  const summary = {
    total: deps.length,
    checked: packages.length,
    vulnerable: packages.filter((p) => p.advisories.length).length,
    advisories: packages.reduce((n, p) => n + p.advisoryCount, 0),
    deprecated: packages.filter((p) => p.deprecated).length,
    stale: packages.filter((p) => p.flags.some((f) => f.startsWith('no release'))).length,
    weakScorecard: packages.filter((p) => p.project?.scorecard != null && p.project.scorecard < 4).length,
    risky: packages.filter((p) => p.risk >= 40).length,
  };
  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = packages
    .filter((p) => p.advisories.some((a) => (a.cvss ?? 0) >= 9))
    .slice(0, 5)
    .map((p) => ({
      id: signalId('audit', p.ecosystem, p.name, p.version ?? '', nowIso.slice(0, 10)),
      module: 'audit',
      title: `Critical vulnerability in ${p.name}@${p.version}`,
      score: clamp(p.risk, 60, 90),
      evidence: p.advisories.slice(0, 3).map((a) => ({ source: 'deps.dev', text: `${a.aliases[0] ?? a.id}: ${a.title}${a.cvss ? ` (CVSS ${a.cvss})` : ''}`, url: a.url })),
      createdAt: nowIso,
    }));
  return { module: 'audit', input: kind, generatedAt: nowIso, result: { manifest: kind, packages, summary, skipped }, signals, provenance };
}
