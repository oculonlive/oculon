/** Launch footprints beyond the web: Hugging Face models, App Store apps, npm packages. All keyless. */
import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

export interface LaunchItem {
  kind: 'model' | 'dataset' | 'space' | 'app' | 'app-update' | 'package';
  title: string;
  date: string;
  url: string;
  detail?: string;
}

/** Newest Hugging Face models, datasets and Spaces of an org. */
export async function huggingFace(ctx: Ctx, org: string, limit = 15): Promise<Sourced<LaunchItem[]>> {
  const kinds = [
    ['models', 'model'],
    ['datasets', 'dataset'],
    ['spaces', 'space'],
  ] as const;
  const results = await Promise.all(
    kinds.map(([path]) => ctx.http.get<{ id: string; createdAt?: string }[]>(`https://huggingface.co/api/${path}?author=${enc(org)}&sort=createdAt&direction=-1&limit=${limit}`, { source: 'huggingface', ttlSec: 3 * 3600 })),
  );
  const first = results.find((r) => r.data) ?? results[0]!;
  if (results.every((r) => !r.data)) return { data: null, prov: first.prov };
  const data = results.flatMap((r, i) =>
    (r.data ?? []).filter((x) => x.createdAt).map((x) => ({ kind: kinds[i]![1], title: x.id, date: x.createdAt!, url: `https://huggingface.co/${kinds[i]![0] === 'models' ? '' : `${kinds[i]![0]}/`}${x.id}` })),
  );
  return { data, prov: first.prov };
}

/** iOS apps whose developer name matches the company: new releases and fresh updates. */
export async function appStore(ctx: Ctx, company: string): Promise<Sourced<LaunchItem[]>> {
  const r = await ctx.http.get<{ results?: { trackName: string; artistName: string; releaseDate: string; currentVersionReleaseDate?: string; version?: string; trackViewUrl: string; releaseNotes?: string }[] }>(
    `https://itunes.apple.com/search?term=${enc(company)}&entity=software&limit=50`,
    { source: 'itunes', ttlSec: 6 * 3600 },
  );
  const name = company.toLowerCase();
  const mine = (r.data?.results ?? []).filter((a) => a.artistName.toLowerCase().includes(name));
  const data: LaunchItem[] = [];
  for (const a of mine) {
    data.push({ kind: 'app', title: a.trackName, date: a.releaseDate, url: a.trackViewUrl, detail: `by ${a.artistName}` });
    if (a.currentVersionReleaseDate && a.currentVersionReleaseDate !== a.releaseDate) {
      data.push({ kind: 'app-update', title: `${a.trackName} ${a.version ?? ''}`.trim(), date: a.currentVersionReleaseDate, url: a.trackViewUrl, ...(a.releaseNotes ? { detail: a.releaseNotes.replace(/\s+/g, ' ').slice(0, 160) } : {}) });
    }
  }
  return { data: r.data ? data : null, prov: r.prov };
}

/** npm packages published under the org's scope (@org/...), with their creation dates. */
export async function npmScope(ctx: Ctx, org: string, limit = 25): Promise<Sourced<LaunchItem[]>> {
  const r = await ctx.http.get<{ objects?: { package: { name: string; date?: string; description?: string; links?: { npm?: string } } }[] }>(
    `https://registry.npmjs.org/-/v1/search?text=${enc(`@${org}`)}&size=${limit}`,
    { source: 'npm', ttlSec: 3 * 3600 },
  );
  const pkgs = (r.data?.objects ?? []).map((o) => o.package).filter((p) => p.name.startsWith(`@${org.toLowerCase()}/`));
  const docs = await Promise.all(pkgs.slice(0, 12).map((p) => ctx.http.get<{ time?: { created?: string } }>(`https://registry.npmjs.org/${enc(p.name).replace('%40', '@')}`, { source: 'npm', ttlSec: 24 * 3600, keep: (d: { time?: { created?: string } }) => ({ time: { created: d?.time?.created } }) })));
  const data = pkgs.slice(0, 12).flatMap((p, i) => {
    const created = docs[i]?.data?.time?.created;
    return created ? [{ kind: 'package' as const, title: p.name, date: created, url: p.links?.npm ?? `https://www.npmjs.com/package/${p.name}`, ...(p.description ? { detail: p.description.slice(0, 140) } : {}) }] : [];
  });
  return { data: r.data ? data : null, prov: r.prov };
}
