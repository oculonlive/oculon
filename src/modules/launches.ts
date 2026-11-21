/**
 * Launch Radar: what a company is about to ship, from every footprint Oculon can see: new hostnames in
 * certificates and scans, newly archived pages, new public repos (Ferret), new Hugging Face models,
 * datasets and Spaces, new iOS apps and app updates, and new npm packages under its scope.
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { appStore, huggingFace, npmScope, type LaunchItem } from '../sources/launch.js';
import { ferret } from './ferret.js';

export interface LaunchFeedItem extends LaunchItem {
  company: string;
  score: number;
}

export interface LaunchResult {
  company: string;
  domain: string | null;
  org: string;
  windowDays: number;
  items: LaunchFeedItem[];
}

const KIND_SCORE: Record<string, number> = { model: 55, space: 45, dataset: 40, app: 70, 'app-update': 30, package: 45, subdomain: 50, page: 40, repo: 45 };

export async function launches(ctx: Ctx, company: string, opts: { domain?: string; org?: string; days?: number } = {}): Promise<ModuleResult<LaunchResult>> {
  const days = opts.days ?? 30;
  const org = (opts.org ?? company).toLowerCase().replace(/[^a-z0-9-]/g, '');
  const domain = opts.domain ?? null;
  const nowMs = ctx.now().getTime();
  const since = nowMs - days * DAY_MS;
  const provenance: Provenance[] = [];

  const [hf, apps, npm, fr] = await Promise.all([
    huggingFace(ctx, org),
    appStore(ctx, company),
    npmScope(ctx, org),
    domain ? ferret(ctx, domain, { days, org }) : Promise.resolve(null),
  ]);
  provenance.push(hf.prov, apps.prov, npm.prov, ...(fr?.provenance ?? []));

  const items: LaunchFeedItem[] = [...(hf.data ?? []), ...(apps.data ?? []), ...(npm.data ?? [])]
    .filter((i) => Date.parse(i.date) >= since)
    .map((i) => ({ ...i, company, score: KIND_SCORE[i.kind] ?? 40 }));
  for (const f of fr?.result.findings ?? []) {
    if (Date.parse(f.firstSeen) < since) continue;
    // Ferret already scored names (pre-release words etc.); keep its score for web footprints.
    items.push({ kind: f.kind === 'repo' ? 'package' : 'app-update', title: f.value, date: f.firstSeen, url: f.url, company, score: f.score, detail: `${f.kind}${f.reasons.length ? `: ${f.reasons.join('; ')}` : ''}` });
  }
  // Re-label web footprints with their real kind for display.
  for (const it of items) if (it.detail?.startsWith('subdomain')) (it as { kind: string }).kind = 'subdomain';
  for (const it of items) if (it.detail?.startsWith('page')) (it as { kind: string }).kind = 'page';
  for (const it of items) if (it.detail?.startsWith('repo')) (it as { kind: string }).kind = 'repo';
  // New things first (models, apps, packages, hosts, repos), routine app updates after; newest first within each.
  items.sort((a, b) => Number(a.kind === 'app-update') - Number(b.kind === 'app-update') || b.date.localeCompare(a.date));

  const nowIso = new Date(nowMs).toISOString();
  const fresh = items.filter((i) => nowMs - Date.parse(i.date) <= 3 * DAY_MS && i.kind !== 'app-update' && i.score >= 50);
  const signals: Signal[] = fresh.slice(0, 5).map((i) => ({
    id: signalId('launch', company, i.kind, i.title),
    module: 'launch',
    title: `${company}: new ${i.kind} ${i.title.slice(0, 100)}`,
    score: Math.min(85, i.score + 10),
    evidence: [{ source: i.kind, text: `${i.title}${i.detail ? ` — ${i.detail}` : ''} (${i.date.slice(0, 10)})`, url: i.url }],
    createdAt: nowIso,
  }));
  signals.forEach((s) => ctx.graph.saveSignal(s));
  const cid = ctx.graph.upsert('company', company);
  for (const i of items.filter((x) => x.kind === 'model').slice(0, 10)) ctx.graph.link(cid, ctx.graph.upsert('repo', i.title, { url: i.url }), 'released_model', 'huggingface');

  return { module: 'launch', input: company, generatedAt: nowIso, result: { company, domain, org, windowDays: days, items }, signals, provenance };
}
