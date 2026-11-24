/**
 * Contradiction finder: reads several independent articles on a topic and lists factual claims that conflict
 * (different numbers, dates, names, or one source denying what another asserts). Each side must cite a page
 * Oculon actually read; anything else is dropped in code.
 */
import type { Ctx } from '../core/context.js';
import { availableProviders, chat } from '../core/llm.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { gnews, guardian, readPage, webSearch } from '../sources/press.js';

export interface Contradiction {
  about: string;
  claimA: string;
  sourceA: string;
  claimB: string;
  sourceB: string;
  severity: 'major' | 'minor';
}

export interface ContradictionResult {
  topic: string;
  sourcesRead: { title: string; url: string }[];
  contradictions: Contradiction[];
}

export async function contradictions(ctx: Ctx, topicInput: string, opts: { maxSources?: number; fetch?: typeof fetch } = {}): Promise<ModuleResult<ContradictionResult>> {
  const topic = topicInput.trim();
  const provenance: Provenance[] = [];
  const nowIso = ctx.now().toISOString();
  const [web, gn, gu] = await Promise.all([webSearch(ctx, topic, 8, true), gnews(ctx, topic, 8), guardian(ctx, topic, 7, 6)]);
  provenance.push(web.prov, gn.prov, gu.prov);
  // One page per site, so "independent" means different outlets.
  const seen = new Set<string>();
  const candidates = [...(web.data ?? []).map((w) => ({ title: w.title, url: w.url })), ...(gu.data ?? []), ...(gn.data ?? [])].filter((c) => {
    try {
      const h = new URL(c.url).hostname.replace(/^www\./, '');
      if (seen.has(h)) return false;
      seen.add(h);
      return true;
    } catch {
      return false;
    }
  });
  const pages: { title: string; url: string; text: string }[] = [];
  // Pages are read in parallel: one at a time, a few slow sites pushed this past a minute and a half.
  const picked = candidates.slice(0, opts.maxSources ?? 6);
  const read = await Promise.all(picked.map((c) => readPage(ctx, c.url, 3500)));
  read.forEach((p, i) => {
    provenance.push(p.prov);
    if (p.data && p.data.length > 400) pages.push({ title: picked[i]!.title, url: picked[i]!.url, text: p.data });
  });
  const result: ContradictionResult = { topic, sourcesRead: pages.map((p) => ({ title: p.title, url: p.url })), contradictions: [] };
  if (pages.length < 2 || !availableProviders().length) {
    if (!availableProviders().length) provenance.push({ source: 'llm', url: '', status: 'UNAVAILABLE', fetchedAt: nowIso, note: 'contradiction finding needs an LLM key' });
    return { module: 'contradictions', input: topic, generatedAt: nowIso, result, signals: [], provenance };
  }
  const r = await chat(
    [
      {
        role: 'system',
        content:
          'You compare news sources on one topic. List factual claims that CONFLICT between sources: different numbers, dates, names, outcomes, or one source denying what another asserts. Ignore differences in emphasis, opinion, or details only one source mentions. Each side must quote or closely paraphrase its source and give that source\'s URL exactly as provided. Reply JSON {"contradictions":[{"about":"...","claim_a":"...","source_a":"url","claim_b":"...","source_b":"url","severity":"major|minor"}]}. Empty list if none.',
      },
      { role: 'user', content: `Topic: ${topic}\n\n${pages.map((p, i) => `SOURCE ${i + 1} (${p.url})\n${p.title}\n${p.text}`).join('\n\n---\n\n')}` },
    ],
    { json: true, temperature: 0, maxTokens: 2500, premium: true, ...(opts.fetch ? { fetch: opts.fetch } : {}) },
  );
  const urls = new Set(pages.map((p) => p.url));
  let raw: { about?: unknown; claim_a?: unknown; source_a?: unknown; claim_b?: unknown; source_b?: unknown; severity?: unknown }[] = [];
  try {
    raw = (JSON.parse(r.message.content ?? '{}') as { contradictions?: typeof raw }).contradictions ?? [];
  } catch {}
  result.contradictions = raw
    .map((c) => ({
      about: String(c.about ?? '').slice(0, 200),
      claimA: String(c.claim_a ?? '').slice(0, 400),
      sourceA: String(c.source_a ?? ''),
      claimB: String(c.claim_b ?? '').slice(0, 400),
      sourceB: String(c.source_b ?? ''),
      severity: (c.severity === 'major' ? 'major' : 'minor') as Contradiction['severity'],
    }))
    .filter((c) => c.claimA && c.claimB && urls.has(c.sourceA) && urls.has(c.sourceB) && c.sourceA !== c.sourceB);

  const signals: Signal[] = result.contradictions
    .filter((c) => c.severity === 'major')
    .slice(0, 3)
    .map((c) => ({
      id: signalId('contradiction', topic, c.about),
      module: 'contradiction',
      title: `Sources disagree on ${topic}: ${c.about}`,
      score: 60,
      evidence: [
        { source: new URL(c.sourceA).hostname, text: c.claimA, url: c.sourceA },
        { source: new URL(c.sourceB).hostname, text: c.claimB, url: c.sourceB },
      ],
      createdAt: nowIso,
    }));
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { module: 'contradictions', input: topic, generatedAt: nowIso, result, signals, provenance };
}
