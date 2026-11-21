/**
 * Fact check: a claim (or the main claim of a linked article) against published fact checks and the open web.
 *   Google Fact Check Tools: ClaimReview ratings from fact-checking organizations (GOOGLE_API_KEY).
 *   Web search (Tavily, Exa fallback) for current reporting; Jina Reader to read a linked article.
 *   An LLM weighs only the evidence gathered here and must cite it by number. Without an LLM the verdict
 *   comes from the published ratings alone.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { complete } from '../core/llm.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal, Sourced } from '../core/types.js';
import { readPage, webSearch } from '../sources/press.js';

export type FactVerdict = 'true' | 'mostly true' | 'mixed' | 'misleading' | 'false' | 'unverified';

export interface Evidence { n: number; kind: 'fact-check' | 'web'; title: string; url: string; publisher: string; date: string | null; rating: string | null; snippet: string }

export interface FactCheckResult {
  claim: string;
  source: string | null;
  verdict: FactVerdict;
  confidence: number;
  summary: string;
  cited: number[];
  factChecks: Evidence[];
  web: Evidence[];
  method: string;
}

interface ClaimReviewRaw { text?: string; claimant?: string; claimDate?: string; claimReview?: { publisher?: { name?: string; site?: string }; url?: string; title?: string; reviewDate?: string; textualRating?: string }[] }

/** Published fact checks matching the claim (Google Fact Check Tools, English and any language). */
export async function publishedFactChecks(ctx: Ctx, claim: string, max = 8): Promise<Sourced<Evidence[]>> {
  const k = key('GOOGLE_API_KEY') ?? key('FACTCHECK_API_KEY');
  if (!k) return { data: null, prov: { source: 'google-factcheck', url: '', status: 'UNAVAILABLE', fetchedAt: new Date().toISOString(), note: 'set GOOGLE_API_KEY with the Fact Check Tools API enabled' } };
  const q = claim.replace(/\s+/g, ' ').trim().slice(0, 200);
  const base = 'https://factchecktools.googleapis.com/v1alpha1/claims:search';
  const r = await ctx.http.get<ClaimReviewRaw[]>(`${base}?query=${encodeURIComponent(q)}&pageSize=${max}&key=${k}`, { source: 'google-factcheck', ttlSec: 6 * 3600, keep: (d: { claims?: ClaimReviewRaw[] }) => d.claims ?? [] });
  const data = (r.data ?? []).flatMap((c) =>
    (c.claimReview ?? []).slice(0, 1).map((rv) => ({
      n: 0,
      kind: 'fact-check' as const,
      title: c.text?.slice(0, 240) ?? rv.title ?? '',
      url: rv.url ?? '',
      publisher: rv.publisher?.name ?? rv.publisher?.site ?? 'fact checker',
      date: rv.reviewDate ?? c.claimDate ?? null,
      rating: rv.textualRating ?? null,
      snippet: `${c.claimant ? `${c.claimant} claimed: ` : ''}${c.text ?? ''}`.slice(0, 300),
    })),
  );
  // The request URL carries the key; keep it out of provenance.
  return { data: r.data ? data : null, prov: { ...r.prov, url: base } };
}

const FALSE_RE = /\b(false|fake|hoax|incorrect|pants on fire|baseless|fabricated|no evidence|not true|wrong|debunked|scam)\b/i;
const MISLEADING_RE = /\b(misleading|missing context|partly|half|mixed|exaggerat|out of context|distort|unproven|satire)\b/i;
const TRUE_RE = /\b(true|correct|accurate|confirmed)\b/i;

/** Verdict from published ratings alone (used when no LLM is configured). */
export function ratingsVerdict(ratings: string[]): { verdict: FactVerdict; confidence: number } {
  if (!ratings.length) return { verdict: 'unverified', confidence: 0 };
  const f = ratings.filter((r) => FALSE_RE.test(r) && !/mostly true/i.test(r)).length;
  const m = ratings.filter((r) => MISLEADING_RE.test(r)).length;
  const t = ratings.filter((r) => TRUE_RE.test(r) && !FALSE_RE.test(r) && !MISLEADING_RE.test(r)).length;
  const top = Math.max(f, m, t);
  const confidence = Math.round((top / ratings.length) * 70);
  if (top === 0) return { verdict: 'unverified', confidence: 20 };
  if (f === top) return { verdict: 'false', confidence };
  if (m === top) return { verdict: 'misleading', confidence };
  return { verdict: 'mostly true', confidence };
}

const VERDICTS: FactVerdict[] = ['true', 'mostly true', 'mixed', 'misleading', 'false', 'unverified'];

export async function factCheck(ctx: Ctx, input: string): Promise<ModuleResult<FactCheckResult>> {
  const raw = input.trim();
  if (!raw) throw new Error('missing claim');
  const provenance: Provenance[] = [];
  let claim = raw;
  let source: string | null = null;
  if (/^https?:\/\//i.test(raw)) {
    source = raw;
    const page = await readPage(ctx, raw, 5000);
    provenance.push(page.prov);
    if (!page.data) throw new Error(`could not read ${raw}`);
    const title = /^Title:\s*(.+)$/m.exec(page.data)?.[1]?.trim();
    claim = title ?? page.data.slice(0, 200);
    try {
      const x = await complete('Extract the single main factual claim of this article as one plain sentence. Reply with the sentence only.', page.data.slice(0, 4000), { maxTokens: 120, temperature: 0 });
      if (x.text && x.text.length > 10) claim = x.text.replace(/^["']|["']$/g, '').slice(0, 300);
    } catch {
      // no LLM: keep the headline as the claim
    }
  }

  const [fc, web] = await Promise.all([publishedFactChecks(ctx, claim), webSearch(ctx, claim, 6)]);
  provenance.push(fc.prov, web.prov);
  let n = 0;
  const factChecks = (fc.data ?? []).map((e) => ({ ...e, n: ++n }));
  const webEv: Evidence[] = (web.data ?? [])
    .filter((w) => w.url !== source)
    .slice(0, 6)
    .map((w) => ({ n: ++n, kind: 'web', title: w.title, url: w.url, publisher: (() => { try { return new URL(w.url).hostname.replace(/^www\./, ''); } catch { return 'web'; } })(), date: w.date, rating: null, snippet: w.snippet }));
  const all = [...factChecks, ...webEv];

  let verdict: FactVerdict;
  let confidence: number;
  let summary: string;
  let cited: number[] = [];
  let method = 'published ratings';
  const byRatings = ratingsVerdict(factChecks.map((f) => f.rating ?? '').filter(Boolean));
  if (!all.length) {
    ({ verdict, confidence } = byRatings);
    summary = 'No published fact checks or reporting were found for this claim.';
  } else {
    try {
      const evidence = all.map((e) => `[${e.n}] ${e.kind === 'fact-check' ? `FACT CHECK by ${e.publisher}${e.rating ? `, rated "${e.rating}"` : ''}` : `WEB ${e.publisher}`}${e.date ? ` (${e.date.slice(0, 10)})` : ''}: ${e.title}. ${e.snippet}`).join('\n');
      const x = await complete(
        `You check claims for an OSINT tool. Judge the claim ONLY from the numbered evidence. Reply as JSON: {"verdict": one of ${VERDICTS.map((v) => `"${v}"`).join(', ')}, "confidence": 0-100, "summary": "2-3 sentences, cite evidence like [2]", "cited": [numbers]}. Use "unverified" when the evidence does not settle it. Published fact checks about the same claim weigh most. Today is ${ctx.now().toISOString().slice(0, 10)}.`,
        `Claim: ${claim}\n\nEvidence:\n${evidence}`,
        { json: true, maxTokens: 400, temperature: 0 },
      );
      const j = JSON.parse(x.text.replace(/^```(json)?|```$/g, '')) as { verdict?: string; confidence?: number; summary?: string; cited?: number[] };
      verdict = VERDICTS.includes(j.verdict as FactVerdict) ? (j.verdict as FactVerdict) : 'unverified';
      confidence = Math.max(0, Math.min(100, Math.round(Number(j.confidence ?? 0))));
      summary = String(j.summary ?? '').slice(0, 800);
      cited = (j.cited ?? []).map(Number).filter((c) => c >= 1 && c <= all.length);
      method = `${x.provider} over ${all.length} sources`;
    } catch {
      ({ verdict, confidence } = byRatings);
      summary = factChecks.length ? `Published fact checks: ${factChecks.slice(0, 3).map((f) => `${f.publisher} rated it "${f.rating}" [${f.n}]`).join('; ')}.` : 'Only general reporting was found; no published fact check rates this claim.';
      cited = factChecks.slice(0, 3).map((f) => f.n);
    }
  }

  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = [];
  if ((verdict === 'false' || verdict === 'misleading') && factChecks.length >= 2) {
    const s: Signal = {
      id: signalId('factcheck', claim.toLowerCase(), nowIso.slice(0, 10)),
      module: 'factcheck',
      title: `Claim rated ${verdict}: ${claim.slice(0, 90)}`,
      score: Math.min(80, 40 + factChecks.length * 8),
      evidence: factChecks.slice(0, 3).map((f) => ({ source: f.publisher, text: `rated "${f.rating}"`, url: f.url })),
      createdAt: nowIso,
    };
    ctx.graph.saveSignal(s);
    signals.push(s);
  }
  return { module: 'factcheck', input: raw, generatedAt: nowIso, result: { claim, source, verdict, confidence, summary, cited, factChecks, web: webEv, method }, signals, provenance };
}
