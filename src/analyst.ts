/**
 * Oculon Analyst: the tool-using agent behind /ask, answering as an intelligence brief instead of chat prose.
 * - Every source a tool touched gets a number; findings cite those numbers, and only those (invented links are dropped).
 * - The brief carries a 0-100 confidence with its reason, what is still unknown and what would change the conclusion.
 * - Cross-examination: other models re-read the same evidence and mark each finding supported, partly or unsupported.
 * Models run through OpenRouter; the choice is the user's.
 */
import { randomBytes } from 'node:crypto';
import { runAgent } from './agent.js';
import { chat, type ChatMessage } from './core/llm.js';
import { scrubSecrets } from './core/keys.js';
import type { Oculon } from './index.js';

export const ANALYST_MODELS = {
  haiku: { id: 'anthropic/claude-haiku-5.5', label: 'Claude Haiku 5.5', note: 'fast' },
  opus: { id: 'anthropic/claude-opus-5.5', label: 'Claude Opus 5.5', note: 'thorough' },
  gpt: { id: 'openai/gpt-6.2-astra', label: 'GPT-6.2 Astra', note: 'second view' },
} as const;
export type AnalystModel = keyof typeof ANALYST_MODELS;
export const isAnalystModel = (m: unknown): m is AnalystModel => typeof m === 'string' && m in ANALYST_MODELS;

export interface Source {
  n: number;
  kind: 'feed' | 'link';
  label: string;
  url?: string;
  host?: string;
  status?: string;
  tool: string;
}

export interface Finding {
  text: string;
  sources: number[];
}

export interface Brief {
  headline: string;
  bottomLine: string;
  confidence: number;
  confidenceWhy: string;
  findings: Finding[];
  unknowns: string[];
  changeMyMind: string;
  followUps: string[];
  watch: string | null;
}

export interface AnalystEvent {
  type: 'start' | 'step' | 'stepdone' | 'brief' | 'error';
  [k: string]: unknown;
}

export interface AnalystResult {
  id: string;
  question: string;
  model: AnalystModel;
  brief: Brief;
  sources: Source[];
  steps: { tool: string; label: string; ok: boolean; ms: number }[];
  ms: number;
}

const SYSTEM = `You are Oculon Analyst, an open-source intelligence analyst. You answer by checking live public data with your tools, then writing a short intelligence brief.
How to work:
- Check before you answer: call the tools that can verify the question (1-5 calls; independent calls in parallel). Do not answer from memory when a tool can check it.
- Tool results end with "Numbered sources". Cite them as numbers. Never cite anything that is not in those lists.
- Sources marked ERROR or UNAVAILABLE returned nothing; never present them as evidence.
- Prefer concrete facts: numbers, dates, names, places. Separate what the data shows from what it suggests.
When you are done, reply with ONE JSON object and nothing else:
{
  "headline": "the answer in at most 10 words",
  "bottomLine": "1-3 sentences that answer the question directly",
  "confidence": 0-100 (how well the checked data supports the bottom line; low when sources are few, stale or failed),
  "confidenceWhy": "one sentence: why this confidence",
  "findings": [{"text": "one concrete finding", "sources": [1, 2]}] (2-6 findings, each with at least one source number),
  "unknowns": ["what the data could not show"] (0-3 items),
  "changeMyMind": "the new evidence that would change the bottom line",
  "followUps": ["three short follow-up questions the user might ask next"],
  "watch": "a plain-language monitor request worth setting up (e.g. 'internet outages in Iran'), or null"
}
Write every text field in the language of the user's question.`;

const REVIEW_SYSTEM = `You are a skeptical reviewer cross-examining an intelligence brief written by another analyst.
You get the evidence the analyst saw (tool results with numbered sources) and the brief.
Judge only against that evidence, not your own knowledge. Reply with ONE JSON object and nothing else:
{
  "findings": [{"i": 0, "verdict": "supported" | "partly" | "unsupported", "note": "at most 15 words"}] (one per finding, same order),
  "bottomLine": "agree" | "partly" | "disagree",
  "missed": "one sentence on something important in the evidence the brief left out, or null"
}`;

const LINK_TEXT = ['title', 'headline', 'name', 'question', 'text', 'summary', 'description', 'id'];

/** Pull feed names (with their best status) and article-like links out of a tool result. */
function collectSources(raw: unknown, tool: string): { feeds: { label: string; status: string }[]; links: { label: string; url: string }[] } {
  const feeds: { label: string; status: string }[] = [];
  const links: { label: string; url: string }[] = [];
  const rank = ['LIVE', 'CACHED', 'UNAVAILABLE', 'ERROR'];
  // Provenance comes either summarized ({ sources: { name: { LIVE: 2 } } }) or as the raw list of fetches.
  const provRaw = (raw as { provenance?: unknown } | null)?.provenance;
  const counts = new Map<string, Record<string, number>>();
  if (Array.isArray(provRaw)) {
    for (const p of provRaw as { source?: unknown; status?: unknown }[]) {
      if (typeof p?.source !== 'string') continue;
      const c = counts.get(p.source) ?? {};
      c[String(p.status)] = (c[String(p.status)] ?? 0) + 1;
      counts.set(p.source, c);
    }
  } else if (provRaw && typeof provRaw === 'object' && (provRaw as { sources?: unknown }).sources) {
    for (const [label, c] of Object.entries((provRaw as { sources: Record<string, Record<string, number>> }).sources)) counts.set(label, c);
  }
  // Some tools (web search, page reader) report a single source at the top level instead.
  const top = raw as { source?: unknown; status?: unknown } | null;
  if (typeof top?.source === 'string' && typeof top?.status === 'string' && !counts.has(top.source)) counts.set(top.source, { [top.status]: 1 });
  for (const [label, c] of counts) feeds.push({ label, status: rank.find((s) => c[s]) ?? Object.keys(c)[0] ?? 'UNKNOWN' });
  const seen = new Set<string>();
  const walk = (v: unknown, depth: number) => {
    if (links.length >= 8 || depth > 6 || !v || typeof v !== 'object') return;
    if (Array.isArray(v)) { for (const x of v.slice(0, 25)) walk(x, depth + 1); return; }
    const o = v as Record<string, unknown>;
    // CVE records often carry no link; their NVD page is the canonical one.
    const cve = [o.cveID, o.cve, o.id].find((x) => typeof x === 'string' && /^CVE-\d{4}-\d{4,}$/.test(x)) as string | undefined;
    const url = typeof o.url === 'string' ? o.url : typeof o.link === 'string' ? o.link : cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : null;
    if (url && /^https?:\/\//.test(url) && !seen.has(url) && !/[?&](api[_-]?key|key|token|apikey)=/i.test(url)) {
      const named = LINK_TEXT.map((k) => o[k]).find((x) => typeof x === 'string' && x.trim().length > 2) as string | undefined;
      const text = cve ? `${cve}${typeof o.vulnerabilityName === 'string' ? ` · ${o.vulnerabilityName}` : named && named !== cve ? ` · ${named}` : ''}` : named;
      if (text) { seen.add(url); links.push({ label: text.replace(/\s+/g, ' ').trim().slice(0, 140), url }); }
    }
    for (const [k, x] of Object.entries(o)) if (k !== 'provenance') walk(x, depth + 1);
  };
  // The whole result, minus provenance (its URLs are API endpoints, not something to read).
  walk(raw, 0);
  void tool;
  return { feeds, links };
}

/** Lenient JSON from a model reply: strips code fences and takes the outermost object. */
function parseJson(text: string): Record<string, unknown> | null {
  const t = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '');
  const a = t.indexOf('{');
  const b = t.lastIndexOf('}');
  if (a < 0 || b <= a) return null;
  try {
    return JSON.parse(t.slice(a, b + 1)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

const str = (v: unknown, max: number) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const strList = (v: unknown, n: number, max: number) => (Array.isArray(v) ? v.map((x) => str(x, max)).filter(Boolean).slice(0, n) : []);

function toBrief(answer: string, validN: Set<number>): Brief {
  const j = parseJson(answer);
  if (!j) {
    return { headline: '', bottomLine: answer.trim().slice(0, 1200) || 'No answer.', confidence: 0, confidenceWhy: 'The model did not return a structured brief.', findings: [], unknowns: [], changeMyMind: '', followUps: [], watch: null };
  }
  const findings: Finding[] = (Array.isArray(j.findings) ? j.findings : [])
    .map((f) => {
      const o = (f ?? {}) as Record<string, unknown>;
      const sources = (Array.isArray(o.sources) ? o.sources : []).map(Number).filter((n) => validN.has(n));
      return { text: str(o.text, 400), sources: [...new Set(sources)].slice(0, 6) };
    })
    .filter((f) => f.text)
    .slice(0, 8);
  const c = Number(j.confidence);
  return {
    headline: str(j.headline, 120),
    bottomLine: str(j.bottomLine, 900),
    confidence: Number.isFinite(c) ? Math.max(0, Math.min(100, Math.round(c))) : 0,
    confidenceWhy: str(j.confidenceWhy, 300),
    findings,
    unknowns: strList(j.unknowns, 4, 240),
    changeMyMind: str(j.changeMyMind, 300),
    followUps: strList(j.followUps, 3, 140),
    watch: str(j.watch, 200) || null,
  };
}

/** "oculon_url_check" -> "URL check" */
export function toolLabel(name: string): string {
  const s = name.replace(/^oculon_/, '').replace(/_/g, ' ');
  return s.replace(/\b(url|cve|cves|bgp|mcp|sdk|ip|faa|ais)\b/gi, (m) => m.toUpperCase()).replace(/^./, (c) => c.toUpperCase());
}

/** Evidence kept for cross-examination, by brief id, for two hours. */
const EVIDENCE = new Map<string, { at: number; question: string; brief: Brief; evidence: string; model: AnalystModel }>();
function remember(id: string, v: { question: string; brief: Brief; evidence: string; model: AnalystModel }) {
  const now = Date.now();
  for (const [k, e] of EVIDENCE) if (now - e.at > 2 * 3600_000 || EVIDENCE.size > 400) EVIDENCE.delete(k);
  EVIDENCE.set(id, { at: now, ...v });
}

export interface AnalystOptions {
  question: string;
  model: AnalystModel;
  /** Earlier turns: the question and the brief's bottom line, oldest first. */
  history?: { q: string; a: string }[];
  onEvent?: (e: AnalystEvent) => void;
}

export async function analyst(o: Oculon, opts: AnalystOptions): Promise<AnalystResult> {
  const t0 = Date.now();
  const model = ANALYST_MODELS[opts.model];
  const emit = (e: AnalystEvent) => { try { opts.onEvent?.(e); } catch {} };
  const sources: Source[] = [];
  const byKey = new Map<string, number>();
  const steps: AnalystResult['steps'] = [];
  const add = (key: string, s: Omit<Source, 'n'>): number => {
    const had = byKey.get(key);
    if (had) return had;
    const n = sources.length + 1;
    sources.push({ n, ...s });
    byKey.set(key, n);
    return n;
  };
  emit({ type: 'start', model: opts.model, label: model.label });
  const history: ChatMessage[] = (opts.history ?? []).slice(-4).flatMap((h) => [
    { role: 'user' as const, content: h.q.slice(0, 500) },
    { role: 'assistant' as const, content: `(earlier brief) ${h.a.slice(0, 700)}` },
  ]);
  const run = await runAgent(o, SYSTEM, opts.question, {
    route: model.id,
    premium: false,
    maxSteps: 6,
    maxTokens: 2200,
    history,
    onToolStart: ({ id, tool, args }) => emit({ type: 'step', id, tool, label: toolLabel(tool), args: scrubSecrets(JSON.stringify(args)).slice(0, 160) }),
    onToolResult: ({ id, tool, ok, ms, raw }) => {
      const { feeds, links } = ok ? collectSources(raw, tool) : { feeds: [], links: [] };
      const lines: string[] = [];
      const touched: Source[] = [];
      for (const f of feeds) {
        const n = add(`feed:${f.label}`, { kind: 'feed', label: f.label, status: f.status, tool });
        const s = sources[n - 1]!;
        if (s.status !== 'LIVE' && f.status === 'LIVE') s.status = 'LIVE';
        touched.push(s);
        lines.push(`[${n}] data feed: ${f.label} (${f.status})`);
      }
      for (const l of links) {
        let host = '';
        try { host = new URL(l.url).hostname.replace(/^www\./, ''); } catch {}
        const n = add(`link:${l.url}`, { kind: 'link', label: l.label, url: l.url, host, tool });
        touched.push(sources[n - 1]!);
        lines.push(`[${n}] ${l.label} (${host})`);
      }
      steps.push({ tool, label: toolLabel(tool), ok, ms });
      emit({ type: 'stepdone', id, tool, ok, ms, sources: touched.map((s) => ({ n: s.n, kind: s.kind, label: s.label, status: s.status ?? null, host: s.host ?? null })) });
      return lines.length ? `Numbered sources:\n${lines.join('\n')}` : undefined;
    },
  });
  const brief = toBrief(run.answer, new Set(sources.map((s) => s.n)));
  const id = randomBytes(9).toString('base64url');
  const evidence = run.messages.filter((m) => m.role === 'tool').map((m) => `### ${m.name}\n${m.content ?? ''}`).join('\n\n').slice(0, 60_000);
  remember(id, { question: opts.question, brief, evidence, model: opts.model });
  const result: AnalystResult = { id, question: opts.question, model: opts.model, brief, sources, steps, ms: Date.now() - t0 };
  emit({ type: 'brief', ...result });
  return result;
}

export interface Review {
  model: AnalystModel;
  label: string;
  findings: { i: number; verdict: 'supported' | 'partly' | 'unsupported'; note: string }[];
  bottomLine: 'agree' | 'partly' | 'disagree';
  missed: string | null;
  error?: string;
}

/** The other models re-read the same evidence and judge each finding. */
export async function crossExamine(id: string): Promise<{ id: string; reviews: Review[] }> {
  const e = EVIDENCE.get(id);
  if (!e) throw new Error('this brief has expired; ask again to cross-examine it');
  const reviewers = (Object.keys(ANALYST_MODELS) as AnalystModel[]).filter((m) => m !== e.model);
  const briefText = JSON.stringify({ question: e.question, bottomLine: e.brief.bottomLine, findings: e.brief.findings.map((f, i) => ({ i, text: f.text, sources: f.sources })) });
  const reviews = await Promise.all(
    reviewers.map(async (m): Promise<Review> => {
      const label = ANALYST_MODELS[m].label;
      try {
        const r = await chat(
          [
            { role: 'system', content: REVIEW_SYSTEM },
            { role: 'user', content: `EVIDENCE\n${e.evidence}\n\nBRIEF\n${briefText}` },
          ],
          { route: ANALYST_MODELS[m].id, maxTokens: 1200, temperature: 0 },
        );
        const j = parseJson(r.message.content ?? '');
        if (!j) throw new Error('the reviewer did not return a verdict');
        const verdicts = new Set(['supported', 'partly', 'unsupported']);
        const findings = (Array.isArray(j.findings) ? j.findings : [])
          .map((f) => f as Record<string, unknown>)
          .filter((f) => Number.isInteger(Number(f.i)) && verdicts.has(String(f.verdict)))
          .map((f) => ({ i: Number(f.i), verdict: String(f.verdict) as Review['findings'][number]['verdict'], note: str(f.note, 140) }));
        const bl = String(j.bottomLine);
        return { model: m, label, findings, bottomLine: bl === 'agree' || bl === 'disagree' ? bl : 'partly', missed: str(j.missed, 240) || null };
      } catch (err) {
        return { model: m, label, findings: [], bottomLine: 'partly', missed: null, error: scrubSecrets((err as Error).message).slice(0, 160) };
      }
    }),
  );
  return { id, reviews };
}
