/**
 * Case Files: long-running investigations. A question becomes a case; an agent runs a deeper tool loop,
 * then writes a structured case file (answer, findings with confidence, timeline, entities, open questions).
 * Citations are checked in code: a finding may only cite URLs that appeared in tool results.
 * Watched cases are re-investigated on a schedule and only NEW findings are raised as signals.
 */
import { runAgent, type AskStep } from './agent.js';
import type { EntityKind } from './core/graph.js';
import { chat } from './core/llm.js';
import { keywords, overlap, signalId } from './core/text.js';
import type { Signal } from './core/types.js';
import type { Oculon } from './index.js';

export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  claim: string;
  confidence: Confidence;
  sources: string[];
}

export interface CaseReport {
  answer: string;
  confidence: Confidence;
  summary: string;
  findings: Finding[];
  timeline: { date: string; event: string; source?: string }[];
  entities: { name: string; kind: string }[];
  openQuestions: string[];
  steps: AskStep[];
  providers: string[];
}

export interface CaseFile {
  id: number;
  question: string;
  createdAt: string;
  updatedAt: string;
  runs: number;
  watch: boolean;
  report: CaseReport | null;
  markdown: string | null;
}

interface Row {
  id: number;
  question: string;
  created_at: number;
  updated_at: number;
  runs: number;
  watch: number;
  report: string | null;
  markdown: string | null;
}

const toCase = (r: Row): CaseFile => ({
  id: r.id,
  question: r.question,
  createdAt: new Date(r.created_at).toISOString(),
  updatedAt: new Date(r.updated_at).toISOString(),
  runs: r.runs,
  watch: r.watch === 1,
  report: r.report ? (JSON.parse(r.report) as CaseReport) : null,
  markdown: r.markdown,
});

const INVESTIGATOR = `You are Oculon running an OSINT investigation for a case file.
Method:
- Break the question into what must be checked. Use up to 8 tool calls; run independent calls in parallel.
- Cross-check: prefer facts confirmed by two independent sources. Actively look for evidence AGAINST the obvious answer.
- Read primary sources when a search result is ambiguous (oculon_read_page).
- Tool results carry provenance; ERROR/UNAVAILABLE sources returned nothing and are not evidence.
- Use only facts from tool results. Never invent names, numbers, dates or URLs.
When done, reply with a short plain summary of what you found.`;

const EXTRACT = `Turn the investigation above into a case file. Respond with JSON only:
{"answer": "one or two sentences directly answering the question, or saying it cannot be answered yet",
 "confidence": "high|medium|low",
 "summary": "3-5 sentences",
 "findings": [{"claim": "one concrete fact", "confidence": "high|medium|low", "sources": ["URLs from the tool results"]}],
 "timeline": [{"date": "YYYY-MM-DD", "event": "what happened", "source": "URL from tool results"}],
 "entities": [{"name": "...", "kind": "company|person|domain|token|wallet|aircraft|vessel|place|topic"}],
 "open_questions": ["what is still unknown"]}
Rules: 3-10 findings; only URLs that appeared in tool results; "high" only when two independent sources agree; no emoji.`;

const CONF: Confidence[] = ['high', 'medium', 'low'];
const asConf = (v: unknown): Confidence => (CONF.includes(v as Confidence) ? (v as Confidence) : 'low');
const str = (v: unknown, max = 500) => String(v ?? '').trim().slice(0, max);

/** Validate model output: keep only cited URLs that tools really returned; unsourced findings drop to low. */
export function normalizeReport(raw: Record<string, unknown>, allowed: Set<string>): Omit<CaseReport, 'steps' | 'providers'> {
  const ok = (u: unknown) => {
    const s = str(u, 600).replace(/[).,;]+$/, '');
    return allowed.has(s) ? s : null;
  };
  const findings = (Array.isArray(raw.findings) ? raw.findings : [])
    .slice(0, 12)
    .map((f: Record<string, unknown>) => {
      const sources = (Array.isArray(f.sources) ? f.sources : []).map(ok).filter((x): x is string => Boolean(x));
      const conf = asConf(f.confidence);
      return { claim: str(f.claim, 400), confidence: sources.length ? (conf === 'high' && sources.length < 2 ? 'medium' : conf) : 'low', sources } as Finding;
    })
    .filter((f) => f.claim);
  return {
    answer: str(raw.answer, 600) || 'No answer yet.',
    confidence: asConf(raw.confidence),
    summary: str(raw.summary, 1500),
    findings,
    timeline: (Array.isArray(raw.timeline) ? raw.timeline : [])
      .slice(0, 20)
      .map((t: Record<string, unknown>) => {
        const src = ok(t.source);
        return { date: str(t.date, 10), event: str(t.event, 300), ...(src ? { source: src } : {}) };
      })
      .filter((t) => /^\d{4}-\d{2}-\d{2}$/.test(t.date) && t.event)
      .sort((a, b) => a.date.localeCompare(b.date)),
    entities: (Array.isArray(raw.entities) ? raw.entities : []).slice(0, 20).map((e: Record<string, unknown>) => ({ name: str(e.name, 120), kind: str(e.kind, 20) || 'topic' })).filter((e) => e.name),
    openQuestions: (Array.isArray(raw.open_questions) ? raw.open_questions : []).slice(0, 8).map((q) => str(q, 300)).filter(Boolean),
  };
}

export function renderCase(c: { id: number; question: string; updatedAt: string; runs: number }, r: CaseReport): string {
  const host = (u: string) => {
    try {
      return new URL(u).hostname.replace(/^www\./, '');
    } catch {
      return 'source';
    }
  };
  const lines = [
    `# Case #${c.id}: ${c.question}`,
    '',
    `**Answer** (${r.confidence} confidence): ${r.answer}`,
    '',
    r.summary,
    '',
    '## Findings',
    ...r.findings.map((f) => `- [${f.confidence}] ${f.claim}${f.sources.length ? ` ${f.sources.map((u) => `[${host(u)}](${u})`).join(' ')}` : ' (unsourced)'}`),
  ];
  if (r.timeline.length) lines.push('', '## Timeline', ...r.timeline.map((t) => `- ${t.date}: ${t.event}${t.source ? ` [${host(t.source)}](${t.source})` : ''}`));
  if (r.entities.length) lines.push('', '## Entities', r.entities.map((e) => `${e.name} (${e.kind})`).join(', '));
  if (r.openQuestions.length) lines.push('', '## Open questions', ...r.openQuestions.map((q) => `- ${q}`));
  lines.push('', `_Run ${c.runs}, updated ${c.updatedAt.slice(0, 16).replace('T', ' ')} UTC. ${r.steps.length} tool calls via ${[...new Set(r.providers)].join(', ')}. AI-written from tool results; check the sources._`);
  return lines.join('\n');
}

const KIND_MAP: Record<string, EntityKind> = { company: 'company', person: 'topic', domain: 'domain', token: 'event', wallet: 'event', aircraft: 'aircraft', vessel: 'event', place: 'topic', topic: 'topic' };

export function getCase(o: Oculon, id: number): CaseFile | null {
  const r = o.ctx.store.db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as Row | undefined;
  return r ? toCase(r) : null;
}

export function listCases(o: Oculon): CaseFile[] {
  return (o.ctx.store.db.prepare('SELECT * FROM cases ORDER BY updated_at DESC').all() as unknown as Row[]).map(toCase);
}

export function setCaseWatch(o: Oculon, id: number, on: boolean): boolean {
  return o.ctx.store.db.prepare('UPDATE cases SET watch = ? WHERE id = ?').run(on ? 1 : 0, id).changes > 0;
}

/** Findings in `now` that no finding in `before` already states (keyword overlap below 0.6). */
export function newFindings(before: Finding[], now: Finding[]): Finding[] {
  return now.filter((f) => !before.some((b) => overlap(keywords(b.claim), keywords(f.claim)).score >= 0.6));
}

/** Open a case (question) or re-run an existing one (id). */
export async function investigate(o: Oculon, input: { question?: string; id?: number }, opts: { onStep?: (s: string) => void; fetch?: typeof fetch } = {}): Promise<{ case: CaseFile; added: Finding[]; signals: Signal[] }> {
  const db = o.ctx.store.db;
  const now = o.ctx.now().getTime();
  let existing = input.id ? getCase(o, input.id) : null;
  if (input.id && !existing) throw new Error(`no case #${input.id}`);
  const question = existing?.question ?? str(input.question, 500);
  if (!question) throw new Error('missing question');
  if (!existing) {
    const id = Number(db.prepare('INSERT INTO cases (question, created_at, updated_at) VALUES (?, ?, ?)').run(question, now, now).lastInsertRowid);
    existing = getCase(o, id)!;
  }

  const prior = existing.report ? `\nEarlier findings on this case (verify, update or contradict them):\n${existing.report.findings.map((f) => `- ${f.claim}`).join('\n')}` : '';
  const run = await runAgent(o, INVESTIGATOR, `Case question: ${question}${prior}`, { maxSteps: 10, maxTokens: 2500, premium: 'deep', ...opts });
  const ex = await chat([...run.messages, { role: 'assistant', content: run.answer }, { role: 'user', content: EXTRACT }], { json: true, temperature: 0, maxTokens: 3500, premium: 'deep', ...(opts.fetch ? { fetch: opts.fetch } : {}) });
  let raw: Record<string, unknown> = {};
  try {
    raw = JSON.parse((ex.message.content ?? '{}').replace(/^```(?:json)?|```$/g, '').trim()) as Record<string, unknown>;
  } catch {
    raw = { answer: run.answer, confidence: 'low', summary: run.answer, findings: [] };
  }
  const report: CaseReport = { ...normalizeReport(raw, run.urls), steps: run.steps, providers: [...run.providers, ex.provider] };
  const runs = existing.runs + 1;
  const updatedAt = new Date(o.ctx.now().getTime()).toISOString();
  const markdown = renderCase({ id: existing.id, question, updatedAt, runs }, report);
  db.prepare('UPDATE cases SET report = ?, markdown = ?, runs = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(report), markdown, runs, Date.parse(updatedAt), existing.id);

  // Graph: the case links to every entity it names.
  const caseId = o.ctx.graph.upsert('event', `case #${existing.id}: ${question.slice(0, 80)}`);
  for (const e of report.entities) o.ctx.graph.link(caseId, o.ctx.graph.upsert(KIND_MAP[e.kind] ?? 'topic', e.name), 'investigates', 'case');

  const added = existing.report ? newFindings(existing.report.findings, report.findings).filter((f) => f.confidence !== 'low') : [];
  const signals: Signal[] = added.map((f) => ({
    id: signalId('case', String(existing!.id), f.claim),
    module: 'case',
    title: `Case #${existing!.id} new finding: ${f.claim.slice(0, 140)}`,
    score: f.confidence === 'high' ? 75 : 60,
    evidence: f.sources.map((u) => ({ source: 'case', text: f.claim, url: u })),
    createdAt: updatedAt,
  }));
  signals.forEach((s) => o.ctx.graph.saveSignal(s));
  return { case: getCase(o, existing.id)!, added, signals };
}
