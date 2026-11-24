/**
 * Octopus: a tool-using agent over Oculon. It reads the question, calls Oculon tools through the
 * LLM's function calling (free-tier providers with fallback), and answers with sources.
 * Read-only by design: tools that write forecasts or stamp proofs are not exposed to it.
 */
import { carryRaw, chat, type ChatMessage, type ToolSpec } from './core/llm.js';
import { scrubSecrets } from './core/keys.js';
import type { Oculon } from './index.js';
import { activeTools, TOOLS } from './mcp.js';

/** Tools the agent may call. Side-effecting tools and the agent itself are excluded. */
const EXCLUDED = new Set(['oculon_ask', 'oculon_forecast', 'oculon_auto_forecast', 'oculon_stamp_proofs', 'oculon_resolve_forecasts', 'oculon_satellite_image', 'oculon_watch_add', 'oculon_watch_run', 'oculon_brief', 'oculon_case_new', 'oculon_fence_add', 'oculon_fence_check']);
export const AGENT_TOOLS = TOOLS.filter((t) => !EXCLUDED.has(t.name));
/** Agent tools for this build (on-chain tools only when OCULON_ONCHAIN=1). */
const agentTools = () => activeTools().filter((t) => !EXCLUDED.has(t.name));

export interface AskStep {
  tool: string;
  args: Record<string, unknown>;
  ok: boolean;
  ms: number;
  chars: number;
}

export interface AskResult {
  question: string;
  answer: string;
  steps: AskStep[];
  providers: string[];
}

const SYSTEM = `You are Oculon, an OSINT analyst. Answer the user's question using the tools; do not answer from memory when a tool can check it.
Rules:
- Prefer 1-4 well-chosen tool calls. Call independent tools in parallel when useful.
- Every tool result carries provenance. Sources marked ERROR or UNAVAILABLE returned nothing; never present them as findings.
- Use only facts from tool results. If the data does not answer the question, say what is missing.
- Lead with the biggest concrete events (leadership changes, lawsuits, deals, launches, outages, price moves) found in headlines, timelines and signals, before softer indicators like page views.
- Cite sources inline by name (e.g. "per Finnhub", "Guardian, 18 Nov") and include the most useful URLs.
- Be concrete: numbers, dates, names. Keep the answer under about 250 words unless the question needs more.
- Reply in the same language as the question.`;

/**
 * Shrink a tool result evenly instead of cutting it off at the end: every array keeps its first items and
 * every long string is shortened, so late sections (timelines, headlines) still reach the model.
 */
export function condense(v: unknown, arrayMax = 10, strMax = 240, depth = 0): unknown {
  if (typeof v === 'string') return v.length > strMax ? `${v.slice(0, strMax)}…` : v;
  if (Array.isArray(v)) {
    const kept = v.slice(0, arrayMax).map((x) => condense(x, arrayMax, strMax, depth + 1));
    return v.length > arrayMax ? [...kept, `…${v.length - arrayMax} more`] : kept;
  }
  if (v && typeof v === 'object') {
    if (depth > 6) return '…';
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== null && x !== undefined).map(([k, x]) => [k, condense(x, arrayMax, strMax, depth + 1)]));
  }
  return v;
}

/** Tool output for the model: condensed JSON with a hard cap as a last resort. */
export function forModel(out: unknown, max = 14_000): string {
  let s = scrubSecrets(JSON.stringify(condense(out)));
  if (s.length > max) s = scrubSecrets(JSON.stringify(condense(out, 5, 160)));
  return s.length > max ? `${s.slice(0, max)}…[truncated]` : s;
}

export interface AgentRun {
  answer: string;
  steps: AskStep[];
  providers: string[];
  messages: ChatMessage[];
  /** Every http(s) URL that appeared in tool results: the only links an answer may cite. */
  urls: Set<string>;
}

export interface AgentOptions {
  maxSteps?: number;
  onStep?: (s: string) => void;
  fetch?: typeof fetch;
  maxTokens?: number;
  /** Paid Claude first when configured; 'deep' for the most capable model. */
  premium?: boolean | 'deep';
  /** Use exactly this OpenRouter model for every round. */
  route?: string;
  /** Called before a tool runs. */
  onToolStart?: (call: { id: string; tool: string; args: Record<string, unknown> }) => void;
  /** Called with the raw result; text it returns is appended to what the model sees (e.g. numbered sources). */
  onToolResult?: (call: { id: string; tool: string; args: Record<string, unknown>; ok: boolean; ms: number; raw: unknown }) => string | void;
  /** Earlier turns of a conversation, placed before the new question. */
  history?: ChatMessage[];
}

/** The tool loop shared by `ask` and case investigations. */
export async function runAgent(o: Oculon, system: string, user: string, opts: AgentOptions = {}): Promise<AgentRun> {
  const tools: ToolSpec[] = agentTools().map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.inputSchema } }));
  const messages: ChatMessage[] = [
    { role: 'system', content: `${system}\nToday is ${o.ctx.now().toISOString().slice(0, 10)}.` },
    ...(opts.history ?? []),
    { role: 'user', content: user },
  ];
  const steps: AskStep[] = [];
  const providers: string[] = [];
  const urls = new Set<string>();
  const maxSteps = opts.maxSteps ?? 6;

  for (let round = 0; round < maxSteps; round++) {
    // On the last round, withhold tools so the model must answer.
    const r = await chat(messages, { tools: round < maxSteps - 1 ? tools : [], maxTokens: opts.maxTokens ?? 1800, premium: opts.premium ?? true, ...(opts.route ? { route: opts.route } : {}), ...(opts.fetch ? { fetch: opts.fetch } : {}) });
    providers.push(r.provider);
    const calls = r.message.tool_calls ?? [];
    if (!calls.length) {
      return { answer: (r.message.content ?? '').trim() || '(no answer)', steps, providers, messages, urls };
    }
    messages.push(carryRaw(r.message, { role: 'assistant', content: r.message.content ?? '', tool_calls: calls }));
    const results = await Promise.all(
      calls.map(async (c) => {
        const tool = agentTools().find((t) => t.name === c.function.name);
        let args: Record<string, unknown> = {};
        try {
          args = JSON.parse(c.function.arguments || '{}') as Record<string, unknown>;
        } catch {}
        const t0 = Date.now();
        opts.onStep?.(`${c.function.name}(${JSON.stringify(args)})`);
        opts.onToolStart?.({ id: c.id, tool: c.function.name, args });
        let content: string;
        let ok = true;
        let raw: unknown = null;
        if (!tool) {
          content = `error: unknown tool ${c.function.name}`;
          ok = false;
        } else {
          try {
            raw = await tool.run(o, args);
            content = forModel(raw);
          } catch (e) {
            content = `error: ${scrubSecrets((e as Error).message)}`;
            ok = false;
          }
        }
        const extra = opts.onToolResult?.({ id: c.id, tool: c.function.name, args, ok, ms: Date.now() - t0, raw });
        if (extra) content += `\n${extra}`;
        steps.push({ tool: c.function.name, args, ok, ms: Date.now() - t0, chars: content.length });
        for (const u of content.match(/https?:\/\/[^\s"'<>\\]+/g) ?? []) urls.add(u.replace(/[).,;]+$/, ''));
        return { role: 'tool' as const, tool_call_id: c.id, name: c.function.name, content };
      }),
    );
    messages.push(...results);
  }
  return { answer: '(stopped: step limit reached)', steps, providers, messages, urls };
}

export async function ask(o: Oculon, question: string, opts: AgentOptions = {}): Promise<AskResult> {
  const r = await runAgent(o, SYSTEM, question, opts);
  return { question, answer: r.answer, steps: r.steps, providers: r.providers };
}
