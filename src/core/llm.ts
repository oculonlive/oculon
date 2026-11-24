/**
 * LLM layer over free-tier, OpenAI-compatible chat APIs with automatic fallback:
 * Groq -> Gemini -> Mistral -> OpenRouter (free models). Only providers with a key are tried.
 * Calls are not cached and go straight to fetch (they are POSTs with large bodies).
 */
import { key, scrubSecrets } from './keys.js';

export interface ToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
  name?: string;
}

export interface ToolSpec {
  type: 'function';
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

export interface ChatResult {
  message: ChatMessage;
  provider: string;
  model: string;
}

interface Provider {
  name: string;
  env: string;
  url: string;
  model: string;
  extraHeaders?: Record<string, string>;
  /** Extra tokens for models that think before answering, so the answer is not cut off. */
  reasoningHeadroom?: number;
}

export const PROVIDERS: Provider[] = [
  { name: 'groq', env: 'GROQ_API_KEY', url: 'https://api.groq.com/openai/v1/chat/completions', model: process.env.OCULON_GROQ_MODEL || 'openai/gpt-oss-120b' },
  { name: 'gemini', env: 'GEMINI_API_KEY', url: 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', model: process.env.OCULON_GEMINI_MODEL || 'gemini-2.5-flash' },
  { name: 'mistral', env: 'MISTRAL_API_KEY', url: 'https://api.mistral.ai/v1/chat/completions', model: process.env.OCULON_MISTRAL_MODEL || 'mistral-medium-latest' },
  // NVIDIA NIM (free developer credits). Its models reason before answering, which counts toward max_tokens.
  { name: 'nvidia', env: 'NVIDIA_API_KEY', url: 'https://integrate.api.nvidia.com/v1/chat/completions', model: process.env.OCULON_NVIDIA_MODEL || 'nvidia/nemotron-3-ultra-550b-a55b', reasoningHeadroom: 4000 },
  {
    name: 'openrouter',
    env: 'OPENROUTER_API_KEY',
    url: 'https://openrouter.ai/api/v1/chat/completions',
    model: process.env.OCULON_OPENROUTER_MODEL || 'nvidia/nemotron-3.5-super-vl:free',
    extraHeaders: { 'x-title': 'Oculon' },
  },
];

export const availableProviders = () => [...(key('ANTHROPIC_API_KEY') ? [{ name: 'anthropic' }] : []), ...PROVIDERS.filter((p) => key(p.env))];

export interface ChatOptions {
  tools?: ToolSpec[];
  temperature?: number;
  maxTokens?: number;
  json?: boolean;
  fetch?: typeof fetch;
  timeoutMs?: number;
  /**
   * Use the paid Claude model first when ANTHROPIC_API_KEY is set. Off by default so that high-volume
   * background work (radar linking, market matching, narratives) stays on free tiers.
   * 'deep' picks the most capable model, for case investigations.
   */
  premium?: boolean | 'deep';
  /** Call exactly this OpenRouter model (e.g. "anthropic/claude-opus-5.5"), with no fallback to other providers. */
  route?: string;
}

/** Daily budget hook for the paid provider; the SDK registers one backed by the quota table. */
let paidQuota: (source: string) => boolean = () => true;
export function setPaidQuota(fn: (source: string) => boolean): void {
  paidQuota = fn;
}

export const CLAUDE_MODEL = () => process.env.OCULON_CLAUDE_MODEL || 'claude-opus-5-5';
export const CLAUDE_DEEP_MODEL = () => process.env.OCULON_CLAUDE_DEEP_MODEL || 'claude-fable-5-2';

type Block =
  | { type: 'text'; text: string }
  | { type: 'tool_use'; id: string; name: string; input: unknown }
  | { type: 'tool_result'; tool_use_id: string; content: string }
  | { type: 'thinking' | 'redacted_thinking'; [k: string]: unknown };

/** Raw Claude content kept on assistant messages so thinking blocks can be passed back unchanged. */
const RAW = new WeakMap<ChatMessage, Block[]>();

/** OpenAI-style history to the Messages API shape: system lifted out, tool calls and results as blocks. */
export function toAnthropic(messages: ChatMessage[]): { system: string; messages: { role: 'user' | 'assistant'; content: Block[] }[] } {
  const system = messages.filter((m) => m.role === 'system').map((m) => m.content ?? '').join('\n\n');
  const out: { role: 'user' | 'assistant'; content: Block[] }[] = [];
  const push = (role: 'user' | 'assistant', blocks: Block[]) => {
    if (!blocks.length) return;
    const last = out[out.length - 1];
    if (last && last.role === role) last.content.push(...blocks);
    else out.push({ role, content: blocks });
  };
  for (const m of messages) {
    if (m.role === 'system') continue;
    if (m.role === 'tool') push('user', [{ type: 'tool_result', tool_use_id: m.tool_call_id ?? '', content: m.content ?? '' }]);
    else if (m.role === 'user') push('user', [{ type: 'text', text: m.content || ' ' }]);
    else {
      const raw = RAW.get(m);
      if (raw) push('assistant', raw);
      else {
        const blocks: Block[] = m.content ? [{ type: 'text', text: m.content }] : [];
        for (const c of m.tool_calls ?? []) {
          let input: unknown = {};
          try {
            input = JSON.parse(c.function.arguments || '{}');
          } catch {}
          blocks.push({ type: 'tool_use', id: c.id, name: c.function.name, input });
        }
        push('assistant', blocks.length ? blocks : [{ type: 'text', text: ' ' }]);
      }
    }
  }
  return { system, messages: out };
}

async function callClaude(messages: ChatMessage[], opts: ChatOptions, doFetch: typeof fetch): Promise<ChatResult> {
  const model = opts.premium === 'deep' ? CLAUDE_DEEP_MODEL() : CLAUDE_MODEL();
  const { system, messages: msgs } = toAnthropic(messages);
  const res = await doFetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': key('ANTHROPIC_API_KEY')!,
      'anthropic-version': '2023-06-01',
      // drop_block: Oculon trims old tool output between rounds; affected thinking blocks are dropped instead of a 400.
      // server-side fallback: a safety decline is retried on a fallback model inside the same call.
      'anthropic-beta': 'thinking-binding-controls-2026-08-01,server-side-fallback-2026-07-01',
    },
    body: JSON.stringify({
      model,
      // Thinking counts toward max_tokens on these models, so leave room above the answer size callers ask for.
      max_tokens: Math.max(16_000, (opts.maxTokens ?? 1500) * 4),
      thinking: { type: 'adaptive', block_binding: { prefix_mismatch_behavior: 'drop_block' } },
      output_config: { effort: opts.premium === 'deep' ? 'high' : 'medium' },
      fallbacks: 'default',
      system: opts.json ? `${system}\n\nReply with a single JSON object and nothing else.` : system,
      messages: msgs,
      ...(opts.tools?.length ? { tools: opts.tools.map((t) => ({ name: t.function.name, description: t.function.description, input_schema: t.function.parameters })) } : {}),
    }),
    signal: AbortSignal.timeout(opts.timeoutMs ?? (opts.premium === 'deep' ? 300_000 : 180_000)),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status} ${scrubSecrets(text).replace(/\s+/g, ' ').slice(0, 160)}`);
  const j = JSON.parse(text) as { content?: Block[]; stop_reason?: string; model?: string };
  if (j.stop_reason === 'refusal') throw new Error('declined by safety classifier');
  const content = (j.content ?? []).filter((b) => (b.type as string) !== 'fallback');
  let answer = content.filter((b): b is { type: 'text'; text: string } => b.type === 'text').map((b) => b.text).join('').trim();
  if (opts.json) answer = answer.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  const calls: ToolCall[] = content.filter((b): b is { type: 'tool_use'; id: string; name: string; input: unknown } => b.type === 'tool_use').map((b) => ({ id: b.id, type: 'function', function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) } }));
  const message: ChatMessage = { role: 'assistant', content: answer || null, ...(calls.length ? { tool_calls: calls } : {}) };
  RAW.set(message, content);
  return { message, provider: 'anthropic', model: j.model ?? model };
}

/** Remember the raw Claude blocks when a caller copies an assistant message into its own history. */
export function carryRaw(from: ChatMessage, to: ChatMessage): ChatMessage {
  const raw = RAW.get(from);
  if (raw) RAW.set(to, raw);
  return to;
}

/** One chat completion; falls through providers on errors and rate limits. */
export async function chat(messages: ChatMessage[], opts: ChatOptions = {}): Promise<ChatResult> {
  const doFetch = opts.fetch ?? fetch;
  if (opts.route) {
    const or = PROVIDERS.find((p) => p.name === 'openrouter')!;
    if (!key(or.env)) throw new Error('OPENROUTER_API_KEY is not set');
    return callProvider({ ...or, model: opts.route, reasoningHeadroom: 6000 }, messages, opts, doFetch, opts.timeoutMs ?? 180_000);
  }
  const providers = PROVIDERS.filter((p) => key(p.env));
  const errors: string[] = [];
  if (opts.premium && key('ANTHROPIC_API_KEY')) {
    if (!paidQuota('anthropic')) errors.push('anthropic: daily budget spent (OCULON_QUOTA_ANTHROPIC)');
    else {
      try {
        return await callClaude(messages, opts, doFetch);
      } catch (e) {
        errors.push(`anthropic: ${(e as Error).name === 'TimeoutError' ? 'timeout' : scrubSecrets((e as Error).message)}`);
      }
    }
  }
  if (!providers.length && !errors.length) throw new Error('no LLM key configured (set ANTHROPIC_API_KEY, GROQ_API_KEY, GEMINI_API_KEY, MISTRAL_API_KEY, NVIDIA_API_KEY or OPENROUTER_API_KEY)');
  for (const p of providers) {
    try {
      const res = await doFetch(p.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${key(p.env)}`, ...p.extraHeaders },
        body: JSON.stringify({
          model: p.model,
          messages,
          temperature: opts.temperature ?? 0.2,
          max_tokens: (opts.maxTokens ?? 1500) + (p.reasoningHeadroom ?? 0),
          ...(opts.tools?.length ? { tools: opts.tools, tool_choice: 'auto' } : {}),
          ...(opts.json ? { response_format: { type: 'json_object' } } : {}),
        }),
        signal: AbortSignal.timeout(opts.timeoutMs ?? 60_000),
      });
      const text = await res.text();
      if (!res.ok) {
        errors.push(`${p.name}: HTTP ${res.status} ${scrubSecrets(text).replace(/\s+/g, ' ').slice(0, 120)}`);
        continue;
      }
      const j = JSON.parse(text) as { choices?: { message?: ChatMessage }[] };
      const message = j.choices?.[0]?.message;
      // An empty answer (e.g. all tokens spent reasoning) falls through to the next provider.
      if (!message || (!message.content?.trim() && !message.tool_calls?.length)) {
        errors.push(`${p.name}: empty response`);
        continue;
      }
      return { message: { role: 'assistant', content: message.content ?? null, ...(message.tool_calls?.length ? { tool_calls: message.tool_calls } : {}) }, provider: p.name, model: p.model };
    } catch (e) {
      errors.push(`${p.name}: ${(e as Error).name === 'TimeoutError' ? 'timeout' : scrubSecrets((e as Error).message)}`);
    }
  }
  throw new Error(`all LLM providers failed: ${errors.join(' | ')}`);
}

/** One OpenAI-compatible call to a single provider; throws on any failure. */
async function callProvider(p: Provider, messages: ChatMessage[], opts: ChatOptions, doFetch: typeof fetch, timeoutMs: number): Promise<ChatResult> {
  const res = await doFetch(p.url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${key(p.env)}`, ...p.extraHeaders },
    body: JSON.stringify({
      model: p.model,
      messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens: (opts.maxTokens ?? 1500) + (p.reasoningHeadroom ?? 0),
      ...(opts.tools?.length ? { tools: opts.tools, tool_choice: 'auto' } : {}),
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${p.model}: HTTP ${res.status} ${scrubSecrets(text).replace(/\s+/g, ' ').slice(0, 160)}`);
  const j = JSON.parse(text) as { choices?: { message?: ChatMessage }[]; model?: string };
  const message = j.choices?.[0]?.message;
  if (!message || (!message.content?.trim() && !message.tool_calls?.length)) throw new Error(`${p.model}: empty response`);
  return { message: { role: 'assistant', content: message.content ?? null, ...(message.tool_calls?.length ? { tool_calls: message.tool_calls } : {}) }, provider: p.name, model: j.model ?? p.model };
}

/** Plain-text completion helper. */
export async function complete(system: string, user: string, opts: ChatOptions = {}): Promise<{ text: string; provider: string; model: string }> {
  const r = await chat(
    [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    opts,
  );
  return { text: (r.message.content ?? '').trim(), provider: r.provider, model: r.model };
}
