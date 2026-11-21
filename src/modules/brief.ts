/**
 * Daily brief: the strongest signals of the last 24 hours plus watchlist changes, written up by a free-tier
 * LLM (or a plain template when none is configured). One brief per UTC day is stored; refresh to rewrite it.
 */
import type { Ctx } from '../core/context.js';
import { availableProviders, complete } from '../core/llm.js';
import type { Signal } from '../core/types.js';
import { catalysts } from './calendar.js';

export interface Brief {
  day: string;
  markdown: string;
  model: string | null;
  createdAt: string;
  signals: number;
}

function recentSignals(ctx: Ctx, hours = 24): Signal[] {
  const since = ctx.now().getTime() - hours * 3_600_000;
  return ctx.graph.recentSignals(500).filter((s) => Date.parse(s.createdAt) >= since);
}

/** Pick a balanced set: watchlist changes first, then the strongest per module so one source cannot fill the brief. */
export function pickSignals(all: Signal[], max = 18): Signal[] {
  const watch = all.filter((s) => s.module === 'meerkat').sort((a, b) => b.score - a.score).slice(0, 6);
  const rest = all.filter((s) => s.module !== 'meerkat').sort((a, b) => b.score - a.score);
  const perModule = new Map<string, number>();
  const picked: Signal[] = [...watch];
  const seen = new Set(watch.map((s) => s.title));
  for (const s of rest) {
    if (picked.length >= max) break;
    if (seen.has(s.title) || (perModule.get(s.module) ?? 0) >= 5) continue;
    perModule.set(s.module, (perModule.get(s.module) ?? 0) + 1);
    seen.add(s.title);
    picked.push(s);
  }
  return picked;
}

export function templateBrief(day: string, signals: Signal[]): string {
  if (!signals.length) return `# Oculon brief, ${day}\n\nNo signals in the last 24 hours. Run the radar or add watchlist items.`;
  const lines = [`# Oculon brief, ${day}`, ''];
  const watch = signals.filter((s) => s.module === 'meerkat');
  if (watch.length) lines.push('## Watchlist changes', ...watch.map((s) => `- ${s.title}`), '');
  lines.push('## Top signals', ...signals.filter((s) => s.module !== 'meerkat').map((s) => `- **${Math.round(s.score)}** ${s.title} _(${s.module})_${s.evidence[0]?.url ? ` [source](${s.evidence[0].url})` : ''}`));
  return lines.join('\n');
}

/**
 * Enforce the link rule in code, not just in the prompt: normalize odd bracket styles some models emit,
 * keep links whose URL appears in the input, and drop every other link (keeping its text).
 */
export function sanitizeLinks(markdown: string, allowed: Set<string>): string {
  const norm = (u: string) => u.replace(/[).,;]+$/, '');
  return markdown
    .replace(/【([^】]*)】\s*\((https?:\/\/[^)\s]+)\)/g, '[$1]($2)')
    // Bare bracketed URLs ("【https://…】") become source links; bracketed labels without a URL ("【goplus】") go.
    .replace(/【\s*(https?:\/\/[^】\s]+)\s*】/g, (_m, url: string) => `[source](${url})`)
    .replace(/【[^】]*】/g, '')
    .replace(/\[([^\]]*)\]\((https?:\/\/[^)\s]+)\)/g, (_m, text: string, url: string) => (allowed.has(norm(url)) ? `[${text.trim() || 'source'}](${norm(url)})` : text.trim() === 'source' ? '' : text))
    .replace(/(^|[\s(])(https?:\/\/[^\s)]+)/g, (m, pre: string, url: string) => (allowed.has(norm(url)) ? m : pre))
    // Scores copied from the input ("[55]") are noise for a reader.
    .replace(/\s\[\d{1,3}\](?!\()/g, '')
    .replace(/[ \t]+([.,;])/g, '$1')
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/[ \t]+$/gm, '');
}

export async function makeBrief(ctx: Ctx, opts: { refresh?: boolean; lang?: string; fetch?: typeof fetch } = {}): Promise<Brief> {
  const day = ctx.now().toISOString().slice(0, 10);
  if (!opts.refresh) {
    const row = ctx.store.db.prepare('SELECT * FROM briefs WHERE day = ?').get(day) as { day: string; markdown: string; model: string | null; created_at: number } | undefined;
    if (row) return { day: row.day, markdown: row.markdown, model: row.model, createdAt: new Date(row.created_at).toISOString(), signals: -1 };
  }
  const signals = pickSignals(recentSignals(ctx));
  const lang = opts.lang ?? process.env.OCULON_BRIEF_LANG ?? 'en';
  let markdown = templateBrief(day, signals);
  let model: string | null = null;
  if (signals.length && availableProviders().length) {
    const input = signals
      .map((s, i) => `${i + 1}. [${Math.round(s.score)}] (${s.module}) ${s.title}\n${s.evidence.slice(0, 4).map((e) => `   - ${e.source}: ${e.text.slice(0, 200)}${e.url ? ` <${e.url}>` : ''}`).join('\n')}`)
      .join('\n');
    try {
      const r = await complete(
        `You write a short morning intelligence brief from OSINT signals. Language: ${lang === 'en' ? 'English' : lang}.
Format: Markdown. Title "# Oculon brief, ${day}". Then "## Watchlist" (only if there are meerkat items), "## What matters today" (3-6 bullets, most important first, each one sentence with the key number and a source link from the input), and "## Also on the radar" (short bullets).
Rules:
- Use only facts in the input; keep numbers exact.
- Never state or imply a cause between two items unless the input says so (no "after", "because", "due to" linking separate signals).
- Links: only URLs that appear in the input, written as [source](url). If an item has no URL, give no link.
- No emoji. No hype words. Group items about the same event. Under 300 words. Finish every sentence.`,
        input,
        { maxTokens: 3000, premium: true, ...(opts.fetch ? { fetch: opts.fetch } : {}) },
      );
      if (r.text.length > 40) {
        const allowed = new Set(signals.flatMap((s) => s.evidence.map((e) => e.url).filter((u): u is string => Boolean(u))));
        markdown = `${sanitizeLinks(r.text, allowed)}\n\n_Written by ${r.provider} (${r.model}) from ${signals.length} Oculon signals. Check linked sources._`;
        model = `${r.provider}:${r.model}`;
      }
    } catch {
      // keep the template
    }
  }
  // Scheduled catalysts for today and tomorrow, straight from the calendar (no model involved).
  try {
    const cal = (await catalysts(ctx, 1)).result.items.filter((i) => i.kind !== 'market' || i.watched).slice(0, 8);
    if (cal.length) markdown += `\n\n## On the calendar\n${cal.map((i) => `- ${i.date} ${i.watched ? '(watched) ' : ''}${i.title}${i.detail ? `: ${i.detail}` : ''}`).join('\n')}`;
  } catch {}
  const createdAt = ctx.now().getTime();
  ctx.store.db
    .prepare('INSERT INTO briefs (day, markdown, model, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(day) DO UPDATE SET markdown = excluded.markdown, model = excluded.model, created_at = excluded.created_at')
    .run(day, markdown, model, createdAt);
  return { day, markdown, model, createdAt: new Date(createdAt).toISOString(), signals: signals.length };
}
