/**
 * Narrative Tracker: groups the day's headlines into storylines that persist across days ("Nvidia leadership
 * crisis", "Anthropic IPO"), tracks how many stories each narrative gets per day, and flags narratives that
 * are new and already busy, or growing fast. Assignment is done by an LLM; without one, nothing is grouped.
 */
import { DAY_MS, type Ctx } from '../core/context.js';
import { availableProviders, chat } from '../core/llm.js';
import { trend, type Phase } from '../core/stats.js';
import { keywords, overlap, signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { frontPage, hnItemUrl } from '../sources/hackernews.js';
import { guardianDay, nytTopStories } from '../sources/press.js';

export interface Narrative {
  id: number;
  name: string;
  createdAt: string;
  updatedAt: string;
  /** Stories per day for the last 7 days, oldest first. */
  daily: number[];
  total: number;
  phase: Phase;
  latest: { title: string; url: string; source: string; day: string }[];
}

interface Item {
  title: string;
  url: string;
  source: string;
}

const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export function listNarratives(ctx: Ctx, activeDays = 14): Narrative[] {
  const db = ctx.store.db;
  const nowMs = ctx.now().getTime();
  const since = nowMs - activeDays * DAY_MS;
  const rows = db.prepare('SELECT * FROM narratives WHERE updated_at >= ? ORDER BY updated_at DESC').all(since) as { id: number; name: string; created_at: number; updated_at: number }[];
  return rows
    .map((r) => {
      const counts = db.prepare('SELECT day, COUNT(*) AS n FROM narrative_items WHERE narrative_id = ? GROUP BY day').all(r.id) as { day: string; n: number }[];
      const byDay = new Map(counts.map((c) => [c.day, c.n]));
      const daily = Array.from({ length: 7 }, (_, i) => byDay.get(day(nowMs - (6 - i) * DAY_MS)) ?? 0);
      const latest = db.prepare('SELECT title, url, source, day FROM narrative_items WHERE narrative_id = ? ORDER BY added_at DESC LIMIT 6').all(r.id) as Narrative['latest'];
      return { id: r.id, name: r.name, createdAt: new Date(r.created_at).toISOString(), updatedAt: new Date(r.updated_at).toISOString(), daily, total: counts.reduce((a, c) => a + c.n, 0), phase: trend(daily).phase, latest };
    })
    .sort((a, b) => b.daily[6]! + b.daily[5]! - (a.daily[6]! + a.daily[5]!));
}

async function collectHeadlines(ctx: Ctx): Promise<{ items: Item[]; provenance: Provenance[] }> {
  const nowMs = ctx.now().getTime();
  const [g0, g1, nyt, hn] = await Promise.all([guardianDay(ctx, day(nowMs), 40), guardianDay(ctx, day(nowMs - DAY_MS), 40), nytTopStories(ctx), frontPage(ctx)]);
  const items: Item[] = [
    ...[...(g0.data ?? []), ...(g1.data ?? [])].map((n) => ({ title: n.title, url: n.url, source: 'guardian' })),
    ...(nyt.data ?? []).map((n) => ({ title: n.title, url: n.url, source: 'nyt' })),
    ...(hn.data ?? []).filter((s) => s.points >= 100).map((s) => ({ title: s.title, url: hnItemUrl(s.objectID), source: 'hackernews' })),
    ...ctx.graph
      .recentSignals(200)
      .filter((s) => s.module === 'owl' && nowMs - Date.parse(s.createdAt) < DAY_MS)
      .map((s) => ({ title: s.title, url: s.evidence[0]?.url ?? `oculon:${s.id}`, source: 'oculon' })),
  ];
  return { items, provenance: [g0.prov, g1.prov, nyt.prov, hn.prov] };
}

/** Assign new headlines to narratives (existing or new). Returns the narratives touched. */
export async function runNarratives(ctx: Ctx, opts: { fetch?: typeof fetch } = {}): Promise<ModuleResult<{ added: number; created: string[]; narratives: Narrative[] }>> {
  const nowMs = ctx.now().getTime();
  const nowIso = new Date(nowMs).toISOString();
  const db = ctx.store.db;
  const { items, provenance } = await collectHeadlines(ctx);
  const known = new Set((db.prepare('SELECT url FROM narrative_items').all() as { url: string }[]).map((r) => r.url));
  const fresh = items.filter((i) => !known.has(i.url)).slice(0, 120);
  if (!fresh.length || !availableProviders().length) {
    return { module: 'narratives', input: 'run', generatedAt: nowIso, result: { added: 0, created: [], narratives: listNarratives(ctx) }, signals: [], provenance: [...provenance, ...(availableProviders().length ? [] : [{ source: 'llm', url: '', status: 'UNAVAILABLE' as const, fetchedAt: nowIso, note: 'narratives need an LLM key' }])] };
  }
  const active = listNarratives(ctx).slice(0, 40);
  // Batches of 40 keep each JSON answer short enough to arrive complete.
  let assign: { item?: unknown; narrative?: unknown; new?: unknown }[] = [];
  for (let start = 0; start < fresh.length; start += 40) {
    const batch = fresh.slice(start, start + 40);
    const prompt = `Existing narratives:\n${active.map((n) => `#${n.id} ${n.name} (e.g. ${n.latest.slice(0, 2).map((l) => l.title).join(' / ')})`).join('\n') || '(none yet)'}\n\nNew headlines:\n${batch.map((f, i) => `${i}. ${f.title}`).join('\n')}`;
    try {
      const r = await chat(
        [
          {
            role: 'system',
            content:
              'You track news narratives: storylines that continue across days (a company crisis, an election, a conflict, a product launch). For each headline: give the id of the existing narrative it continues, or a short new narrative name (3-6 words) if it starts or belongs to a storyline with other headlines in this batch, or skip it if it is a one-off. Be strict: same storyline, not same broad topic. Reply JSON {"assign":[{"item":n,"narrative":id}|{"item":n,"new":"name"}]}.',
          },
          { role: 'user', content: prompt },
        ],
        { json: true, temperature: 0, maxTokens: 4000, ...(opts.fetch ? { fetch: opts.fetch } : {}) },
      );
      const part = (JSON.parse(r.message.content ?? '{}') as { assign?: typeof assign }).assign ?? [];
      assign.push(...part.map((a) => ({ ...a, item: Number(a.item) + start })));
    } catch (e) {
      // Skip this batch (its headlines are picked up next run), but say so instead of failing silently.
      provenance.push({ source: 'llm', url: '', status: 'ERROR', fetchedAt: nowIso, note: `narrative batch ${start / 40 + 1}: ${(e as Error).message.slice(0, 200)}` });
    }
  }

  // New narratives need at least two headlines in this batch: a single story is not yet a storyline.
  const newGroups = new Map<string, number[]>();
  for (const a of assign) if (typeof a.new === 'string' && a.new.trim()) newGroups.set(a.new.trim().slice(0, 60), [...(newGroups.get(a.new.trim().slice(0, 60)) ?? []), Number(a.item)]);
  const created: string[] = [];
  const newIds = new Map<string, number>();
  // Batches can name the same storyline twice ("APEC summit tensions" / "APEC summit leadership meeting");
  // fold a new name into an existing or just-created narrative when their key words overlap.
  const named: { name: string; id: number }[] = active.map((n) => ({ name: n.name, id: n.id }));
  const sameStory = (a: string, b: string) => {
    const ov = overlap(keywords(a), keywords(b));
    return ov.shared.length >= 2 || (ov.shared.length >= 1 && ov.score >= 0.5 && Math.min(keywords(a).size, keywords(b).size) <= 2);
  };
  for (const [name, idxs] of newGroups) {
    const twin = named.find((n) => sameStory(n.name, name));
    if (twin) {
      newIds.set(name, twin.id);
      continue;
    }
    if (idxs.filter((i) => fresh[i]).length < 2) continue;
    const id = Number(db.prepare('INSERT INTO narratives (name, created_at, updated_at) VALUES (?, ?, ?)').run(name, nowMs, nowMs).lastInsertRowid);
    newIds.set(name, id);
    named.push({ name, id });
    created.push(name);
  }
  const activeIds = new Set(active.map((n) => n.id));
  const ins = db.prepare('INSERT OR IGNORE INTO narrative_items (url, narrative_id, title, source, day, added_at) VALUES (?, ?, ?, ?, ?, ?)');
  const touch = db.prepare('UPDATE narratives SET updated_at = ? WHERE id = ?');
  let added = 0;
  for (const a of assign) {
    const it = fresh[Number(a.item)];
    if (!it) continue;
    const nid = typeof a.new === 'string' ? newIds.get(a.new.trim().slice(0, 60)) : activeIds.has(Number(a.narrative)) ? Number(a.narrative) : undefined;
    if (!nid) continue;
    added += Number(ins.run(it.url, nid, it.title, it.source, day(nowMs), nowMs).changes);
    touch.run(nowMs, nid);
  }

  const narratives = listNarratives(ctx);
  const signals: Signal[] = [];
  for (const n of narratives) {
    const today = n.daily[6]!;
    const before = n.daily.slice(0, 6);
    const avg = before.reduce((x, y) => x + y, 0) / 6;
    const isNew = nowMs - Date.parse(n.createdAt) < DAY_MS;
    if ((isNew && today >= 4) || (!isNew && today >= 4 && today >= 2 * Math.max(1, avg))) {
      signals.push({
        id: signalId('narrative', String(n.id), day(nowMs)),
        module: 'narrative',
        title: `${isNew ? 'New narrative' : 'Narrative growing'}: ${n.name} (${today} stories today)`,
        score: Math.min(85, 50 + today * 3),
        evidence: n.latest.slice(0, 4).map((l) => ({ source: l.source, text: l.title, url: l.url.startsWith('http') ? l.url : undefined })).map((e) => (e.url ? e : { source: e.source, text: e.text })),
        createdAt: nowIso,
      });
    }
  }
  signals.forEach((s) => ctx.graph.saveSignal(s));
  return { module: 'narratives', input: 'run', generatedAt: nowIso, result: { added, created, narratives }, signals, provenance };
}
