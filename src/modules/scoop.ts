/**
 * First to Know: for each strong signal, find when major media first covered the same subject and record
 * the lead time. Positive = Oculon saw it first; negative = media was first (recorded just the same).
 * Media: The Guardian and the New York Times (quota-friendly), GNews as a third check.
 */
import type { Ctx } from '../core/context.js';
import { keywords } from '../core/text.js';
import type { Signal } from '../core/types.js';
import { gnews, guardian, nytSearch } from '../sources/press.js';
import { mentions } from './hound.js';

export interface Scoop {
  signalId: string;
  subject: string;
  oculonAt: string;
  mediaAt: string | null;
  mediaSource: string | null;
  mediaUrl: string | null;
  /** Hours from Oculon's signal to the first media story; null while uncovered. */
  leadHours: number | null;
}

export interface Scoreboard {
  checked: number;
  covered: number;
  oculonFirst: number;
  mediaFirst: number;
  medianLeadHours: number | null;
  best: Scoop[];
  pending: Scoop[];
}

const MODULES = new Set(['owl', 'hound', 'heron', 'condor', 'falcon', 'case']);

/** Subject to search for: the signal's title without module boilerplate. */
export function subjectOf(s: Signal): string {
  return s.title
    .replace(/^Watch \w+ /, '')
    .replace(/^Case #\d+ new finding: /, '')
    .replace(/:.*$/, '')
    .replace(/\s+\(.*\)$/, '')
    .trim()
    .slice(0, 80);
}

interface Row {
  signal_id: string;
  subject: string;
  oculon_at: number;
  media_at: number | null;
  media_source: string | null;
  media_url: string | null;
  lead_hours: number | null;
  checked_at: number;
}

const toScoop = (r: Row): Scoop => ({
  signalId: r.signal_id,
  subject: r.subject,
  oculonAt: new Date(r.oculon_at).toISOString(),
  mediaAt: r.media_at ? new Date(r.media_at).toISOString() : null,
  mediaSource: r.media_source,
  mediaUrl: r.media_url,
  leadHours: r.lead_hours,
});

/** Check up to `max` signals: new ones 6h-72h old, and uncovered ones again until they are 7 days old. */
export async function checkScoops(ctx: Ctx, max = 8): Promise<Scoop[]> {
  const nowMs = ctx.now().getTime();
  const db = ctx.store.db;
  const known = new Map((db.prepare('SELECT * FROM scoops').all() as unknown as Row[]).map((r) => [r.signal_id, r]));
  const candidates = ctx.graph
    .recentSignals(500)
    .filter((s) => MODULES.has(s.module) && s.score >= 60)
    .filter((s) => {
      const age = nowMs - Date.parse(s.createdAt);
      const k = known.get(s.id);
      if (!k) return age >= 6 * 3_600_000 && age <= 72 * 3_600_000;
      return k.media_at === null && age <= 7 * 86_400_000 && nowMs - k.checked_at >= 12 * 3_600_000;
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, max);

  const out: Scoop[] = [];
  for (const s of candidates) {
    const subject = subjectOf(s);
    if (keywords(subject).size === 0) continue;
    const oculonAt = Date.parse(s.createdAt);
    // Search oldest-first from a week before the signal: earlier coverage must be found, or "Oculon first" is a lie.
    const earliest = { fromIso: new Date(oculonAt - 7 * 86_400_000).toISOString() };
    const [gu, ny, gn] = await Promise.all([guardian(ctx, subject, 0, 10, earliest), nytSearch(ctx, subject, 0, earliest), gnews(ctx, subject, 10, earliest)]);
    const stories = [...(gu.data ?? []), ...(ny.data ?? []), ...(gn.data ?? [])].filter((n) => n.date && mentions(n.title, subject)).sort((a, b) => a.date.localeCompare(b.date));
    const first = stories[0];
    const mediaAt = first ? Date.parse(first.date) : null;
    const lead = mediaAt !== null ? Math.round(((mediaAt - oculonAt) / 3_600_000) * 10) / 10 : null;
    db.prepare(
      `INSERT INTO scoops (signal_id, subject, oculon_at, media_at, media_source, media_url, lead_hours, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(signal_id) DO UPDATE SET media_at = excluded.media_at, media_source = excluded.media_source, media_url = excluded.media_url, lead_hours = excluded.lead_hours, checked_at = excluded.checked_at`,
    ).run(s.id, subject, oculonAt, mediaAt, first?.source ?? null, first?.url ?? null, lead, nowMs);
    out.push(toScoop(db.prepare('SELECT * FROM scoops WHERE signal_id = ?').get(s.id) as unknown as Row));
  }
  return out;
}

export function scoreboard(ctx: Ctx): Scoreboard {
  const all = (ctx.store.db.prepare('SELECT * FROM scoops ORDER BY oculon_at DESC').all() as unknown as Row[]).map(toScoop);
  const covered = all.filter((s) => s.leadHours !== null);
  const leads = covered.map((s) => s.leadHours!).sort((a, b) => a - b);
  const mid = leads.length ? leads[Math.floor(leads.length / 2)]! : null;
  return {
    checked: all.length,
    covered: covered.length,
    oculonFirst: covered.filter((s) => s.leadHours! > 0).length,
    mediaFirst: covered.filter((s) => s.leadHours! <= 0).length,
    medianLeadHours: mid,
    best: [...covered].filter((s) => s.leadHours! > 0).sort((a, b) => b.leadHours! - a.leadHours!).slice(0, 10),
    pending: all.filter((s) => s.leadHours === null).slice(0, 10),
  };
}
