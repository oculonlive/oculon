/**
 * Listen: turn audio into evidence. Transcribes any public audio or video file URL with Deepgram (pay per
 * minute; free starting credit), then reports a summary, topics, and every passage that mentions the subject
 * with its timestamp. `podcast()` finds recent episodes about a subject through the iTunes podcast directory
 * and transcribes the newest one.
 */
import { enc, type Ctx } from '../core/context.js';
import { key, missingKey } from '../core/keys.js';
import { keywords } from '../core/text.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export interface Passage {
  start: number;
  text: string;
}

export interface Transcript {
  url: string;
  title: string | null;
  durationSec: number;
  language: string | null;
  summary: string | null;
  topics: string[];
  words: number;
  mentions: Passage[];
  /** First passages, to read the opening. */
  opening: Passage[];
}

interface DgResponse {
  metadata?: { duration?: number };
  results?: {
    channels?: { detected_language?: string; alternatives?: { transcript?: string; paragraphs?: { paragraphs?: { sentences?: { text: string; start: number }[] }[] } }[] }[];
    summary?: { short?: string };
    topics?: { segments?: { topics?: { topic: string }[] }[] };
  };
  err_msg?: string;
}

const DG_URL = 'https://api.deepgram.com/v1/listen?model=nova-3&smart_format=true&paragraphs=true&summarize=v2&topics=true&detect_language=true';

export const fmtTime = (s: number) => `${Math.floor(s / 3600) ? `${Math.floor(s / 3600)}:` : ''}${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}:${String(Math.floor(s % 60)).padStart(2, '0')}`;

/** Sentences that mention any keyword of the subject, merged when close together. */
export function findMentions(sentences: { text: string; start: number }[], subject: string, max = 12): Passage[] {
  const keys = [...keywords(subject)];
  if (!keys.length) return [];
  const out: Passage[] = [];
  for (let i = 0; i < sentences.length && out.length < max; i++) {
    const s = sentences[i]!;
    if (!keys.some((k) => new RegExp(`\\b${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i').test(s.text))) continue;
    const ctxText = [sentences[i - 1]?.text, s.text, sentences[i + 1]?.text].filter(Boolean).join(' ');
    const last = out[out.length - 1];
    if (last && s.start - last.start < 30) continue;
    out.push({ start: Math.max(0, sentences[i - 1]?.start ?? s.start), text: ctxText.slice(0, 600) });
  }
  return out;
}

export async function transcribe(ctx: Ctx, url: string, subject = '', title: string | null = null): Promise<ModuleResult<Transcript | null>> {
  const now = ctx.now().toISOString();
  const provenance: Provenance[] = [];
  const empty = (p: Provenance): ModuleResult<Transcript | null> => ({ module: 'listen', input: url, generatedAt: now, result: null, signals: [], provenance: [...provenance, p] });
  const k = key('DEEPGRAM_API_KEY');
  if (!k) return empty(missingKey('deepgram', 'DEEPGRAM_API_KEY'));
  if (!/^https?:\/\//.test(url)) throw new Error('give a public http(s) URL of an audio or video file');
  const cacheKey = `derived:deepgram:${url}`;
  const cached = ctx.store.cacheGet(cacheKey);
  let j: DgResponse;
  if (cached) {
    j = JSON.parse(cached.body) as DgResponse;
    provenance.push({ source: 'deepgram', url, status: 'CACHED', fetchedAt: new Date(cached.fetchedAt).toISOString() });
  } else {
    // postBytes counts the call against OCULON_QUOTA_DEEPGRAM and labels failures.
    const r = await ctx.http.postBytes(DG_URL, new TextEncoder().encode(JSON.stringify({ url })), { source: 'deepgram', headers: { authorization: `Token ${k}`, 'content-type': 'application/json' }, timeoutMs: 600_000, retries: 0 });
    if (!r.data) return empty({ ...r.prov, url });
    try {
      j = JSON.parse(r.data.toString('utf8')) as DgResponse;
    } catch {
      return empty({ ...r.prov, url, status: 'ERROR', note: 'invalid response' });
    }
    if (j.err_msg) return empty({ ...r.prov, url, status: 'ERROR', note: j.err_msg.slice(0, 200) });
    // Keep the transcript (not the word-level timings) so re-reading is free.
    const alt = j.results?.channels?.[0]?.alternatives?.[0];
    const slim: DgResponse = {
      metadata: { duration: j.metadata?.duration },
      results: {
        channels: [{ detected_language: j.results?.channels?.[0]?.detected_language, alternatives: [{ transcript: alt?.transcript, paragraphs: { paragraphs: alt?.paragraphs?.paragraphs?.map((p) => ({ sentences: p.sentences?.map((s) => ({ text: s.text, start: s.start })) })) } }] }],
        summary: j.results?.summary,
        topics: j.results?.topics,
      },
    };
    ctx.store.cachePut(cacheKey, JSON.stringify(slim));
    j = slim;
    provenance.push({ source: 'deepgram', url, status: 'LIVE', fetchedAt: now, note: `${Math.round(j.metadata?.duration ?? 0)} s of audio` });
  }
  const ch = j.results?.channels?.[0];
  const alt = ch?.alternatives?.[0];
  const sentences = (alt?.paragraphs?.paragraphs ?? []).flatMap((p) => p.sentences ?? []);
  const topics = [...new Set((j.results?.topics?.segments ?? []).flatMap((s) => s.topics?.map((t) => t.topic) ?? []))].slice(0, 12);
  const result: Transcript = {
    url,
    title,
    durationSec: Math.round(j.metadata?.duration ?? 0),
    language: ch?.detected_language ?? null,
    // Deepgram's summary and topics are English-only; for other languages it returns a notice instead.
    summary: ch?.detected_language && ch.detected_language !== 'en' ? null : (j.results?.summary?.short ?? null),
    topics,
    words: (alt?.transcript ?? '').split(/\s+/).filter(Boolean).length,
    mentions: subject ? findMentions(sentences, subject) : [],
    opening: sentences.slice(0, 4).map((s) => ({ start: s.start, text: s.text })),
  };
  return { module: 'listen', input: url, generatedAt: now, result, signals: [], provenance };
}

export interface Episode {
  show: string;
  title: string;
  date: string;
  audioUrl: string;
  pageUrl: string | null;
}

/** Recent podcast episodes about a subject (iTunes directory, free), newest first. */
export async function findEpisodes(ctx: Ctx, subject: string, max = 8): Promise<{ data: Episode[]; prov: Provenance }> {
  const r = await ctx.http.get<{ results?: { collectionName?: string; trackName?: string; releaseDate?: string; episodeUrl?: string; trackViewUrl?: string }[] }>(
    `https://itunes.apple.com/search?term=${enc(subject)}&media=podcast&entity=podcastEpisode&limit=25`,
    { source: 'itunes', ttlSec: 3 * 3600 },
  );
  const data = (r.data?.results ?? [])
    .filter((e) => e.episodeUrl && e.trackName)
    .map((e) => ({ show: e.collectionName ?? '?', title: e.trackName!, date: e.releaseDate ?? '', audioUrl: e.episodeUrl!, pageUrl: e.trackViewUrl ?? null }))
    .sort((a, b) => b.date.localeCompare(a.date))
    .slice(0, max);
  return { data, prov: r.prov };
}

/** Titles that announce another language ("- CN:", "(Español)"); skipped when picking automatically. */
const FOREIGN = { test: (s: string) => /(^|[\s([-])(CN|ZH|ES|DE|FR|JP|KR|PT)\b/.test(s) || /\b(español|deutsch|français)\b|中文|日本語/i.test(s) };

export async function podcast(ctx: Ctx, subject: string, pick?: number): Promise<ModuleResult<{ episodes: Episode[]; transcript: Transcript | null; picked: Episode | null }>> {
  const eps = await findEpisodes(ctx, subject);
  // Automatic pick: the newest episode that does not announce another language; one retry if it still is not English.
  const order = pick !== undefined ? [pick] : eps.data.map((_, i) => i).filter((i) => !FOREIGN.test(`${eps.data[i]!.show} ${eps.data[i]!.title}`));
  let picked: Episode | null = null;
  let t: ModuleResult<Transcript | null> | null = null;
  for (const i of order.slice(0, pick !== undefined ? 1 : 2)) {
    picked = eps.data[i] ?? null;
    if (!picked) break;
    t = await transcribe(ctx, picked.audioUrl, subject, `${picked.show}: ${picked.title}`);
    if (!t.result || t.result.language === 'en' || t.result.language === null) break;
  }
  return {
    module: 'listen',
    input: subject,
    generatedAt: ctx.now().toISOString(),
    result: { episodes: eps.data, transcript: t?.result ?? null, picked },
    signals: [],
    provenance: [eps.prov, ...(t?.provenance ?? [])],
  };
}
