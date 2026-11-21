/**
 * Live layer: listens continuously to two free real-time streams and flags things before they become news.
 *   Wikipedia EventStreams: an English article suddenly edited by several people (breaking events get edited
 *     within minutes, well before page views or articles catch up).
 *   Bluesky Jetstream: a name or hashtag in English posts surging against its own last hour; watched topics
 *     and companies get a lower bar.
 * Runs inside `oculon serve` (or `oculon live`). State is in memory; signals go to the store and alerts.
 */
import { keywords, signalId } from './core/text.js';
import type { Signal } from './core/types.js';
import type { Oculon } from './index.js';

export interface LiveOptions {
  log?: (m: string) => void;
  onSignals?: (s: Signal[]) => Promise<void> | void;
  /** Extra Bluesky terms to watch closely (lowercase). Defaults to watchlist topics and companies. */
  watchTerms?: () => string[];
  wiki?: boolean;
  bluesky?: boolean;
}

const MIN = 60_000;
const UA = 'Oculon/0.1 (open-source OSINT engine)';

const STOP_TERMS = new Set(
  'the and you for that this with have just like what your from they will about when there been more would people their time today good know only really think also because make love need want going still even back much here thank thanks happy look great right last first many most other some year years day days week night morning new now get got one two can all out how why who our was are not but has its his her him she them did does'.split(
    ' ',
  ),
);

/** Terms worth counting in a post: hashtags and capitalized words or two-word names. */
export function postTerms(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/#([\p{L}\p{N}_]{3,40})/gu)) out.add(`#${m[1]!.toLowerCase()}`);
  const words = text.replace(/https?:\/\/\S+/g, ' ').split(/[^\p{L}\p{N}'’-]+/u).filter(Boolean);
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (!/^\p{Lu}[\p{L}\p{N}'’-]{2,}$/u.test(w) || STOP_TERMS.has(w.toLowerCase())) continue;
    // Skip sentence-initial capitals unless the word is all caps (an acronym).
    const sentenceStart = i === 0 || /[.!?]$/.test(words[i - 1] ?? '');
    const next = words[i + 1];
    if (next && /^\p{Lu}[\p{L}]{2,}$/u.test(next) && !STOP_TERMS.has(next.toLowerCase())) out.add(`${w} ${next}`.toLowerCase());
    if (!sentenceStart || w === w.toUpperCase()) out.add(w.toLowerCase());
  }
  return [...out];
}

/** Per-minute counters with a one-hour memory. */
export class TermCounter {
  private buckets = new Map<number, Map<string, number>>();
  add(term: string, minute: number) {
    const b = this.buckets.get(minute) ?? new Map<string, number>();
    b.set(term, (b.get(term) ?? 0) + 1);
    this.buckets.set(minute, b);
  }
  prune(nowMinute: number) {
    for (const m of this.buckets.keys()) if (m < nowMinute - 60) this.buckets.delete(m);
  }
  /** Counts in the last `recent` minutes and the per-window average over the rest of the hour. */
  surge(nowMinute: number, recent = 10): { term: string; recent: number; baseline: number }[] {
    const rec = new Map<string, number>();
    const old = new Map<string, number>();
    let oldMinutes = 0;
    for (const [m, b] of this.buckets) {
      const target = m > nowMinute - recent ? rec : old;
      if (target === old) oldMinutes++;
      for (const [t, n] of b) target.set(t, (target.get(t) ?? 0) + n);
    }
    const windows = Math.max(1, oldMinutes / recent);
    return [...rec].map(([term, n]) => ({ term, recent: n, baseline: (old.get(term) ?? 0) / windows }));
  }
  minutesCovered(): number {
    return this.buckets.size;
  }
}

export class LiveMonitor {
  private stopped = false;
  private wikiEdits = new Map<string, { t: number; user: string }[]>();
  private flagged = new Map<string, number>();
  private terms = new TermCounter();
  private timer: NodeJS.Timeout | null = null;
  private ws: WebSocket | null = null;
  private abort: AbortController | null = null;
  readonly stats = { wikiEdits: 0, posts: 0, signals: 0, startedAt: new Date().toISOString() };

  constructor(
    private readonly o: Oculon,
    private readonly opts: LiveOptions = {},
  ) {}

  private log(m: string) {
    this.opts.log?.(`live ${m}`);
  }

  start(): void {
    if (this.opts.wiki !== false) void this.wikiLoop();
    if (this.opts.bluesky !== false) this.blueskyConnect();
    this.timer = setInterval(() => void this.evaluate(), MIN);
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.abort?.abort();
    this.ws?.close();
  }

  private async wikiLoop(): Promise<void> {
    while (!this.stopped) {
      this.abort = new AbortController();
      try {
        const res = await fetch('https://stream.wikimedia.org/v2/stream/recentchange', { headers: { accept: 'text/event-stream', 'user-agent': UA }, signal: this.abort.signal });
        const dec = new TextDecoder();
        let buf = '';
        for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
          buf += dec.decode(chunk, { stream: true });
          let i: number;
          while ((i = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, i);
            buf = buf.slice(i + 1);
            if (!line.startsWith('data:')) continue;
            try {
              const e = JSON.parse(line.slice(5)) as { wiki?: string; namespace?: number; type?: string; bot?: boolean; title?: string; user?: string; timestamp?: number };
              if (e.wiki !== 'enwiki' || e.namespace !== 0 || e.type !== 'edit' || e.bot || !e.title) continue;
              this.stats.wikiEdits++;
              const list = this.wikiEdits.get(e.title) ?? [];
              list.push({ t: Date.now(), user: e.user ?? '?' });
              this.wikiEdits.set(e.title, list);
            } catch {}
          }
        }
      } catch (e) {
        if (this.stopped) return;
        this.log(`wikipedia stream dropped (${(e as Error).message}); reconnecting`);
      }
      await new Promise((r) => setTimeout(r, 5000));
    }
  }

  private blueskyConnect(): void {
    if (this.stopped) return;
    try {
      this.ws = new WebSocket('wss://jetstream2.us-east.bsky.network/subscribe?wantedCollections=app.bsky.feed.post');
    } catch {
      setTimeout(() => this.blueskyConnect(), 10_000);
      return;
    }
    this.ws.onmessage = (ev: MessageEvent) => {
      try {
        const m = JSON.parse(String(ev.data)) as { commit?: { operation?: string; record?: { text?: string; langs?: string[] } } };
        const r = m.commit?.record;
        if (m.commit?.operation !== 'create' || !r?.text || !r.langs?.includes('en')) return;
        this.stats.posts++;
        const minute = Math.floor(Date.now() / MIN);
        for (const t of postTerms(r.text)) this.terms.add(t, minute);
      } catch {}
    };
    this.ws.onclose = () => {
      if (!this.stopped) setTimeout(() => this.blueskyConnect(), 5000);
    };
  }

  /** Called every minute: decide what is surging. Exposed for tests. */
  async evaluate(nowMs = Date.now()): Promise<Signal[]> {
    const signals: Signal[] = [];
    const nowIso = new Date(nowMs).toISOString();
    const fresh = (key: string) => {
      const last = this.flagged.get(key);
      if (last && nowMs - last < 6 * 3_600_000) return false;
      this.flagged.set(key, nowMs);
      return true;
    };

    // Wikipedia: 6+ edits by 3+ different people in 15 minutes.
    for (const [title, list] of this.wikiEdits) {
      const recent = list.filter((e) => nowMs - e.t <= 15 * MIN);
      if (!recent.length) {
        this.wikiEdits.delete(title);
        continue;
      }
      this.wikiEdits.set(title, recent);
      const editors = new Set(recent.map((e) => e.user)).size;
      if (recent.length >= 6 && editors >= 3 && !/^(List of|Deaths in|\d{4} in )/.test(title) && fresh(`wiki:${title}`)) {
        signals.push({
          id: signalId('live', 'wiki', title, nowIso.slice(0, 13)),
          module: 'live',
          title: `Edit surge on Wikipedia: ${title} (${recent.length} edits by ${editors} editors in 15 min)`,
          score: Math.min(85, 50 + recent.length * 2 + editors * 3),
          evidence: [{ source: 'wikipedia-live', text: `${recent.length} human edits by ${editors} different editors in the last 15 minutes`, url: `https://en.wikipedia.org/w/index.php?title=${encodeURIComponent(title)}&action=history` }],
          createdAt: nowIso,
        });
      }
    }

    // Bluesky: needs at least 20 minutes of history before any baseline means something.
    const minute = Math.floor(nowMs / MIN);
    this.terms.prune(minute);
    if (this.terms.minutesCovered() >= 20) {
      const watched = new Set((this.opts.watchTerms?.() ?? this.o.watchList().filter((w) => w.kind === 'topic' || w.kind === 'company').map((w) => w.target.toLowerCase())).map((t) => t.toLowerCase()));
      for (const s of this.terms.surge(minute)) {
        const isWatched = watched.has(s.term) || [...watched].some((w) => keywords(w).has(s.term));
        const minRecent = isWatched ? 8 : 25;
        const ratio = s.recent / Math.max(1, s.baseline);
        if (s.recent < minRecent || ratio < (isWatched ? 3 : 5)) continue;
        if (!fresh(`bsky:${s.term}`)) continue;
        signals.push({
          id: signalId('live', 'bsky', s.term, nowIso.slice(0, 13)),
          module: 'live',
          title: `Surging on Bluesky: "${s.term}" (${s.recent} posts in 10 min, ${ratio.toFixed(0)}x its last hour)${isWatched ? ' [watched]' : ''}`,
          score: Math.min(85, Math.round(45 + Math.log2(ratio) * 6 + (isWatched ? 10 : 0))),
          evidence: [{ source: 'bluesky-live', text: `${s.recent} English posts mention it in 10 minutes vs ~${s.baseline.toFixed(1)} per 10 minutes before`, url: `https://bsky.app/search?q=${encodeURIComponent(s.term)}` }],
          createdAt: nowIso,
        });
      }
    }

    // Only the strongest few per minute; streams can be noisy.
    const top = signals.sort((a, b) => b.score - a.score).slice(0, 5);
    for (const s of top) this.o.ctx.graph.saveSignal(s);
    this.stats.signals += top.length;
    if (top.length) {
      this.log(`${top.length} live signal(s): ${top.map((s) => s.title.slice(0, 60)).join(' | ')}`);
      await this.opts.onSignals?.(top);
    }
    return top;
  }

  /** Test hooks: feed events without network. */
  _wikiEdit(title: string, user: string, t = Date.now()) {
    const l = this.wikiEdits.get(title) ?? [];
    l.push({ t, user });
    this.wikiEdits.set(title, l);
  }
  _post(text: string, t = Date.now()) {
    for (const term of postTerms(text)) this.terms.add(term, Math.floor(t / MIN));
  }
}
