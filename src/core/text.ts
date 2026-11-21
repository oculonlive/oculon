import { createHash } from 'node:crypto';

const STOP = new Set(
  `the a an and or of to in on for with by at from is are was were be been will would can could should this that these those it its as
   into over after before about than then vs via new how why what who when where which says said year years day days week weeks
   your you our their his her they them we us not no yes more most will just like also first last next time people`.split(/\s+/),
);

/** Lowercase content words: length >= 4, capitalized names >= 3 ("Fed"), or acronyms >= 2 ("AI", "NBA"). */
export function keywords(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.replace(/_/g, ' ').split(/[^\p{L}\p{N}]+/u)) {
    if (!raw) continue;
    const w = raw.toLowerCase();
    if (STOP.has(w)) continue;
    const capitalized = /^\p{Lu}/u.test(raw);
    const acronym = raw.length >= 2 && raw === raw.toUpperCase() && /\p{L}/u.test(raw);
    if (w.length >= 4 || acronym || (capitalized && w.length >= 3)) out.add(w);
  }
  return out;
}

/** Overlap score between two keyword sets: shared / size of the smaller set. */
export function overlap(a: Set<string>, b: Set<string>): { score: number; shared: string[] } {
  const shared = [...a].filter((w) => b.has(w));
  const denom = Math.min(a.size, b.size);
  return { score: denom ? shared.length / denom : 0, shared };
}

export function signalId(module: string, ...parts: string[]): string {
  return `${module}-${createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 12)}`;
}

export const articleTitle = (a: string) => a.replace(/_/g, ' ');
