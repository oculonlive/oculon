/**
 * One plain verdict from any check result: what it says, how bad, and why. Used by the verdict cards in AI chat
 * apps, PDF reports, "seen before" changes and brief mode, so every check gets them without its own code.
 * Results differ per module; this reads the fields they share (verdict, risk, level, reasons, flags, warnings).
 */

export type Tone = 'bad' | 'warn' | 'ok' | 'info';

export interface Verdict {
  /** What was checked, as shown to people. */
  title: string;
  verdict: string | null;
  tone: Tone;
  risk: number | null;
  points: string[];
  sources: { live: number; cached: number; failed: number; names: string[] };
}

type Any = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const BAD = /\b(likely scam|scam|malicious|danger|dangerous|spoof|spoofed|high|critical|not valid|invalid|leaked|likely edited|edited|sanction|sanctioned|honeypot|poisoned|cannot sell|vulnerable|exploited|unprotected|not protected|fake|fraud)\b/i;
const WARN = /\b(suspicious|caution|medium|moderate|partly|warn|warning|signs of|unknown|unverified|elevated|risky|check)\b/i;
const OK = /\b(ok|safe|valid|protected|clean|low|no known|not found|none found|no signs|legit|genuine|active|operational|no recalls)\b/i;

export function toneOf(verdict: string | null, risk: number | null): Tone {
  if (verdict) {
    // "no signs of editing", "no known threats": a negated finding is good news, whatever words follow.
    if (/^(no|nothing|none)\b|\b(not found|none found)\b/i.test(verdict.trim())) return 'ok';
    if (BAD.test(verdict) && !/\bno\b|not (a )?scam/i.test(verdict)) return 'bad';
    if (WARN.test(verdict)) return 'warn';
    if (OK.test(verdict)) return 'ok';
  }
  if (risk !== null) return risk >= 70 ? 'bad' : risk >= 35 ? 'warn' : 'ok';
  return 'info';
}

const text = (v: unknown): string | null => {
  if (typeof v === 'string') return v.trim() || null;
  if (v && typeof v === 'object') {
    const o = v as Any;
    for (const k of ['text', 'title', 'reason', 'message', 'detail', 'name']) if (typeof o[k] === 'string' && o[k].trim()) return o[k].trim();
  }
  return null;
};

function pickVerdict(x: Any): string | null {
  for (const k of ['verdict', 'status', 'level', 'grade', 'assessment']) {
    const v = x[k];
    if (typeof v === 'string' && v.trim() && v.length < 60) return k === 'level' && !/risk/i.test(v) ? `${v} risk` : v.trim();
  }
  if (typeof x.risk === 'string' && x.risk.length < 30) return `${x.risk} risk`;
  if (typeof x.valid === 'boolean') return x.valid ? 'valid' : 'not valid';
  return null;
}

function pickRisk(x: Any): number | null {
  for (const k of ['risk', 'riskScore', 'score']) {
    const v = x[k];
    if (typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 100) return Math.round(v);
  }
  return null;
}

function pickPoints(x: Any): string[] {
  for (const k of ['reasons', 'flags', 'warnings', 'findings', 'points', 'issues']) {
    const arr = x[k];
    if (Array.isArray(arr) && arr.length) {
      const pts = arr.map(text).filter((t): t is string => Boolean(t));
      if (pts.length) return pts.slice(0, 12);
    }
  }
  return [];
}

function sourcesOf(out: Any): Verdict['sources'] {
  const s = { live: 0, cached: 0, failed: 0, names: [] as string[] };
  const prov = out?.provenance;
  if (Array.isArray(prov)) {
    for (const p of prov as Any[]) {
      if (p.status === 'LIVE') s.live++; else if (p.status === 'CACHED') s.cached++; else s.failed++;
      if (!s.names.includes(p.source)) s.names.push(p.source);
    }
  } else if (prov && typeof prov === 'object' && prov.sources) {
    // The compact { sources: { name: { LIVE: n } } } summary used by the web API and MCP.
    for (const [name, counts] of Object.entries(prov.sources as Record<string, Record<string, number>>)) {
      s.names.push(name);
      s.live += counts.LIVE ?? 0;
      s.cached += counts.CACHED ?? 0;
      s.failed += (counts.ERROR ?? 0) + (counts.UNAVAILABLE ?? 0);
    }
  }
  return s;
}

/** The verdict of a module result (or the compact form the API returns). */
export function verdictOf(out: unknown, label?: string): Verdict {
  const o = (out ?? {}) as Any;
  const x = (o.result && typeof o.result === 'object' && !Array.isArray(o.result) ? o.result : o) as Any;
  const verdict = pickVerdict(x);
  const risk = pickRisk(x);
  let points = pickPoints(x);
  if (!points.length && Array.isArray(o.signals)) points = (o.signals as Any[]).map((s) => text(s)).filter((t): t is string => Boolean(t)).slice(0, 8);
  const title = label ?? (typeof o.input === 'string' && o.input ? o.input : typeof x.input === 'string' ? x.input : '');
  return { title: title.slice(0, 160), verdict, tone: toneOf(verdict, risk), risk, points, sources: sourcesOf(o) };
}

/** What changed between two verdicts of the same target, in plain words. Empty when nothing did. */
export function verdictChanges(before: Verdict, now: Verdict): string[] {
  const out: string[] = [];
  if ((before.verdict ?? '') !== (now.verdict ?? '')) out.push(`verdict: ${before.verdict ?? 'none'} -> ${now.verdict ?? 'none'}`);
  if (before.risk !== now.risk && before.risk !== null && now.risk !== null) out.push(`risk ${before.risk} -> ${now.risk}`);
  const was = new Set(before.points), is = new Set(now.points);
  for (const p of now.points) if (!was.has(p)) out.push(`new: ${p}`);
  for (const p of before.points) if (!is.has(p)) out.push(`gone: ${p}`);
  return out.slice(0, 12);
}

/**
 * Brief mode: a short answer for agents. Verdict, risk, top points, which sources answered, and the check id
 * for the full result. Results without a verdict are trimmed instead (first items of long lists, no long text).
 */
export function briefOf(out: unknown, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const v = verdictOf(out);
  if (v.verdict || v.risk !== null) {
    return {
      ...(v.title ? { target: v.title } : {}),
      verdict: v.verdict,
      ...(v.risk !== null ? { risk: v.risk } : {}),
      points: v.points.slice(0, 5),
      sources: `${v.sources.live} live, ${v.sources.cached} cached, ${v.sources.failed} failed${v.sources.names.length ? ` (${v.sources.names.slice(0, 8).join(', ')})` : ''}`,
      ...extra,
    };
  }
  return { ...(trim(out, 0) as Record<string, unknown>), ...extra };
}

function trim(v: unknown, depth: number): unknown {
  if (typeof v === 'string') return v.length > 280 ? `${v.slice(0, 277)}...` : v;
  if (Array.isArray(v)) {
    const head = v.slice(0, 5).map((x) => trim(x, depth + 1));
    return v.length > 5 ? [...head, `(${v.length - 5} more)`] : head;
  }
  if (v && typeof v === 'object') {
    if (depth > 3) return '(...)';
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === 'provenance' && x && typeof x === 'object' && !Array.isArray(x)) {
        o.sources = Object.keys((x as Any).sources ?? {}).join(', ');
        continue;
      }
      if (k === 'provenance' && Array.isArray(x)) {
        o.sources = [...new Set((x as Any[]).map((p) => p.source))].join(', ');
        continue;
      }
      o[k] = trim(x, depth + 1);
    }
    return o;
  }
  return v;
}
