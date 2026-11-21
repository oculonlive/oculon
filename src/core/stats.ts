export const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);
export const mean = (xs: number[]) => (xs.length ? sum(xs) / xs.length : 0);

export function median(xs: number[]): number {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

export function std(xs: number[]): number {
  if (xs.length < 2) return 0;
  const m = mean(xs);
  return Math.sqrt(sum(xs.map((x) => (x - m) ** 2)) / (xs.length - 1));
}

/** Robust z-score of `x` against `baseline` (median/MAD, falls back to std). */
export function robustZ(x: number, baseline: number[]): number {
  if (!baseline.length) return 0;
  const med = median(baseline);
  const mad = median(baseline.map((b) => Math.abs(b - med))) * 1.4826;
  const spread = mad > 0 ? mad : std(baseline);
  if (spread === 0) return x === med ? 0 : x > med ? 10 : -10;
  return (x - med) / spread;
}

/** How many times larger `x` is than the baseline median. */
export function spikeRatio(x: number, baseline: number[]): number {
  const med = median(baseline);
  return med > 0 ? x / med : x > 0 ? Infinity : 1;
}

export const clamp = (x: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, x));

/** Sum consecutive groups of `size` (from the end, so the last bucket is always full). */
export function bucketFromEnd(xs: number[], size: number, agg: (g: number[]) => number = sum): number[] {
  const out: number[] = [];
  for (let end = xs.length; end - size >= 0; end -= size) out.unshift(agg(xs.slice(end - size, end)));
  return out;
}

export type Phase = 'DORMANT' | 'EMERGING' | 'RISING' | 'PEAK' | 'COOLING' | 'STEADY';

export interface Trend {
  phase: Phase;
  /** recent (last 2 buckets) mean / earlier mean. */
  momentum: number;
  /** last bucket / previous bucket. */
  acceleration: number;
}

/**
 * Classify a series (oldest -> newest, at least 4 buckets) into a hype phase.
 * Rules are deliberately simple and documented so results are explainable.
 */
export function trend(series: number[]): Trend {
  const n = series.length;
  if (n < 4 || sum(series) === 0) return { phase: 'DORMANT', momentum: 1, acceleration: 1 };
  const recent = mean(series.slice(n - 2));
  const earlier = mean(series.slice(0, n - 2));
  const last = series[n - 1]!;
  const prev = series[n - 2]!;
  const eps = 1e-9;
  const momentum = earlier > eps ? recent / earlier : recent > 0 ? Infinity : 1;
  const acceleration = prev > eps ? last / prev : last > 0 ? Infinity : 1;

  let phase: Phase;
  if (earlier <= eps && recent > 0) phase = 'EMERGING';
  else if (momentum >= 1.5 && acceleration >= 0.9) phase = 'RISING';
  else if (momentum >= 1.2 && acceleration < 0.9) phase = 'PEAK';
  else if (momentum <= 0.75) phase = 'COOLING';
  else phase = 'STEADY';
  return { phase, momentum, acceleration };
}
