/**
 * EVM signature decoding (no keys): 4-byte function selectors and 32-byte event topics to text signatures.
 *   Primary: openchain.xyz signature database (batch lookup, verified-contract hint, spam filter).
 *   Fallback: 4byte.directory (one request per hash; the oldest submission is taken as canonical).
 * Signatures never change, so every answer is kept in the derived cache (not pruned); unknown hashes are
 * re-asked after a week because new signatures get submitted all the time.
 */
import type { Ctx } from '../core/context.js';

const OPENCHAIN = 'https://api.openchain.xyz/signature-database/v1/lookup';
const FOURBYTE = 'https://www.4byte.directory/api/v1';
const BATCH = 40;
/** 4byte answers one hash per request, so the fallback is capped per call. */
const FOURBYTE_MAX = 25;
const NULL_TTL_MS = 7 * 86_400_000;

type Kind = 'function' | 'event';
const PATTERN: Record<Kind, RegExp> = { function: /^0x[0-9a-f]{8}$/, event: /^0x[0-9a-f]{64}$/ };

const cacheKey = (kind: Kind, hash: string) => `derived:sig:${kind}:${hash}`;

function normalise(kind: Kind, raw: string): string | null {
  let h = raw.trim().toLowerCase();
  if (!h.startsWith('0x')) h = `0x${h}`;
  // Accept full calldata for functions: the selector is its first four bytes.
  if (kind === 'function' && /^0x[0-9a-f]{8,}$/.test(h)) h = h.slice(0, 10);
  return PATTERN[kind].test(h) ? h : null;
}

interface OpenchainResponse {
  ok?: boolean;
  result?: { function?: Record<string, { name: string; filtered?: boolean; hasVerifiedContract?: boolean }[] | null>; event?: Record<string, { name: string; filtered?: boolean; hasVerifiedContract?: boolean }[] | null> };
}

/** Pick the best candidate: unfiltered first, then one seen in a verified contract. */
function pickOpenchain(list: { name: string; filtered?: boolean; hasVerifiedContract?: boolean }[] | null | undefined): string | null {
  if (!list?.length) return null;
  const ok = list.filter((x) => !x.filtered);
  const pool = ok.length ? ok : list;
  return (pool.find((x) => x.hasVerifiedContract) ?? pool[0])!.name;
}

async function decode(ctx: Ctx, kind: Kind, input: string[]): Promise<Record<string, string | null>> {
  const out: Record<string, string | null> = {};
  const nowMs = ctx.now().getTime();
  const todo: string[] = [];
  for (const raw of input) {
    const h = normalise(kind, raw);
    if (!h) {
      out[raw] = null;
      continue;
    }
    if (h in out) continue;
    const c = ctx.store.cacheGet(cacheKey(kind, h));
    if (c) {
      try {
        const v = (JSON.parse(c.body) as { name: string | null }).name;
        if (v !== null || nowMs - c.fetchedAt < NULL_TTL_MS) {
          out[h] = v;
          continue;
        }
      } catch {}
    }
    out[h] = null;
    todo.push(h);
  }
  if (!todo.length) return out;

  const save = (h: string, name: string | null) => {
    out[h] = name;
    ctx.store.cachePut(cacheKey(kind, h), JSON.stringify({ name }), nowMs);
  };

  // openchain: batch lookup.
  const missing: string[] = [];
  let openchainUp = true;
  for (let i = 0; i < todo.length; i += BATCH) {
    const chunk = todo.slice(i, i + BATCH);
    const r = await ctx.http.get<OpenchainResponse>(`${OPENCHAIN}?${kind}=${chunk.join(',')}&filter=true`, { source: 'openchain', ttlSec: 86_400, timeoutMs: 20_000, retries: 1 });
    const res = r.data?.ok !== false ? r.data?.result?.[kind] : undefined;
    if (!res) {
      openchainUp = false;
      missing.push(...chunk);
      continue;
    }
    for (const h of chunk) {
      const name = pickOpenchain(res[h]);
      if (name) save(h, name);
      else missing.push(h);
    }
  }

  // 4byte.directory: fallback when openchain is down, and a second opinion for hashes openchain does not know.
  const path = kind === 'function' ? 'signatures' : 'event-signatures';
  for (const h of missing.slice(0, FOURBYTE_MAX)) {
    const r = await ctx.http.get<{ results?: { id: number; text_signature: string }[] }>(`${FOURBYTE}/${path}/?hex_signature=${h}`, { source: '4byte', ttlSec: 86_400, timeoutMs: 20_000, retries: 1 });
    // A failed request is not cached as "unknown", so the next call asks again.
    if (!r.data) continue;
    const best = [...(r.data.results ?? [])].sort((a, b) => a.id - b.id)[0];
    save(h, best?.text_signature ?? null);
  }
  // Past the 4byte cap: remember openchain's "unknown" answer for a week.
  if (openchainUp) for (const h of missing.slice(FOURBYTE_MAX)) save(h, null);
  return out;
}

/** Decode 4-byte function selectors (or full calldata) to text signatures such as `transfer(address,uint256)`. Keys are lowercase selectors; unknown or malformed input maps to null. */
export function decodeSelectors(ctx: Ctx, selectors: string[]): Promise<Record<string, string | null>> {
  return decode(ctx, 'function', selectors);
}

/** Decode 32-byte event topics (topic0) to text signatures such as `Transfer(address,address,uint256)`. */
export function decodeEvents(ctx: Ctx, topics: string[]): Promise<Record<string, string | null>> {
  return decode(ctx, 'event', topics);
}

/** `transfer(address,uint256)` to `transfer`: a short method label for transaction lists. */
export const methodName = (sig: string | null | undefined): string | null => (sig ? sig.split('(')[0]! : null);
