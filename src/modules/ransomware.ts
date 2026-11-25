/**
 * Ransomware victims: claims posted on ransomware group leak sites, collected by ransomware.live (keyless).
 * Empty query: the newest claims with counts by group, country and sector.
 * A two-letter country code, a sector name, or any word (company, domain) narrows the list.
 * Leak-site (.onion) links are never passed on; each victim links to its ransomware.live page.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';

export interface Victim {
  victim: string;
  group: string;
  country: string | null;
  sector: string | null;
  domain: string | null;
  attacked: string | null;
  discovered: string | null;
  description: string | null;
  url: string | null;
}

export interface RansomwareResult {
  query: string;
  mode: 'recent' | 'country' | 'sector' | 'search';
  total: number;
  victims: Victim[];
  byGroup: { name: string; count: number }[];
  byCountry: { name: string; count: number }[];
  bySector: { name: string; count: number }[];
  note: string;
}

const SECTORS = ['Agriculture and Food Production', 'Business Services', 'Construction', 'Consumer Services', 'Education', 'Energy', 'Financial Services', 'Government', 'Healthcare', 'Hospitality', 'Manufacturing', 'Not Found', 'Professional Services', 'Public Sector', 'Retail', 'Technology', 'Telecommunication', 'Transportation/Logistics'];

interface RawVictim { victim?: string; post_title?: string; group?: string; group_name?: string; country?: string; activity?: string; domain?: string; website?: string; attackdate?: string; discovered?: string; published?: string; description?: string; url?: string }

const clip = (s: string | undefined, n: number) => {
  const t = (s ?? '').replace(/\s+/g, ' ').replace(/^\[AI generated\]\s*/i, '').trim();
  // Some upstream summaries are placeholders or a model declining to answer; leave those out.
  if (!t || /^n\/a\b|^none\b|i don't have reliable|i'm not able|i cannot find|no (reliable|verified) information/i.test(t)) return null;
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

export function toVictim(x: RawVictim): Victim {
  const url = typeof x.url === 'string' && /^https:\/\/(www\.)?ransomware\.live\//.test(x.url) ? x.url : null;
  return {
    victim: (x.victim ?? x.post_title ?? '').trim() || 'unnamed',
    group: (x.group ?? x.group_name ?? '').trim() || 'unknown',
    country: x.country?.trim() || null,
    sector: x.activity && x.activity !== 'Not Found' ? x.activity : null,
    domain: (x.domain ?? x.website ?? '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim() || null,
    attacked: x.attackdate ?? null,
    discovered: x.discovered ?? x.published ?? null,
    description: clip(x.description, 240),
    url,
  };
}

const tally = (xs: (string | null)[], n = 8) => {
  const m = new Map<string, number>();
  for (const x of xs) if (x) m.set(x, (m.get(x) ?? 0) + 1);
  return [...m].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, n);
};

export async function ransomware(ctx: Ctx, input = ''): Promise<ModuleResult<RansomwareResult>> {
  const q = input.trim();
  const base = 'https://api.ransomware.live/v2';
  const sector = SECTORS.find((s) => s.toLowerCase() === q.toLowerCase() || s.toLowerCase().startsWith(`${q.toLowerCase()} `));
  const mode: RansomwareResult['mode'] = !q ? 'recent' : /^[a-z]{2}$/i.test(q) ? 'country' : sector ? 'sector' : 'search';
  if (mode === 'search' && q.length < 3) throw new Error('give at least 3 characters to search for');
  const url = mode === 'recent' ? `${base}/recentvictims` : mode === 'country' ? `${base}/countryvictims/${q.toUpperCase()}` : mode === 'sector' ? `${base}/sectorvictims/${encodeURIComponent(sector!)}` : `${base}/searchvictims/${encodeURIComponent(q)}`;
  const r = await ctx.http.get<RawVictim[] | { error?: string }>(url, {
    source: 'ransomware-live',
    ttlSec: 1800,
    timeoutMs: 30_000,
    retries: 1,
    keep: (d: unknown) => (Array.isArray(d) ? (d as RawVictim[]).slice(0, 300).map((x) => ({ victim: x.victim ?? x.post_title, group: x.group ?? x.group_name, country: x.country, activity: x.activity, domain: x.domain ?? x.website, attackdate: x.attackdate, discovered: x.discovered ?? x.published, description: (x.description ?? '').slice(0, 300), url: x.url })) : d),
  });
  const provenance: Provenance[] = [r.prov];
  const notFound = !Array.isArray(r.data) && (r.prov.note === 'HTTP 404' || /no victims/i.test(String((r.data as { error?: string } | null)?.error ?? '')));
  if (!Array.isArray(r.data) && !notFound) throw new Error(`ransomware.live is not answering right now (${r.prov.note ?? r.prov.status})`);
  if (notFound) provenance[0] = { ...r.prov, status: 'LIVE', note: 'no matching victims' };
  const all = (Array.isArray(r.data) ? r.data : []).map(toVictim).sort((a, b) => (b.discovered ?? b.attacked ?? '').localeCompare(a.discovered ?? a.attacked ?? ''));
  const victims = all.slice(0, 40);

  const nowIso = ctx.now().toISOString();
  const signals: Signal[] = [];
  if (mode === 'search' && all.length) {
    const s: Signal = {
      id: signalId('ransomware', q.toLowerCase(), all.slice(0, 5).map((v) => `${v.group}:${v.victim}`).join(',')),
      module: 'ransomware',
      title: `${q}: ${all.length} ransomware leak-site claim${all.length === 1 ? '' : 's'}, newest by ${all[0]!.group}`,
      score: 60,
      entity: q.toLowerCase(),
      evidence: all.slice(0, 3).map((v) => ({ source: 'ransomware.live', text: `${v.group} claims ${v.victim}${v.discovered ? ` (${v.discovered.slice(0, 10)})` : ''}`, ...(v.url ? { url: v.url } : {}) })),
      createdAt: nowIso,
    };
    signals.push(s);
  }
  return {
    module: 'ransomware',
    input: q,
    generatedAt: nowIso,
    result: {
      query: q,
      mode,
      total: all.length,
      victims,
      byGroup: tally(all.map((v) => v.group)),
      byCountry: tally(all.map((v) => v.country)),
      bySector: tally(all.map((v) => v.sector)),
      note: 'These are claims posted by ransomware groups on their leak sites. Groups sometimes exaggerate or list the wrong company; confirm with the organization before acting.',
    },
    signals,
    provenance,
  };
}
