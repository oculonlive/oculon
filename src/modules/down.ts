/**
 * Is it down? A board of popular services and whether they work right now.
 *   Official status pages: Atlassian Statuspage `summary.json` (overall indicator, components with problems,
 *     open incidents) and Slack's own status API. These say what the company itself reports.
 *   Our probe: for big services without a public status JSON (X, Google, YouTube, Instagram, WhatsApp, Telegram...)
 *     the server makes one small HTTPS request and records the status code and latency. That is one probe from one
 *     location, never an official outage report, and every such result says so.
 * Answers are cached for two and a half minutes.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export type DownState = 'operational' | 'degraded' | 'outage' | 'unknown';
type Kind = 'statuspage' | 'slack' | 'probe';

interface ServiceDef { id: string; name: string; category: string; kind: Kind; url: string; page: string }

const sp = (id: string, name: string, category: string, base: string): ServiceDef => ({ id, name, category, kind: 'statuspage', url: `${base}/api/v2/summary.json`, page: base });
const probe = (id: string, name: string, category: string, url: string, page: string): ServiceDef => ({ id, name, category, kind: 'probe', url, page });

/** Every status page here was checked to answer `summary.json` (November 2026). */
export const SERVICES: ServiceDef[] = [
  probe('x', 'X (Twitter)', 'social', 'https://x.com/robots.txt', 'https://x.com'),
  probe('google', 'Google Search', 'web', 'https://www.google.com/generate_204', 'https://www.google.com'),
  probe('youtube', 'YouTube', 'social', 'https://www.youtube.com/generate_204', 'https://www.youtube.com'),
  probe('instagram', 'Instagram', 'social', 'https://www.instagram.com/robots.txt', 'https://www.instagram.com'),
  probe('facebook', 'Facebook', 'social', 'https://www.facebook.com/robots.txt', 'https://www.facebook.com'),
  probe('whatsapp', 'WhatsApp Web', 'messaging', 'https://web.whatsapp.com/robots.txt', 'https://web.whatsapp.com'),
  probe('telegram', 'Telegram', 'messaging', 'https://telegram.org/favicon.ico', 'https://telegram.org'),
  probe('tiktok', 'TikTok', 'social', 'https://www.tiktok.com/robots.txt', 'https://www.tiktok.com'),
  probe('spotify', 'Spotify', 'media', 'https://open.spotify.com/robots.txt', 'https://open.spotify.com'),
  probe('netflix', 'Netflix', 'media', 'https://www.netflix.com/robots.txt', 'https://www.netflix.com'),
  probe('amazon', 'Amazon', 'shopping', 'https://www.amazon.com/robots.txt', 'https://www.amazon.com'),
  { id: 'slack', name: 'Slack', category: 'work', kind: 'slack', url: 'https://slack-status.com/api/v2.0.0/current', page: 'https://slack-status.com' },
  sp('discord', 'Discord', 'messaging', 'https://discordstatus.com'),
  sp('reddit', 'Reddit', 'social', 'https://www.redditstatus.com'),
  sp('twitch', 'Twitch', 'media', 'https://status.twitch.com'),
  sp('pinterest', 'Pinterest', 'social', 'https://www.pintereststatus.com'),
  sp('openai', 'OpenAI (ChatGPT)', 'ai', 'https://status.openai.com'),
  sp('claude', 'Claude (Anthropic)', 'ai', 'https://status.claude.com'),
  sp('github', 'GitHub', 'developer', 'https://www.githubstatus.com'),
  sp('cloudflare', 'Cloudflare', 'infrastructure', 'https://www.cloudflarestatus.com'),
  sp('vercel', 'Vercel', 'developer', 'https://www.vercel-status.com'),
  sp('netlify', 'Netlify', 'developer', 'https://www.netlifystatus.com'),
  sp('digitalocean', 'DigitalOcean', 'infrastructure', 'https://status.digitalocean.com'),
  sp('npm', 'npm', 'developer', 'https://status.npmjs.org'),
  sp('docker', 'Docker Hub', 'developer', 'https://www.dockerstatus.com'),
  sp('twilio', 'Twilio', 'developer', 'https://status.twilio.com'),
  sp('zoom', 'Zoom', 'work', 'https://www.zoomstatus.com'),
  sp('dropbox', 'Dropbox', 'work', 'https://status.dropbox.com'),
  sp('notion', 'Notion', 'work', 'https://www.notion-status.com'),
  sp('figma', 'Figma', 'work', 'https://status.figma.com'),
  sp('canva', 'Canva', 'work', 'https://www.canvastatus.com'),
  sp('atlassian', 'Atlassian (Jira, Confluence)', 'work', 'https://status.atlassian.com'),
  sp('shopify', 'Shopify', 'shopping', 'https://www.shopifystatus.com'),
  sp('coinbase', 'Coinbase', 'crypto', 'https://status.coinbase.com'),
  sp('kraken', 'Kraken', 'crypto', 'https://status.kraken.com'),
  sp('robinhood', 'Robinhood', 'finance', 'https://status.robinhood.com'),
  sp('ledger', 'Ledger', 'crypto', 'https://status.ledger.com'),
  sp('epicgames', 'Epic Games (Fortnite)', 'gaming', 'https://status.epicgames.com'),
  sp('duolingo', 'Duolingo', 'apps', 'https://status.duolingo.com'),
  sp('1password', '1Password', 'security', 'https://status.1password.com'),
  sp('proton', 'Proton (Mail, VPN)', 'security', 'https://status.proton.me'),
];

export interface DownIncident { title: string; impact: string; status: string; started: string | null; updated: string | null; detail: string; url: string }

export interface DownService {
  id: string;
  name: string;
  category: string;
  state: DownState;
  /** Who says so: "official status page" or "our probe from one location". */
  source: string;
  official: boolean;
  summary: string;
  page: string;
  components: { name: string; status: string }[];
  incidents: DownIncident[];
  /** `answer` is "2xx" for any success code, otherwise the exact HTTP status, or null when nothing answered. */
  probe: { url: string; answer: string | null; latencyMs: number | null; error: string | null } | null;
  checkedAt: string;
}

export interface DownReport {
  checked: number;
  counts: Record<DownState, number>;
  services: DownService[];
  note: string;
}

const CACHE_SEC = 150;
const PROBE_TIMEOUT_MS = 8000;
const SLOW_MS = 4000;
const RANK: Record<DownState, number> = { outage: 0, degraded: 1, unknown: 2, operational: 3 };
const OFFICIAL = 'official status page';
const PROBE = 'our probe from one location';
const NOTE = 'Official status pages report what each company says about itself. Services marked "our probe from one location" have no public status feed: Oculon makes one small HTTPS request from its own server, so a failed probe can also be a problem on our side or in one region, and it is not an official outage report.';

const strip = (s: string) => s.replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, ' ').trim();

interface SpIncident { name: string; status: string; impact?: string; created_at?: string; updated_at?: string; shortlink?: string; incident_updates?: { body?: string }[] }
interface SpComponent { name: string; status: string; group?: boolean }
interface SpSummary { status?: { indicator?: string; description?: string }; components?: SpComponent[]; incidents?: SpIncident[] }

/**
 * Trim a summary before caching: only components with a problem and the first update of each incident.
 * The cloud outage module reads the same URL from the cache, so the fields it uses are kept.
 */
export function trimSummary(d: SpSummary): SpSummary {
  return {
    status: d.status,
    components: (d.components ?? []).filter((c) => c.status && c.status !== 'operational').slice(0, 40).map((c) => ({ name: c.name, status: c.status, group: c.group })),
    incidents: (d.incidents ?? []).slice(0, 10).map((i) => ({ name: i.name, status: i.status, impact: i.impact, created_at: i.created_at, updated_at: i.updated_at, shortlink: i.shortlink, incident_updates: (i.incident_updates ?? []).slice(0, 1).map((u) => ({ body: u.body })) })),
  };
}

const COMPONENT_WORDS: Record<string, string> = { degraded_performance: 'degraded performance', partial_outage: 'partial outage', major_outage: 'major outage', under_maintenance: 'maintenance' };

/** Turn a Statuspage summary into a state. */
export function readSummary(d: SpSummary): Pick<DownService, 'state' | 'summary' | 'components' | 'incidents'> {
  const comps = (d.components ?? []).filter((c) => c.status && c.status !== 'operational' && !c.group).slice(0, 12).map((c) => ({ name: c.name, status: COMPONENT_WORDS[c.status] ?? c.status.replace(/_/g, ' ') }));
  const incidents = (d.incidents ?? []).slice(0, 8).map((i) => ({ title: i.name, impact: i.impact ?? 'unknown', status: i.status, started: i.created_at ?? null, updated: i.updated_at ?? null, detail: strip(i.incident_updates?.[0]?.body ?? '').slice(0, 400), url: i.shortlink ?? '' }));
  const ind = d.status?.indicator ?? '';
  const anyMajor = (d.components ?? []).some((c) => c.status === 'major_outage');
  let state: DownState;
  if (ind === 'major' || ind === 'critical') state = 'outage';
  else if (ind === 'minor' || ind === 'maintenance' || comps.length || incidents.length) state = anyMajor && ind !== 'none' ? 'outage' : 'degraded';
  else if (ind === 'none') state = 'operational';
  else state = 'unknown';
  let summary = d.status?.description || (state === 'operational' ? 'All Systems Operational' : state);
  if (state !== 'operational' && /all systems operational/i.test(summary)) summary = incidents.length ? `${incidents.length} open incident${incidents.length === 1 ? '' : 's'}` : `${comps.length} component${comps.length === 1 ? '' : 's'} with problems`;
  return { state, summary, components: comps, incidents };
}

interface SlackCurrent { status?: string; date_updated?: string; active_incidents?: { title?: string; type?: string; status?: string; date_created?: string; date_updated?: string; url?: string; notes?: { body?: string }[] }[] }

export function readSlack(d: SlackCurrent): Pick<DownService, 'state' | 'summary' | 'components' | 'incidents'> {
  const list = d.active_incidents ?? [];
  const incidents = list.slice(0, 8).map((i) => ({ title: i.title ?? 'incident', impact: i.type ?? 'unknown', status: i.status ?? 'active', started: i.date_created ?? null, updated: i.date_updated ?? null, detail: strip(i.notes?.[0]?.body ?? '').slice(0, 400), url: i.url ?? 'https://slack-status.com' }));
  if (d.status === 'ok' && !list.length) return { state: 'operational', summary: 'No active incidents', components: [], incidents };
  if (!d.status && !list.length) return { state: 'unknown', summary: 'unrecognised answer', components: [], incidents };
  const outage = list.some((i) => i.type === 'outage');
  return { state: outage ? 'outage' : 'degraded', summary: `${list.length} active incident${list.length === 1 ? '' : 's'}${outage ? ', including an outage' : ''}`, components: [], incidents };
}

/** What one probe answer means. Any HTTP answer below 500 shows the service is reachable. */
export function readProbe(answer: string | null, latencyMs: number | null, error: string | null): Pick<DownService, 'state' | 'summary'> {
  if (answer === null) return { state: 'outage', summary: `Our probe got no answer${error ? ` (${error})` : ''}. One location only; not an official outage report.` };
  const code = answer === '2xx' ? 'a success code (2xx)' : `HTTP ${answer}`;
  if (answer.startsWith('5')) return { state: 'degraded', summary: `Our probe got ${code} in ${latencyMs} ms. One location only; not an official outage report.` };
  if (latencyMs !== null && latencyMs > SLOW_MS) return { state: 'degraded', summary: `Reachable but slow: ${code} in ${latencyMs} ms from our server.` };
  return { state: 'operational', summary: `Reachable: ${code} in ${latencyMs} ms from our server.` };
}

const probeCache = new WeakMap<Ctx, Map<string, { at: number; svc: DownService; prov: Provenance }>>();

async function checkOne(ctx: Ctx, s: ServiceDef): Promise<{ svc: DownService; prov: Provenance }> {
  const nowIso = ctx.now().toISOString();
  const base = { id: s.id, name: s.name, category: s.category, page: s.page, components: [], incidents: [], probe: null, checkedAt: nowIso };
  if (s.kind === 'probe') {
    let cache = probeCache.get(ctx);
    if (!cache) probeCache.set(ctx, (cache = new Map()));
    const hit = cache.get(s.id);
    if (hit && ctx.now().getTime() - hit.at < CACHE_SEC * 1000) return { svc: hit.svc, prov: { ...hit.prov, status: 'CACHED' } };
    const t0 = Date.now();
    const r = await ctx.http.getBytes(s.url, { source: 'down-probe', timeoutMs: PROBE_TIMEOUT_MS, retries: 0, headers: { 'cache-control': 'no-cache' } });
    const ms = Date.now() - t0;
    const answer = r.data ? '2xx' : /^HTTP (\d{3})/.exec(r.prov.note ?? '')?.[1] ?? null;
    const err = answer === null ? (r.prov.note ?? 'no answer') : null;
    const read = readProbe(answer, answer === null ? null : ms, err);
    const svc: DownService = { ...base, ...read, source: PROBE, official: false, probe: { url: s.url, answer, latencyMs: answer === null ? null : ms, error: err } };
    // A 4xx (bot protection, 404) is an answer: the probe itself worked.
    const prov: Provenance = { source: 'down-probe', url: s.url, status: answer === null ? 'ERROR' : 'LIVE', fetchedAt: nowIso, note: `${s.name}: our probe from one location, ${answer ? `${answer === '2xx' ? '2xx' : `HTTP ${answer}`} in ${ms} ms` : err}` };
    cache.set(s.id, { at: ctx.now().getTime(), svc, prov });
    return { svc, prov };
  }
  if (s.kind === 'slack') {
    const r = await ctx.http.get<SlackCurrent>(s.url, { source: 'down-status', ttlSec: CACHE_SEC, timeoutMs: 10_000, retries: 1 });
    if (!r.data) return { svc: { ...base, state: 'unknown', summary: `The status page did not answer (${r.prov.note ?? r.prov.status}).`, source: OFFICIAL, official: true }, prov: { ...r.prov, note: `${s.name}: ${r.prov.note ?? r.prov.status}` } };
    return { svc: { ...base, ...readSlack(r.data), source: OFFICIAL, official: true }, prov: r.prov };
  }
  const r = await ctx.http.get<SpSummary>(s.url, { source: 'down-status', ttlSec: CACHE_SEC, timeoutMs: 10_000, retries: 1, keep: trimSummary });
  if (!r.data) return { svc: { ...base, state: 'unknown', summary: `The status page did not answer (${r.prov.note ?? r.prov.status}).`, source: OFFICIAL, official: true }, prov: { ...r.prov, note: `${s.name}: ${r.prov.note ?? r.prov.status}` } };
  return { svc: { ...base, ...readSummary(r.data), source: OFFICIAL, official: true, ...(r.prov.status === 'CACHED' ? { checkedAt: r.prov.fetchedAt } : {}) }, prov: r.prov };
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]!); } }));
  return out;
}

export function findService(q: string): ServiceDef | undefined {
  const k = q.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  const flat = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  return SERVICES.find((s) => s.id === k) ?? SERVICES.find((s) => flat(s.name) === flat(k) || new URL(s.page).hostname.replace(/^www\./, '') === k)
    ?? (flat(k).length >= 3 ? SERVICES.find((s) => flat(s.name).startsWith(flat(k))) : undefined)
    ?? (k === 'twitter' ? SERVICES.find((s) => s.id === 'x') : k === 'chatgpt' ? SERVICES.find((s) => s.id === 'openai') : k === 'anthropic' ? SERVICES.find((s) => s.id === 'claude') : undefined);
}

/** All services (problems first), or one when `service` names it by id, name or domain. */
export async function downStatus(ctx: Ctx, service?: string): Promise<ModuleResult<DownReport>> {
  let defs = SERVICES;
  if (service?.trim()) {
    const one = findService(service);
    if (!one) throw new Error(`not a service on the board: ${service.trim().slice(0, 60)}. Known: ${SERVICES.map((s) => s.id).join(', ')}`);
    defs = [one];
  }
  const done = await pool(defs, 10, (s) => checkOne(ctx, s));
  const services = done.map((d) => d.svc).sort((a, b) => RANK[a.state] - RANK[b.state] || a.name.localeCompare(b.name));
  const counts: Record<DownState, number> = { outage: 0, degraded: 0, unknown: 0, operational: 0 };
  for (const s of services) counts[s.state]++;
  return {
    module: 'down',
    input: defs.length === 1 ? defs[0]!.id : 'all services',
    generatedAt: ctx.now().toISOString(),
    result: { checked: services.length, counts, services, note: NOTE },
    signals: [],
    provenance: done.map((d) => d.prov),
  };
}
