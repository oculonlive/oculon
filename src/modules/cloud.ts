/**
 * Cloud and service outage radar (no keys): official status pages of the platforms the internet runs on.
 *   Atlassian Statuspage services (GitHub, Cloudflare, OpenAI, Anthropic, Discord, Reddit, Atlassian, Vercel,
 *     Netlify, DigitalOcean, Twilio, Coinbase, Dropbox, npm, Zoom...): overall indicator and open incidents.
 *   Google Cloud (incidents.json), AWS Health (public current events), Azure (status RSS).
 * Major or critical incidents become signals; a cloud provider incident affecting several services scores higher.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';

export const STATUSPAGES: [string, string][] = [
  ['GitHub', 'https://www.githubstatus.com'],
  ['Cloudflare', 'https://www.cloudflarestatus.com'],
  ['OpenAI', 'https://status.openai.com'],
  ['Anthropic', 'https://status.anthropic.com'],
  ['Discord', 'https://discordstatus.com'],
  ['Reddit', 'https://www.redditstatus.com'],
  ['Atlassian', 'https://status.atlassian.com'],
  ['Vercel', 'https://www.vercel-status.com'],
  ['Netlify', 'https://www.netlifystatus.com'],
  ['DigitalOcean', 'https://status.digitalocean.com'],
  ['Twilio', 'https://status.twilio.com'],
  ['Coinbase', 'https://status.coinbase.com'],
  ['Dropbox', 'https://status.dropbox.com'],
  ['npm', 'https://status.npmjs.org'],
  ['Zoom', 'https://status.zoom.us'],
];

export interface ServiceIncident {
  service: string;
  title: string;
  impact: 'none' | 'minor' | 'major' | 'critical' | 'unknown';
  status: string;
  started: string;
  updated: string;
  detail: string;
  url: string;
}

export interface CloudStatus {
  checked: number;
  degraded: { service: string; indicator: string; description: string }[];
  incidents: ServiceIncident[];
}

const IMPACT_RANK: Record<string, number> = { critical: 3, major: 2, minor: 1, none: 0, unknown: 0 };
const strip = (s: string) => s.replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, ' ').trim();

/** AWS serves this feed as UTF-16 with a byte order mark. */
export function decodeAny(buf: Buffer): string {
  const enc = buf[0] === 0xfe && buf[1] === 0xff ? 'utf-16be' : buf[0] === 0xff && buf[1] === 0xfe ? 'utf-16le' : 'utf-8';
  return new TextDecoder(enc).decode(buf).replace(/^﻿/, '');
}

export async function cloudStatus(ctx: Ctx): Promise<ModuleResult<CloudStatus>> {
  const now = ctx.now();
  const provenance: Provenance[] = [];
  const degraded: CloudStatus['degraded'] = [];
  const incidents: ServiceIncident[] = [];

  await Promise.all(
    STATUSPAGES.map(async ([name, base]) => {
      const r = await ctx.http.get<{ status?: { indicator?: string; description?: string }; incidents?: { name: string; status: string; impact?: string; created_at: string; updated_at: string; shortlink?: string; incident_updates?: { body?: string }[] }[] }>(`${base}/api/v2/summary.json`, { source: 'statuspage', ttlSec: 300, timeoutMs: 20_000 });
      provenance.push(r.prov.status === 'LIVE' || r.prov.status === 'CACHED' ? r.prov : { ...r.prov, note: `${name}: ${r.prov.note ?? r.prov.status}` });
      const d = r.data;
      if (!d) return;
      if (d.status?.indicator && d.status.indicator !== 'none') degraded.push({ service: name, indicator: d.status.indicator, description: d.status.description ?? '' });
      for (const i of d.incidents ?? []) {
        incidents.push({ service: name, title: i.name, impact: (['none', 'minor', 'major', 'critical'].includes(i.impact ?? '') ? i.impact : 'unknown') as ServiceIncident['impact'], status: i.status, started: i.created_at, updated: i.updated_at, detail: strip(i.incident_updates?.[0]?.body ?? '').slice(0, 300), url: i.shortlink ?? base });
      }
    }),
  );

  // Google Cloud: incidents without an end are ongoing.
  const gcp = await ctx.http.get<{ begin: string; end?: string | null; modified: string; external_desc: string; severity?: string; uri?: string; most_recent_update?: { text?: string }; affected_products?: { title: string }[] }[]>('https://status.cloud.google.com/incidents.json', { source: 'gcp-status', ttlSec: 300, keep: (d: unknown[]) => (Array.isArray(d) ? d.slice(0, 40) : d) });
  provenance.push(gcp.prov);
  for (const i of gcp.data ?? []) {
    if (i.end) continue;
    incidents.push({ service: 'Google Cloud', title: i.external_desc, impact: i.severity === 'high' ? 'major' : i.severity === 'medium' ? 'minor' : 'unknown', status: 'ongoing', started: i.begin, updated: i.modified, detail: [i.affected_products?.map((p) => p.title).slice(0, 6).join(', '), strip(i.most_recent_update?.text ?? '').slice(0, 200)].filter(Boolean).join(' · '), url: i.uri ? `https://status.cloud.google.com/${i.uri}` : 'https://status.cloud.google.com' });
  }

  // AWS Health public events: keep those updated in the last 3 days.
  const aws = await ctx.http.getBytes('https://health.aws.amazon.com/public/currentevents', { source: 'aws-health', timeoutMs: 30_000 });
  provenance.push(aws.prov);
  if (aws.data) {
    try {
      const list = JSON.parse(decodeAny(aws.data)) as { date: string; region_name?: string; service_name?: string; summary?: string; status?: string; event_log?: { message?: string; timestamp?: number; summary?: string }[] }[];
      for (const e of list) {
        const last = Math.max(Number(e.date) || 0, ...(e.event_log ?? []).map((l) => l.timestamp ?? 0)) * 1000;
        if (now.getTime() - last > 3 * 86_400_000) continue;
        const lastMsg = e.event_log?.at(-1)?.message ?? '';
        incidents.push({ service: 'AWS', title: `${e.service_name ?? 'AWS'}: ${e.summary ?? 'service event'}${e.region_name ? ` (${e.region_name})` : ''}`, impact: 'major', status: 'ongoing', started: new Date(Number(e.date) * 1000).toISOString(), updated: new Date(last).toISOString(), detail: strip(lastMsg).slice(0, 300), url: 'https://health.aws.amazon.com/health/status' });
      }
    } catch {
      provenance.push({ ...aws.prov, status: 'ERROR', note: 'could not parse AWS events' });
    }
  }

  // Azure: the status RSS lists active incidents only.
  const az = await ctx.http.get<string>('https://azure.status.microsoft/en-us/status/feed/', { source: 'azure-status', as: 'text', ttlSec: 300 });
  provenance.push(az.prov);
  for (const item of (az.data ?? '').split('<item>').slice(1)) {
    const title = strip(/<title>([\s\S]*?)<\/title>/.exec(item)?.[1] ?? '');
    if (!title) continue;
    const pub = /<pubDate>([\s\S]*?)<\/pubDate>/.exec(item)?.[1];
    incidents.push({ service: 'Azure', title, impact: 'major', status: 'active', started: pub ? new Date(pub).toISOString() : now.toISOString(), updated: pub ? new Date(pub).toISOString() : now.toISOString(), detail: strip(/<description>([\s\S]*?)<\/description>/.exec(item)?.[1] ?? '').slice(0, 300), url: 'https://azure.status.microsoft/en-us/status' });
  }

  incidents.sort((a, b) => IMPACT_RANK[b.impact]! - IMPACT_RANK[a.impact]! || b.updated.localeCompare(a.updated));
  const signals: Signal[] = incidents
    .filter((i) => (i.impact === 'major' || i.impact === 'critical') && now.getTime() - Date.parse(i.updated) < 24 * 3_600_000)
    .slice(0, 5)
    .map((i) => ({
      id: signalId('cloud', i.service, i.title, i.started.slice(0, 13)),
      module: 'cloud',
      title: `${i.service} ${i.impact} incident: ${i.title}`,
      score: i.impact === 'critical' ? 80 : ['AWS', 'Azure', 'Google Cloud', 'Cloudflare'].includes(i.service) ? 72 : 64,
      evidence: [{ source: `${i.service.toLowerCase().replace(/\s+/g, '-')}-status`, text: `${i.status}, since ${i.started.slice(0, 16).replace('T', ' ')} UTC${i.detail ? `: ${i.detail.slice(0, 200)}` : ''}`, url: i.url }],
      createdAt: now.toISOString(),
    }));
  for (const s of signals) ctx.graph.saveSignal(s);
  return { module: 'cloud', input: 'status pages', generatedAt: now.toISOString(), result: { checked: STATUSPAGES.length + 3, degraded, incidents }, signals, provenance };
}
