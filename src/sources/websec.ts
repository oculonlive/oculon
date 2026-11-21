/** Web security footprints: urlscan.io scan history, Google Safe Browsing. */
import { enc, type Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Sourced } from '../core/types.js';
import { postJson } from './press.js';

export interface Scan {
  url: string;
  host: string;
  time: string;
  ip: string | null;
  country: string | null;
  server: string | null;
  screenshot: string;
}

/** Recent urlscan.io scans of pages on the domain (any subdomain). */
export async function urlscan(ctx: Ctx, domain: string, size = 100): Promise<Sourced<Scan[]>> {
  const k = key('URLSCAN_API_KEY');
  const r = await ctx.http.get<{ results?: { _id: string; page?: { url?: string; domain?: string; ip?: string; country?: string; server?: string }; task?: { time?: string }; screenshot?: string }[] }>(
    `https://urlscan.io/api/v1/search/?q=${enc(`page.apexDomain:${domain}`)}&size=${size}`,
    { source: 'urlscan', ttlSec: 3 * 3600, ...(k ? { headers: { 'api-key': k } } : {}) },
  );
  return {
    data:
      r.data?.results?.map((s) => ({
        url: s.page?.url ?? '',
        host: (s.page?.domain ?? '').toLowerCase(),
        time: s.task?.time ?? '',
        ip: s.page?.ip ?? null,
        country: s.page?.country ?? null,
        server: s.page?.server ?? null,
        screenshot: s.screenshot ?? `https://urlscan.io/screenshots/${s._id}.png`,
      })) ?? null,
    prov: r.prov,
  };
}

/** URLs that Google Safe Browsing flags (malware, phishing, unwanted software). */
export async function safeBrowsing(ctx: Ctx, urls: string[]): Promise<Sourced<{ url: string; threat: string }[]>> {
  const k = key('SAFE_BROWSING_KEY');
  if (!k) return noKey('safe-browsing', 'SAFE_BROWSING_KEY');
  if (!urls.length) return { data: [], prov: { source: 'safe-browsing', url: '', status: 'LIVE', fetchedAt: new Date().toISOString(), note: 'nothing to check' } };
  const r = await postJson<{ matches?: { threat: { url: string }; threatType: string }[] }>(
    ctx,
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${k}`,
    {
      client: { clientId: 'oculon', clientVersion: '0.1' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: urls.slice(0, 500).map((url) => ({ url })),
      },
    },
    {},
    'safe-browsing',
  );
  // The request URL carries the key; keep it out of provenance.
  return { data: r.data ? (r.data.matches ?? []).map((m) => ({ url: m.threat.url, threat: m.threatType })) : null, prov: { ...r.prov, url: 'https://safebrowsing.googleapis.com/v4/threatMatches:find' } };
}
