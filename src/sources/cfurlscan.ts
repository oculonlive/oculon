/**
 * Cloudflare URL Scanner: opens a page in a real browser on Cloudflare's side (scripts run, redirects followed)
 * and reports its verdict, the domains it contacted, the scripts it loaded and the rendered page.
 * Needs CLOUDFLARE_ACCOUNT_ID and a CLOUDFLARE_API_TOKEN with the URL Scanner permission (free). Scans are
 * unlisted and take 10 to 60 seconds.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import type { Provenance } from '../core/types.js';

export interface BrowserScan {
  malicious: boolean;
  categories: string[];
  tags: string[];
  report: string;
  finalUrl: string | null;
  domains: string[];
  scripts: string[];
  dom: string | null;
}

interface Result {
  task?: { status?: string; reportURL?: string; url?: string; domURL?: string };
  verdicts?: { overall?: { malicious?: boolean; categories?: ({ name?: string } | string)[]; tags?: string[] } };
  lists?: { domains?: string[]; urls?: string[] };
  data?: { requests?: { request?: { url?: string; type?: string; resourceType?: string }; response?: { mimeType?: string } }[] };
  page?: { url?: string };
}

export async function browserScan(ctx: Ctx, url: string, opts: { waitSec?: number } = {}): Promise<{ data: BrowserScan | null; prov: Provenance | null }> {
  const token = key('CLOUDFLARE_API_TOKEN'), account = key('CLOUDFLARE_ACCOUNT_ID');
  if (!token || !account) return { data: null, prov: null };
  const base = `https://api.cloudflare.com/client/v4/accounts/${account}/urlscanner/v2`;
  const shown = 'https://api.cloudflare.com/client/v4/accounts/***/urlscanner/v2';
  const auth = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
  const sub = await ctx.http.postBytes(`${base}/scan`, new TextEncoder().encode(JSON.stringify({ url, visibility: 'Unlisted' })), { source: 'cf-urlscan', headers: auth, timeoutMs: 30_000, retries: 0 });
  let uuid: string | undefined;
  try { uuid = sub.data ? (JSON.parse(sub.data.toString('utf8')) as { uuid?: string }).uuid : undefined; } catch {}
  if (!uuid) return { data: null, prov: { ...sub.prov, url: shown, status: 'ERROR', note: sub.prov.note ?? 'scan not started' } };
  const until = Date.now() + (opts.waitSec ?? 60) * 1000;
  await new Promise((r) => setTimeout(r, 8000));
  while (Date.now() < until) {
    const r = await ctx.http.getPage(`${base}/result/${uuid}`, { source: 'cf-urlscan', headers: { authorization: `Bearer ${token}` }, timeoutMs: 20_000, maxBytes: 8_000_000 });
    if (r.data?.status === 200) {
      let j: Result = {};
      try { j = JSON.parse(r.data.body.toString('utf8')) as Result; } catch {}
      const o = j.verdicts?.overall ?? {};
      const reqs = j.data?.requests ?? [];
      const scripts = [...new Set(reqs.filter((q) => /script/i.test(q.request?.resourceType ?? q.request?.type ?? '') || /javascript/i.test(q.response?.mimeType ?? '')).map((q) => q.request?.url ?? '').filter((u) => /^https?:/.test(u)))].slice(0, 40);
      let dom: string | null = null;
      if (j.task?.domURL) {
        const d = await ctx.http.getPage(j.task.domURL, { source: 'cf-urlscan', headers: { authorization: `Bearer ${token}` }, timeoutMs: 20_000, maxBytes: 3_000_000 });
        if (d.data?.status === 200) dom = d.data.body.toString('utf8');
      }
      return {
        data: { malicious: Boolean(o.malicious), categories: (o.categories ?? []).map((c) => (typeof c === 'string' ? c : c.name ?? '')).filter(Boolean), tags: o.tags ?? [], report: j.task?.reportURL ?? `https://radar.cloudflare.com/scan/${uuid}`, finalUrl: j.page?.url ?? null, domains: (j.lists?.domains ?? []).slice(0, 40), scripts, dom },
        prov: { ...r.prov, url: `${shown}/result/${uuid}` },
      };
    }
    if (r.data && r.data.status !== 404) return { data: null, prov: { ...r.prov, url: shown, status: 'ERROR', note: `HTTP ${r.data.status}` } };
    await new Promise((res) => setTimeout(res, 5000));
  }
  return { data: null, prov: { source: 'cf-urlscan', url: shown, status: 'ERROR', fetchedAt: ctx.now().toISOString(), note: `scan still running after ${opts.waitSec ?? 60} s` } };
}
