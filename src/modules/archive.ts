/**
 * Keep evidence of a page: ask the Internet Archive's Wayback Machine to save it now (Save Page Now, free and
 * keyless), and fetch the page here too, recording its final address, status, title and the SHA-256 of what was
 * served. The snapshot link stays valid after a scam site is taken down; the check id and its PDF report keep the
 * hash and time. When saving fails (the archive is busy, or the site blocks it), the newest existing snapshot is
 * given instead, and the result says so.
 */
import { createHash } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import { publicUrl } from '../core/safeurl.js';
import { key } from '../core/keys.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export interface ArchiveReport {
  url: string;
  verdict: 'saved now' | 'earlier snapshot only' | 'not archived';
  risk: number;
  snapshot: string | null;
  snapshotTime: string | null;
  page: { status: number; finalUrl: string; title: string | null; sha256: string; bytes: number; server: string | null } | null;
  fetchedAt: string;
  reasons: string[];
  advice: string[];
}

const stamp = (s: string) => `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`;

/**
 * Save Page Now. With archive.org S3 keys (ARCHIVE_ACCESS_KEY, ARCHIVE_SECRET_KEY, free) the logged-in API is
 * used: a capture job is started and polled until it finishes, with far fewer "busy" answers. Without keys,
 * the anonymous save URL is opened. Either way the answer looks like a page whose final URL is the snapshot.
 */
async function savePage(ctx: Ctx, url: string, provenance: Provenance[]): Promise<Awaited<ReturnType<Ctx['http']['getPage']>>> {
  const ak = key('ARCHIVE_ACCESS_KEY'), sk = key('ARCHIVE_SECRET_KEY');
  if (!ak || !sk) return ctx.http.getPage(`https://web.archive.org/save/${url}`, { source: 'wayback-save', timeoutMs: 120_000, maxBytes: 200_000 });
  const auth = { authorization: `LOW ${ak}:${sk}`, accept: 'application/json' };
  const start = await ctx.http.postBytes('https://web.archive.org/save', new TextEncoder().encode(new URLSearchParams({ url, skip_first_archive: '1', if_not_archived_within: '1h' }).toString()), { source: 'wayback-save', headers: { ...auth, 'content-type': 'application/x-www-form-urlencoded' }, timeoutMs: 60_000, retries: 0 });
  let job: { job_id?: string; message?: string } = {};
  try { job = start.data ? JSON.parse(start.data.toString('utf8')) : {}; } catch {}
  if (!job.job_id) return { data: null, prov: { ...start.prov, status: 'ERROR', note: job.message?.slice(0, 120) ?? start.prov.note ?? 'no capture job' } };
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, i === 0 ? 3000 : 5000));
    const st = await ctx.http.getPage(`https://web.archive.org/save/status/${job.job_id}`, { source: 'wayback-status', headers: auth, timeoutMs: 20_000, maxBytes: 50_000 });
    let s: { status?: string; timestamp?: string; original_url?: string; message?: string } = {};
    try { s = st.data ? JSON.parse(st.data.body.toString('utf8')) : {}; } catch {}
    if (s.status === 'success' && s.timestamp) return { data: { status: 200, finalUrl: `https://web.archive.org/web/${s.timestamp}/${s.original_url ?? url}`, headers: {}, body: Buffer.alloc(0) }, prov: st.prov };
    if (s.status === 'error') return { data: null, prov: { ...st.prov, status: 'ERROR', note: (s.message ?? 'capture failed').slice(0, 120) } };
  }
  provenance.push({ source: 'wayback-save', url: 'https://web.archive.org/save', status: 'ERROR', fetchedAt: ctx.now().toISOString(), note: 'capture still running after 100 s' });
  return { data: null, prov: { source: 'wayback-save', url: 'https://web.archive.org/save', status: 'ERROR', fetchedAt: ctx.now().toISOString(), note: 'capture still running after 100 s' } };
}

export async function archivePage(ctx: Ctx, input: string): Promise<ModuleResult<ArchiveReport>> {
  const u = publicUrl(input);
  const provenance: Provenance[] = [];
  const reasons: string[] = [];
  const fetchedAt = ctx.now().toISOString();
  const [own, save] = await Promise.all([
    ctx.http.getPage(u.href, { source: 'archive-fetch', timeoutMs: 25_000 }),
    savePage(ctx, u.href, provenance),
  ]);
  provenance.push(own.prov, save.prov);
  let page: ArchiveReport['page'] = null;
  if (own.data) {
    const html = own.data.body.toString('utf8');
    page = { status: own.data.status, finalUrl: own.data.finalUrl, title: /<title[^>]*>([^<]{1,200})<\/title>/i.exec(html)?.[1]?.trim() ?? null, sha256: createHash('sha256').update(own.data.body).digest('hex'), bytes: own.data.body.length, server: own.data.headers.server ?? null };
    reasons.push(`fetched here at ${fetchedAt.slice(0, 19).replace('T', ' ')} UTC: HTTP ${page.status}, ${page.bytes.toLocaleString('en-US')} bytes, SHA-256 ${page.sha256.slice(0, 16)}...`);
    if (page.finalUrl !== u.href) reasons.push(`redirected to ${page.finalUrl}`);
  } else reasons.push(`the page did not open from here (${own.prov.note ?? own.prov.status})`);

  let snapshot: string | null = null, snapshotTime: string | null = null, verdict: ArchiveReport['verdict'] = 'not archived';
  const m = save.data ? /\/web\/(\d{14})\//.exec(save.data.finalUrl) ?? /\/web\/(\d{14})\//.exec(save.data.headers['content-location'] ?? '') : null;
  if (m) { snapshot = `https://web.archive.org/web/${m[1]}/${u.href}`; snapshotTime = stamp(m[1]!); verdict = 'saved now'; }
  else {
    const a = await ctx.http.get<{ archived_snapshots?: { closest?: { url?: string; timestamp?: string; available?: boolean } } }>(`https://archive.org/wayback/available?url=${encodeURIComponent(u.href)}`, { source: 'wayback', ttlSec: 300 });
    provenance.push(a.prov);
    const c = a.data?.archived_snapshots?.closest;
    if (c?.available && c.url) { snapshot = c.url.replace(/^http:/, 'https:'); snapshotTime = c.timestamp ? stamp(c.timestamp) : null; verdict = 'earlier snapshot only'; reasons.push(`the Wayback Machine did not save it now (${save.prov.note ?? save.data?.status ?? save.prov.status}); its newest copy is from ${snapshotTime?.slice(0, 10) ?? 'earlier'}`); }
    else reasons.push(`the Wayback Machine did not save it (${save.prov.note ?? save.data?.status ?? save.prov.status}) and has no earlier copy`);
  }
  if (snapshot && verdict === 'saved now') {
    const age = snapshotTime ? (Date.parse(fetchedAt) - Date.parse(snapshotTime)) / 60_000 : 0;
    reasons.unshift(age > 5 ? `the Wayback Machine already had a copy from ${Math.round(age)} minutes ago and kept it: ${snapshot}` : `saved in the Wayback Machine: ${snapshot}`);
  }
  const advice = snapshot
    ? ['Keep the snapshot link and this check id (its PDF report records the time and the hash) when you report the site.', 'Report the site: Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish), the domain\'s registrar, and the brand it copies.']
    : ['Take screenshots with the address bar visible, and try again later: the archive is often busy.'];
  return { module: 'archive', input: u.href, generatedAt: fetchedAt, signals: [], provenance, result: { url: u.href, verdict, risk: 0, snapshot, snapshotTime, page, fetchedAt, reasons, advice } };
}
