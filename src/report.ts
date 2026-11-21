/**
 * Weekly report: a single self-contained HTML file summarizing what Oculon saw over N days: top signals,
 * narratives, case files, watchlist and fence changes, scoops, market disagreements, sanctions hits, company
 * health and calibration. Written locally; nothing is uploaded.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { oculonHome } from './core/paths.js';
import type { Signal } from './core/types.js';
import type { Oculon } from './index.js';

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const safeUrl = (u?: string) => (u && /^https?:\/\//.test(u) ? esc(u) : '');

/** One line per story: titles that differ only in their numbers ("+1663%" vs "+1851%") collapse to the strongest. */
export function dedupeSignals(signals: Signal[]): Signal[] {
  const seen = new Set<string>();
  return signals.filter((s) => {
    const k = `${s.module}|${s.title.replace(/[+\-~]?\d[\d,.]*\s*%?/g, '#').toLowerCase()}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function signalList(input: Signal[], max = 15): string {
  const signals = dedupeSignals(input);
  if (!signals.length) return '<p class="muted">Nothing in this period.</p>';
  return `<ul>${signals
    .slice(0, max)
    .map((s) => {
      const link = s.evidence.find((e) => e.url)?.url;
      return `<li><span class="score">${Math.round(s.score)}</span> ${esc(s.title)} <span class="muted">${esc(s.module)} · ${esc(s.createdAt.slice(0, 10))}</span>${link ? ` <a href="${safeUrl(link)}">source</a>` : ''}</li>`;
    })
    .join('')}</ul>`;
}

export async function buildReport(o: Oculon, opts: { days?: number; out?: string } = {}): Promise<{ file: string; html: string; counts: Record<string, number> }> {
  const days = opts.days ?? 7;
  const nowMs = o.ctx.now().getTime();
  const since = nowMs - days * 86_400_000;
  const all = o.ctx.graph.recentSignals(5000).filter((s) => Date.parse(s.createdAt) >= since);
  const by = (m: string | string[]) => all.filter((s) => (Array.isArray(m) ? m.includes(s.module) : s.module === m)).sort((a, b) => b.score - a.score);
  const top = [...all].filter((s) => !['meerkat', 'fence'].includes(s.module)).sort((a, b) => b.score - a.score);

  const { listNarratives } = await import('./modules/narratives.js');
  const narratives = listNarratives(o.ctx, days);
  const cases = (await o.caseList()).filter((k) => Date.parse(k.updatedAt) >= since);
  const scoops = o.scoops();
  const { loadCalibration } = await import('./modules/calibrate.js');
  const cal = loadCalibration(o.ctx);
  const healthRows = o.ctx.store.db.prepare('SELECT company, day, score FROM health WHERE day >= ? ORDER BY day DESC').all(new Date(since).toISOString().slice(0, 10)) as { company: string; day: string; score: number }[];
  const latestHealth = [...new Map(healthRows.map((h) => [h.company, h])).values()];
  const forecasts = o.scoreboard();
  const from = new Date(since).toISOString().slice(0, 10);
  const to = new Date(nowMs).toISOString().slice(0, 10);

  const section = (title: string, body: string) => `<section><h2>${esc(title)}</h2>${body}</section>`;
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Oculon report ${esc(from)} to ${esc(to)}</title>
<style>
:root{--bg:#0b0e13;--panel:#12161d;--line:#232a35;--text:#e6e9ef;--muted:#8a94a6;--accent:#6ee7b7;--link:#60a5fa}
@media (prefers-color-scheme: light){:root{--bg:#f5f6f8;--panel:#fff;--line:#dfe3ea;--text:#151a22;--muted:#5d6778;--accent:#059669;--link:#2563eb}}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px} h1 span{color:var(--accent)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 10px}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-top:16px}
ul{margin:0;padding-left:18px} li{margin:4px 0}
a{color:var(--link);text-decoration:none} .muted{color:var(--muted);font-size:13px}
.score{display:inline-block;min-width:26px;font:600 12px ui-monospace,Consolas,monospace;color:var(--accent)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.kpi{border:1px solid var(--line);border-radius:8px;padding:8px 10px} .kpi b{display:block;font:700 20px ui-monospace,Consolas,monospace}
</style></head><body><main>
<h1>OCU<span>LON</span> report</h1>
<p class="muted">${esc(from)} to ${esc(to)} · ${all.length} signals · generated ${esc(new Date(nowMs).toISOString().slice(0, 16).replace('T', ' '))} UTC</p>
${section(
  'At a glance',
  `<div class="kpis"><div class="kpi"><b>${all.length}</b>signals</div><div class="kpi"><b>${narratives.length}</b>active narratives</div><div class="kpi"><b>${cases.length}</b>case files updated</div><div class="kpi"><b>${by('meerkat').length + by('fence').length}</b>watch & fence changes</div><div class="kpi"><b>${scoops.oculonFirst}/${scoops.covered}</b>times ahead of media</div><div class="kpi"><b>${forecasts.resolved}</b>forecasts resolved</div></div>`,
)}
${section('Top signals', signalList(top, 20))}
${section('Narratives', narratives.length ? `<ul>${narratives.slice(0, 12).map((n) => `<li><b>${esc(n.name)}</b> <span class="muted">${n.total} stories · ${esc(n.phase.toLowerCase())}</span>${n.latest[0]?.url?.startsWith('http') ? ` <a href="${safeUrl(n.latest[0].url)}">latest</a>` : ''}</li>`).join('')}</ul>` : '<p class="muted">No narratives tracked in this period.</p>')}
${section('Case files', cases.length ? `<ul>${cases.map((k) => `<li><b>#${k.id} ${esc(k.question)}</b><br>${esc(k.report?.answer ?? '')} <span class="muted">(${esc(k.report?.confidence ?? '-')} confidence, ${k.report?.findings.length ?? 0} findings)</span></li>`).join('')}</ul>` : '<p class="muted">No case files updated.</p>')}
${section('Watchlist and fence changes', signalList([...by('meerkat'), ...by('fence')].sort((a, b) => b.createdAt.localeCompare(a.createdAt)), 25))}
${section('Sanctions', signalList(by('sanctions')))}
${section('Robinhood Chain', signalList(by('heron')))}
${section('Markets and launches', signalList([...by('lynx'), ...by('launch')]))}
${section('Company health', latestHealth.length ? `<ul>${latestHealth.map((h) => `<li><b>${esc(h.company)}</b> ${h.score}/100 <span class="muted">${esc(h.day)}</span></li>`).join('')}</ul>` : '<p class="muted">No company scored yet (oculon health &lt;company&gt;).</p>')}
${section('First to know', `<p>${scoops.checked} signals checked against Guardian, NYT and GNews: Oculon first ${scoops.oculonFirst}, media first ${scoops.mediaFirst}${scoops.medianLeadHours !== null ? `, median lead ${scoops.medianLeadHours}h` : ''}.</p>`)}
${section('Calibration', cal ? `<p>${cal.samples} replayed radar items over ${cal.days} days; ${cal.materialized} became news within 3 days. Signal threshold: ${cal.best?.threshold ?? 55}${cal.best?.precision != null ? ` (precision ${cal.best.precision}, recall ${cal.best.recall})` : ''}.</p>` : '<p class="muted">Not calibrated yet (oculon calibrate).</p>')}
<p class="muted">Every item links to its source. Signals are generated automatically from public data; verify before acting on them.</p>
</main></body></html>`;

  const dir = join(oculonHome(), 'reports');
  mkdirSync(dir, { recursive: true });
  const file = opts.out ?? join(dir, `oculon-report-${to}.html`);
  writeFileSync(file, html);
  return { file, html, counts: { signals: all.length, narratives: narratives.length, cases: cases.length } };
}
