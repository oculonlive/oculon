/**
 * Server-rendered pages for the replay log (/replay/<id>), source status (/status) and the AI-agent guides
 * (/llms.txt, /llms-full.txt). Plain HTML in the site's look; no scripts needed to read them.
 */
import type { SourceStatus } from '../core/calls.js';
import type { CheckRecord } from '../modules/checks.js';

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const when = (iso: string) => `${iso.slice(0, 16).replace('T', ' ')} UTC`;

function shell(title: string, desc: string, body: string, canonical: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><meta name="description" content="${esc(desc)}"><meta name="robots" content="noindex">
<link rel="icon" type="image/png" href="/favicon.ico"><meta name="theme-color" content="#000000">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--line:#1f2a2d;--soft:#cfd8da;--mut:#8fa3a7;--y:#00f0ff;--bad:#ff5d6c;--warn:#f5a524;--ok:#3ddc97;--sans:'Space Grotesk',system-ui,sans-serif;--mono:'Space Mono',ui-monospace,Consolas,monospace}
*{box-sizing:border-box}html,body{overflow-x:clip}
body{margin:0;background:#000;color:#fff;font-family:var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--y)}
header{border-bottom:1px solid #222}header .in{display:flex;justify-content:space-between;align-items:center;padding:18px clamp(16px,3vw,40px);gap:16px}
.logo{font-size:16px;font-weight:600;letter-spacing:.4em;text-decoration:none;color:#fff}.logo img{width:20px;height:20px;vertical-align:-4px;margin-right:12px}
header nav{display:flex;gap:20px;font-size:14px}header nav a{color:var(--soft);text-decoration:none}
main{max-width:980px;margin:0 auto;padding:48px clamp(16px,4vw,40px) 90px}
.lbl{font:12px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--mut)}
h1{margin:10px 0 8px;font-size:clamp(28px,4.5vw,44px);font-weight:400;letter-spacing:-.03em;line-height:1.1;overflow-wrap:anywhere}
h2{margin:40px 0 12px;font-size:20px;font-weight:500;padding-top:18px;border-top:1px solid #222}
p,li{color:var(--soft);font-size:16px;line-height:1.65}
.pill{display:inline-block;font:700 13px var(--mono);letter-spacing:.06em;text-transform:uppercase;padding:6px 10px;color:#000;background:var(--mut)}
.pill.bad{background:var(--bad);color:#fff}.pill.warn{background:var(--warn)}.pill.ok{background:var(--ok)}
.kv{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:22px}
.kv div{border:1px solid var(--line);padding:12px 14px;background:rgba(4,10,12,.9)}.kv b{display:block;font:400 11px var(--mono);letter-spacing:.14em;color:var(--mut);text-transform:uppercase}.kv span{display:block;margin-top:6px;font:700 15px var(--mono);overflow-wrap:anywhere}
.tw{overflow-x:auto;border:1px solid var(--line)}
table{width:100%;border-collapse:collapse;font:13px var(--mono)}
th{text-align:left;font-weight:400;color:var(--mut);letter-spacing:.1em;text-transform:uppercase;font-size:11px;padding:10px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:9px 10px;border-bottom:1px solid #111a1c;color:#e8eef0;vertical-align:top}
td.n{text-align:right;white-space:nowrap}
.bar{display:inline-block;height:8px;background:var(--y);vertical-align:middle;min-width:2px}
.s-LIVE{color:var(--ok)}.s-CACHED{color:var(--y)}.s-ERROR{color:var(--bad)}.s-UNAVAILABLE{color:var(--warn)}
.st{font:700 12px var(--mono);text-transform:uppercase;letter-spacing:.08em}.st.up{color:var(--ok)}.st.slow{color:var(--warn)}.st.degraded{color:var(--warn)}.st.down{color:var(--bad)}
.btn{display:inline-block;font:700 13px var(--mono);letter-spacing:.08em;background:var(--y);color:#000;padding:11px 15px;text-decoration:none;margin:6px 10px 0 0}
.btn.o{background:none;color:var(--y);border:1px solid rgba(0,240,255,.5)}
.note{font-size:13px;color:var(--mut)}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#050b0d;border:1px solid var(--line);padding:14px;font:12px/1.6 var(--mono);color:#dfe7e9;max-height:520px;overflow:auto}
footer{border-top:1px solid #222}footer .in{max-width:980px;margin:0 auto;padding:22px clamp(16px,4vw,40px);font:12px var(--mono);color:#5e5e5e;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}footer a{color:var(--mut)}
@media (max-width:720px){.kv{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style><link rel="canonical" href="${esc(canonical)}"></head><body>
<header><div class="in"><a class="logo" href="/"><img src="/assets/logo.svg" alt="">OCULON</a><nav><a href="/app">App</a><a href="/docs">Docs</a><a href="/status">Status</a></nav></div></header>
<main>${body}</main>
<footer><div class="in"><span>Oculon contributors · MIT</span><span><a href="/">Home</a> · <a href="/docs">Docs</a> · <a href="/status">Status</a> · <a href="/thetoken">Token</a></span></div></footer>
</body></html>`;
}

/** /replay/<id>: what a check said and every source it called, in order. */
export function replayPage(c: CheckRecord, history: { id: string; at: string; verdict: string | null; risk: number | null }[], base: string): string {
  const v = c.verdict;
  const t0 = c.calls.length ? Date.parse(c.calls[0]!.at) - c.calls[0]!.ms : Date.parse(c.createdAt);
  const maxMs = Math.max(1, ...c.calls.map((k) => k.ms));
  const rows = c.calls.map((k, i) => `<tr><td class="n">${i + 1}</td><td class="n">+${Math.max(0, ((Date.parse(k.at) - k.ms - t0) / 1000)).toFixed(2)}s</td><td>${esc(k.source)}</td><td>${esc(k.host)}${k.via ? ' <span class="note">(mirror)</span>' : ''}</td><td class="s-${esc(k.status)}">${esc(k.status)}${k.note ? `<div class="note">${esc(k.note)}</div>` : ''}</td><td class="n">${k.ms} ms <span class="bar" style="width:${Math.round((k.ms / maxMs) * 80)}px"></span></td></tr>`).join('');
  const seen = c.seenBefore ? `<h2>Seen before</h2><p>Last checked ${esc(when(c.seenBefore.at))}, verdict then: <b>${esc(c.seenBefore.verdict ?? 'none')}</b>. ${c.seenBefore.changes.length ? '' : 'Nothing changed since then.'}</p>${c.seenBefore.changes.length ? `<ul>${c.seenBefore.changes.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}` : '';
  const hist = history.length > 1 ? `<h2>History of this target</h2><div class="tw"><table><tr><th>When</th><th>Verdict</th><th>Risk</th><th></th></tr>${history.map((h) => `<tr><td>${esc(when(h.at))}</td><td>${esc(h.verdict ?? '-')}</td><td class="n">${h.risk ?? '-'}</td><td>${h.id === c.id ? '<span class="note">this check</span>' : `<a href="/replay/${esc(h.id)}">replay</a>`}</td></tr>`).join('')}</table></div>` : '';
  const result = c.result ? `<h2>Full result</h2><pre>${esc(JSON.stringify(c.result, null, 2).slice(0, 60_000))}</pre>` : '';
  const body = `<div class="lbl">Replay log · ${esc(c.kind)}</div><h1>${esc(c.label)}</h1>
<p><span class="pill ${esc(v.tone)}">${esc(v.verdict ?? 'result')}</span>${v.risk !== null ? ` &nbsp;<span class="note">risk ${v.risk}/100</span>` : ''}</p>
<div class="kv"><div><b>Checked</b><span>${esc(when(c.createdAt))}</span></div><div><b>Took</b><span>${(c.durationMs / 1000).toFixed(1)} s</span></div><div><b>Source calls</b><span>${c.calls.length}</span></div><div><b>Live / cached / failed</b><span>${v.sources.live} / ${v.sources.cached} / ${v.sources.failed}</span></div></div>
<p><a class="btn" href="/report/${esc(c.id)}.pdf">Download PDF report</a><a class="btn o" href="/app#investigate">Run a new check</a></p>
${v.points.length ? `<h2>Why</h2><ul>${v.points.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>` : ''}${seen}
<h2>Every source called</h2><p class="note">In the order they answered. Cached answers took 0 ms. A failed source is not a finding; a mirror answered when the main host was down.</p>
${rows ? `<div class="tw"><table><tr><th>#</th><th>Start</th><th>Source</th><th>Host</th><th>Status</th><th>Time</th></tr>${rows}</table></div>` : '<p>No network calls: this check ran on the input alone.</p>'}
${hist}${result}<p class="note" style="margin-top:28px">Kept for 90 days. Anyone with this link can see it.</p>`;
  return shell(`Replay: ${c.label}`, `Oculon replay log of a ${c.kind} check`, body, `${base}/replay/${c.id}`);
}

/** /status: which sources answered in the last day. */
export function statusPage(list: SourceStatus[], base: string, hours: number): string {
  const n = (s: SourceStatus['state']) => list.filter((x) => x.state === s).length;
  const rows = list.map((s) => `<tr><td>${esc(s.source)}<div class="note">${esc(s.hosts.join(', '))}</div></td><td><span class="st ${s.state}">${s.state}</span>${s.skippedUntil ? `<div class="note">skipped until ${esc(s.skippedUntil.slice(11, 16))} UTC, fallback in use</div>` : ''}</td><td class="n">${s.okPct}%</td><td class="n">${s.calls}</td><td class="n">${s.medianMs === null ? '-' : `${s.medianMs} ms`}</td><td>${s.lastError ? `${esc(s.lastError.at.slice(11, 16))} <span class="note">${esc(s.lastError.note)}</span>` : '<span class="note">none</span>'}</td></tr>`).join('');
  const body = `<div class="lbl">Source status · last ${hours} hours</div><h1>Which sources are up, slow or down.</h1>
<p>Every check calls public sources. This page shows how each one answered Oculon in the last ${hours} hours, measured from real calls. When a source keeps failing it is skipped for a few minutes and a mirror or the last cached answer is used instead, and the result says so.</p>
<div class="kv"><div><b>Up</b><span style="color:var(--ok)">${n('up')}</span></div><div><b>Slow</b><span style="color:var(--warn)">${n('slow')}</span></div><div><b>Degraded</b><span style="color:var(--warn)">${n('degraded')}</span></div><div><b>Down</b><span style="color:var(--bad)">${n('down')}</span></div></div>
<h2>Sources</h2>${rows ? `<div class="tw"><table><tr><th>Source</th><th>State</th><th>Worked</th><th>Calls</th><th>Median</th><th>Last error</th></tr>${rows}</table></div>` : '<p>No live calls yet in this window.</p>'}
<p class="note" style="margin-top:20px">Up: the last calls worked. Degraded: some of the last five failed. Down: they all failed, or the source is being skipped. Slow: median above 5 seconds. JSON: <a href="/api/status">/api/status</a>.</p>`;
  return shell('Oculon status', 'Which Oculon sources are up, slow or down', body, `${base}/status`);
}

export interface ToolDoc {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const FIRST_SENTENCE = /^.*?(?<!\be\.g|\bi\.e|\bvs)[.?!](?=\s+[A-Z("]|$)/;
const WS = /\s+/g;

/** First sentence, not fooled by "e.g." or "i.e.". */
function firstSentence(d: string): string {
  const m = FIRST_SENTENCE.exec(d.replace(WS, ' '));
  return (m ? m[0] : d).trim();
}

/** /llms.txt: a short guide for AI agents (llmstxt.org format). */
export function llmsTxt(tools: ToolDoc[], base: string, mcpUrl: string): string {
  const groups: [string, RegExp][] = [
    ['Everyday checks', /scam|url_check|doc_check|image_check|qr_check|repo_check|domain_report|site_check|email_file|apk_check|job_check|photo_location|archive|invite_check|iban|email_headers|lookalike|phone|password|breaches|company|email_security|recall|travel|fact_check/],
    ['Threat intel', /ip_check|hash|ransomware|vulns|cve|package|exposure|bgp|blackout|cloud/],
    ['Crypto', /token|wallet|honeypot|approvals|tx_explain|token_creator|stock_token|contract_risk|signature|poisoning|trace_funds|address_check|robinhood|defi|protocol|sanctions/],
  ];
  const line = (t: ToolDoc) => `- [${t.name}](${base}/llms-full.txt#${t.name}): ${firstSentence(t.description)}`;
  const used = new Set<string>();
  const sections = groups.map(([g, re]) => {
    const ts = tools.filter((t) => re.test(t.name) && !used.has(t.name));
    ts.forEach((t) => used.add(t.name));
    return `## ${g}\n\n${ts.map(line).join('\n')}`;
  });
  const rest = tools.filter((t) => !used.has(t.name));
  return `# Oculon

> Free, open-source OSINT engine (MIT). Checks things before you trust them: messages, links, documents, IBANs, phone numbers, email headers, IPs, file hashes, tokens and wallets. Every answer lists the sources it used and whether each was live, cached or unavailable.

Use it from an AI agent over MCP: add ${mcpUrl} as a remote MCP server (no key, no sign-in), or run \`npx oculon mcp\` locally. ${tools.length} tools.

Rules for agents:
- Report data as given. A source marked ERROR or UNAVAILABLE is not a finding.
- Check tools return a verdict, a risk score, reasons, and a check id. Pass \`brief: true\` to any tool for a short answer with fewer tokens.
- A check id opens a replay log (${base}/replay/<id>) with every source call, and a PDF report (${base}/report/<id>.pdf).
- Source health: ${base}/status (JSON at ${base}/api/status).

## Docs

- [Full tool reference](${base}/llms-full.txt): every tool with its arguments
- [Documentation](${base.replace('//app.', '//docs.')}): install, CLI, SDK, MCP, web
- [OpenAPI](${base}/openapi.json): the HTTP API
- [Source code](https://github.com/oculonlive/oculon)

${sections.join('\n\n')}

## Optional

${rest.map(line).join('\n')}
`;
}

/** /llms-full.txt: every tool with its full description and arguments. */
export function llmsFull(tools: ToolDoc[], base: string, mcpUrl: string): string {
  const args = (s: Record<string, unknown>) => {
    const props = (s.properties ?? {}) as Record<string, { type?: string; description?: string; enum?: unknown[] }>;
    const req = new Set((s.required ?? []) as string[]);
    const rows = Object.entries(props).map(([k, p]) => `  - \`${k}\` (${p.type ?? 'any'}${req.has(k) ? ', required' : ''})${p.description ? `: ${p.description}` : ''}${p.enum ? ` One of: ${p.enum.join(', ')}.` : ''}`);
    return rows.length ? rows.join('\n') : '  - no arguments';
  };
  return `# Oculon: full tool reference

MCP endpoint: ${mcpUrl} (remote, no key) or \`npx oculon mcp\` (local, stdio).
Every tool also takes \`brief\` (boolean): a short answer for agents (verdict, risk, top reasons, sources, check id).
Check tools return \`check.id\`: replay log at ${base}/replay/<id>, PDF report at ${base}/report/<id>.pdf.

${tools.map((t) => `## ${t.name}\n\n${t.description}\n\nArguments:\n${args(t.inputSchema)}\n`).join('\n')}`;
}
