import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { deflateSync } from 'node:zlib';
import { BREAKER, resetBreakers, withCallLog } from '../src/core/calls.js';
import { renderPdf } from '../src/core/pdf.js';
import { briefOf, verdictChanges, verdictOf } from '../src/core/verdict.js';
import { Oculon } from '../src/index.js';
import { McpServer } from '../src/mcp.js';
import { docCheck, pdfDate, pdfString } from '../src/modules/doc.js';
import { CARD_URI, CARD_URI_OPENAI } from '../src/web/card.js';
import { llmsTxt } from '../src/web/pages.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW, testContext } from './helpers.js';

const pdfWith = (text: string) => renderPdf([{ t: 'title', text: 'Invoice 1042' }, { t: 'p', text }], 'Acme Supplies Ltd');
/** An incremental update that a PDF editor would add: new Info dictionary, a font embedded a second time. */
const editUpdate = (producer: string) => Buffer.from(`\n99 0 obj\n<< /Producer (${producer}) /CreationDate (D:20261101100000Z) /ModDate (D:20261120100000Z) >>\nendobj\n100 0 obj\n<< /Type /Font /BaseFont /ABCDEF+Arial >>\nendobj\n101 0 obj\n<< /Type /Font /BaseFont /GHIJKL+Arial >>\nendobj\ntrailer\n<< /Size 102 /Info 99 0 R >>\nstartxref\n0\n%%EOF\n`, 'latin1');

test('pdf writer: valid structure, offsets and text that reads back', () => {
  const pdf = renderPdf([{ t: 'title', text: 'Report: café “quotes” → arrows' }, { t: 'bullets', items: ['one', 'two'] }, { t: 'table', head: ['a', 'b'], widths: [200, 200], rows: [['x', 'y']] }, { t: 'link', text: 'site', url: 'https://example.com' }], 'footer');
  const s = pdf.toString('latin1');
  assert.ok(s.startsWith('%PDF-1.4'));
  assert.ok(s.trimEnd().endsWith('%%EOF'));
  const xref = Number(/startxref\n(\d+)/.exec(s)![1]);
  assert.equal(s.slice(xref, xref + 4), 'xref');
  // Every object offset in the table points at "<n> 0 obj".
  const offsets = [...s.slice(xref).matchAll(/^(\d{10}) 00000 n $/gm)].map((m) => Number(m[1]));
  offsets.forEach((o, i) => assert.ok(s.startsWith(`${i + 1} 0 obj`, o), `object ${i + 1}`));
  assert.match(s, /\(Report: caf\xe9 "quotes" -> arrows\)/);
  assert.match(s, /\/URI \(https:\/\/example\.com\)/);
});

test('doc: a clean PDF, an edited one, a dangerous one', async () => {
  const ctx = testContext([]);
  const clean = await docCheck(ctx, pdfWith('Pay to IBAN GB82 WEST 1234 5698 7654 32, billing@acme-supplies.com'), 'clean.pdf');
  assert.equal(clean.result.verdict, 'no signs of editing found');
  assert.equal(clean.result.revisions, 1);
  assert.deepEqual(clean.result.ibans.map((i) => [i.iban, i.valid]), [['GB82 WEST 1234 5698 7654 32', true]]);
  assert.deepEqual(clean.result.domains, ['acme-supplies.com']);
  assert.equal(clean.result.text.from, 'text layer');

  const edited = await docCheck(ctx, Buffer.concat([pdfWith('Pay to IBAN GB82 WEST 1234 5698 7654 33'), editUpdate('iLovePDF')]), 'edited.pdf');
  assert.equal(edited.result.verdict, 'likely edited');
  const f = edited.result.flags.join('\n');
  assert.match(f, /online PDF editor \(iLovePDF\)/);
  assert.match(f, /IBAN GB82 WEST 1234 5698 7654 33 .* not valid/);
  assert.match(f, /embedded more than once \(Arial\)/);
  assert.match(f, /modified 19 days after/);
  assert.match(f, /saved 2 times/);
  assert.equal(edited.result.metadata.modified, '2026-11-20 10:00 UTC');
  assert.equal(edited.signals.length, 1);

  // JavaScript and an object stream holding the metadata (PDF 1.5 style, compressed).
  const objstm = deflateSync(Buffer.from('7 0 << /Producer (Sejda) /JS (app.alert(1)) >>', 'latin1'));
  const js = Buffer.concat([Buffer.from(`%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length ${objstm.length} >>\nstream\n`, 'latin1'), objstm, Buffer.from('\nendstream\nendobj\n%%EOF\n', 'latin1')]);
  const bad = await docCheck(ctx, js, 'js.pdf');
  assert.equal(bad.result.verdict, 'dangerous file');
  assert.match(bad.result.flags.join(' '), /JavaScript/);
  assert.match(bad.result.flags.join(' '), /Sejda/);

  await assert.rejects(docCheck(ctx, Buffer.from('hello'), 'x.txt'), /not a PDF, Word, Excel, PowerPoint, JPEG or PNG/);
  await assert.rejects(docCheck(ctx, Buffer.alloc(0)), /empty/);
});

test('doc: image metadata from EXIF and PNG text chunks, text read by a vision model', async () => {
  // JPEG with an EXIF Software tag of Photoshop.
  const sw = Buffer.from('Adobe Photoshop 26.0\0', 'latin1');
  const tiff = Buffer.alloc(8 + 2 + 12 + 4);
  tiff.write('II', 0, 'latin1'); tiff.writeUInt16LE(42, 2); tiff.writeUInt32LE(8, 4); tiff.writeUInt16LE(1, 8);
  tiff.writeUInt16LE(0x0131, 10); tiff.writeUInt16LE(2, 12); tiff.writeUInt32LE(sw.length, 14); tiff.writeUInt32LE(tiff.length, 18);
  const app1 = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff, sw]);
  const seg = Buffer.alloc(4); seg[0] = 0xff; seg[1] = 0xe1; seg.writeUInt16BE(app1.length + 2, 2);
  const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8]), seg, app1, Buffer.from([0xff, 0xd9])]);
  const ctx = testContext([]);
  const j = await docCheck(ctx, jpeg, 'receipt.jpg');
  assert.equal(j.result.type, 'jpeg');
  assert.equal(j.result.metadata.software, 'Adobe Photoshop 26.0');
  assert.match(j.result.flags.join(' '), /image editor \(Adobe Photoshop/);

  // PNG screenshot: no metadata; with an OpenRouter key the text is read and its IBAN checked.
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from([0, 0, 0, 0]), Buffer.from('IEND', 'latin1'), Buffer.alloc(4)]);
  const saved = process.env.OPENROUTER_API_KEY;
  const savedG = process.env.GEMINI_API_KEY;
  process.env.OPENROUTER_API_KEY = 'test-key';
  delete process.env.GEMINI_API_KEY;
  try {
    const octx = testContext([['openrouter.ai', () => ({ body: { choices: [{ message: { content: 'Transfer confirmation\nIBAN: GB82 WEST 1234 5698 7654 33' } }] } })]]);
    const p = await docCheck(octx, png, 'shot.png');
    assert.equal(p.result.text.from, 'ocr');
    assert.equal(p.result.verdict, 'signs of editing');
    assert.match(p.result.flags[0]!, /not valid/);
    assert.match(p.provenance[0]!.note!, /sent to openrouter only to read its text/);
  } finally {
    if (saved === undefined) delete process.env.OPENROUTER_API_KEY; else process.env.OPENROUTER_API_KEY = saved;
    if (savedG !== undefined) process.env.GEMINI_API_KEY = savedG;
  }
});

test('doc helpers: PDF strings and dates', () => {
  assert.equal(pdfString('(a \\(b\\) c)'), 'a (b) c');
  assert.equal(pdfString('<FEFF00480069>'), 'Hi');
  assert.equal(pdfString('(\\101\\102)'), 'AB');
  assert.equal(new Date(pdfDate("D:20261120100000+07'00'")!).toISOString(), '2026-11-20T03:00:00.000Z');
  assert.equal(pdfDate('nonsense'), null);
});

test('verdicts: read from any result, compared, and trimmed for brief mode', () => {
  const a = verdictOf({ input: 'x.top', result: { verdict: 'suspicious', risk: 40, reasons: ['new domain'] }, provenance: [{ source: 'rdap', status: 'LIVE' }, { source: 'urlscan', status: 'ERROR' }] });
  assert.equal(a.tone, 'warn');
  assert.deepEqual(a.sources, { live: 1, cached: 0, failed: 1, names: ['rdap', 'urlscan'] });
  const b = verdictOf({ input: 'x.top', result: { verdict: 'malicious', risk: 90, reasons: ['new domain', 'on URLhaus'] } });
  assert.equal(b.tone, 'bad');
  assert.deepEqual(verdictChanges(a, b), ['verdict: suspicious -> malicious', 'risk 40 -> 90', 'new: on URLhaus']);
  assert.equal(verdictOf({ result: { verdict: 'no signs of editing found' } }).tone, 'ok');
  assert.equal(verdictOf({ result: { valid: false } }).verdict, 'not valid');
  const br = briefOf({ input: 'x', result: { verdict: 'likely scam', risk: 88, reasons: ['a', 'b', 'c', 'd', 'e', 'f'] }, provenance: { sources: { urlscan: { LIVE: 1 } }, notes: [] } });
  assert.deepEqual(br, { target: 'x', verdict: 'likely scam', risk: 88, points: ['a', 'b', 'c', 'd', 'e'], sources: '1 live, 0 cached, 0 failed (urlscan)' });
  const long = briefOf({ result: { items: Array.from({ length: 9 }, (_, i) => i), text: 'y'.repeat(400) } }) as { result: { items: unknown[]; text: string } };
  assert.equal(long.result.items.length, 6);
  assert.ok(long.result.text.length < 290);
});

test('call log, status, breaker and mirror: a failing DNS host is skipped and Cloudflare answers', async () => {
  resetBreakers();
  let googleCalls = 0;
  const ctx = testContext([
    ['dns.google', () => { googleCalls++; return { status: 503, body: 'down' }; }],
    ['cloudflare-dns.com/dns-query', () => ({ body: { Status: 0, Answer: [{ name: 'a.example.', type: 1, data: '1.2.3.4' }] } })],
  ]);
  try {
    const { value, calls } = await withCallLog(() => ctx.http.get<{ Answer: unknown[] }>('https://dns.google/resolve?name=a.example&type=A', { source: 'google-dns', retries: 0 }));
    assert.equal(value.prov.status, 'LIVE');
    assert.match(value.prov.note!, /dns\.google failed \(HTTP 503\); answered by cloudflare-dns\.com/);
    assert.equal(value.data!.Answer.length, 1);
    assert.deepEqual(calls.map((c) => [c.host, c.status, c.via ?? null]), [['dns.google', 'ERROR', null], ['cloudflare-dns.com', 'LIVE', 'cloudflare-dns.com']]);
    // Two more failures open the breaker: the next call does not touch dns.google at all.
    for (const n of ['b', 'c']) await ctx.http.get(`https://dns.google/resolve?name=${n}.example&type=A`, { source: 'google-dns', retries: 0 });
    assert.equal(googleCalls, BREAKER.failures);
    const skipped = await ctx.http.get('https://dns.google/resolve?name=d.example&type=A', { source: 'google-dns', retries: 0 });
    assert.equal(googleCalls, BREAKER.failures, 'skipped while the breaker is open');
    assert.equal(skipped.prov.status, 'LIVE');
    assert.match(skipped.prov.note!, /skipped: dns\.google kept failing/);
    const { sourceStatus } = await import('../src/core/calls.js');
    const st = sourceStatus(ctx.store, 24);
    const g = st.find((s) => s.source === 'google-dns')!;
    assert.equal(g.state, 'down');
    assert.ok(g.skippedUntil);
    assert.equal(g.failed, 3);
  } finally {
    resetBreakers();
  }
});

test('checks: kept with their source calls, seen before says what changed, PDF report', async () => {
  let verdict = 'suspicious';
  const o = new Oculon({ dbPath: ':memory:', fetch: mockFetch([['example.org', () => ({ body: { ok: true } })]]).fetch, throttle: false, now: () => NOW });
  const run = async () => {
    const r = await o.ctx.http.get('https://example.org/x', { source: 'example', ttlSec: 0 });
    return { module: 'url', input: 'x.top', generatedAt: NOW.toISOString(), result: { verdict, risk: verdict === 'suspicious' ? 40 : 90, reasons: ['new domain'] }, signals: [], provenance: [r.prov] };
  };
  const first = await o.recordCheck('url', 'X.top ', run);
  assert.equal(first.check.seenBefore, null);
  assert.match(first.check.id, /^[A-Za-z0-9_-]{16}$/);
  verdict = 'malicious';
  const second = await o.recordCheck('url', 'x.top', run);
  assert.equal(second.check.seenBefore!.id, first.check.id);
  assert.deepEqual(second.check.seenBefore!.changes, ['verdict: suspicious -> malicious', 'risk 40 -> 90']);
  const rec = o.check(second.check.id)!;
  assert.equal(rec.calls.length, 1);
  assert.equal(rec.calls[0]!.host, 'example.org');
  assert.equal(o.checkHistory(second.check.id).length, 2);
  const pdf = o.checkPdf(second.check.id, 'https://app.example.org')!.toString('latin1');
  assert.match(pdf, /\(MALICIOUS   risk 90\/100\)/);
  assert.match(pdf, /verdict: suspicious -> malicious/);
  assert.match(pdf, /\/URI \(https:\/\/app\.example\.org\/replay\//);
  assert.equal(o.check('nope'), null);
  o.close();
});

test('MCP: brief on every tool, verdict cards on check tools, UI resources, replay', async () => {
  const s = new McpServer(() => new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW }), { baseUrl: 'https://app.example.org' });
  const init = (await s.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })) as { result: { capabilities: Record<string, unknown> } };
  assert.ok(init.result.capabilities.resources);
  const list = (await s.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' })) as { result: { tools: { name: string; inputSchema: { properties: Record<string, unknown> }; _meta?: Record<string, unknown> }[] } };
  const tools = list.result.tools;
  assert.ok(tools.every((t) => 'brief' in t.inputSchema.properties));
  const iban = tools.find((t) => t.name === 'oculon_iban_check')!;
  assert.equal(iban._meta!['openai/outputTemplate'], CARD_URI_OPENAI);
  assert.deepEqual(iban._meta!.ui, { resourceUri: CARD_URI });
  assert.equal(tools.find((t) => t.name === 'oculon_radar')!._meta, undefined);
  for (const n of ['oculon_doc_check', 'oculon_replay', 'oculon_status']) assert.ok(tools.some((t) => t.name === n), n);

  const res = (await s.handle({ jsonrpc: '2.0', id: 3, method: 'resources/list' })) as { result: { resources: { uri: string; mimeType: string }[] } };
  assert.deepEqual(res.result.resources.map((r) => r.mimeType), ['text/html;profile=mcp-app', 'text/html+skybridge']);
  const read = (await s.handle({ jsonrpc: '2.0', id: 4, method: 'resources/read', params: { uri: CARD_URI } })) as { result: { contents: { text: string }[] } };
  assert.match(read.result.contents[0]!.text, /ui\/notifications\/tool-result/);

  const call = async (name: string, args: Record<string, unknown>) => ((await s.handle({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name, arguments: args } })) as { result: { content: { text: string }[]; structuredContent?: Record<string, unknown>; isError?: boolean } }).result;
  const full = await call('oculon_iban_check', { iban: 'GB82 WEST 1234 5698 7654 33' });
  const body = JSON.parse(full.content[0]!.text);
  assert.equal(body.result.valid, false);
  assert.match(body.check.replay, /^https:\/\/app\.example\.org\/replay\//);
  assert.equal(full.structuredContent!.verdict, 'not valid');
  assert.equal(full.structuredContent!.tone, 'bad');

  const brief = JSON.parse((await call('oculon_iban_check', { iban: 'GB82 WEST 1234 5698 7654 33', brief: true })).content[0]!.text);
  assert.equal(brief.verdict, 'not valid');
  assert.deepEqual(brief.check.changedSinceLast, []);
  assert.ok(JSON.stringify(brief).length < JSON.stringify(body).length);

  const rp = JSON.parse((await call('oculon_replay', { id: body.check.id })).content[0]!.text);
  assert.equal(rp.kind, 'iban');
  assert.equal(rp.history.length, 2);

  const pdf = Buffer.concat([pdfWith('IBAN GB82 WEST 1234 5698 7654 32'), editUpdate('Smallpdf')]).toString('base64');
  const doc = await call('oculon_doc_check', { data: pdf, name: 'inv.pdf' });
  assert.equal(doc.structuredContent!.verdict, 'likely edited');
  assert.match((await call('oculon_doc_check', { url: 'https://127.0.0.1/x.pdf' })).content[0]!.text, /public hosts/);
  s.close();
});

test('web: status page, replay page, PDF report, document upload and llms.txt', async () => {
  const { server, stop } = createWebServer({ port: 0, burnRpcUrl: '', oculon: new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW }) });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const iban = await (await fetch(`${base}/api/iban?iban=GB82WEST12345698765432`)).json() as { check: { id: string; replay: string; report: string } };
    assert.equal((await (await fetch(`${base}/api/iban?iban=GB82WEST12345698765432`)).json() as { check: { seenBefore: { id: string } } }).check.seenBefore.id, iban.check.id);
    const page = await fetch(base + iban.check.replay);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Every source called/);
    const pdf = await fetch(base + iban.check.report);
    assert.equal(pdf.headers.get('content-type'), 'application/pdf');
    assert.ok(Buffer.from(await pdf.arrayBuffer()).toString('latin1').startsWith('%PDF'));
    assert.equal((await fetch(`${base}/replay/AAAAAAAAAAAAAAAA`)).status, 404);
    assert.equal((await fetch(`${base}/status`)).status, 200);
    assert.ok(Array.isArray(((await (await fetch(`${base}/api/status`)).json()) as { sources: unknown[] }).sources));
    const llms = await (await fetch(`${base}/llms.txt`)).text();
    assert.match(llms, /^# Oculon/);
    assert.match(llms, /oculon_doc_check/);
    assert.match(await (await fetch(`${base}/llms-full.txt`)).text(), /## oculon_iban_check[\s\S]*`iban` \(string, required\)/);

    const data = Buffer.concat([pdfWith('ok'), editUpdate('PDFescape')]).toString('base64');
    const up = await fetch(`${base}/api/doc`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1' }, body: JSON.stringify({ name: 'a.pdf', data }) });
    const j = (await up.json()) as { result: { verdict: string }; check: { id: string } };
    assert.equal(j.result.verdict, 'likely edited');
    assert.ok(j.check.id);
    assert.equal((await fetch(`${base}/api/doc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 403, 'needs the dashboard header');
  } finally {
    await stop();
  }
});

test('llms.txt groups tools and keeps the first sentence whole', () => {
  const txt = llmsTxt([{ name: 'oculon_recall', description: 'Is this car recalled? Pass a VIN, "year make model" (e.g. 2018 Honda Accord) or a product.', inputSchema: {} }, { name: 'oculon_radar', description: 'Global radar.', inputSchema: {} }], 'https://app.x.org', 'https://mcp.x.org');
  assert.match(txt, /## Everyday checks\n\n- \[oculon_recall\]\(https:\/\/app\.x\.org\/llms-full\.txt#oculon_recall\): Is this car recalled\?\n/);
  assert.match(txt, /## Optional\n\n- \[oculon_radar\]/);
});
