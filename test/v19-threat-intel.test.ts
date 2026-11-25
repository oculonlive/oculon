import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { inCidr, isPublicIp } from '../src/sources/threatintel.js';
import { ipCheck, scoreIp } from '../src/modules/ipintel.js';
import { hashAlgorithm, hashCheck } from '../src/modules/hashcheck.js';
import { ransomware } from '../src/modules/ransomware.js';
import { companyCheck, parseVat, rankByName } from '../src/modules/company.js';
import { breaches, passwordCheck, sha1Hex } from '../src/modules/breach.js';
import { offlinePhone, phoneCheck, toE164 } from '../src/modules/phone.js';
import { orbitFrom, satellites } from '../src/modules/satellites.js';
import { TOOLS, McpServer } from '../src/mcp.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW, testContext } from './helpers.js';

const KEYS = ['ABUSEIPDB_API_KEY', 'OTX_API_KEY', 'IPINFO_TOKEN', 'VIRUSTOTAL_API_KEY', 'NUMVERIFY_API_KEY', 'ABUSECH_AUTH_KEY'];
function withKeys<T>(f: () => Promise<T>): Promise<T> {
  const old = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  for (const k of KEYS) process.env[k] = `test-${k.toLowerCase()}`;
  return f().finally(() => { for (const k of KEYS) { if (old[k] === undefined) delete process.env[k]; else process.env[k] = old[k]; } });
}

test('CIDR matching and public addresses, IPv4 and IPv6', () => {
  assert.equal(inCidr('1.10.16.5', '1.10.16.0/20'), true);
  assert.equal(inCidr('1.10.32.1', '1.10.16.0/20'), false);
  assert.equal(inCidr('2001:db8::1', '2001:db8::/32'), true);
  assert.equal(inCidr('2001:db9::1', '2001:db8::/32'), false);
  assert.equal(isPublicIp('8.8.8.8'), true);
  for (const ip of ['10.1.2.3', '192.168.1.1', '127.0.0.1', '172.20.0.1', '::1', 'fe80::1', '169.254.1.1']) assert.equal(isPublicIp(ip), false, ip);
});

test('IP check: sources combine into a verdict, benign services are not alarmed', async () => {
  const bad = scoreIp({ abuseipdb: { score: 100, reports: 400, reporters: 90, lastReported: null, usageType: null, isp: null, domain: null, countryCode: null, isTor: false, whitelisted: false }, greynoise: null, otx: null, virustotal: null, threatfox: [], drop: { listed: false, entry: null, asnListed: false }, flags: { tor: false, proxy: false, hosting: false, mobile: false, scanner: false, knownGood: false } });
  assert.equal(bad.verdict, 'malicious');
  const google = scoreIp({ abuseipdb: { score: 0, reports: 200, reporters: 60, lastReported: null, usageType: null, isp: null, domain: null, countryCode: null, isTor: false, whitelisted: true }, greynoise: null, otx: null, virustotal: { malicious: 1, suspicious: 0, harmless: 53, undetected: 38, engines: 92, reputation: 0, label: null, name: null, type: null, size: null, firstSeen: null, owner: null, link: '' }, threatfox: [], drop: { listed: false, entry: null, asnListed: false }, flags: { tor: false, proxy: true, hosting: true, mobile: false, scanner: false, knownGood: true } });
  assert.equal(google.verdict, 'no known abuse');
  assert.ok(!google.reasons.some((r) => /proxy/.test(r)), 'no proxy warning for a known benign service');

  await withKeys(async () => {
    const ctx = testContext([
      ['ip-api.com', () => ({ body: { status: 'success', country: 'Germany', countryCode: 'DE', city: 'Berlin', isp: 'Example ISP', as: 'AS64500 Example', proxy: false, hosting: true } })],
      ['api.ipinfo.io/lite', () => ({ body: { asn: 'AS64500', as_name: 'Example Net', country: 'Germany', country_code: 'DE' } })],
      ['api.abuseipdb.com', () => ({ body: { data: { abuseConfidenceScore: 90, totalReports: 50, numDistinctUsers: 20, isTor: false, isWhitelisted: false } } })],
      ['api.greynoise.io', () => ({ status: 404, body: { message: 'not observed' } })],
      ['otx.alienvault.com', () => ({ body: { pulse_info: { count: 3, pulses: [{ id: 'p1', name: 'SSH brute force', tags: ['ssh'] }] } } })],
      ['virustotal.com', () => ({ body: { data: { attributes: { last_analysis_stats: { malicious: 9, suspicious: 0, harmless: 50, undetected: 30 } } } } })],
      ['threatfox-api.abuse.ch', () => ({ body: { query_status: 'no_result' } })],
      ['torbulkexitlist', () => ({ body: '203.0.113.9\n198.51.100.7\n' })],
      ['spamhaus.org/drop/drop_v4', () => ({ body: '{"cidr":"5.5.0.0/16","sblid":"SBL1"}\n{"type":"metadata"}' })],
      ['spamhaus.org/drop', () => ({ body: '' })],
      ['internetdb.shodan.io', () => ({ body: { ports: [22, 80], vulns: [], hostnames: [], tags: [] } })],
      ['peeringdb.com', () => ({ body: { data: [{ name: 'Example Net', info_type: 'NSP' }] } })],
    ]);
    const r = await ipCheck(ctx, '5.5.1.1');
    assert.equal(r.result.verdict, 'malicious');
    assert.equal(r.result.drop.listed, true);
    assert.equal(r.result.greynoise?.observed, false, 'a GreyNoise 404 means "not seen scanning"');
    assert.equal(r.result.network.type, 'NSP');
    assert.ok(r.result.reasons.some((x) => /Spamhaus DROP/.test(x)));
    await assert.rejects(ipCheck(ctx, '192.168.0.1'), /not a public IP/);
    await assert.rejects(ipCheck(ctx, 'not an ip!'), /not an IP address or domain/);
  });
});

test('IP check without keys: keyed sources say how to enable them', async () => {
  const saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  for (const k of KEYS) delete process.env[k];
  try {
    const ctx = testContext([['ip-api.com', () => ({ body: { status: 'success', country: 'US' } })]]);
    const r = await ipCheck(ctx, '8.8.4.4');
    const ab = r.provenance.find((p) => p.source === 'abuseipdb');
    assert.equal(ab?.status, 'UNAVAILABLE');
    assert.match(ab?.note ?? '', /ABUSEIPDB_API_KEY/);
    assert.equal(r.result.verdict, 'no known abuse');
  } finally {
    for (const k of KEYS) if (saved[k] !== undefined) process.env[k] = saved[k];
  }
});

test('hash check: malware, known good and unknown', async () => {
  assert.equal(hashAlgorithm('d41d8cd98f00b204e9800998ecf8427e'), 'md5');
  assert.equal(hashAlgorithm('a'.repeat(64)), 'sha256');
  assert.equal(hashAlgorithm('xyz'), null);
  await withKeys(async () => {
    const mal = 'b'.repeat(64);
    const ctx = testContext([
      [`hashlookup.circl.lu/lookup/sha256/${mal}`, () => ({ status: 404, body: {} })],
      ['hashlookup.circl.lu/lookup/md5', () => ({ body: { FileName: 'kernel32.dll', FileSize: '1000', source: 'NSRL' } })],
      ['mb-api.abuse.ch', (u) => ({ body: { query_status: 'hash_not_found' } })],
      ['threatfox-api.abuse.ch', () => ({ body: { query_status: 'no_result' } })],
      ['otx.alienvault.com', () => ({ body: { pulse_info: { count: 0, pulses: [] } } })],
      [`virustotal.com/api/v3/files/${mal}`, () => ({ body: { data: { attributes: { last_analysis_stats: { malicious: 40, harmless: 0, undetected: 30 }, popular_threat_classification: { suggested_threat_label: 'trojan.agent' } } } } })],
      ['virustotal.com/api/v3/files', () => ({ status: 404, body: {} })],
    ]);
    const bad = await hashCheck(ctx, mal);
    assert.equal(bad.result.verdict, 'malicious');
    assert.equal(bad.result.family, 'trojan.agent');
    const good = await hashCheck(ctx, 'D41D8CD98F00B204E9800998ECF8427E');
    assert.equal(good.result.verdict, 'known good');
    const unk = await hashCheck(ctx, 'c'.repeat(40));
    assert.equal(unk.result.verdict, 'unknown');
    await assert.rejects(hashCheck(ctx, 'abc'), /not a file hash/);
  });
});

test('ransomware: modes, onion links dropped, empty search is a result', async () => {
  const v = { victim: 'Acme GmbH', group: 'lockbit', country: 'DE', activity: 'Manufacturing', domain: 'acme.de', discovered: '2026-11-17T10:00:00Z', claim_url: 'http://abc.onion/x', url: 'https://www.ransomware.live/id/abc' };
  const ctx = testContext([
    ['/v2/recentvictims', () => ({ body: [v, { ...v, victim: 'Beta Ltd', group: 'akira', country: 'GB' }] })],
    ['/v2/countryvictims/DE', () => ({ body: [v] })],
    ['/v2/sectorvictims/Healthcare', () => ({ body: [] })],
    ['/v2/searchvictims/acme', () => ({ body: [v] })],
    ['/v2/searchvictims/nothing', () => ({ status: 404, body: { error: "No victims found for keyword 'nothing'." } })],
  ]);
  const recent = await ransomware(ctx, '');
  assert.equal(recent.result.mode, 'recent');
  assert.equal(recent.result.total, 2);
  assert.ok(!JSON.stringify(recent.result).includes('.onion'), 'leak-site links are never passed on');
  assert.equal((await ransomware(ctx, 'de')).result.mode, 'country');
  assert.equal((await ransomware(ctx, 'healthcare')).result.mode, 'sector');
  const s = await ransomware(ctx, 'acme');
  assert.equal(s.result.victims[0]?.victim, 'Acme GmbH');
  assert.equal(s.signals.length, 1);
  assert.equal((await ransomware(ctx, 'nothing')).result.total, 0);
  await assert.rejects(ransomware(ctx, 'x'), /at least 3 characters/);
});

test('company: VAT parsing, VIES, LEI and name ranking', async () => {
  assert.deepEqual(parseVat('NL 0044.95445.B01'), { country: 'NL', number: '004495445B01' });
  assert.deepEqual(parseVat('GR123456789'), { country: 'EL', number: '123456789' });
  assert.equal(parseVat('Siemens'), null);
  const rec = (lei: string, name: string) => ({ lei, name, otherNames: [], status: 'ACTIVE', registration: 'ISSUED', jurisdiction: null, legalForm: null, registeredAs: null, address: null, headquarters: null, country: null, created: null, lastUpdate: null, nextRenewal: null, parent: null, url: '' });
  assert.equal(rankByName([rec('1', 'Siemens Energy Ltd'), rec('2', 'Siemens Aktiengesellschaft'), rec('3', 'Fund of Siemens')], 'Siemens')[0]?.lei, '2');
  const g = (lei: string, name: string, status = 'ISSUED') => ({ id: lei, attributes: { lei, entity: { legalName: { name }, legalAddress: { addressLines: ['1 Main St'], city: 'Amsterdam', country: 'NL' }, status: 'ACTIVE' }, registration: { status } } });
  const ctx = testContext([
    ['vies/rest-api/ms/NL/vat/004495445B01', () => ({ body: { isValid: true, name: 'ACME BV', address: 'Main St 1\nAmsterdam', userError: 'VALID' } })],
    ['vies/rest-api/ms/NL/vat/999999999B01', () => ({ body: { isValid: false, userError: 'INVALID' } })],
    [/lei-records\/[A-Z0-9]{20}\/ultimate-parent/, () => ({ status: 404, body: {} })],
    ['lei-records/529900T8BM49AURSDO55', () => ({ body: { data: g('529900T8BM49AURSDO55', 'ACME BV', 'LAPSED') } })],
    ['lei-records?filter', () => ({ body: { data: [g('529900T8BM49AURSDO55', 'ACME BV')] } })],
  ]);
  const vat = await companyCheck(ctx, 'NL004495445B01');
  assert.equal(vat.result.kind, 'vat');
  assert.equal(vat.result.vat?.valid, true);
  assert.equal(vat.result.vat?.address, 'Main St 1, Amsterdam');
  const badVat = await companyCheck(ctx, 'NL999999999B01');
  assert.ok(badVat.result.warnings.some((w) => /not valid/.test(w)));
  const lei = await companyCheck(ctx, '529900T8BM49AURSDO55');
  assert.ok(lei.result.warnings.some((w) => /lapsed/.test(w)));
  const byName = await companyCheck(ctx, 'acme');
  assert.equal(byName.result.records[0]?.name, 'ACME BV');
});

test('password and breaches: k-anonymity, no password in the result', async () => {
  const hash = sha1Hex('hunter2');
  const ctx = testContext([
    [`pwnedpasswords.com/range/${hash.slice(0, 5)}`, () => ({ body: `${hash.slice(5)}:17043\r\n0000000000000000000000000000000000A:0` })],
    ['haveibeenpwned.com/api/v3/breaches', () => ({ body: [
      { Name: 'Adobe', Title: 'Adobe', Domain: 'adobe.com', BreachDate: '2013-10-04', AddedDate: '2013-12-04T00:00:00Z', PwnCount: 152445165, DataClasses: ['Passwords'], Description: '<a href="x">Adobe</a> was breached.' },
      { Name: 'Secret', Title: 'Secret', Domain: 'secret.example', BreachDate: '2020-01-01', AddedDate: '2026-11-10T00:00:00Z', PwnCount: 5, IsSensitive: true },
      { Name: 'New', Title: 'New Co', Domain: 'new.example', BreachDate: '2026-10-01', AddedDate: '2026-11-15T00:00:00Z', PwnCount: 1000, DataClasses: ['Email addresses'] },
    ] })],
  ]);
  const r = await passwordCheck(ctx, 'hunter2');
  assert.equal(r.result.pwned, true);
  assert.equal(r.result.count, 17043);
  assert.ok(!JSON.stringify(r).includes('hunter2'), 'the password is never echoed');
  assert.ok(ctx.calls.every((u) => !u.includes(hash.slice(5))), 'only the 5-character prefix is sent');
  assert.equal((await passwordCheck(ctx, `sha1:${hash.toLowerCase()}`)).result.count, 17043);
  const recent = await breaches(ctx, '');
  assert.equal(recent.result.breaches[0]?.name, 'New', 'newest added first');
  assert.ok(!recent.result.breaches.some((b) => b.name === 'Secret'), 'sensitive breaches are left out');
  const adobe = await breaches(ctx, 'https://www.adobe.com/');
  assert.equal(adobe.result.total, 1);
  assert.equal(adobe.result.breaches[0]?.description, 'Adobe was breached.');
});

test('phone: E.164, offline warnings, Numverify line type', async () => {
  assert.deepEqual(toE164('+44 20 7946 0958'), { digits: '442079460958', code: '44' });
  assert.deepEqual(toE164('0044 20 7946 0958'), { digits: '442079460958', code: '44' });
  assert.deepEqual(toE164('(415) 555-0100', 'US'), { digits: '14155550100', code: '1' });
  assert.equal(toE164('0812 3456 7890'), null);
  assert.equal(offlinePhone('18765550100', '1').country, 'Jamaica');
  assert.ok(offlinePhone('18765550100', '1').warnings.some((w) => /one ring/.test(w)));
  assert.equal(offlinePhone('19005550100', '1').lineType, 'premium rate');
  assert.ok(offlinePhone('447012345678', '44').warnings.some((w) => /070/.test(w)));
  await withKeys(async () => {
    const ctx = testContext([['apilayer.net/api/validate', () => ({ body: { valid: true, country_code: 'US', carrier: 'Example Wireless', line_type: 'voip', location: 'Novato' } })]]);
    const r = await phoneCheck(ctx, '+1 415 555 0100');
    assert.equal(r.result.lineType, 'voip');
    assert.equal(r.result.risk, 'medium');
    assert.ok(r.result.warnings.some((w) => /VoIP/.test(w)));
  });
  const offline = await phoneCheck(testContext([]), '+1 876 555 0100');
  assert.equal(offline.result.risk, 'high');
});

test('satellites: orbit math, recent launches, search and no match', async () => {
  const iss = orbitFrom(15.4958, 0.0007433, 51.63)!;
  assert.equal(iss.regime, 'LEO');
  assert.ok(iss.perigeeKm > 400 && iss.apogeeKm < 440, `${iss.perigeeKm}-${iss.apogeeKm}`);
  assert.equal(orbitFrom(1.0027, 0.0002, 0.05)!.regime, 'GEO');
  const ctx = testContext([
    ['GROUP=last-30-days', () => ({ body: [{ OBJECT_NAME: 'STARLINK-1', OBJECT_ID: '2026-250A', MEAN_MOTION: 15.5, ECCENTRICITY: 0.0001, INCLINATION: 53, NORAD_CAT_ID: 1 }, { OBJECT_NAME: 'STARLINK-2', OBJECT_ID: '2026-250B', MEAN_MOTION: 15.5, ECCENTRICITY: 0.0001, INCLINATION: 53, NORAD_CAT_ID: 2 }, { OBJECT_NAME: 'CZ-8A R/B', OBJECT_ID: '2026-251B', MEAN_MOTION: 15, ECCENTRICITY: 0.01, INCLINATION: 50, NORAD_CAT_ID: 3 }] })],
    ['satcat/records.php', () => ({ body: [{ NORAD_CAT_ID: 25544, OBJECT_TYPE: 'PAY', OPS_STATUS_CODE: '+', OWNER: 'ISS', LAUNCH_DATE: '1998-11-20' }] })],
    ['CATNR=25544&FORMAT=json', () => ({ body: [{ OBJECT_NAME: 'ISS (ZARYA)', OBJECT_ID: '1998-067A', MEAN_MOTION: 15.4958, ECCENTRICITY: 0.0007, INCLINATION: 51.63, NORAD_CAT_ID: 25544, EPOCH: '2026-11-17T10:00:00.000' }] })],
    ['NAME=zzz', () => ({ status: 404, body: 'No GP data found' })],
  ]);
  const recent = await satellites(ctx, '');
  assert.equal(recent.result.launches[0]?.id, '2026-251');
  assert.equal(recent.result.launches[1]?.objects, 2);
  const s = await satellites(ctx, '25544');
  assert.equal(s.result.objects[0]?.status, 'operational');
  assert.equal(s.result.objects[0]?.type, 'payload');
  assert.equal((await satellites(ctx, 'zzz')).result.objects.length, 0);
});

test('surfaces: MCP tools, remote hides the password check, API routes and status codes', async () => {
  for (const n of ['oculon_ip_check', 'oculon_hash_check', 'oculon_ransomware', 'oculon_company_lookup', 'oculon_password_check', 'oculon_breaches', 'oculon_phone_check', 'oculon_satellites']) assert.ok(TOOLS.some((t) => t.name === n), n);
  const offline = () => new Oculon({ dbPath: ':memory:', fetch: mockFetch([]).fetch, throttle: false, now: () => NOW });
  const remote = new McpServer(offline, { remote: true });
  const list = (await remote.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list' })) as { result: { tools: { name: string }[] } };
  assert.ok(!list.result.tools.some((t) => t.name === 'oculon_password_check'), 'no password tool on a public server');
  assert.ok(list.result.tools.some((t) => t.name === 'oculon_ip_check'));
  remote.close();

  const { server, stop } = createWebServer({ port: 0, oculon: offline() });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const st = async (p: string) => (await fetch(base + p)).status;
    assert.equal(await st('/api/ip?ip=10.0.0.1'), 400);
    assert.equal(await st('/api/hash?hash=nope'), 400);
    assert.equal(await st('/api/pwned?prefix=zz'), 400);
    assert.equal(await st('/api/phone?number=12'), 400);
    assert.equal(await st('/api/ransomware?q=x'), 400);
    assert.equal(await st('/api/company'), 400);
  } finally {
    await stop();
  }
});
