import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { Oculon } from '../src/index.js';
import { parseVehicle, recall } from '../src/modules/recall.js';
import { analyzeDmarc, analyzeSpf, emailSecurity } from '../src/modules/emailsec.js';
import { invertAbstract } from '../src/modules/papers.js';
import { findCountry } from '../src/modules/country.js';
import { findAirport, parseFaaStatus } from '../src/modules/airport.js';
import { summarize } from '../src/web/share.js';
import { createWebServer } from '../src/web/server.js';
import { mockFetch, NOW, testContext, type Route } from './helpers.js';

test('recall: vehicles by VIN or "year make model", products from CPSC and FDA', async () => {
  assert.deepEqual(parseVehicle('2018 Honda Accord'), { year: 2018, make: 'Honda', model: 'Accord' });
  assert.deepEqual(parseVehicle('Ford F-150 2021'), { year: 2021, make: 'Ford', model: 'F-150' });
  assert.equal(parseVehicle('stroller'), null);
  const ctx = testContext([
    ['vpic.nhtsa.dot.gov', () => ({ body: { Results: [{ Make: 'HONDA', Model: 'Accord', ModelYear: '2018' }] } })],
    ['api.nhtsa.gov/recalls', () => ({ body: { results: [{ NHTSACampaignNumber: '20V314000', ReportReceivedDate: '28/05/2020', Component: 'FUEL SYSTEM:PUMP', Consequence: 'Engine stall', Remedy: 'Replace pump', parkIt: true }] } })],
    ['saferproducts.gov', () => ({ body: [{ RecallNumber: '26639', RecallDate: '2026-07-23T00:00:00', Title: 'Stroller bags recalled', URL: 'https://www.cpsc.gov/x', Hazards: [{ Name: 'Choking' }], Remedies: [{ Name: 'Refund' }] }] })],
  ]);
  const v = await recall(ctx, '1HGCV1F30JA123456');
  assert.equal(v.result.kind, 'vehicle');
  assert.equal(v.result.vehicle?.make, 'HONDA');
  assert.equal(v.result.recalls[0]?.date, '2020-05-28');
  assert.equal(v.signals.length, 1, 'a do-not-drive recall becomes a signal');
  const p = await recall(ctx, 'stroller');
  assert.equal(p.result.kind, 'product');
  assert.equal(p.result.recalls[0]?.source, 'CPSC');
});

test('email security: SPF and DMARC analysis, verdict and fixes', async () => {
  assert.equal(analyzeSpf(['v=spf1 include:_spf.google.com -all']).all, '-all (fail)');
  assert.ok(analyzeSpf(['v=spf1 +all']).problems.some((p) => /\+all/.test(p)));
  assert.ok(analyzeSpf(['v=spf1 -all', 'v=spf1 ~all']).problems.some((p) => /2 SPF records/.test(p)));
  assert.equal(analyzeDmarc(['v=DMARC1; p=reject; rua=mailto:d@x.com']).policy, 'reject');
  assert.ok(analyzeDmarc(['v=DMARC1; p=none']).problems.some((p) => /"none"/.test(p)));
  const dns = (name: string, type: string, data: string[]): Route => [new RegExp(`name=${name.replace(/\./g, '\\.')}&type=${type}`), () => ({ body: { Status: 0, AD: type === 'SOA', Answer: data.map((d) => ({ name: `${name}.`, type: type === 'MX' ? 15 : type === 'SOA' ? 6 : 16, data: d })) } })];
  const ctx = testContext([
    dns('acme.test', 'MX', ['10 mx.acme.test.']),
    dns('acme.test', 'TXT', ['"v=spf1 include:_spf.google.com -all"']),
    dns('_dmarc.acme.test', 'TXT', ['"v=DMARC1; p=reject; rua=mailto:dmarc@acme.test"']),
    dns('google._domainkey.acme.test', 'TXT', ['"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx"']),
    dns('acme.test', 'SOA', ['ns.acme.test. hostmaster.acme.test. 1 2 3 4 5']),
    [/dns\.google/, () => ({ body: { Status: 0, Answer: [] } })],
  ]);
  const r = await emailSecurity(ctx, 'someone@acme.test');
  assert.equal(r.result.domain, 'acme.test');
  assert.equal(r.result.verdict, 'protected');
  assert.deepEqual(r.result.dkim.selectorsFound, ['google']);
  assert.equal(r.result.dnssec, true);
  await assert.rejects(emailSecurity(ctx, 'not a domain'), /not a domain/);
});

test('papers, country and airport helpers', () => {
  assert.equal(invertAbstract({ batteries: [1], Solid: [0], 'fail.': [2] }), 'Solid batteries fail.');
  const list = [
    { id: 'KOR', iso2Code: 'KR', name: 'Korea, Rep.', capitalCity: 'Seoul' },
    { id: 'EGY', iso2Code: 'EG', name: 'Egypt, Arab Rep.', capitalCity: 'Cairo' },
    { id: 'ARG', iso2Code: 'AR', name: 'Argentina', capitalCity: 'Buenos Aires' },
  ];
  assert.equal(findCountry(list, 'South Korea')?.id, 'KOR');
  assert.equal(findCountry(list, 'egypt')?.id, 'EGY');
  assert.equal(findCountry(list, 'AR')?.id, 'ARG');
  assert.equal(findCountry(list, 'Atlantis'), null);
  const airports = [
    { ident: 'KJFK', iata: 'JFK', name: 'John F. Kennedy International Airport', type: 'large_airport' as const, lat: 40.6, lon: -73.8, country: 'US', region: 'US-NY', city: 'New York' },
    { ident: 'EGLL', iata: 'LHR', name: 'London Heathrow Airport', type: 'large_airport' as const, lat: 51.5, lon: -0.5, country: 'GB', region: 'GB-ENG', city: 'London' },
  ];
  assert.equal(findAirport(airports, 'jfk')?.ident, 'KJFK');
  assert.equal(findAirport(airports, 'EGLL')?.iata, 'LHR');
  assert.equal(findAirport(airports, 'heathrow')?.ident, 'EGLL');
  const xml = '<AIRPORT_STATUS_INFORMATION><Delay_type><Name>Ground Stop Programs</Name><Ground_Stop_List><Program><ARPT>JFK</ARPT><Reason>weather / thunderstorms</Reason><End_Time>8:30 pm EDT</End_Time></Program></Ground_Stop_List></Delay_type><Delay_type><Name>Airport Closures</Name><Airport_Closure_List><Airport><ARPT>LAX</ARPT><Reason>!LAX 05/277 LAX AD AP CLSD TO NON SKED TRANSIENT GA</Reason></Airport></Airport_Closure_List></Delay_type></AIRPORT_STATUS_INFORMATION>';
  const d = parseFaaStatus(xml, 'JFK');
  assert.equal(d.length, 1);
  assert.equal(d[0]?.type, 'Ground Stop Programs');
  assert.match(d[0]!.detail, /until 8:30 pm EDT/);
});

test('share summaries read every shareable result', () => {
  const s = summarize('url', { result: { host: 'bad.top', verdict: 'malicious', risk: 100, reasons: ['Safe Browsing flags it'], scans: null } });
  assert.equal(s.tone, 'bad');
  assert.equal(s.label, 'Link check');
  const e = summarize('emailsec', { result: { domain: 'x.com', verdict: 'spoofable', score: 20, spf: { all: null, record: null }, dmarc: { policy: null }, dkim: { selectorsFound: [] }, fixes: ['Add DMARC'] } });
  assert.ok(e.points.includes('Add DMARC'));
});

test('share links: the server runs the check, stores a snapshot and serves a page with preview tags', async () => {
  const fetchMock = mockFetch([
    [/dns\.google.*name=_dmarc/, () => ({ body: { Status: 0, Answer: [] } })],
    [/dns\.google.*type=SOA/, () => ({ body: { Status: 0, AD: false, Answer: [{ name: 'acme.test.', type: 6, data: 'ns. h. 1 2 3 4 5' }] } })],
    [/dns\.google/, () => ({ body: { Status: 0, Answer: [] } })],
  ]);
  const oculon = new Oculon({ dbPath: ':memory:', fetch: fetchMock.fetch, throttle: false, now: () => NOW });
  const { server, stop } = createWebServer({ port: 0, oculon });
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (body: unknown) => fetch(base + '/api/share', { method: 'POST', headers: { 'content-type': 'application/json', 'x-oculon': '1' }, body: JSON.stringify(body) });
  try {
    const r = await post({ kind: 'emailsec', q: 'acme.test' });
    assert.equal(r.status, 200);
    const j = (await r.json()) as { id: string; path: string };
    assert.match(j.path, /^\/r\/[\w-]+$/);
    const again = (await (await post({ kind: 'emailsec', q: 'acme.test' })).json()) as { id: string };
    assert.equal(again.id, j.id, 'the same check reuses its link for a while');
    const page = await (await fetch(base + j.path)).text();
    assert.match(page, /<meta property="og:title" content="Email security: acme\.test · spoofable"/);
    assert.match(page, /og:image" content="[^"]+\/assets\/og\.png"/);
    assert.match(page, /Add a DMARC record/);
    assert.equal(((await (await fetch(base + '/api/share?id=' + j.id)).json()) as { kind: string }).kind, 'emailsec');
    assert.equal((await post({ kind: 'nope', q: 'x' })).status, 400);
    assert.equal((await fetch(base + '/r/doesnotexist')).status, 404);
  } finally {
    await stop();
    oculon.close();
  }
});
