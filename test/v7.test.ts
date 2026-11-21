import assert from 'node:assert/strict';
import { test } from 'node:test';
import { blackout } from '../src/modules/blackout.js';
import { darkShips, seaBox, vesselIdentity } from '../src/modules/darkships.js';
import { hazards } from '../src/modules/hazards.js';
import { NOW, testContext } from './helpers.js';

const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();

test('blackout: confirmed outages become signals, IODA corroborates, explained anomalies are not repeated', async () => {
  process.env.CLOUDFLARE_API_TOKEN = 'cf-test-000000000000000';
  try {
    const ctx = testContext([
      [
        'radar/annotations/outages',
        () => ({
          body: {
            result: {
              annotations: [
                { description: 'Government-directed shutdown', startDate: hoursAgo(5), endDate: null, linkedUrl: 'https://x.test/1', outage: { outageCause: 'GOVERNMENT_DIRECTED', outageType: 'NATIONWIDE' }, locationsDetails: [{ code: 'XA', name: 'Exampleland' }], asnsDetails: [] },
                { description: 'Old outage', startDate: hoursAgo(100), endDate: hoursAgo(90), outage: { outageCause: 'UNKNOWN' }, asnsDetails: [{ asn: '1', name: 'NET-1', location: { code: 'XB', name: 'Otherland' } }] },
              ],
            },
          },
        }),
      ],
      ['radar/traffic_anomalies', () => ({ body: { result: { trafficAnomalies: [{ status: 'VERIFIED', type: 'LOCATION', startDate: hoursAgo(5), locationDetails: { code: 'XA', name: 'Exampleland' }, outageId: '9' }, { status: 'TP', type: 'AS', startDate: hoursAgo(2), asnDetails: { asn: '7', name: 'NET-7', location: { code: 'XC', name: 'Thirdland' } } }] } } })],
      ['ioda.inetintel', () => ({ body: { data: [{ scores: { overall: 9000 }, event_cnt: 3, entity: { code: 'XA', name: 'Exampleland' } }] } })],
    ]);
    const r = await blackout(ctx, 2);
    assert.equal(r.result.outages.length, 3, 'annotation-linked anomaly skipped');
    assert.equal(r.signals.length, 1, 'only confirmed and recent');
    assert.match(r.signals[0]!.title, /Internet disruption in Exampleland \(government directed\), ongoing/);
    assert.equal(r.signals[0]!.score, 85);
    assert.equal(r.signals[0]!.evidence[1]!.source, 'ioda');
    assert.equal(r.result.outages.find((o) => o.network === 'NET-7 (AS7)')!.verified, false);
  } finally {
    delete process.env.CLOUDFLARE_API_TOKEN;
  }
  const noKey = await blackout(testContext([['ioda', () => ({ body: { data: [] } })]]), 2);
  assert.equal(noKey.provenance[0]!.status, 'UNAVAILABLE');
});

test('hazards: GDACS alerts parsed, current ones become signals', async () => {
  const ctx = testContext([
    [
      'gdacs.org',
      () => ({
        body: {
          features: [
            { geometry: { coordinates: [85.4, 15.1] }, properties: { eventtype: 'TC', eventid: 1, name: 'Tropical Cyclone TEST', alertlevel: 'Red', country: 'Exampleland', fromdate: '2026-11-16T00:00:00', todate: '2026-11-18T06:00:00', iscurrent: 'true', severitydata: { severitytext: 'Category 4' }, url: { report: 'https://gdacs.test/r1' } } },
            { properties: { eventtype: 'DR', eventid: 2, name: 'Drought', alertlevel: 'Orange', fromdate: '2026-01-01T00:00:00', todate: '2026-11-01T00:00:00', iscurrent: false } },
          ],
        },
      }),
    ],
  ]);
  const r = await hazards(ctx, 7);
  assert.equal(r.result[0]!.level, 'Red');
  assert.equal(r.result[0]!.type, 'tropical cyclone');
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0]!.title, /GDACS red alert: Tropical Cyclone TEST \(Exampleland\)/);
});

test('dark ships: intentional gaps only, buoys dropped, recent cluster is a signal; vessel identity with sanctions', async () => {
  process.env.GFW_API_TOKEN = 'gfw-test-000000000000';
  try {
    const gap = (name: string, type: string, intentional: boolean, onH: number) => ({ start: hoursAgo(onH + 30), end: hoursAgo(onH), vessel: { id: `v-${name}`, name, ssvid: '123', flag: 'XAA', type }, gap: { intentionalDisabling: intentional, durationHours: 30.4, distanceKm: '120.6' } });
    const ctx = testContext([
      ['nominatim', () => ({ body: [{ display_name: 'Example Strait', lat: '10', lon: '20', boundingbox: ['9.9', '10.1', '19.9', '20.1'], type: 'strait', importance: 0.6 }] })],
      ['gateway.api.globalfishingwatch.org/v3/events', () => ({ body: { total: 5, entries: [gap('A', 'fishing', true, 10), gap('B', 'carrier', true, 20), gap('C', 'fishing', true, 30), gap('BUOY', 'gear', true, 5), gap('D', 'fishing', false, 5)] } })],
      ['vessels/search', () => ({ body: { entries: [{ selfReportedInfo: [{ id: 'x1', ssvid: '111', shipname: 'NEW NAME', imo: '7406784', transmissionDateFrom: '2024-01-01', transmissionDateTo: '2026-11-01' }, { id: 'x0', ssvid: '110', shipname: 'OLD NAME', transmissionDateFrom: '2019-01-01', transmissionDateTo: '2023-12-31' }], registryInfo: [], registryOwners: [{ name: 'Example Shipping', flag: 'XAA', dateFrom: '2020-01-01' }], combinedSourcesInfo: [{ shiptypes: [{ name: 'TANKER' }] }] }] } })],
      ['treasury.gov', () => ({ body: '9002,"EBANO",-0- ,"CUBA","vessel",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Vessel Registration Identification IMO 7406784."' })],
    ]);
    const r = await darkShips(ctx, 'Example Strait', 30);
    assert.deepEqual(r.result.gaps.map((g) => g.vessel), ['A', 'B', 'C']);
    assert.equal(r.result.gaps[0]!.km, 121);
    assert.equal(r.signals.length, 1);
    assert.match(r.signals[0]!.title, /3 vessels near Example Strait reappeared/);
    const [s, n, w, e] = seaBox(r.result.place!);
    assert.ok(n - s >= 2 && e - w >= 2, 'small places padded');
    const v = await vesselIdentity(ctx, 'NEW NAME');
    assert.equal(v.result[0]!.name, 'NEW NAME');
    assert.deepEqual(v.result[0]!.earlierNames, ['OLD NAME']);
    assert.equal(v.result[0]!.sanctions, 'SANCTIONED');
    assert.deepEqual(v.result[0]!.types, ['TANKER']);
  } finally {
    delete process.env.GFW_API_TOKEN;
  }
});

test('sentinel: OAuth token once, PNG saved per window, before/after pair', async () => {
  const { mkdtempSync, existsSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { sentinel } = await import('../src/modules/condor.js');
  process.env.COPERNICUS_CLIENT_ID = 'sh-test';
  process.env.COPERNICUS_CLIENT_SECRET = 'secret-test-000000000';
  const dir = mkdtempSync(join(tmpdir(), 'oculon-s2-'));
  try {
    let tokens = 0;
    const bodies: string[] = [];
    const png = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
    const ctx = testContext([
      ['nominatim', () => ({ body: [{ display_name: 'Example Port', lat: '51.9', lon: '4.4', boundingbox: ['51.89', '51.91', '4.39', '4.41'], type: 'port', importance: 0.6 }] })],
      ['openid-connect/token', () => (tokens++, { body: { access_token: 'tok', expires_in: 1800 } })],
      ['api/v1/process', () => ({ body: new Uint8Array(png) })],
    ]);
    const realFetch = ctx.http;
    void realFetch;
    const r = await sentinel(ctx, 'Example Port', { date: '2026-11-18', compareTo: '2026-06-30', dir });
    assert.equal(r.result.shots.length, 2);
    assert.equal(r.result.shots[0]!.to, '2026-11-18');
    assert.equal(r.result.shots[1]!.from, '2026-06-10');
    assert.ok(r.result.shots.every((s) => s.file && existsSync(s.file)));
    assert.ok(tokens <= 1, 'token reused');
    void bodies;
  } finally {
    delete process.env.COPERNICUS_CLIENT_ID;
    delete process.env.COPERNICUS_CLIENT_SECRET;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fires: FIRMS CSV parsing and clustering', async () => {
  const { parseFirmsCsv, clusterHotspots } = await import('../src/modules/fires.js');
  const csv = ['latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,satellite,instrument,confidence,version,bright_ti5,frp,daynight', '10.000,20.000,330,0.4,0.4,2026-11-18,436,N,VIIRS,h,2.0NRT,290,120.5,N', '10.010,20.010,320,0.4,0.4,2026-11-18,1450,N,VIIRS,n,2.0NRT,290,30,D', '11.000,21.000,310,0.4,0.4,2026-11-17,105,N,VIIRS,l,2.0NRT,290,2,N'].join('\n');
  const hs = parseFirmsCsv(csv, 'Suomi NPP');
  assert.equal(hs.length, 3);
  assert.equal(hs[0]!.time, '2026-11-18T04:36:00Z');
  assert.equal(hs[0]!.confidence, 'high');
  assert.equal(hs[2]!.confidence, 'low');
  const cl = clusterHotspots(hs);
  assert.equal(cl.length, 2);
  assert.deepEqual([cl[0]!.count, cl[0]!.frp, cl[0]!.last], [2, 151, '2026-11-18T14:50:00Z']);
  assert.deepEqual(parseFirmsCsv('Invalid MAP_KEY', 'x'), []);
});

test('sanctions: worldwide match marks names listed outside OFAC', async () => {
  const { screen } = await import('../src/modules/sanctions.js');
  process.env.OPENSANCTIONS_API_KEY = 'os-test-000000000000';
  try {
    const ctx = testContext([
      ['treasury.gov', () => ({ body: '36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ' })],
      ['api.opensanctions.org/match', () => ({ body: { responses: { q: { results: [{ id: 'Q1', caption: 'Example Oil', schema: 'Company', score: 0.97, datasets: ['eu_fsf', 'gb_hmt'], properties: { topics: ['sanction'], country: ['xx'] } }, { id: 'Q2', caption: 'Weak', schema: 'Company', score: 0.5 }] } } } })],
    ]);
    const r = await screen(ctx, 'Example Oil');
    assert.equal(r.result.verdict, 'LISTED_ELSEWHERE');
    assert.equal(r.result.worldwide.length, 1, 'weak matches dropped');
    assert.equal(r.result.worldwide[0]!.url, 'https://www.opensanctions.org/entities/Q1/');
    assert.match(r.signals[0]!.title, /non-US sanctions lists/);
  } finally {
    delete process.env.OPENSANCTIONS_API_KEY;
  }
});
