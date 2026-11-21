import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createContext } from '../src/core/context.js';
import { darkShips, parseEncounters, vesselIdentity } from '../src/modules/darkships.js';
import { dedupeHotspots, fires, parseAvailability, parseFirmsCsv } from '../src/modules/fires.js';
import { spaceWeather } from '../src/modules/sky.js';
import { isGroundOrTest, squawks } from '../src/modules/squawk.js';
import { byCallsign, fromAdsbLol, ladd, privacy } from '../src/sources/aircraft.js';
import { parseDonkiCme, parseForecast3Day, parseSwpcAlert } from '../src/sources/space.js';
import { NOW, testContext } from './helpers.js';

const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();
const adsb = (ac: unknown[]) => ({ body: { ac, msg: 'No error', now: NOW.getTime(), total: ac.length } });

test('squawk: emergency codes ranked 7500 > 7700 > 7600, ground tests ignored, hexdb fills registration', async () => {
  const ctx = testContext([
    ['api.adsb.lol/v2/sqk/7500', () => adsb([{ hex: 'abc123', flight: 'EXA101  ', r: 'X-ABCD', t: 'A320', alt_baro: 35000, gs: 450, track: 90, squawk: '7500', emergency: 'unlawful', lat: 26.5, lon: 56.3, seen_pos: 1.2 }])],
    [
      'api.adsb.lol/v2/sqk/7700',
      () =>
        adsb([
          { hex: 'def456', flight: 'EXA202', alt_baro: 12000, gs: 280, squawk: '7700', emergency: 'general', lat: 36.7, lon: -119.8, seen_pos: 0.5 },
          { hex: '111111', flight: 'GROUND1', alt_baro: 'ground', gs: 0, squawk: '7700', lat: 37.6, lon: -122.4, seen_pos: 2 },
          { hex: '222222', flight: 'STALE1', alt_baro: 9000, gs: 250, squawk: '7700', lat: 15.0, lon: 41.0, seen_pos: 900 },
        ]),
    ],
    ['api.adsb.lol/v2/sqk/7600', () => adsb([{ hex: '333333', flight: 'EXA303', r: 'X-RADI', t: 'B738', alt_baro: 8000, gs: 220, squawk: '7600', lat: 13.5, lon: 43.0, seen_pos: 3 }])],
    ['hexdb.io/api/v1/aircraft/DEF456', () => ({ body: { ModeS: 'DEF456', Registration: 'X-DEFG', Manufacturer: 'Exampleair', Type: 'E190', ICAOTypeCode: 'E190', RegisteredOwners: 'Exampleland Airways' } })],
  ]);
  const r = await squawks(ctx);
  assert.deepEqual(r.result.aircraft.map((a) => a.code), ['7500', '7700', '7600']);
  assert.equal(r.result.ignored, 2, 'ground test and stale position dropped');
  assert.deepEqual(r.result.byCode, { '7500': 1, '7600': 1, '7700': 1 });
  const em = r.result.aircraft[1]!;
  assert.equal(em.registration, 'X-DEFG');
  assert.equal(em.owner, 'Exampleland Airways');
  assert.equal(em.emergency, 'general');
  const scores = r.signals.map((s) => s.score);
  assert.ok(scores[0]! > scores[1]! && scores[1]! > scores[2]!, `scores ordered: ${scores}`);
  assert.match(r.signals[0]!.title, /Squawk 7500 \(hijack \/ unlawful interference\): EXA101 \/ X-ABCD \/ A320/);
  assert.equal(r.signals[0]!.score, 95, 'emergency flag confirms the code');
});

test('squawk helpers: ground filter, emergency/dbFlags mapped, callsign / LADD / PIA endpoints', async () => {
  const s = fromAdsbLol({ hex: '~A1B2C3', alt_baro: 'ground', gs: 0, emergency: 'none', dbFlags: 8, lat: 1, lon: 1 });
  assert.equal(s.hex, 'a1b2c3');
  assert.equal(s.dbFlags, 8);
  assert.equal(s.emergency, 'none');
  assert.equal(isGroundOrTest(s), true);
  assert.equal(isGroundOrTest({ ...s, onGround: false, altFt: 3000, speedKt: 180 }), false);
  const ctx = testContext([
    ['/v2/callsign/UAE44', () => adsb([{ hex: '8963d0', flight: 'UAE44   ', r: 'A6-EPA', t: 'B77W', alt_baro: 11350, gs: 369.5, lat: 25.6, lon: 54.9 }])],
    ['/v2/ladd', () => adsb([{ hex: 'a8bf91', flight: 'NCR482', r: 'N663CA', t: 'B744', dbFlags: 8, alt_baro: 34000 }])],
    ['/v2/pia', () => adsb([{ hex: 'a092e7', flight: 'XAA4927', dbFlags: 4, alt_baro: 43000 }])],
  ]);
  assert.equal((await byCallsign(ctx, 'uae44')).data![0]!.registration, 'A6-EPA');
  assert.equal((await ladd(ctx)).data![0]!.dbFlags, 8);
  assert.equal((await privacy(ctx)).data![0]!.callsign, 'XAA4927');
});

const FORECAST = `:Product: 3-Day Forecast
:Issued: 2026 Nov 18 1230 UTC
# Prepared by the U.S. Dept. of Commerce, NOAA, Space Weather Prediction Center
#
A. NOAA Geomagnetic Activity Observation and Forecast

The greatest observed 3 hr Kp over the past 24 hours was 4 (below NOAA
Scale levels).
The greatest expected 3 hr Kp for Nov 18-Nov 20 2026 is 7.33 (NOAA Scale
G3).

NOAA Kp index breakdown Nov 18-Nov 20 2026

             Nov 18       Nov 19       Nov 20
00-03UT       2.00         7.33 (G3)    3.00
03-06UT       2.67         6.00 (G2)    2.67
06-09UT       1.67         4.00         2.00

Rationale: G3 (Strong) storm levels are likely on 19 Nov due to the
anticipated arrival of the 16 Nov CME.

B. NOAA Solar Radiation Activity Observation and Forecast
`;

test('space weather: SWPC alerts, solar wind, scales, forecast, DONKI CME arrival and NEO become signals', async () => {
  process.env.NASA_API_KEY = 'nasa-test-0000000000000';
  try {
    const ctx = testContext([
      ['noaa-planetary-k-index.json', () => ({ body: [{ time_tag: '2026-11-18T09:00:00', Kp: 4 }] })],
      ['xray-flares-7-day.json', () => ({ body: [{ max_class: 'M1.2', max_time: '2026-11-17T08:00Z', begin_time: '2026-11-17T07:50Z' }] })],
      [
        'products/alerts.json',
        () => ({
          body: [
            { product_id: 'K07A', issue_datetime: '2026-11-18 06:10:00.000', message: 'Space Weather Message Code: ALTK07\r\nSerial Number: 100\r\nIssue Time: 2026 Nov 18 0610 UTC\r\n\r\nALERT: Geomagnetic K-index of 7\nThreshold Reached: 2026 Nov 18 0609 UTC\nSynoptic Period: 0600-0900\nActive Warning: Yes\nNOAA Scale: G3 - Strong\r\n' },
            { product_id: 'K04W', issue_datetime: '2026-11-18 01:18:16.670', message: 'Space Weather Message Code: WARK04\r\nSerial Number: 5457\r\nIssue Time: 2026 Nov 18 0118 UTC\r\n\r\nEXTENDED WARNING: Geomagnetic K-index of 4 expected\nNow Valid Until: 2026 Nov 18 0900 UTC\r\n' },
            { product_id: 'SUMX', issue_datetime: '2026-11-18 02:00:00.000', message: 'Space Weather Message Code: SUMX01\r\nSUMMARY: X-ray Event exceeded M5\r\n' },
          ],
        }),
      ],
      ['summary/solar-wind-speed.json', () => ({ body: [{ proton_speed: 720, time_tag: '2026-11-18T11:58:00Z' }] })],
      ['summary/solar-wind-mag-field.json', () => ({ body: [{ bt: 22, bz_gsm: -18, time_tag: '2026-11-18T11:58:00Z' }] })],
      ['noaa-scales.json', () => ({ body: { '0': { DateStamp: '2026-11-18', R: { Scale: '1' }, S: { Scale: '0' }, G: { Scale: '3' } }, '1': { DateStamp: '2026-11-18', R: { MinorProb: '25', MajorProb: '5' }, S: { Prob: '5' }, G: { Scale: '3' } } } })],
      ['3-day-forecast.txt', () => ({ body: FORECAST })],
      [
        'DONKI/CME?',
        () => ({
          body: [
            { activityID: '2026-11-16T10:00:00-CME-001', startTime: '2026-11-16T10:00Z', link: 'https://ccmc.test/cme1', cmeAnalyses: [{ isMostAccurate: true, speed: 1250, halfAngle: 45, type: 'O', enlilList: [{ estimatedShockArrivalTime: '2026-11-19T02:00Z', isEarthGB: false, kp_90: 6, kp_180: 8 }] }] },
            { activityID: '2026-11-15T01:00:00-CME-001', startTime: '2026-11-15T01:00Z', cmeAnalyses: [{ isMostAccurate: true, speed: 400, enlilList: [{ estimatedShockArrivalTime: null, isEarthGB: false }] }] },
          ],
        }),
      ],
      ['DONKI/GST', () => ({ body: [{ gstID: '2026-11-18T06:00:00-GST-001', startTime: '2026-11-18T06:00Z', allKpIndex: [{ kpIndex: 6.67 }, { kpIndex: 7.33 }], link: 'https://ccmc.test/gst' }] })],
      ['DONKI/notifications', () => ({ body: [{ messageType: 'CME', messageID: '20261116-AL-001', messageIssueTime: '2026-11-16T14:00Z', messageURL: 'https://ccmc.test/n1', messageBody: '## Message Type: Space Weather Notification - CME (Earth)\n##\n## Summary:\n\nO-type CME detected. Estimated speed: ~1250 km/s.\n\n## Notes:\nx' }] })],
      [
        'neo/rest/v1/feed',
        () => ({
          body: {
            near_earth_objects: {
              '2026-11-19': [
                { id: '999', name: '(2026 XA1)', is_potentially_hazardous_asteroid: true, estimated_diameter: { meters: { estimated_diameter_min: 150, estimated_diameter_max: 340 } }, close_approach_data: [{ close_approach_date_full: '2026-Nov-19 03:49', miss_distance: { lunar: '0.62', kilometers: '238000' }, relative_velocity: { kilometers_per_second: '12.34' }, orbiting_body: 'Earth' }] },
                { id: '998', name: '(2026 XB2)', is_potentially_hazardous_asteroid: false, estimated_diameter: { meters: { estimated_diameter_min: 5, estimated_diameter_max: 12 } }, close_approach_data: [{ close_approach_date_full: '2026-Nov-19 10:00', miss_distance: { lunar: '0.05', kilometers: '19000' }, relative_velocity: { kilometers_per_second: '9' }, orbiting_body: 'Earth' }] },
                { id: '997', name: '(2020 AB)', is_potentially_hazardous_asteroid: true, close_approach_data: [{ close_approach_date_full: '2026-Nov-19 11:00', miss_distance: { lunar: '30.1', kilometers: '11500000' }, relative_velocity: { kilometers_per_second: '20' }, orbiting_body: 'Earth' }] },
              ],
            },
          },
        }),
      ],
    ]);
    const r = await spaceWeather(ctx, 7);
    const x = r.result;
    assert.equal(x.alerts!.length, 2, 'summary left out');
    assert.equal(x.alerts![0]!.code, 'ALTK07');
    assert.equal(x.alerts![0]!.scale, 'G3');
    assert.deepEqual(x.solarWind, { time: '2026-11-18T11:58:00Z', speedKmS: 720, bt: 22, bz: -18 });
    assert.equal(x.scales!.now.g, 3);
    assert.equal(x.forecast!.expectedKpMax, 7.33);
    assert.equal(x.forecast!.kpByDay['Nov 19'], 7.33);
    assert.equal(x.cmes![0]!.earthArrival, '2026-11-19T02:00Z');
    assert.equal(x.storms![0]!.kpMax, 7.33);
    assert.match(x.notifications![0]!.summary, /O-type CME detected/);
    assert.deepEqual(x.neo!.map((n) => n.name), ['2026 XB2', '2026 XA1', '2020 AB']);
    const titles = r.signals.map((s) => s.title);
    assert.ok(titles.some((t) => /NOAA SWPC alert: G3 geomagnetic storm/.test(t)), titles.join(' | '));
    assert.ok(titles.some((t) => /NOAA forecasts G3 strong storm/.test(t)));
    const cme = r.signals.find((s) => /Earth-directed CME/.test(s.title))!;
    assert.equal(cme.score, 75, 'model Kp 8 and fast CME');
    assert.ok(titles.some((t) => /Asteroid 2026 XA1 passes 0.62 lunar distances/.test(t)));
    assert.ok(!titles.some((t) => /2026 XB2|2020 AB/.test(t)), 'tiny or distant objects are not signals');
    assert.ok(ctx.calls.every((u) => !u.includes('DONKI/FLR')));

    const quiet = testContext([]);
    const q = await spaceWeather(quiet, 7, { nasa: false });
    assert.ok(quiet.calls.every((u) => !u.includes('api.nasa.gov')), 'nasa: false skips NASA');
    assert.equal(q.signals.length, 0);
  } finally {
    delete process.env.NASA_API_KEY;
  }
});

test('space parsers: SWPC alert kinds, forecast text, DONKI CME without analyses', () => {
  const w = parseSwpcAlert({ product_id: 'A20F', issue_datetime: '2026-11-18 03:00:00.000', message: 'Space Weather Message Code: WATA20\r\nWATCH: Geomagnetic Storm Category G2 Predicted\r\nHighest Storm Level Predicted by Day:\r\nNOAA Scale: G2 - Moderate' });
  assert.equal(w.kind, 'WATCH');
  assert.equal(w.scale, 'G2');
  assert.equal(w.issued, '2026-11-18T03:00:00Z');
  const f = parseForecast3Day(FORECAST);
  assert.equal(f.observedKpMax24h, 4);
  assert.match(f.rationale!, /G3 \(Strong\) storm levels are likely/);
  const c = parseDonkiCme({ activityID: 'x', startTime: '2026-11-18T00:00Z' });
  assert.equal(c.earthArrival, null);
  assert.equal(c.speedKmS, null);
});

/** A context whose fetch answers GFW POST /events by the dataset named in the JSON body. */
function gfwContext(byDataset: Record<string, unknown[]>, extra: [string, unknown][] = []) {
  const calls: { url: string; body: Record<string, unknown> | null }[] = [];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const raw = init?.body;
    const body = raw ? (JSON.parse(typeof raw === 'string' ? raw : new TextDecoder().decode(raw as Uint8Array)) as Record<string, unknown>) : null;
    calls.push({ url, body });
    if (url.includes('/v3/events') && body) {
      const ds = (body.datasets as string[])[0]!;
      const entries = byDataset[ds] ?? [];
      return new Response(JSON.stringify({ total: entries.length, entries }), { status: 201 });
    }
    const hit = extra.find(([m]) => url.includes(m));
    if (!hit) return new Response('not found', { status: 404 });
    return new Response(typeof hit[1] === 'string' ? hit[1] : JSON.stringify(hit[1]), { status: 200 });
  }) as typeof fetch;
  const ctx = createContext({ dbPath: ':memory:', fetch: fetchFn, throttle: false, retryDelayMs: 1, now: () => NOW });
  return Object.assign(ctx, { gfwCalls: calls });
}

// ofac.ts memoizes the parsed list per process, so both GFW tests share one SDN file.
const SDN_CSV = [
  '9100,"LISTED TANKER",-0- ,"EXAMPLE-EO","vessel",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Vessel Registration Identification IMO 9123456."',
  '9002,"EBANO",-0- ,"CUBA","vessel",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Vessel Registration Identification IMO 7406784."',
].join('\n');

const V = (id: string, name: string, type = 'carrier', flag = 'XAA') => ({ id, name, ssvid: `${id.length}${id.charCodeAt(1)}000`, flag, type });

test('dark ships: encounters deduped, gap-linked and OFAC-listed encounters score high, port visits of vessels of interest', async () => {
  process.env.GFW_API_TOKEN = 'gfw-test-000000000000';
  try {
    const enc = (a: ReturnType<typeof V>, b: ReturnType<typeof V>, startH: number) => ({ id: `e-${a.id}`, type: 'encounter', start: hoursAgo(startH), end: hoursAgo(startH - 6), position: { lat: 13.1, lon: 42.9 }, vessel: a, encounter: { vessel: b, type: 'carrier-fishing', potentialRisk: true, medianDistanceKilometers: 0.03 } });
    const dark = V('v-dark', 'DARK ONE', 'fishing');
    const reefer = V('v-reefer', 'COLD CARRIER');
    const listed = V('v-listed', 'LISTED TANKER', 'other');
    const other = V('v-other', 'PLAIN FISHER', 'fishing');
    const ctx = gfwContext(
      {
        'public-global-gaps-events:latest': [{ start: hoursAgo(80), end: hoursAgo(50), vessel: dark, gap: { intentionalDisabling: true, durationHours: 30, distanceKm: '90' } }],
        'public-global-encounters-events:latest': [enc(reefer, dark, 40), enc(dark, reefer, 40), enc(listed, other, 20), enc(other, listed, 20)],
        'public-global-loitering-events:latest': [{ type: 'loitering', start: hoursAgo(30), end: hoursAgo(10), position: { lat: 13, lon: 43 }, vessel: reefer, loitering: { totalTimeHours: 20, averageDistanceFromShoreKm: 60 } }],
        'public-global-port-visits-events:latest': [{ type: 'port_visit', start: hoursAgo(9), end: hoursAgo(2), position: { lat: 12.8, lon: 45.0 }, vessel: listed, port_visit: { durationHrs: 7, intermediateAnchorage: { name: null, flag: 'XBB' }, endAnchorage: { name: 'EXAMPLE PORT', flag: 'XBB' } } }],
      },
      [
        ['nominatim', [{ display_name: 'Red Sea', lat: '20', lon: '38', boundingbox: ['12', '28', '32', '44'], type: 'sea', importance: 0.7 }]],
        ['/v3/vessels?datasets[0]=public-global-vessel-identity', { entries: [{ selfReportedInfo: [{ id: 'v-listed' }], registryInfo: [{ imo: '9123456' }] }, { selfReportedInfo: [{ id: 'v-reefer' }], registryInfo: [{ imo: '9000001' }] }] }],
        ['treasury.gov', SDN_CSV],
      ],
    );
    const r = await darkShips(ctx, 'Red Sea', 30);
    const x = r.result;
    assert.equal(x.encounters!.length, 2, 'each encounter listed once');
    const linked = x.encounters!.find((e) => e.gapLinked)!;
    assert.deepEqual([linked.a.name, linked.b.name].sort(), ['COLD CARRIER', 'DARK ONE']);
    const sanc = x.encounters!.find((e) => e.a.sanctioned || e.b.sanctioned)!;
    assert.equal([sanc.a, sanc.b].find((v) => v.sanctioned)!.imo, '9123456');
    assert.equal(x.loitering![0]!.linked, true);
    assert.equal(x.portVisits![0]!.port, 'EXAMPLE PORT');
    assert.equal(x.portVisits![0]!.vessel.sanctioned, 'LISTED TANKER');
    const pvBody = ctx.gfwCalls.find((c) => (c.body?.datasets as string[] | undefined)?.[0] === 'public-global-port-visits-events:latest')!.body!;
    assert.deepEqual([...(pvBody.vessels as string[])].sort(), ['v-dark', 'v-listed', 'v-other', 'v-reefer']);
    const sTitles = r.signals.map((s) => `${s.score} ${s.title}`);
    const stsListed = r.signals.find((s) => /ship-to-ship/.test(s.title) && /OFAC-listed/.test(s.title))!;
    const stsDark = r.signals.find((s) => /ship-to-ship/.test(s.title) && /went dark/.test(s.title))!;
    assert.ok(stsListed.score > stsDark.score && stsDark.score >= 68, sTitles.join(' | '));
    assert.ok(r.signals.some((s) => /OFAC-listed vessel LISTED TANKER called at EXAMPLE PORT \(XBB\)/.test(s.title)), sTitles.join(' | '));
    assert.deepEqual(x.totals, { gaps: 1, encounters: 4, loitering: 1, portVisits: 1 });

    const lean = await darkShips(ctx, 'Red Sea', 30, { extra: false });
    assert.equal(lean.result.encounters, undefined);
  } finally {
    delete process.env.GFW_API_TOKEN;
  }
});

test('vessel identity: per-vessel event history across all GFW ids, sanctioned and active is a signal', async () => {
  process.env.GFW_API_TOKEN = 'gfw-test-000000000000';
  try {
    const me = V('id-new', 'NEW NAME', 'other');
    const ctx = gfwContext(
      {
        'public-global-gaps-events:latest': [{ start: hoursAgo(500), end: hoursAgo(400), vessel: me, gap: { intentionalDisabling: true, durationHours: 100, distanceKm: 300, offPosition: { lat: 26, lon: 56 } } }],
        'public-global-encounters-events:latest': [{ type: 'encounter', start: hoursAgo(300), end: hoursAgo(290), position: { lat: 25.9, lon: 56.4 }, vessel: me, encounter: { vessel: V('id-x', 'SHADOW', 'other', 'XCC'), type: 'tanker-tanker' } }],
        'public-global-port-visits-events:latest': [
          { type: 'port_visit', start: hoursAgo(100), end: hoursAgo(90), vessel: me, port_visit: { intermediateAnchorage: { name: 'EXAMPLE HARBOUR', flag: 'XDD' } } },
          { type: 'port_visit', start: hoursAgo(50), end: hoursAgo(40), vessel: me, port_visit: { intermediateAnchorage: { name: 'EXAMPLE HARBOUR', flag: 'XDD' } } },
        ],
      },
      [
        ['vessels/search', { entries: [{ selfReportedInfo: [{ id: 'id-new', ssvid: '111', shipname: 'NEW NAME', imo: '7406784', transmissionDateTo: '2026-11-01' }, { id: 'id-old', ssvid: '110', shipname: 'OLD NAME', transmissionDateTo: '2023-12-31' }], registryInfo: [], registryOwners: [], combinedSourcesInfo: [] }] }],
        ['treasury.gov', SDN_CSV],
      ],
    );
    const v = await vesselIdentity(ctx, 'NEW NAME');
    const h = v.result[0]!.history!;
    assert.deepEqual(v.result[0]!.ids, ['id-new', 'id-old']);
    assert.deepEqual([h.gaps, h.encounters, h.loitering, h.portVisits], [1, 1, 0, 2]);
    assert.equal(h.recent[0]!.kind, 'port_visit');
    assert.equal(h.recent.find((e) => e.kind === 'encounter')!.detail, 'SHADOW (XCC) other');
    assert.deepEqual(h.ports, [{ port: 'EXAMPLE HARBOUR', flag: 'XDD', visits: 2 }]);
    const evBody = ctx.gfwCalls.find((c) => c.url.includes('/v3/events'))!.body!;
    assert.deepEqual(evBody.vessels, ['id-new', 'id-old']);
    assert.equal(v.signals.length, 1);
    assert.match(v.signals[0]!.title, /OFAC-listed vessel NEW NAME active in the last 365 days: 1 encounters, 1 AIS gaps, 2 port visits/);
    const noHist = await vesselIdentity(ctx, 'NEW NAME', { history: false });
    assert.equal(noHist.result[0]!.history, undefined);
  } finally {
    delete process.env.GFW_API_TOKEN;
  }
});

test('encounter parser drops rows without an encounter block', () => {
  assert.deepEqual(parseEncounters([{ start: hoursAgo(2), end: hoursAgo(1), vessel: V('a', 'A') }]), []);
});

const VIIRS_HEAD = 'latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,satellite,instrument,confidence,version,bright_ti5,frp,daynight';
const MODIS_HEAD = 'latitude,longitude,brightness,scan,track,acq_date,acq_time,satellite,instrument,confidence,version,bright_t31,frp,daynight';

test('fires: products picked from data_availability, MODIS merged with numeric confidence, VIIRS duplicates removed', async () => {
  process.env.FIRMS_MAP_KEY = 'firms-test-000000000000';
  try {
    const ctx = testContext([
      ['nominatim', () => ({ body: [{ display_name: 'Sierra Nevada, California', lat: '37.5', lon: '-119.5', boundingbox: ['36', '39', '-121', '-118'], type: 'mountain_range', importance: 0.6 }] })],
      ['data_availability', () => ({ body: 'data_id,min_date,max_date\nMODIS_NRT,2026-09-01,2026-11-18\nVIIRS_NOAA20_NRT,2026-08-01,2026-11-18\nVIIRS_NOAA21_NRT,2024-01-17,2026-11-18\nVIIRS_SNPP_NRT,2026-08-01,2026-11-02\nLANDSAT_NRT,2022-06-20,2026-11-18\n' })],
      ['VIIRS_NOAA21_NRT', () => ({ body: `${VIIRS_HEAD}\n37.24412,-119.42036,330,0.4,0.4,2026-11-18,351,N21,VIIRS,h,2.0NRT,290,40.5,N\n37.24412,-119.42036,330,0.4,0.4,2026-11-18,351,N21,VIIRS,h,2.0NRT,290,40.5,N` })],
      ['VIIRS_NOAA20_NRT', () => ({ body: `${VIIRS_HEAD}\n38.39749,-120.18743,310,0.4,0.4,2026-11-18,1008,N20,VIIRS,n,2.0NRT,280,3.1,N` })],
      ['MODIS_NRT', () => ({ body: `${MODIS_HEAD}\n37.24635,-119.40721,305.86,1.21,1.09,2026-11-18,355,Terra,MODIS,66,6.1NRT,270.2,15.77,N\n36.22198,-118.70312,301.8,1.17,1.08,2026-11-18,1830,Aqua,MODIS,85,6.1NRT,272.98,12.16,D` })],
    ]);
    const r = await fires(ctx, 'Sierra Nevada, California', 2);
    assert.ok(!ctx.calls.some((u) => u.includes('VIIRS_SNPP_NRT')), 'stopped feed skipped');
    assert.ok(!ctx.calls.some((u) => u.includes('LANDSAT_NRT')), 'Landsat only on request');
    const hs = r.result.hotspots;
    assert.equal(hs.length, 3, 'exact VIIRS duplicate and the MODIS copy of the same pass dropped');
    const aqua = hs.find((h) => h.satellite === 'MODIS Aqua')!;
    assert.equal(aqua.confidence, 'high');
    assert.equal(aqua.product, 'MODIS_NRT');
    assert.deepEqual(new Set(hs.map((h) => h.product)), new Set(['VIIRS_NOAA21_NRT', 'VIIRS_NOAA20_NRT', 'MODIS_NRT']));

    const only = await fires(ctx, 'Sierra Nevada, California', 2, { products: ['LANDSAT_NRT', 'NOT_A_PRODUCT'] });
    assert.deepEqual(only.provenance.filter((p) => p.source === 'firms').length, 1);
  } finally {
    delete process.env.FIRMS_MAP_KEY;
  }
});

test('fires helpers: availability parsing, MODIS confidence buckets, dedupe keeps separate passes', () => {
  assert.deepEqual(parseAvailability('data_id,min_date,max_date\nMODIS_NRT,2026-09-01,2026-11-18\nMODIS_SP,2000-11-01,2026-08-31\nVIIRS_SNPP_NRT,2026-08-01,2026-11-02', '2026-11-15'), ['MODIS_NRT']);
  const m = parseFirmsCsv(`${MODIS_HEAD}\n10,20,300,1,1,2026-11-18,100,Terra,MODIS,20,6.1NRT,270,5,N\n10,20.5,300,1,1,2026-11-18,100,Terra,MODIS,50,6.1NRT,270,5,N`, 'MODIS');
  assert.deepEqual(m.map((h) => h.confidence), ['low', 'nominal']);
  assert.equal(m[0]!.satellite, 'MODIS Terra');
  const v = parseFirmsCsv(`${VIIRS_HEAD}\n10.001,20.001,330,0.4,0.4,2026-11-18,300,N21,VIIRS,n,2.0NRT,290,4,N`, 'NOAA-21');
  // VIIRS two hours later at the same spot: a different pass, so the MODIS detection stays.
  assert.equal(dedupeHotspots([...v, ...m]).length, 3);
});
