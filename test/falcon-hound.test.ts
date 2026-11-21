import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeChange, locate, mil, track } from '../src/modules/falcon.js';
import { hound, mentions } from '../src/modules/hound.js';
import { parseAirports, parseCsvLine, type Airport } from '../src/sources/airports.js';
import { matchCompany } from '../src/sources/sec.js';
import { NOW, testContext, type Route } from './helpers.js';

const CSV = [
  '"id","ident","type","name","latitude_deg","longitude_deg","elevation_ft","continent","iso_country","iso_region","municipality","scheduled_service","gps_code","iata_code"',
  '1,"KSJC","large_airport","Norman Y. Mineta San Jose International Airport",37.362,-121.929,62,"NA","US","US-CA","San Jose","yes","KSJC","SJC"',
  '2,"KVNY","medium_airport","Van Nuys Airport",34.21,-118.49,802,"NA","US","US-CA","Los Angeles","no","KVNY","VNY"',
  '3,"EGLL","large_airport","London Heathrow Airport",51.47,-0.4543,83,"EU","GB","GB-ENG","London","yes","EGLL","LHR"',
  '4,"XX01","small_airport","Tiny Strip",10,10,0,"AF","NG","NG-1","Nowhere","no","",""',
].join('\n');

const airportsList = parseAirports(CSV);

test('csv parsing keeps large and medium airports only', () => {
  assert.deepEqual(parseCsvLine('"a","b, c",3,"d ""q"""'), ['a', 'b, c', '3', 'd "q"']);
  assert.equal(airportsList.length, 3);
  assert.equal(airportsList[0]?.iata, 'SJC');
});

test('locate and describeChange', () => {
  const base = { hex: 'a835af', registration: null, type: null, callsign: null, speedKt: 0, track: 0, squawk: null, seenSec: 1, source: 'adsb.lol' as const };
  const atSjc = locate(airportsList, { ...base, lat: 37.37, lon: -121.93, altFt: 0, onGround: true })!;
  assert.equal(atSjc.relation, 'at');
  assert.equal(atSjc.ident, 'KSJC');
  const cruising = locate(airportsList, { ...base, lat: 36.5, lon: -121.0, altFt: 41000, onGround: false });
  assert.equal(cruising?.relation, 'over');
  const atVny = locate(airportsList, { ...base, lat: 34.21, lon: -118.49, altFt: 0, onGround: true })!;
  assert.match(describeChange({ status: 'ON_GROUND', place: atVny, at: '' }, 'ON_GROUND', atSjc) ?? '', /moved from Van Nuys.*to Norman/);
  assert.match(describeChange({ status: 'ON_GROUND', place: atVny, at: '' }, 'AIRBORNE', cruising) ?? '', /^took off/);
  assert.equal(describeChange(null, 'AIRBORNE', cruising), null);
});

const trackRoutes = (lat: number, lon: number): Route[] => [
  ['ourairports', () => ({ body: CSV })],
  ['hexdb.io/reg-hex', () => ({ body: 'A835AF' })],
  ['hexdb.io/api/v1/aircraft', () => ({ body: { ModeS: 'A835AF', Registration: 'N628TS', Manufacturer: 'Gulfstream Aerospace', Type: 'G650 ER', ICAOTypeCode: 'G650', RegisteredOwners: 'Falcon Landing LLC' } })],
  ['api.adsb.lol/v2/hex', () => ({ body: { ac: [{ hex: 'a835af', r: 'N628TS', t: 'GLF6', lat, lon, alt_baro: 'ground', gs: 0 }] } })],
];

test('track resolves registration, links owner, and detects a move between checks', async () => {
  const ctx = testContext(trackRoutes(34.21, -118.49));
  const r1 = await track(ctx, 'N628TS');
  assert.equal(r1.result.hex, 'a835af');
  assert.equal(r1.result.status, 'ON_GROUND');
  assert.equal(r1.result.place?.ident, 'KVNY');
  assert.equal(r1.result.change, null);
  assert.ok(ctx.graph.neighbors('aircraft:a835af').some((n) => n.id === 'company:falcon landing llc'));

  (ctx as { http: unknown }).http = testContext(trackRoutes(37.365, -121.93)).http;
  const r2 = await track(ctx, 'N628TS');
  assert.match(r2.result.change ?? '', /moved from Van Nuys/);
  assert.equal(r2.signals.length, 1);
});

test('mil groups by region and flags notable roles; never claims a surge without history', async () => {
  const ac = [
    { hex: 'ae0001', t: 'K35R', flight: 'QID01', lat: 51.6, lon: -0.5, alt_baro: 28000 },
    { hex: 'ae0002', t: 'R135', flight: 'RCH02', lat: 51.2, lon: 0.1, alt_baro: 31000 },
    { hex: 'ae0003', t: 'C17', lat: 51.4, lon: -0.3, alt_baro: 20000 },
    { hex: 'ae0004', t: 'H60', lat: 37.3, lon: -121.9, alt_baro: 1000 },
    { hex: 'ae0005', t: 'P8', lat: 0, lon: -150, alt_baro: 25000 },
  ];
  const ctx = testContext([
    ['ourairports', () => ({ body: CSV })],
    ['api.adsb.lol/v2/mil', () => ({ body: { ac } })],
  ]);
  const r = await mil(ctx);
  assert.equal(r.result.withPosition, 5);
  const gb = r.result.regions.find((g) => g.key === 'GB')!;
  assert.equal(gb.count, 3);
  assert.ok(r.result.regions.some((g) => g.key === 'US-CA'), 'large countries split by region');
  assert.deepEqual(gb.notable.map((n) => n.role).sort(), ['ISR', 'tanker']);
  assert.ok(r.result.regions.some((g) => g.key === 'OCEAN'));
  assert.equal(r.result.firstRuns, true);
  assert.ok(r.signals.every((s) => !/surge/.test(s.title)));
  assert.ok(r.signals.some((s) => /tanker/.test(s.title) && /London/.test(s.title)));
});

test('mentions and SEC company matching', () => {
  assert.ok(mentions('Nvidia stopped disclosing Singapore sales', 'Nvidia'));
  assert.ok(!mentions('A new GPU startup raises money', 'Nvidia'));
  const list = [
    { cik: 1, ticker: 'NVDA', name: 'NVIDIA CORP' },
    { cik: 2, ticker: 'NVDX', name: 'Leveraged NVIDIA Daily ETF Trust' },
  ];
  assert.equal(matchCompany(list, 'nvda')?.cik, 1);
  assert.equal(matchCompany(list, 'Nvidia')?.cik, 1);
  assert.equal(matchCompany(list, 'apple'), null);
});

test('hound builds a dossier, timeline and fused signal; SEC stays off without contact', async () => {
  delete process.env.OCULON_CONTACT;
  const day = 86_400_000;
  const views = Array.from({ length: 30 }, (_, i) => ({ timestamp: `${new Date(NOW.getTime() - (30 - i) * day).toISOString().slice(0, 10).replace(/-/g, '')}00`, views: i === 29 ? 50_000 : 5000 }));
  const ctx = testContext([
    ['opensearch', () => ({ body: ['nvidia', ['Nvidia']] })],
    ['page/summary', () => ({ body: { title: 'Nvidia', description: 'American technology company', extract: '...', content_urls: { desktop: { page: 'https://en.wikipedia.org/wiki/Nvidia' } } } })],
    ['per-article', () => ({ body: { items: views } })],
    ['hn.algolia.com', () => ({ body: { hits: [{ objectID: '9', title: 'Nvidia stopped disclosing Singapore sales', url: null, points: 450, num_comments: 300, created_at_i: NOW.getTime() / 1000 - 3600 }, { objectID: '8', title: 'Unrelated story', url: null, points: 900, num_comments: 1, created_at_i: NOW.getTime() / 1000 - 3600 }] } })],
    ['gdeltproject', () => ({ body: { articles: [{ url: 'https://n.test/a', title: 'Nvidia shares fall', seendate: '20261118T090000Z', domain: 'n.test' }] } })],
    ['public-search', () => ({ body: { events: [{ closed: false, markets: [{ id: 1, question: 'Will Jensen Huang rejoin Nvidia?', slug: 'jh', outcomes: '["Yes","No"]', outcomePrices: '["0.03","0.97"]', volume24hr: 9e5, oneDayPriceChange: -0.12 }] }] } })],
    ['api.github.com/orgs/nvidia', () => ({ body: [{ name: 'x', full_name: 'NVIDIA/x', html_url: 'https://github.com/NVIDIA/x', description: 'new', created_at: new Date(NOW.getTime() - 2 * day).toISOString(), pushed_at: '', stargazers_count: 1, language: null, fork: false }] })],
  ]);
  const r = await hound(ctx, 'Nvidia');
  const d = r.result;
  assert.equal(d.wikipedia?.title, 'Nvidia');
  assert.ok((d.wikipedia?.spike ?? 0) >= 9);
  assert.equal(d.stories.length, 1, 'unrelated story filtered');
  assert.equal(d.markets.length, 1);
  assert.equal(d.github?.repos.length, 1);
  assert.equal(d.sec, null);
  assert.equal(r.provenance.find((p) => p.source === 'sec-edgar')?.status, 'UNAVAILABLE');
  assert.ok(d.timeline.length >= 3);
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0]!.title, /independent sources/);
  assert.ok(ctx.graph.neighbors('org:nvidia').length >= 3);
  assert.ok(!ctx.calls.some((u) => u.includes('sec.gov')), 'no SEC calls without contact');
});
