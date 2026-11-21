import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bgp, countryRouting } from '../src/modules/bgp.js';
import { cloudStatus, decodeAny } from '../src/modules/cloud.js';
import { hazards } from '../src/modules/hazards.js';
import { NOW, testContext } from './helpers.js';

const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();

test('cloud: status pages, Google Cloud, AWS (UTF-16) and Azure merged; major incidents become signals', async () => {
  const aws = JSON.stringify([
    { date: String(Math.floor(NOW.getTime() / 1000) - 3600), region_name: 'Example Region', service_name: 'Compute', summary: 'Increased Error Rates', event_log: [{ message: 'Investigating.', timestamp: Math.floor(NOW.getTime() / 1000) - 600 }] },
    { date: '1700000000', region_name: 'Old', service_name: 'Old', summary: 'Old event', event_log: [] },
  ]);
  const utf16be = Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(aws, 'utf16le').swap16()]);
  assert.equal(JSON.parse(decodeAny(utf16be)).length, 2);
  const ctx = testContext([
    ['githubstatus.com', () => ({ body: { status: { indicator: 'major', description: 'Partial System Outage' }, incidents: [{ name: 'Actions delayed', status: 'investigating', impact: 'major', created_at: hoursAgo(2), updated_at: hoursAgo(1), shortlink: 'https://stspg.io/x', incident_updates: [{ body: '<p>We are investigating</p>' }] }] } })],
    ['/api/v2/summary.json', () => ({ body: { status: { indicator: 'none' }, incidents: [] } })],
    ['status.cloud.google.com', () => ({ body: [{ begin: hoursAgo(3), end: null, modified: hoursAgo(1), external_desc: 'Load balancing errors', severity: 'high', affected_products: [{ title: 'Cloud Load Balancing' }] }, { begin: hoursAgo(90), end: hoursAgo(80), modified: hoursAgo(80), external_desc: 'Resolved', severity: 'high' }] })],
    ['health.aws.amazon.com', () => ({ body: new Uint8Array(utf16be) })],
    ['azure.status.microsoft', () => ({ body: '<rss><channel><item><title>Networking issue in Example Region</title><pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate><description>Mitigating</description></item></channel></rss>' })],
  ]);
  const r = await cloudStatus(ctx);
  const services = r.result.incidents.map((i) => i.service).sort();
  assert.deepEqual(services, ['AWS', 'Azure', 'GitHub', 'Google Cloud']);
  assert.equal(r.result.incidents.find((i) => i.service === 'GitHub')!.detail, 'We are investigating');
  assert.deepEqual(r.result.degraded, [{ service: 'GitHub', indicator: 'major', description: 'Partial System Outage' }]);
  assert.ok(r.signals.some((s) => /AWS major incident: Compute: Increased Error Rates \(Example Region\)/.test(s.title)));
  assert.ok(r.signals.some((s) => /GitHub major incident: Actions delayed/.test(s.title)));
});

test('bgp: country prefix change against the median, AS visibility', async () => {
  const stats = [...Array.from({ length: 20 }, (_, i) => ({ timeline: [{ starttime: hoursAgo(24 - i) }], v4_prefixes_ris: 1000, v6_prefixes_ris: 200, asns_ris: 50 })), { timeline: [{ starttime: hoursAgo(1) }], v4_prefixes_ris: 600, v6_prefixes_ris: 120, asns_ris: 30 }];
  const ctx = testContext([
    ['country-routing-stats', () => ({ body: { data: { stats } } })],
    ['routing-status', () => ({ body: { data: { visibility: { v4: { ris_peers_seeing: 300, total_ris_peers: 320 } }, announced_space: { v4: { prefixes: 12 }, v6: { prefixes: 3 } }, observed_neighbours: 40 } } })],
    ['as-overview', () => ({ body: { data: { holder: 'EXAMPLE-NET' } } })],
  ]);
  const c = await countryRouting(ctx, 'xa');
  assert.equal(c.data!.v4Change, -0.4);
  assert.equal(c.data!.country, 'XA');
  const a = await bgp(ctx, 'as64500');
  assert.deepEqual(a.result.asn, { asn: 'AS64500', name: 'EXAMPLE-NET', visibilityV4: 0.94, visibilityV6: null, prefixesV4: 12, prefixesV6: 3, neighbours: 40 });
  await assert.rejects(bgp(ctx, 'Exampleland'), /country code/);
});

test('hazards: tsunami warnings and extreme US alerts become signals, information statements do not', async () => {
  const entry = (title: string, cat: string, h: number) => `<entry><title>${title}</title><updated>${hoursAgo(h)}</updated><link href="https://tsunami.test/${h}"/><summary><strong>Category:</strong> ${cat}<br/><strong>Affected Region: </strong>Example Coast<br/></summary></entry>`;
  const ctx = testContext([
    ['gdacs.org', () => ({ body: { features: [] } })],
    ['PAAQAtom', () => ({ body: `<feed>${entry('Info quake', 'Information', 3)}${entry('Big quake', 'Warning', 2)}${entry('Old', 'Warning', 100)}</feed>` })],
    ['PHEBAtom', () => ({ body: '<feed></feed>' })],
    ['api.weather.gov', () => ({ body: { features: [{ properties: { event: 'Hurricane Warning', severity: 'Extreme', areaDesc: 'Coastal Example; Inland Example', sent: hoursAgo(1), id: 'https://nws.test/1' } }, { properties: { event: 'Winter Storm Warning', severity: 'Severe', areaDesc: 'Mountains', sent: hoursAgo(1) } }] } })],
  ]);
  const r = await hazards(ctx, 7);
  assert.equal(r.result.bulletins!.length, 4, 'two recent tsunami bulletins and two NWS alerts');
  const titles = r.signals.map((s) => s.title);
  assert.deepEqual(titles.sort(), ['Hurricane Warning: Coastal Example; Inland Example', 'Tsunami warning: Big quake']);
  assert.equal(r.signals.find((s) => /Tsunami/.test(s.title))!.score, 88);
});
