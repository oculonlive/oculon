import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Oculon } from '../src/index.js';
import { TOOLS } from '../src/mcp.js';
import { hazards } from '../src/modules/hazards.js';
import { hound } from '../src/modules/hound.js';
import { ROUTES } from '../src/web/server.js';
import { NOW, testContext } from './helpers.js';

const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();
/** What a browser or an MCP client actually receives. */
const overTheWire = <T>(x: unknown) => JSON.parse(JSON.stringify(x)) as T;

function hazardsCtx() {
  return testContext([
    ['gdacs.org', () => ({ body: { features: [{ geometry: { coordinates: [10, 20] }, properties: { eventtype: 'EQ', eventid: 1, name: 'Earthquake in Exampleland', alertlevel: 'Red', country: 'Exampleland', fromdate: hoursAgo(5), todate: hoursAgo(1), iscurrent: true } }] } })],
    ['PAAQAtom', () => ({ body: `<feed><entry><title>Big quake</title><updated>${hoursAgo(2)}</updated><link href="https://tsunami.test/1"/><summary><strong>Category:</strong> Warning<br/><strong>Affected Region: </strong>Example Coast<br/></summary></entry></feed>` })],
    ['PHEBAtom', () => ({ body: '<feed></feed>' })],
    ['api.weather.gov', () => ({ body: { features: [{ properties: { event: 'Winter Storm Warning', severity: 'Severe', areaDesc: 'Mountains', sent: hoursAgo(1), id: 'https://nws.test/1' } }] } })],
  ]);
}

test('hazards: tsunami and US weather bulletins survive JSON in the web API and the MCP tool', async () => {
  const ctx = hazardsCtx();
  const o = { hazards: (days: number) => hazards(ctx, days) } as unknown as Oculon;

  type Bul = { source: string; title: string }[];
  const web = overTheWire<{ result: { name: string }[]; bulletins: Bul }>(await ROUTES['/api/hazards']!(new URLSearchParams('days=7'), o));
  assert.deepEqual(web.result.map((h) => h.name), ['Earthquake in Exampleland']);
  assert.deepEqual(web.bulletins.map((b) => `${b.source}:${b.title}`), ['NTWC:Big quake', 'NWS:Winter Storm Warning']);

  const tool = TOOLS.find((t) => t.name === 'oculon_hazards')!;
  const mcp = overTheWire<{ result: { alerts: { name: string }[]; bulletins: Bul }; signals: unknown[] }>(await tool.run(o, {}));
  assert.equal(mcp.result.alerts.length, 1);
  assert.equal(mcp.result.bulletins.length, 2);
  assert.ok(mcp.signals.length >= 2, 'red alert and tsunami warning are signals');
});

test('hound: the hiring change since the last check survives JSON as hiringChange', async () => {
  process.env.ADZUNA_APP_ID = 'test-id';
  process.env.ADZUNA_APP_KEY = 'test-key';
  try {
    const ctx = testContext([
      ['api.adzuna.com/v1/api/jobs/us', () => ({ body: { count: 90, results: [] } })],
      ['api.adzuna.com/v1/api/jobs/gb', () => ({ body: { count: 30, results: [] } })],
    ]);
    ctx.graph.observe('org:examplecorp', 'hound', 'job_openings', 80, 'adzuna', {}, NOW.getTime() - 86_400_000);
    const r = await hound(ctx, 'Examplecorp');
    assert.equal(r.result.hiring!.change, 0.5, '120 openings now vs 80 a day ago');
    const wire = overTheWire<{ hiring: { change?: number }; hiringChange: number | null }>(r.result);
    assert.equal(wire.hiring.change, undefined, 'JSON drops the property on the array');
    assert.equal(wire.hiringChange, 0.5);
  } finally {
    delete process.env.ADZUNA_APP_ID;
    delete process.env.ADZUNA_APP_KEY;
  }
});
