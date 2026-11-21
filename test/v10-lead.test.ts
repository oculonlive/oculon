import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chat } from '../src/core/llm.js';
import { bgp, incidentSignals, ipRouting, type BgpIncidents } from '../src/modules/bgp.js';
import { exposure } from '../src/modules/exposure.js';
import { relatedEntities } from '../src/modules/sanctions.js';
import { NOW, testContext } from './helpers.js';

const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString().replace('Z', '');

const withEnv = async (vars: Record<string, string | undefined>, fn: () => Promise<void>) => {
  const old = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) v === undefined ? delete process.env[k] : (process.env[k] = v);
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries(old)) v === undefined ? delete process.env[k] : (process.env[k] = v);
  }
};

test('bgp world: confident hijacks and big route leaks become signals; sister networks and small leaks do not', async () => {
  await withEnv({ CLOUDFLARE_API_TOKEN: 'test-radar-token-123' }, async () => {
    const ctx = testContext([
      ['bgp/hijacks/events', () => ({
        body: {
          result: {
            asn_info: [
              { asn: 64500, org_name: 'EXAMPLE TRANSIT', country_code: 'XA' },
              { asn: 64501, org_name: 'VICTIM BANK NET', country_code: 'XB' },
              { asn: 64510, org_name: 'SAME ORG', country_code: 'XC' },
              { asn: 64511, org_name: 'SAME ORG', country_code: 'XC' },
            ],
            events: [
              { id: 1, hijacker_asn: 64500, hijacker_country: 'XA', victim_asns: [64501], victim_countries: ['XB'], prefixes: ['192.0.2.0/24'], confidence_score: 10, peer_ip_count: 40, min_hijack_ts: hoursAgo(3), max_hijack_ts: hoursAgo(1), duration: 7200, on_going_count: 1, is_stale: false, tags: [{ name: 'rpki_new_origin_invalid', score: 8 }, { name: 'irr_old_origin_valid', score: -2 }] },
              { id: 2, hijacker_asn: 64510, victim_asns: [64511], prefixes: ['198.51.100.0/24'], confidence_score: 12, peer_ip_count: 30, min_hijack_ts: hoursAgo(5), max_hijack_ts: hoursAgo(2), duration: 9000, on_going_count: 0 },
              { id: 3, hijacker_asn: 64500, victim_asns: [64501], prefixes: ['203.0.113.0/24'], confidence_score: 10, peer_ip_count: 1, min_hijack_ts: hoursAgo(2), max_hijack_ts: hoursAgo(2), duration: 0, on_going_count: 0 },
            ],
          },
        },
      })],
      ['bgp/leaks/events', () => ({
        body: {
          result: {
            asn_info: [{ asn: 64520, org_name: 'LEAKY ISP' }],
            events: [
              { id: 10, leak_asn: 64520, countries: ['XA', 'XB'], leak_seg: [64500, 64520, 64501], prefix_count: 1500, origin_count: 300, leak_count: 9000, min_ts: hoursAgo(6), max_ts: hoursAgo(1), finished: false },
              { id: 11, leak_asn: 64520, prefix_count: 12, origin_count: 1, leak_count: 20, min_ts: hoursAgo(6), max_ts: hoursAgo(5), finished: true },
            ],
          },
        },
      })],
      ['attacks/layer7/top/locations/target', () => ({ body: { result: { top_0: [{ targetCountryAlpha2: 'XA', targetCountryName: 'Exampleland', value: '41.5' }] } } })],
      ['attacks/layer3/top/locations/target', () => ({ body: { result: { top_0: [{ targetCountryAlpha2: 'XB', targetCountryName: 'Otherland', value: '12.25' }] } } })],
    ]);
    const r = await bgp(ctx, 'world');
    const inc = r.result.incidents!;
    assert.equal(inc.hijacks.length, 3);
    assert.equal(inc.hijacks[0]!.hijacker, 'EXAMPLE TRANSIT (AS64500)');
    assert.deepEqual(inc.hijacks[0]!.tags, ['rpki_new_origin_invalid'], 'only tags that count against the announcement');
    assert.equal(inc.hijacks[0]!.start.endsWith('Z'), true, 'Radar timestamps are UTC without a zone');
    assert.deepEqual(inc.attacks, { layer7: [{ country: 'XA', name: 'Exampleland', share: 0.415 }], layer3: [{ country: 'XB', name: 'Otherland', share: 0.123 }] });
    const titles = r.signals.map((s) => s.title);
    assert.equal(titles.length, 2, titles.join(' | '));
    assert.ok(titles.some((t) => /^Possible BGP hijack: EXAMPLE TRANSIT \(AS64500\) announced 1 prefix of VICTIM BANK NET \(AS64501\), ongoing/.test(t)));
    assert.ok(titles.some((t) => /^BGP route leak by LEAKY ISP \(AS64520\): 1500 prefixes from 300 networks, ongoing/.test(t)));
    assert.ok(ctx.calls.every((u) => !u.includes('test-radar-token')), 'token only in headers');
  });
});

test('bgp without a Radar token still answers an IP lookup and marks incidents unavailable', async () => {
  await withEnv({ CLOUDFLARE_API_TOKEN: undefined }, async () => {
    const ctx = testContext([
      ['prefix-overview', () => ({ body: { data: { announced: true, resource: '192.0.2.0/24', asns: [{ asn: 64500, holder: 'EXAMPLE-NET' }], block: { desc: 'Administered by Example RIR' } } } })],
      ['abuse-contact-finder', () => ({ body: { data: { abuse_contacts: ['abuse@example.net'] } } })],
      ['maxmind-geo-lite', () => ({ body: { data: { located_resources: [{ locations: [{ country: 'XA', city: 'Example City' }] }] } } })],
      ['rpki-validation', (u) => ({ body: { data: { status: u.includes('resource=AS64500') && u.includes('prefix=192.0.2.0%2F24') ? 'invalid' : 'unknown' } } })],
    ]);
    const ip = await ipRouting(ctx, '192.0.2.10');
    assert.deepEqual(ip.data, { ip: '192.0.2.10', prefix: '192.0.2.0/24', announced: true, origins: [{ asn: 'AS64500', name: 'EXAMPLE-NET' }], rpki: 'invalid', abuse: ['abuse@example.net'], country: 'XA', city: 'Example City', registry: 'Administered by Example RIR' });
    const w = await bgp(ctx, 'world');
    assert.equal(w.result.incidents, null);
    assert.equal(w.provenance[0]!.status, 'UNAVAILABLE');
    await assert.rejects(bgp(ctx, 'Exampleland'), /country code/);
  });
});

test('incident signals ignore stale events', () => {
  const inc: BgpIncidents = {
    hijacks: [{ id: 5, hijacker: 'A (AS1)', hijackerCountry: null, victims: ['B (AS2)'], victimCountries: [], prefixes: Array.from({ length: 12 }, (_, i) => `10.${i}.0.0/16`), confidence: 11, peers: 80, start: '2026-11-01T00:00:00Z', end: '2026-11-01T05:00:00Z', durationSec: 18000, ongoing: false, tags: [], sameOrg: false, url: 'https://radar.cloudflare.com/routing/as1' }],
    leaks: [],
    attacks: null,
  };
  assert.equal(incidentSignals(inc, NOW).length, 0);
  inc.hijacks[0]!.end = new Date(NOW.getTime() - 3_600_000).toISOString();
  const [s] = incidentSignals(inc, NOW);
  assert.equal(s!.score, 74, '62 + 12 prefixes (6) + 50+ peers (6)');
});

test('OpenSanctions related entities: other side of each relationship, sanctioned first, self excluded', async () => {
  await withEnv({ OPENSANCTIONS_API_KEY: 'test-os-key-123456' }, async () => {
    const ctx = testContext([
      ['api.opensanctions.org/entities/NK-main', () => ({
        body: {
          id: 'NK-main',
          caption: 'Examplecorp Holding',
          schema: 'Company',
          properties: {
            ownershipOwner: [
              { id: 'own-1', schema: 'Ownership', properties: { owner: [{ id: 'NK-main', caption: 'Examplecorp Holding', schema: 'Company' }], asset: [{ id: 'sub-1', caption: 'Examplecorp Shipping', schema: 'Company', properties: { topics: ['sanction'] } }], percentage: ['100.00'] } },
            ],
            ownershipAsset: [{ id: 'own-2', schema: 'Ownership', properties: { owner: [{ id: 'par-1', caption: 'Example State Fund', schema: 'Organization' }], asset: [{ id: 'NK-main', caption: 'Examplecorp Holding', schema: 'Company' }] } }],
            directorshipOrganization: [{ id: 'dir-1', schema: 'Directorship', properties: { director: [{ id: 'p-1', caption: 'Jane Example', schema: 'Person' }], role: ['Chief Executive'] } }],
            securities: [{ id: 'sec-1', schema: 'Security', properties: { issuer: [{ id: 'NK-main' }] } }],
          },
        },
      })],
    ]);
    const r = await relatedEntities(ctx, 'NK-main');
    assert.deepEqual(r.data!.map((x) => `${x.relation}|${x.name}|${x.detail}|${x.sanctioned}`), ['owns|Examplecorp Shipping|100.00%|true', 'owned by|Example State Fund|null|false', 'director|Jane Example|Chief Executive|false']);
    assert.equal(r.data![0]!.url, 'https://www.opensanctions.org/entities/sub-1/');
  });
});

test('exposure flags CVEs exploited in the wild (CISA KEV) and names the network of direct machines', async () => {
  const ctx = testContext([
    ['dns.google', (u) => ({ body: u.includes('name=example.com&') ? { Answer: [{ type: 1, data: '192.0.2.10' }] } : {} })],
    ['internetdb.shodan.io/192.0.2.10', () => ({ body: { ports: [22, 443], vulns: ['CVE-2023-0001', 'CVE-2020-1111'], cpes: ['cpe:/a:openbsd:openssh'], hostnames: ['example.com'] } })],
    ['known_exploited_vulnerabilities.json', () => ({ body: { catalogVersion: '2026.11.18', dateReleased: '2026-11-18T00:00:00Z', count: 1, vulnerabilities: [{ cveID: 'CVE-2023-0001', vendorProject: 'Example', product: 'Server', vulnerabilityName: 'Example RCE', dateAdded: '2026-11-01', shortDescription: 'x', requiredAction: 'patch', dueDate: '2026-11-22', knownRansomwareCampaignUse: 'Known', notes: '', cwes: [] }] } })],
    ['prefix-overview', () => ({ body: { data: { announced: true, resource: '192.0.2.0/24', asns: [{ asn: 64500, holder: 'EXAMPLE-HOSTING' }] } } })],
    ['abuse-contact-finder', () => ({ body: { data: { abuse_contacts: ['abuse@example-hosting.test'] } } })],
    ['rpki-validation', () => ({ body: { data: { status: 'valid' } } })],
  ]);
  const r = await exposure(ctx, 'example.com');
  assert.deepEqual(r.result.exploited, ['CVE-2023-0001']);
  const ip = r.result.ips[0]!;
  assert.deepEqual(ip.exploited, ['CVE-2023-0001']);
  assert.equal(ip.network?.origin, 'EXAMPLE-HOSTING (AS64500)');
  assert.deepEqual(ip.network?.abuse, ['abuse@example-hosting.test']);
  assert.match(r.signals[0]!.title, /2 known vulnerabilities \(1 exploited in the wild\), exposed SSH/);
  assert.match(r.signals[0]!.evidence[0]!.text, /exploited in the wild \(CISA KEV\): CVE-2023-0001; network EXAMPLE-HOSTING/);
});

test('llm: NVIDIA gets reasoning headroom, and an empty answer falls through to the next provider', async () => {
  await withEnv({ ANTHROPIC_API_KEY: undefined, GROQ_API_KEY: undefined, GEMINI_API_KEY: undefined, MISTRAL_API_KEY: undefined, NVIDIA_API_KEY: 'nv-test-key-123456', OPENROUTER_API_KEY: 'or-test-key-123456' }, async () => {
    const bodies: { url: string; max_tokens: number }[] = [];
    const f = (async (url: string, init: RequestInit) => {
      const b = JSON.parse(String(init.body)) as { max_tokens: number };
      bodies.push({ url, max_tokens: b.max_tokens });
      const content = url.includes('nvidia') ? '' : 'answer from openrouter';
      return new Response(JSON.stringify({ choices: [{ message: { role: 'assistant', content } }] }), { status: 200 });
    }) as unknown as typeof fetch;
    const r = await chat([{ role: 'user', content: 'hi' }], { fetch: f, maxTokens: 300 });
    assert.equal(r.provider, 'openrouter');
    assert.equal(r.message.content, 'answer from openrouter');
    assert.deepEqual(bodies.map((b) => [new URL(b.url).hostname, b.max_tokens]), [['integrate.api.nvidia.com', 4300], ['openrouter.ai', 300]]);
  });
});
