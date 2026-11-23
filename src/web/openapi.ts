/** OpenAPI 3.1 description of the public read API, for ChatGPT Actions, n8n, Zapier and other tools. */
import { SERVER_INFO } from '../mcp.js';

type P = { name: string; desc: string; example: string; required?: boolean };
const E: [string, string, string, P[]][] = [
  ['/api/scam', 'scamCheck', 'Is this SMS, email or chat message a scam? Checks its links, sender and known scam patterns.', [{ name: 'message', desc: 'The full message text', example: 'USPS: your package is on hold, pay $1.99 at usps-help.top', required: true }]],
  ['/api/url', 'urlCheck', 'Is a link dangerous? Safe Browsing, URLhaus, urlscan.io history, domain age and look-alike checks.', [{ name: 'url', desc: 'Link or domain', example: 'paypa1-secure-login.top/verify', required: true }]],
  ['/api/factcheck', 'factCheck', 'Fact check a claim or a news link against published fact checks and current reporting.', [{ name: 'claim', desc: 'Claim text or article URL', example: 'The Great Wall of China is visible from space', required: true }]],
  ['/api/recall', 'recall', 'Vehicle recalls by VIN or "year make model", or product recalls by name (NHTSA, CPSC, FDA).', [{ name: 'q', desc: 'VIN, vehicle or product', example: '2018 Honda Accord', required: true }]],
  ['/api/emailsec', 'emailSecurity', 'Can someone spoof email from this domain? SPF, DMARC, DKIM, MTA-STS, DNSSEC, with fixes.', [{ name: 'domain', desc: 'Domain', example: 'example.com', required: true }]],
  ['/api/travel', 'travelRisk', 'Travel risk for the coming week: official advice, weather, air, outbreaks, disasters, quakes, outages.', [{ name: 'place', desc: 'City or country', example: 'Lisbon', required: true }]],
  ['/api/airport', 'airportStatus', 'Airport weather (METAR, TAF), FAA delays and ground stops, nearby emergency squawks.', [{ name: 'code', desc: 'IATA or ICAO code, or name', example: 'JFK', required: true }]],
  ['/api/country', 'countryBrief', 'Country brief: economy, IMF outlook, leaders, currency, travel advice, outages, headlines.', [{ name: 'name', desc: 'Country name or ISO code', example: 'Argentina', required: true }]],
  ['/api/papers', 'researchPapers', 'Research brief: most cited and newest papers on a topic, growth per year, a cited overview.', [{ name: 'topic', desc: 'Research topic', example: 'solid-state battery', required: true }]],
  ['/api/audit', 'dependencyAudit', 'Dependency health: vulnerabilities, deprecation, staleness, OpenSSF Scorecard.', [{ name: 'packages', desc: 'Space-separated npm:name@version or pypi:name==version items', example: 'npm:lodash@4.17.15 pypi:requests==2.19.0', required: true }]],
  ['/api/cve', 'cve', 'One CVE in depth: severity, exploitation odds, exploited-in-the-wild status, fixes.', [{ name: 'id', desc: 'CVE id', example: 'CVE-2024-3400', required: true }]],
  ['/api/vulns', 'exploitedVulnerabilities', 'Vulnerabilities newly exploited in the wild, new critical CVEs and package advisories.', [{ name: 'days', desc: 'Look-back window (1-30)', example: '7' }, { name: 'vendor', desc: 'Vendor or product filter', example: 'Microsoft' }]],
  ['/api/hazards', 'disasterAlerts', 'Official orange and red disaster alerts worldwide, tsunami bulletins and severe US weather.', []],
  ['/api/blackout', 'internetOutages', 'Internet outages and shutdowns by country and network.', []],
  ['/api/cloud', 'cloudOutages', 'Open incidents on AWS, Azure, Google Cloud, GitHub, Cloudflare, OpenAI and more.', []],
  ['/api/bgp', 'bgpRouting', 'BGP hijacks and route leaks worldwide, or routing of a country, network or IP.', [{ name: 'q', desc: 'world, a country code, ASN or IP', example: 'world' }]],
  ['/api/air', 'airQuality', 'PM2.5 air quality near a place.', [{ name: 'place', desc: 'Place', example: 'New Delhi', required: true }]],
  ['/api/space', 'spaceWeather', 'Geomagnetic storms, solar flares and coronal mass ejections.', []],
  ['/api/radar', 'radar', 'What the world is suddenly paying attention to, fused across sources.', []],
  ['/api/signals', 'signals', 'Latest scored signals from every module.', [{ name: 'limit', desc: 'How many (max 200)', example: '20' }]],
];

export function openApiSpec(serverUrl: string): Record<string, unknown> {
  const paths: Record<string, unknown> = {};
  for (const [path, op, summary, params] of E) {
    paths[path] = {
      get: {
        operationId: op,
        summary,
        parameters: params.map((p) => ({ name: p.name, in: 'query', required: Boolean(p.required), description: p.desc, schema: { type: 'string' }, example: p.example })),
        responses: {
          '200': { description: 'Result with provenance (which sources answered, live or cached).', content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
          '400': { description: 'Missing or invalid parameter.' },
        },
      },
    };
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'Oculon API',
      version: SERVER_INFO.version,
      description: 'Open-source intelligence checks with sources on every answer: scam messages, links, claims, recalls, email domains, travel risk, airports, countries, research papers, dependencies, vulnerabilities, outages and disasters. Free, no key. MCP clients can use https://mcp.oculon.live instead.',
      license: { name: 'MIT', url: 'https://github.com/oculonlive/oculon/blob/main/LICENSE' },
    },
    servers: [{ url: serverUrl }],
    paths,
  };
}
