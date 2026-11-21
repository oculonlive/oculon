import assert from 'node:assert/strict';
import { test } from 'node:test';
import { regs, upcomingRegDates } from '../src/modules/regs.js';
import { cve, kevSet, packageVulns, vulns } from '../src/modules/vulns.js';
import { NOW, testContext } from './helpers.js';

const day = (n: number) => new Date(NOW.getTime() + n * 86_400_000).toISOString().slice(0, 10);

// Shapes copied from the live CISA KEV feed (fields trimmed to what the module reads).
const kevEntry = (id: string, vendor: string, product: string, added: string, due: string, ransomware = 'Unknown') => ({
  cveID: id,
  vendorProject: vendor,
  product,
  vulnerabilityName: `${vendor} ${product} Example Vulnerability`,
  dateAdded: added,
  shortDescription: `${vendor} ${product} contains an example vulnerability that could allow remote code execution.`,
  requiredAction: 'Apply mitigations per vendor instructions. '.repeat(20),
  dueDate: due,
  knownRansomwareCampaignUse: ransomware,
  forensicTriage: 'No',
  notes: 'https://nvd.nist.gov/vuln/detail/' + id,
  cwes: ['CWE-78'],
});

const KEV = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: '2026.11.18',
  dateReleased: '2026-11-18T19:17:41.0354Z',
  count: 4,
  vulnerabilities: [
    kevEntry('CVE-2026-1001', 'Examplecorp', 'Edge Gateway', day(-1), day(2), 'Known'),
    kevEntry('CVE-2026-1002', 'Acme', 'Mail Server', day(-3), day(18)),
    kevEntry('CVE-2025-0003', 'Examplecorp', 'VPN Client', day(-40), day(-19)),
    kevEntry('CVE-2021-44228', 'Apache', 'Log4j2', '2021-12-10', '2021-12-24', 'Known'),
  ],
};

const kevRoute = ['known_exploited_vulnerabilities.json', () => ({ body: KEV })] as const;

test('vulns: KEV set, window, vendor filter and KEV signals scored by ransomware use and due date', async () => {
  const ctx = testContext([
    [...kevRoute],
    ['api.first.org', () => ({ body: { status: 'OK', data: [{ cve: 'CVE-2026-1001', epss: '0.612340000', percentile: '0.980000000', date: day(0) }, { cve: 'CVE-2026-1002', epss: '0.012510000', percentile: '0.700140000', date: day(0) }] } })],
    ['services.nvd.nist.gov', () => ({ body: { resultsPerPage: 1, totalResults: 1, vulnerabilities: [{ cve: { id: 'CVE-2026-2001', published: `${day(-1)}T10:17:28.927`, descriptions: [{ lang: 'en', value: 'Example plugin is vulnerable to remote code execution.' }], metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] } } }] } })],
    ['api.github.com/advisories', () => ({ body: [{ ghsa_id: 'GHSA-aaaa-bbbb-cccc', cve_id: 'CVE-2026-3001', html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', summary: 'Example Runtime: authentication bypass in RPC layer', description: 'long', type: 'reviewed', severity: 'critical', published_at: `${day(-1)}T00:45:46Z`, withdrawn_at: null, cvss: { score: null }, vulnerabilities: [{ package: { ecosystem: 'go', name: 'example.org/runtime' }, vulnerable_version_range: '< 0.11.1', first_patched_version: '0.11.1' }] }] })],
  ]);

  const set = await kevSet(ctx);
  assert.equal(set.size, 4);
  assert.ok(set.has('CVE-2021-44228'));

  const r = await vulns(ctx, { days: 7 });
  assert.deepEqual(r.result.kev.map((v) => v.cveID), ['CVE-2026-1001', 'CVE-2026-1002'], 'only entries added in the window, newest first');
  assert.equal(r.result.catalog!.count, 4);
  assert.equal(r.result.kev[0]!.epss, 0.61234);
  assert.equal(r.result.kev[0]!.daysToDue, 3);
  assert.ok(!('requiredAction' in r.result.kev[0]!), 'catalog is slimmed before caching');
  assert.equal(r.result.criticalCves[0]!.cvss, 9.8);
  assert.equal(r.result.advisories[0]!.packages[0]!.patched, '0.11.1');

  const kevSignals = r.signals.filter((s) => s.title.startsWith('Actively exploited'));
  assert.equal(kevSignals.length, 2);
  const top = kevSignals.find((s) => s.title.includes('CVE-2026-1001'))!;
  assert.match(top.title, /used by ransomware/);
  assert.equal(top.score, 95, 'ransomware + due in 3 days + EPSS >= 0.5');
  assert.equal(kevSignals.find((s) => s.title.includes('CVE-2026-1002'))!.score, 68);
  assert.ok(r.signals.some((s) => /Critical open-source advisory: Example Runtime/.test(s.title) && s.score === 58));

  const f = await vulns(ctx, { days: 60, vendor: 'examplecorp' });
  assert.deepEqual(f.result.kev.map((v) => v.cveID), ['CVE-2026-1001', 'CVE-2025-0003']);
  assert.equal(f.result.advisories.length, 0, 'advisories are filtered by vendor too');
  assert.ok(ctx.calls.some((u) => u.includes('keywordSearch=examplecorp')), 'NVD query is narrowed by vendor');
});

test('vulns: cve() merges NVD, EPSS trend, KEV, OSV and GitHub advisories', async () => {
  const ctx = testContext([
    [...kevRoute],
    ['services.nvd.nist.gov', () => ({ body: { totalResults: 1, vulnerabilities: [{ cve: {
      id: 'CVE-2021-44228', published: '2021-12-10T10:15:09.143', lastModified: '2026-08-11T19:33:44.513', vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.' }],
      metrics: { cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', baseScore: 10, baseSeverity: 'CRITICAL' } }] },
      weaknesses: [{ source: 'security@apache.org', type: 'Secondary', description: [{ lang: 'en', value: 'CWE-502' }, { lang: 'en', value: 'NVD-CWE-noinfo' }] }],
      configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*' }, { vulnerable: false, criteria: 'cpe:2.3:h:example:board:-:*:*:*:*:*:*:*' }] }] }],
      references: [{ url: 'https://logging.apache.org/log4j/2.x/security.html', source: 'security@apache.org', tags: ['Vendor Advisory'] }],
    } }] } })],
    ['api.first.org', () => ({ body: { status: 'OK', data: [{ cve: 'CVE-2021-44228', epss: '0.950000000', percentile: '1.000000000', date: day(0), 'time-series': [{ epss: '0.900000000', percentile: '0.99', date: day(-1) }, { epss: '0.600000000', percentile: '0.98', date: day(-30) }] }] } })],
    ['api.osv.dev/v1/vulns/', () => ({ body: { id: 'CVE-2021-44228', aliases: ['GHSA-jfh8-c2jp-5v3q'], affected: [{ ranges: [{ type: 'GIT', repo: 'https://github.com/apache/logging-log4j2', events: [{ introduced: '0' }, { fixed: 'abc' }] }] }, { package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.13.0' }, { fixed: '2.15.0' }] }] }] } })],
    ['api.github.com/advisories', () => ({ body: [{ ghsa_id: 'GHSA-jfh8-c2jp-5v3q', cve_id: 'CVE-2021-44228', html_url: 'https://github.com/advisories/GHSA-jfh8-c2jp-5v3q', summary: 'Remote code injection in Log4j', severity: 'critical', published_at: '2021-12-10T00:40:56Z', withdrawn_at: null, cvss: { score: 10 }, vulnerabilities: [{ package: { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core' }, vulnerable_version_range: '>= 2.13.0, < 2.15.0', first_patched_version: '2.15.0' }, { package: { ecosystem: 'maven', name: 'org.example:log4j-shaded' }, vulnerable_version_range: '<= 1.0', first_patched_version: null }] }] })],
  ]);
  const r = await cve(ctx, 'cve-2021-44228');
  const d = r.result;
  assert.equal(d.id, 'CVE-2021-44228');
  assert.deepEqual(d.cvss, { version: '3.1', score: 10, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' });
  assert.deepEqual(d.cwes, ['CWE-502']);
  assert.deepEqual(d.products, ['apache:log4j']);
  assert.equal(d.kev!.knownRansomwareCampaignUse, 'Known');
  assert.equal(d.epss!.change30d, 0.35);
  assert.deepEqual(d.packages.map((p) => `${p.source}:${p.name}:${p.fixed.join('|')}`), ['osv:org.apache.logging.log4j:log4j-core:2.15.0', 'github:org.example:log4j-shaded:'], 'OSV and GitHub merged without duplicates; GIT ranges ignored');
  assert.deepEqual(d.aliases, ['GHSA-jfh8-c2jp-5v3q']);
  assert.deepEqual(r.signals.map((s) => s.score).sort(), [64, 82]);
  await assert.rejects(cve(ctx, 'Log4Shell'), /not a CVE id/);
});

test('vulns: packageVulns pages through OSV and flags KEV-listed vulnerabilities', async () => {
  let page = 0;
  const ctx = testContext([
    [...kevRoute],
    ['api.osv.dev/v1/query', () => {
      page++;
      return page === 1
        ? { body: { vulns: [{ id: 'GHSA-29mw-wpgm-hmr9', summary: 'Regular Expression Denial of Service (ReDoS) in lodash', aliases: ['CVE-2020-28500'], published: '2022-01-06T20:30:46Z', modified: '2025-09-29T21:12:31Z', database_specific: { severity: 'MODERATE' }, affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }], next_page_token: 'tok' } }
        : { body: { vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz', summary: 'Example exploited flaw', aliases: ['CVE-2026-1002'], published: '2026-11-01T00:00:00Z', modified: '2026-11-02T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.18.0' }] }] }] }, { id: 'GHSA-gone-gone-gone', withdrawn: '2026-01-01T00:00:00Z', aliases: [] }] } };
    }],
  ]);
  const r = await packageVulns(ctx, 'npm', 'lodash', '4.17.15');
  assert.equal(page, 2, 'followed next_page_token');
  assert.deepEqual(r.result.vulns.map((v) => v.id), ['GHSA-xxxx-yyyy-zzzz', 'GHSA-29mw-wpgm-hmr9'], 'exploited first, withdrawn dropped');
  assert.deepEqual(r.result.vulns[1]!.fixed, ['4.17.21']);
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0]!.title, /npm lodash 4\.17\.15 has an actively exploited vulnerability: CVE-2026-1002/);
  assert.equal(r.signals[0]!.score, 76);
});

// Shapes copied from the live Federal Register documents and public inspection endpoints.
const agencyRef = (name: string, slug: string) => ({ raw_name: name.toUpperCase(), name, id: 1, url: `https://www.federalregister.gov/agencies/${slug}`, json_url: '', parent_id: null, slug });
const doc = (n: string, o: Record<string, unknown>) => ({ title: `Document ${n}`, type: 'Rule', subtype: null, abstract: null, action: 'Final rule.', document_number: n, html_url: `https://www.federalregister.gov/documents/x/${n}`, publication_date: day(0), effective_on: null, comments_close_on: null, agencies: [agencyRef('Securities and Exchange Commission', 'securities-and-exchange-commission')], significant: null, executive_order_number: null, signing_date: null, docket_ids: [], regulation_id_numbers: [], ...o });

test('regs: documents, executive orders, public inspection and signals', async () => {
  const ctx = testContext([
    [/federalregister\.gov\/api\/v1\/agencies$/, () => ({ body: [{ name: 'Homeland Security Department', short_name: 'DHS', slug: 'homeland-security-department', id: 227 }, { name: 'Securities and Exchange Commission', short_name: 'SEC', slug: 'securities-and-exchange-commission', id: 466 }] })],
    ['presidential_document_type', () => ({ body: { count: 2, results: [doc('2026-90001', { title: 'Strengthening Example Supply Chains', type: 'Presidential Document', subtype: 'Executive Order', action: null, executive_order_number: '14438', signing_date: day(-2), publication_date: day(-1), agencies: [agencyRef('Executive Office of the President', 'executive-office-of-the-president')] }), doc('2026-90000', { title: 'Old order', type: 'Presidential Document', subtype: 'Executive Order', executive_order_number: '14430', publication_date: day(-6) })] } })],
    ['conditions[type][]=NOTICE', () => ({ body: { count: 1, results: [doc('2026-90010', { type: 'Notice', title: 'Sunshine Act Meeting', action: 'Notice.' })] } })],
    ['documents.json', () => ({ body: { count: 4, results: [
      doc('2026-90002', { title: 'Example Disclosure Rule', significant: true, effective_on: day(30) }),
      doc('2026-90003', { title: 'Example Disclosure Rule; Correction', significant: true, action: 'Correcting amendment.' }),
      doc('2026-90004', { title: 'Routine Rule', significant: false }),
      doc('2026-90005', { title: 'Proposed Example Standard', type: 'Proposed Rule', action: 'Proposed rule.', comments_close_on: day(20), significant: true }),
    ] } })],
    ['public-inspection-documents/current.json', () => ({ body: { count: 3, results: [
      { agency_names: ['Executive Office of the President'], document_number: '2026-90020', filed_at: '2026-11-18T08:45:00.000-05:00', filing_type: 'special', html_url: 'https://www.federalregister.gov/public-inspection/2026-90020/x', pdf_url: 'https://public-inspection.federalregister.gov/2026-90020.pdf', publication_date: day(1), title: 'Continuation of the National Emergency With Respect to Exampleland', type: 'Presidential Document' },
      { agency_names: ['Securities and Exchange Commission'], document_number: '2026-90021', filed_at: '2026-11-18T08:45:00.000-05:00', filing_type: 'regular', html_url: 'https://www.federalregister.gov/public-inspection/2026-90021/x', publication_date: day(1), title: 'Self-Regulatory Organizations; Notice', type: 'Notice' },
      { agency_names: ['Securities and Exchange Commission'], document_number: '2026-90022', filed_at: '2026-11-18T08:45:00.000-05:00', filing_type: 'regular', html_url: 'https://www.federalregister.gov/public-inspection/2026-90022/x', publication_date: day(1), title: 'Example Disclosure Amendments', type: 'Rule' },
    ] } })],
  ]);

  const r = await regs(ctx, { days: 7 });
  assert.deepEqual(r.result.types, ['rule', 'proposed', 'presidential'], 'notices excluded by default without a query or agency');
  assert.ok(!r.result.documents.some((d) => d.type === 'Notice'));
  assert.equal(r.result.documents.find((d) => d.documentNumber === '2026-90005')!.commentsCloseOn, day(20));
  assert.equal(r.result.executiveOrders[0]!.executiveOrder, '14438');
  assert.deepEqual(r.result.publicInspection.map((d) => d.documentNumber), ['2026-90020', '2026-90022']);
  const titles = r.signals.map((s) => s.title).sort();
  assert.deepEqual(titles, [
    'Executive Order 14438: Strengthening Example Supply Chains',
    'Presidential document on public inspection: Continuation of the National Emergency With Respect to Exampleland',
    'Significant final rule: Example Disclosure Rule',
  ], 'old EO, corrections, routine and proposed rules are not signals');

  const a = await regs(ctx, { agency: 'SEC', days: 7 });
  assert.equal(a.result.agency, 'securities-and-exchange-commission');
  assert.ok(ctx.calls.some((u) => u.includes('conditions[agencies][]=securities-and-exchange-commission')));
  assert.ok(a.result.documents.some((d) => d.type === 'Notice'), 'notices included when an agency narrows the search');
  assert.deepEqual(a.result.publicInspection.map((d) => d.documentNumber), ['2026-90021', '2026-90022'], 'public inspection filtered by agency');

  const dhs = await regs(ctx, { agency: 'Department of Homeland Security', types: ['rule'] });
  assert.equal(dhs.result.agency, 'homeland-security-department');
});

test('regs: upcomingRegDates returns effective dates and comment deadlines in range, sorted', async () => {
  const ctx = testContext([
    ['conditions[effective_date]', () => ({ body: { results: [doc('2026-1', { title: 'Rule A', effective_on: day(5) }), doc('2026-2', { title: 'Rule B', effective_on: day(400) })] } })],
    ['conditions[comment_date]', () => ({ body: { results: [doc('2026-3', { title: 'Proposal C', type: 'Proposed Rule', comments_close_on: day(2) })] } })],
  ]);
  const u = await upcomingRegDates(ctx, 14);
  assert.deepEqual(u.map(({ date, title, kind }) => ({ date, title, kind })), [
    { date: day(2), title: 'Proposal C', kind: 'comments-close' },
    { date: day(5), title: 'Rule A', kind: 'effective' },
  ]);
  assert.equal(u[0]!.url, 'https://www.federalregister.gov/documents/x/2026-3');
  assert.equal(u[0]!.agency, 'Securities and Exchange Commission');
});

test('bgp: AS names that arrive double-encoded are repaired', async () => {
  const { cleanOrgName } = await import('../src/modules/bgp.js');
  assert.equal(cleanOrgName('WANTEL TECNOLOGIA LTDA. Â­ EPP'), 'WANTEL TECNOLOGIA LTDA. EPP');
  assert.equal(cleanOrgName('TelefÃ³nica de EspaÃ±a'), 'Telefónica de España');
  assert.equal(cleanOrgName('ZAIN BAHRAIN B.S.C.'), 'ZAIN BAHRAIN B.S.C.');
});
