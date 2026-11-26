import assert from 'node:assert/strict';
import { test } from 'node:test';
import { charityCheck, fmtEin, imitates, normName, programmeShare } from '../src/modules/charity.js';
import { testContext } from './helpers.js';

const org = (o: Record<string, unknown> = {}) => ({ id: 530196605, ein: 530196605, name: 'American National Red Cross', address: '431 18TH ST NW', city: 'Washington', state: 'DC', zipcode: '20006-5310', subsection_code: 3, ruling_date: '1938-12-01', deductibility_code: 1, ntee_code: 'P210', tax_period: '2025-06-01', updated_at: '2026-11-10T00:00:00Z', ...o });
const filing = (yr: number, o: Record<string, unknown> = {}) => ({ tax_prd: yr * 100 + 6, tax_prd_yr: yr, formtype: 0, pdf_url: `https://projects.propublica.org/x/${yr}.pdf`, totrevenue: 3_804_377_344, totfuncexpns: 3_530_489_124, totassetsend: 4_565_143_729, totliabend: 1_142_559_888, ...o });

test('charity: names, EINs and lookalike names of well-known charities', () => {
  assert.equal(fmtEin(60726487), '06-0726487');
  assert.equal(normName('The Salvation Army, Inc.'), 'salvation army');
  assert.equal(imitates('American National Red Cros', '111111111')?.ein, '53-0196605');
  assert.equal(imitates('American National Red Cross', '530196605'), null, 'the real EIN is not flagged');
  assert.equal(imitates('Red Cross Civitans', '581771391'), null);
  assert.equal(programmeShare(filing(2024)), null, 'no programme expense field, no share');
  assert.equal(programmeShare({ totfuncexpns: 1000, totprgmsrvcexpns: 800 }), 80);
});

test('charity: a name search lists matches, opens the well-known charity and warns about close names', async () => {
  const ctx = testContext([
    ['/search.json?q=red%20cross', () => ({ body: { total_results: 3, organizations: [
      { ein: 581771391, name: 'Red Cross Civitans', city: 'Climax', state: 'NC', ntee_code: 'T30', subseccd: 4 },
      { ein: 111111111, name: 'American Red Cross', city: 'Miami', state: 'FL', ntee_code: 'P20', subseccd: 3 },
      { ein: 530196605, name: 'American National Red Cross', city: 'Washington', state: 'DC', ntee_code: 'P210', subseccd: 3 },
    ] } })],
    ['/organizations/530196605.json', () => ({ body: { organization: org(), filings_with_data: [filing(2024), filing(2023)], filings_without_data: [{ tax_prd_yr: 2025, formtype_str: '990', pdf_url: 'https://x/2025.pdf' }] } })],
  ]);
  const r = await charityCheck(ctx, 'red cross');
  const d = r.result;
  assert.equal(d.kind, 'name');
  assert.match(d.coverage, /US-registered nonprofits only/);
  assert.equal(d.matches.length, 3);
  assert.deepEqual(d.matches[0]!.ntee, { code: 'T30', category: 'Philanthropy, Voluntarism and Grantmaking Foundations' });
  assert.equal(d.matches[0]!.subsection, '501(c)(4)');
  assert.equal(d.organization?.ein, '53-0196605');
  assert.equal(d.selectedBy, 'well-known name');
  assert.equal(d.organization?.rulingYear, 1938);
  assert.equal(d.organization?.deductibility, 'contributions are deductible');
  assert.equal(d.filings[0]!.revenue, 3_804_377_344);
  assert.equal(d.filings[0]!.form, '990');
  assert.equal(d.programmeSpending.share, null);
  assert.match(d.programmeSpending.note, /^not available/);
  assert.equal(d.warnings.length, 1);
  assert.match(d.warnings[0]!, /"American Red Cross" \(EIN 11-1111111, Miami, FL\)/);
});

test('charity: EIN lookup warns on old filings, revocation and non-501(c)(3)', async () => {
  const ctx = testContext([
    ['/organizations/123456789.json', () => ({ body: { organization: org({ id: 123456789, ein: 123456789, name: 'Helping Hands Society', subsection_code: 4, deductibility_code: 2, revocation_date: '2023-05-15' }), filings_with_data: [filing(2019)], filings_without_data: [] } })],
    ['/organizations/999999999.json', () => ({ body: { organization: { id: 999999999, ein: 999999999, name: 'Unknown Organization', city: null, subsection_code: null } } })],
  ]);
  const d = (await charityCheck(ctx, '12-3456789')).result;
  assert.equal(d.kind, 'ein');
  assert.equal(d.matches.length, 1);
  const w = d.warnings.join(' | ');
  assert.match(w, /no filings in the last 3 years: the latest is for tax year 2019/);
  assert.match(w, /revocation \(revocation_date: 2023-05-15\)/);
  assert.match(w, /501\(c\)\(4\) organisation, not a 501\(c\)\(3\)/);
  assert.match(w, /not deductible/);

  const none = (await charityCheck(ctx, '999999999')).result;
  assert.equal(none.organization, null);
  assert.match(none.warnings[0]!, /no US nonprofit with EIN 99-9999999/);
});

test('charity: no results and a failed source are said plainly', async () => {
  const ctx = testContext([
    ['q=zzzz', () => ({ status: 404, body: { total_results: 0, organizations: [] } })],
    ['q=broken', () => ({ status: 503, body: 'down' })],
  ]);
  const empty = await charityCheck(ctx, 'zzzz');
  assert.equal(empty.result.matches.length, 0);
  assert.match(empty.result.warnings[0]!, /no US-registered nonprofit matches/);
  assert.equal(empty.provenance[0]!.status, 'LIVE');
  const failed = await charityCheck(ctx, 'broken');
  assert.match(failed.result.warnings[0]!, /did not answer/);
  assert.equal(failed.provenance[0]!.status, 'ERROR');
  await assert.rejects(charityCheck(ctx, '  '), /give a charity name/);
});
