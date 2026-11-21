import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { catalysts } from '../src/modules/calendar.js';
import { decodeItem, filings, officerLeaving, phraseQuery, recentEvents } from '../src/modules/filings.js';
import { coreName, hound } from '../src/modules/hound.js';
import { recalls, sponsorTrials } from '../src/sources/fda.js';
import { bullishShare, insiderSentiment, ipoCalendar, metrics, peers, recommendations } from '../src/sources/finance.js';
import { parseDisplayName } from '../src/sources/sec.js';
import { testContext, type Route } from './helpers.js';

const saved = { contact: process.env.OCULON_CONTACT, fh: process.env.FINNHUB_API_KEY };
before(() => {
  process.env.OCULON_CONTACT = 'test@example.com';
  process.env.FINNHUB_API_KEY = 'test-finnhub-key-000';
});
after(() => {
  for (const [k, v] of [['OCULON_CONTACT', saved.contact], ['FINNHUB_API_KEY', saved.fh]] as const) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

/* ---------- SEC full-text search ---------- */

const EFTS = {
  took: 84,
  hits: {
    total: { value: 3, relation: 'eq' },
    hits: [
      { _id: '0000000001-26-000113:ex99-1.htm', _source: { ciks: ['0000000001'], display_names: ['Examplecorp Inc.  (EXPC)  (CIK 0000000001)'], root_forms: ['8-K'], form: '8-K', file_date: '2026-11-09', file_type: 'EX-99.1', items: ['1.05', '9.01'], biz_locations: ['Austin, TX'], adsh: '0000000001-26-000113' } },
      { _id: '0000000001-26-000113:main8k.htm', _source: { ciks: ['0000000001'], display_names: ['Examplecorp Inc.  (EXPC)  (CIK 0000000001)'], root_forms: ['8-K'], form: '8-K', file_date: '2026-11-09', file_type: '8-K', items: ['1.05', '9.01'], adsh: '0000000001-26-000113' } },
      { _id: '0000000002-26-000037:ex99.htm', _source: { ciks: ['0000000002'], display_names: ['Sample Airlines, Inc.  (CIK 0000000002)'], root_forms: ['8-K'], form: '8-K', file_date: '2026-11-12', file_type: 'EX-99.1', items: ['8.01'], adsh: '0000000002-26-000037' } },
    ],
  },
  aggregations: { entity_filter: { buckets: [{ key: 'Examplecorp Inc.  (EXPC)  (CIK 0000000001)', doc_count: 2 }, { key: 'Sample Airlines, Inc.  (CIK 0000000002)', doc_count: 1 }] } },
};

test('filings: full-text search merges exhibits per filing, decodes items and builds archive links', async () => {
  const ctx = testContext([['efts.sec.gov/LATEST/search-index', () => ({ body: EFTS })]]);
  const r = await filings(ctx, 'cybersecurity incident', { forms: ['8-K'], days: 30 });
  const url = ctx.calls[0]!;
  assert.match(url, /q=%22cybersecurity%20incident%22/);
  assert.match(url, /forms=8-K/);
  assert.match(url, /startdt=2026-10-19&enddt=2026-11-18/);
  assert.equal(r.result.hits.length, 2, 'two documents of one filing become one hit');
  assert.equal(r.result.hits[0]!.company, 'Sample Airlines, Inc.', 'newest first');
  const ex = r.result.hits[1]!;
  assert.equal(ex.ticker, 'EXPC');
  assert.equal(ex.url, 'https://www.sec.gov/Archives/edgar/data/1/000000000126000113/ex99-1.htm');
  assert.deepEqual(ex.itemTitles, ['Material cybersecurity incident']);
  assert.deepEqual(r.result.topCompanies[0], { name: 'Examplecorp Inc.', docs: 2 });
  assert.equal(r.provenance[0]!.status, 'LIVE');
});

test('filings: no SEC calls without contact details; query helpers', async () => {
  delete process.env.OCULON_CONTACT;
  try {
    const ctx = testContext([]);
    const r = await filings(ctx, 'going concern');
    assert.equal(r.provenance[0]!.status, 'UNAVAILABLE');
    assert.equal(ctx.calls.length, 0);
  } finally {
    process.env.OCULON_CONTACT = 'test@example.com';
  }
  assert.equal(phraseQuery('going concern'), '"going concern"');
  assert.equal(phraseQuery('"material weakness" OR restatement'), '"material weakness" OR restatement');
  assert.equal(phraseQuery('restatement'), 'restatement');
  assert.deepEqual(parseDisplayName('Examplecorp Inc.  (EXPC, EXPC-WT)  (CIK 0000000001)'), { name: 'Examplecorp Inc.', ticker: 'EXPC' });
  assert.equal(decodeItem('4.02'), 'Non-reliance on previously issued financial statements (restatement)');
});

/* ---------- 8-K events ---------- */

const TICKERS = { '0': { cik_str: 1, ticker: 'EXPC', title: 'Examplecorp Inc.' } };
const submissions = (rows: [form: string, date: string, items: string, doc: string][]) => ({
  cik: '0000000001',
  name: 'Examplecorp Inc.',
  filings: {
    recent: {
      accessionNumber: rows.map((_, i) => `0000000001-26-00000${i}`),
      filingDate: rows.map((r) => r[1]),
      form: rows.map((r) => r[0]),
      items: rows.map((r) => r[2]),
      primaryDocument: rows.map((r) => r[3]),
      primaryDocDescription: rows.map((r) => r[0]),
    },
  },
});
const SUBS = submissions([
  ['8-K', '2026-11-17', '1.05,9.01', 'cyber.htm'],
  ['8-K', '2026-11-10', '5.02', 'officer.htm'],
  ['10-Q', '2026-11-01', '', 'q3.htm'],
  ['8-K', '2026-10-30', '2.02,9.01', 'earnings.htm'],
  ['8-K', '2026-01-05', '4.02', 'old.htm'],
]);
const OFFICER_DOC = '<html><body><p>Item 5.02 Departure of Directors or Certain Officers.</p><p>On November 7, 2026, Jane Roe notified the Board that she will resign as Chief Financial Officer of Examplecorp Inc., effective December 31, 2026.</p><p>The Board appointed John Doe as interim Chief Executive Officer.</p></body></html>';

const secRoutes: Route[] = [
  ['company_tickers.json', () => ({ body: TICKERS })],
  ['data.sec.gov/submissions/CIK0000000001', () => ({ body: SUBS })],
  ['/officer.htm', () => ({ body: OFFICER_DOC })],
];

test('recentEvents decodes 8-K items, reads 5.02 text for a CFO departure, and raises signals', async () => {
  const ctx = testContext(secRoutes);
  const r = await recentEvents(ctx, 'EXPC', { days: 90 });
  assert.equal(r.result.company?.cik, 1);
  assert.equal(r.result.events.length, 3, '10-Q and the January 8-K are out of the window');
  const [cyber, officer, earn] = r.result.events;
  assert.equal(cyber!.summary, 'Material cybersecurity incident');
  assert.equal(officer!.officerDeparture, 'CFO', 'an interim CEO appointment is not a CEO departure');
  assert.equal(officer!.impact, 80);
  assert.equal(earn!.summary, 'Results of operations (earnings release)');
  assert.equal(r.signals.length, 2);
  assert.ok(r.signals[0]!.title.includes('Material cybersecurity incident'));
  assert.ok(r.signals[0]!.score > r.signals[1]!.score || r.signals[0]!.score >= 80);
  assert.ok(r.signals.some((s) => /CFO departure/.test(s.title)));
  assert.equal(ctx.calls.filter((u) => u.includes('.htm')).length, 1, 'only the 5.02 filing is read');
  assert.ok(ctx.graph.recentSignals(10).some((s) => s.module === 'filings'));
});

test('officerLeaving: departure verbs near CEO/CFO only', () => {
  assert.equal(officerLeaving('Mr. Smith will retire as Chief Executive Officer. Ms. Lee resigned as CFO.'), 'CEO and CFO');
  assert.equal(officerLeaving('The Board appointed Ms. Lee as Chief Financial Officer.'), null);
  assert.equal(officerLeaving('A director resigned from the Board.'), null);
});

test('recentEvents with an unknown ticker returns an empty result instead of failing', async () => {
  const ctx = testContext(secRoutes);
  const r = await recentEvents(ctx, 'NOPE');
  assert.equal(r.result.company, null);
  assert.equal(r.signals.length, 0);
});

/* ---------- Finnhub extras ---------- */

const RECS = [
  { symbol: 'EXPC', period: '2026-10-01', strongBuy: 10, buy: 20, hold: 8, sell: 2, strongSell: 0 },
  { symbol: 'EXPC', period: '2026-11-01', strongBuy: 6, buy: 14, hold: 16, sell: 3, strongSell: 1 },
];
const finnhubRoutes: Route[] = [
  ['/stock/recommendation', () => ({ body: RECS })],
  ['/stock/insider-sentiment', () => ({ body: { data: [{ symbol: 'EXPC', year: 2026, month: 10, change: -45000, mspr: -62.51234 }, { symbol: 'EXPC', year: 2026, month: 11, change: 1200, mspr: 12.3 }], symbol: 'EXPC' } })],
  ['/stock/peers', () => ({ body: ['EXPC', 'SMPL', 'DEMO'] })],
  ['/stock/metric', () => ({ body: { metric: { peTTM: 31.2, '52WeekHigh': 120.5, '52WeekLow': 80.1, beta: 1.1, netProfitMarginTTM: 22.4, marketCapitalization: 45000 }, series: { annual: { eps: Array.from({ length: 40 }, (_, i) => ({ period: `${1990 + i}-12-31`, v: i })) } } } })],
  ['/stock/earnings', () => ({ body: [{ symbol: 'EXPC', period: '2026-09-30', actual: 1.2, estimate: 1.1, surprise: 0.1, surprisePercent: 9.09 }] })],
  ['/calendar/ipo', () => ({ body: { ipoCalendar: [
    { date: '2026-11-20', exchange: 'NASDAQ Global', name: 'Sample Acquisition Corp', numberOfShares: 10_000_000, price: '10.00', status: 'expected', symbol: 'SMPLU', totalSharesValue: 115_000_000 },
    { date: '2026-11-24', exchange: 'NYSE', name: 'Examplecorp Robotics Inc', numberOfShares: 30_000_000, price: '17.00-19.00', status: 'expected', symbol: 'EXRB', totalSharesValue: 570_000_000 },
    { date: '2026-11-25', exchange: 'NYSE', name: 'Gone Corp', numberOfShares: null, price: null, status: 'withdrawn', symbol: '', totalSharesValue: null },
  ] } })],
];

test('finnhub extras: recommendations, insider sentiment, peers, compact metrics, IPOs', async () => {
  const ctx = testContext(finnhubRoutes);
  const rec = await recommendations(ctx, 'EXPC');
  assert.equal(rec.data?.[0]?.period, '2026-11-01', 'newest first');
  assert.equal(bullishShare(rec.data![0]!), 0.5);
  const is = await insiderSentiment(ctx, 'EXPC');
  assert.deepEqual(is.data?.[1], { month: '2026-10', change: -45000, mspr: -62.5 });
  assert.match(ctx.calls.find((u) => u.includes('insider-sentiment'))!, /from=2025-11-01&to=2026-11-18/);
  assert.deepEqual((await peers(ctx, 'EXPC')).data, ['SMPL', 'DEMO']);
  const m = await metrics(ctx, 'EXPC');
  assert.equal(m.data?.peTTM, 31.2);
  assert.equal(m.data?.netMarginTTM, 22.4);
  assert.equal(m.data?.dividendYield, null);
  assert.ok(!('series' in (m.data as object)), 'history series is dropped before caching');
  const ipo = await ipoCalendar(ctx, '2026-11-18', '2026-12-02');
  assert.equal(ipo.data?.length, 3);
  assert.equal(ipo.data?.[2]?.price, '');
  assert.ok(ctx.calls.every((u) => u.includes('token=test-finnhub-key-000')));
});

test('finnhub premium endpoints (403) degrade to null', async () => {
  const ctx = testContext([['/stock/recommendation', () => ({ status: 403, body: { error: "You don't have access to this resource." } })]]);
  const r = await recommendations(ctx, 'EXPC');
  assert.equal(r.data, null);
  assert.equal(r.prov.status, 'ERROR');
});

test('calendar: IPOs in the window, largest first, withdrawn dropped', async () => {
  const ctx = testContext(finnhubRoutes);
  const r = await catalysts(ctx, 14);
  const ipos = r.result.items.filter((i) => i.kind === 'ipo');
  assert.equal(ipos.length, 2);
  const big = ipos.find((i) => i.title.includes('EXRB'))!;
  assert.equal(big.date, '2026-11-24');
  assert.match(big.detail, /\$17\.00-19\.00 per share/);
  assert.match(big.detail, /up to \$570\.0M/);
  assert.equal(big.url, 'https://finnhub.io/quote/EXRB');
  assert.ok(r.provenance.some((p) => p.url.includes('/calendar/ipo')));
});

/* ---------- openFDA and ClinicalTrials.gov ---------- */

const fdaRow = (firm: string, cls: string, reported: string, n: string) => ({
  status: 'Ongoing',
  classification: cls,
  recalling_firm: firm,
  recall_number: n,
  product_description: 'Examplecillin 250 mg capsules, 30-count bottle',
  reason_for_recall: 'Failed dissolution specifications',
  product_quantity: '12,000 bottles',
  distribution_pattern: 'Nationwide',
  recall_initiation_date: '20261101',
  report_date: reported,
  voluntary_mandated: 'Voluntary: Firm initiated',
  openfda: {},
});
const FDA_DRUG = {
  meta: { results: { skip: 0, limit: 10, total: 3 } },
  results: [fdaRow('Examplecorp Pharma Inc', 'Class I', '20261111', 'D-0101-2027'), fdaRow('Examplecorpse Ltd', 'Class I', '20261111', 'D-0102-2027'), fdaRow('Examplecorp Pharma Inc', 'Class II', '20260301', 'D-0500-2026')],
};
const NOT_FOUND = { status: 404, body: { error: { code: 'NOT_FOUND', message: 'No matches found!' } } };
const study = (id: string, phases: string[], completion: string, why: string) => ({
  protocolSection: {
    identificationModule: { nctId: id, briefTitle: `Study ${id} of Examplecillin` },
    statusModule: { overallStatus: 'TERMINATED', whyStopped: why, completionDateStruct: { date: completion }, lastUpdatePostDateStruct: { date: '2026-11-15' } },
    sponsorCollaboratorsModule: { leadSponsor: { name: 'Examplecorp' } },
    conditionsModule: { conditions: ['Hypertension'] },
    designModule: { phases, enrollmentInfo: { count: 812 } },
  },
});
const fdaRoutes: Route[] = [
  ['api.fda.gov/drug/enforcement', () => ({ body: FDA_DRUG })],
  ['api.fda.gov/device/enforcement', () => NOT_FOUND],
  ['api.fda.gov/food/enforcement', () => NOT_FOUND],
  ['filter.overallStatus=RECRUITING', () => ({ body: { totalCount: 14, studies: [{}] } })],
  ['filter.overallStatus=ACTIVE_NOT_RECRUITING', () => ({ body: { totalCount: 9, studies: [{}] } })],
  ['filter.overallStatus=COMPLETED', () => ({ body: { totalCount: 120, studies: [{}] } })],
  ['filter.overallStatus=TERMINATED', () => ({ body: { totalCount: 31, studies: [study('NCT09000001', ['PHASE3'], '2026-10-28', 'Futility at interim analysis'), study('NCT09000002', ['PHASE2'], '2026-08-01', 'Sponsor decision'), study('NCT09000003', ['PHASE3'], '2024-02-01', 'Slow enrollment')] } })],
];

test('recalls: look-alike firms are dropped, 404 means none, new Class I flagged', async () => {
  const ctx = testContext(fdaRoutes);
  const r = await recalls(ctx, 'Examplecorp', { days: 90 });
  assert.match(ctx.calls[0]!, /search=recalling_firm:%22Examplecorp%22&sort=report_date:desc/);
  const d = r.data!;
  assert.deepEqual(d.totals, { drug: 2, device: 0, food: 0 });
  assert.equal(d.recent.length, 2);
  assert.equal(d.recent[0]!.reported, '2026-11-11');
  assert.deepEqual(d.newClassI.map((x) => x.recallNumber), ['D-0101-2027']);
  assert.match(d.newClassI[0]!.url, /recall_number:%22D-0101-2027%22/);
});

test('sponsorTrials: counts by status and terminations inside the window', async () => {
  const ctx = testContext(fdaRoutes);
  const r = await sponsorTrials(ctx, 'Examplecorp', 180);
  assert.deepEqual(r.data?.counts, { recruiting: 14, active: 9, completed: 120, terminated: 31 });
  assert.deepEqual(r.data?.recentlyTerminated.map((t) => t.nctId), ['NCT09000001', 'NCT09000002']);
  assert.equal(r.data?.recentlyTerminated[0]!.url, 'https://clinicaltrials.gov/study/NCT09000001');
});

/* ---------- Hound wiring ---------- */

test('hound: pharma company gets analyst, insider, peers, FDA, trials and decoded 8-K fields', async () => {
  const ctx = testContext([
    ['finnhub.io/api/v1/search', () => ({ body: { result: [{ symbol: 'EXPC', type: 'Common Stock', description: 'EXAMPLECORP INC' }] } })],
    ['/stock/profile2', () => ({ body: { name: 'Examplecorp Inc', ticker: 'EXPC', exchange: 'NYSE', finnhubIndustry: 'Pharmaceuticals', marketCapitalization: 45000, weburl: 'https://www.examplecorp.test/', country: 'US' } })],
    ['finnhub.io/api/v1/quote', () => ({ body: { c: 100, dp: -1.2, h: 101, l: 98, pc: 101.2 } })],
    ...finnhubRoutes,
    ...secRoutes,
    ...fdaRoutes,
  ]);
  const r = await hound(ctx, 'Examplecorp');
  const d = r.result;
  assert.equal(d.stock?.symbol, 'EXPC');
  assert.equal(d.recommendations?.[0]?.period, '2026-11-01');
  assert.equal(d.insiderSentiment?.length, 2);
  assert.deepEqual(d.peers, ['SMPL', 'DEMO']);
  assert.equal(d.metrics?.peTTM, 31.2);
  assert.equal(d.earnings?.[0]?.surprisePct, 9.09);
  assert.equal(d.lobbying, undefined, 'deep extras only on request');
  assert.equal(d.fda?.newClassI.length, 1);
  assert.equal(d.trials?.counts.recruiting, 14);
  assert.equal(d.events?.[0]?.summary, 'Material cybersecurity incident');
  assert.equal(d.hiringChange, null, 'hiringChange stays');
  const ev = r.signals[0]!.evidence.map((e) => `${e.source}: ${e.text}`);
  assert.ok(ev.some((t) => t.startsWith('sec-edgar: 8-K item 1.05')), 'fresh cybersecurity 8-K is a moving item');
  assert.ok(ev.some((t) => t.startsWith('openfda: new Class I drug recall D-0101-2027')));
  assert.ok(ev.some((t) => t.startsWith('clinicaltrials: phase 3 trial NCT09000001 terminated')));
  assert.ok(ev.some((t) => /analyst buy ratings down from 75% to 50%/.test(t)));
  assert.ok(!ev.some((t) => t.includes('NCT09000003')), 'old termination is not news');
  assert.ok(d.timeline.some((t) => t.source === 'openfda'));
  assert.ok(ctx.graph.neighbors(r.signals[0]!.entity!).some((n) => n.id === 'company:smpl'));
  assert.ok(!JSON.stringify(r.provenance).includes('test-finnhub-key-000'), 'keys are masked in provenance');
});

test('hound: non-health company makes no FDA or trial requests', async () => {
  const ctx = testContext([
    ['finnhub.io/api/v1/search', () => ({ body: { result: [{ symbol: 'EXPC', type: 'Common Stock', description: 'EXAMPLECORP INC' }] } })],
    ['/stock/profile2', () => ({ body: { name: 'Examplecorp Inc', ticker: 'EXPC', exchange: 'NYSE', finnhubIndustry: 'Technology', marketCapitalization: 45000, weburl: '', country: 'US' } })],
  ]);
  const r = await hound(ctx, 'Examplecorp');
  assert.equal(r.result.fda, undefined);
  assert.equal(r.result.trials, undefined);
  assert.equal(r.result.recommendations, undefined, 'unmatched (404) Finnhub extras are simply absent');
  assert.ok(!ctx.calls.some((u) => u.includes('api.fda.gov') || u.includes('clinicaltrials.gov')));
  assert.equal(coreName('Examplecorp Holdings, Inc.'), 'Examplecorp');
});

