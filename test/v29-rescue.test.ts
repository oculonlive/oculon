import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildPlan, COUNTRIES, LINKS_CHECKED, rescuePlan, SITUATIONS } from '../src/modules/rescue.js';
import { testContext } from './helpers.js';

test('rescue: every situation starts with a first step, names report kinds, and links are https', () => {
  assert.ok(SITUATIONS.length >= 11);
  for (const s of SITUATIONS) {
    assert.ok(s.steps.some((x) => x.phase === 'now'), `${s.id} has a first step`);
    assert.ok(s.reports.length, `${s.id} names report kinds`);
  }
  for (const c of COUNTRIES) for (const r of c.reports) assert.match(r.url, /^https:\/\//, `${c.code} ${r.name}`);
  for (const code of ['US', 'GB', 'CA', 'AU']) assert.ok(COUNTRIES.find((c) => c.code === code)!.reports.length >= 2, code);
  assert.match(LINKS_CHECKED, /^\d{4}-\d{2}-\d{2}$/);
});

test('rescue: merged plan lists shared steps once, in phase order, with the country reports', () => {
  const p = buildPlan('password,takeover', 'uk');
  assert.deepEqual(p.selected, ['password', 'takeover']);
  assert.equal(p.country, 'GB');
  const ids = p.checklist.flatMap((g) => g.steps.map((s) => s.id));
  assert.equal(ids.length, new Set(ids).size, 'no duplicates');
  const signOut = p.checklist[0]!.steps.find((s) => s.id === 'sign-out')!;
  assert.deepEqual(signOut.situations, ['password', 'takeover']);
  assert.deepEqual(p.checklist.map((g) => g.phase), ['now', 'today', 'week']);
  assert.ok(p.reports.some((r) => r.url.includes('ncsc.gov.uk')));
  assert.ok(ids.includes('report'));
});

test('rescue: report links follow the situation, the catalog is always there, bad input is refused', () => {
  const id = buildPlan(['id'], 'US');
  assert.ok(id.reports.some((r) => r.name === 'IdentityTheft.gov'));
  assert.ok(!id.reports.some((r) => r.name === 'Google Safe Browsing'), 'no phishing site to report for sent documents');
  const empty = buildPlan();
  assert.equal(empty.selected.length, 0);
  assert.ok(empty.situations.length >= 11 && empty.countries.length >= 6);
  assert.equal(empty.checklist.flatMap((g) => g.steps).length, 0);
  assert.throws(() => buildPlan('lottery'), /unknown situation/);
  assert.throws(() => buildPlan('link', 'ZZ'), /unknown country/);
});

test('rescue: module result has provenance and no network calls', async () => {
  const ctx = testContext([]);
  const r = await rescuePlan(ctx, 'seed', 'CA');
  assert.equal(r.module, 'rescue');
  assert.equal(r.provenance[0]!.status, 'LIVE');
  assert.equal(ctx.calls.length, 0);
  assert.ok(r.result.checklist[0]!.steps.some((s) => s.id === 'new-wallet'));
});
