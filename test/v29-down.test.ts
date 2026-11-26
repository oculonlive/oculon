import assert from 'node:assert/strict';
import { test } from 'node:test';
import { downStatus, findService, readProbe, readSlack, readSummary, SERVICES, trimSummary } from '../src/modules/down.js';
import { testContext } from './helpers.js';

const ok = { status: { indicator: 'none', description: 'All Systems Operational' }, components: [{ name: 'API', status: 'operational' }], incidents: [] };

test('down: statuspage summaries map to states, with problem components and incidents', () => {
  assert.equal(readSummary(ok).state, 'operational');
  const minor = readSummary({ status: { indicator: 'minor', description: 'Partially Degraded Service' }, components: [{ name: 'API', status: 'degraded_performance' }, { name: 'Web', status: 'operational' }, { name: 'Group', status: 'partial_outage', group: true }], incidents: [{ name: 'Slow API', status: 'investigating', impact: 'minor', created_at: '2026-11-18T10:00:00Z', updated_at: '2026-11-18T11:00:00Z', shortlink: 'https://stspg.io/x', incident_updates: [{ body: 'We are <b>looking</b> into it' }] }] });
  assert.equal(minor.state, 'degraded');
  assert.deepEqual(minor.components, [{ name: 'API', status: 'degraded performance' }], 'groups and healthy components are left out');
  assert.equal(minor.incidents[0]!.detail, 'We are looking into it');
  assert.equal(readSummary({ status: { indicator: 'major', description: 'Partial System Outage' } }).state, 'outage');
  assert.equal(readSummary({ status: { indicator: 'minor' }, components: [{ name: 'Login', status: 'major_outage' }] }).state, 'outage');
  const incOnly = readSummary({ status: { indicator: 'none', description: 'All Systems Operational' }, incidents: [{ name: 'INR payments down', status: 'identified' }] });
  assert.equal(incOnly.state, 'degraded');
  assert.equal(incOnly.summary, '1 open incident', 'the summary does not say all systems operational next to an open incident');
  assert.equal(readSummary({}).state, 'unknown');
  const trimmed = trimSummary({ ...ok, components: [...ok.components, { name: 'DB', status: 'partial_outage' }] });
  assert.deepEqual(trimmed.components?.map((c) => c.name), ['DB'], 'the cached copy keeps only components with problems');
});

test('down: Slack status and probes are read honestly', () => {
  assert.equal(readSlack({ status: 'ok', active_incidents: [] }).state, 'operational');
  assert.equal(readSlack({ status: 'active', active_incidents: [{ title: 'Messages fail', type: 'outage' }] }).state, 'outage');
  assert.equal(readSlack({ status: 'active', active_incidents: [{ title: 'Slow search', type: 'incident' }] }).state, 'degraded');
  assert.equal(readProbe('2xx', 120, null).state, 'operational');
  assert.equal(readProbe('403', 120, null).state, 'operational', 'bot protection still means the site answered');
  assert.equal(readProbe('2xx', 6000, null).state, 'degraded');
  assert.equal(readProbe('503', 120, null).state, 'degraded');
  const none = readProbe(null, null, 'timeout');
  assert.equal(none.state, 'outage');
  assert.match(none.summary, /not an official outage/);
});

test('down: lookup by id, name, domain and alias', () => {
  assert.equal(findService('twitter')?.id, 'x');
  assert.equal(findService('GitHub')?.id, 'github');
  assert.equal(findService('https://www.githubstatus.com')?.id, 'github');
  assert.equal(findService('discord.com'), undefined);
  assert.equal(findService('chatgpt')?.id, 'openai');
  assert.ok(SERVICES.length >= 30);
  assert.equal(new Set(SERVICES.map((s) => s.id)).size, SERVICES.length, 'ids are unique');
});

test('down: the board puts problems first, labels probes and reports a failed status page as unknown', async () => {
  const ctx = testContext([
    ['githubstatus.com/api/v2/summary.json', () => ({ body: { status: { indicator: 'major', description: 'Major outage' }, components: [{ name: 'Git operations', status: 'major_outage' }], incidents: [{ name: 'Git is down', status: 'investigating', impact: 'major', created_at: '2026-11-18T11:00:00Z', updated_at: '2026-11-18T11:30:00Z' }] } })],
    ['discordstatus.com', () => ({ status: 500, body: 'oops' })],
    ['slack-status.com', () => ({ body: { status: 'ok', active_incidents: [] } })],
    ['x.com/robots.txt', () => ({ status: 403, body: 'blocked' })],
    ['www.google.com/generate_204', () => ({ body: 'ok' })],
    ['/api/v2/summary.json', () => ({ body: ok })],
  ]);
  const r = await downStatus(ctx);
  const s = r.result.services;
  assert.equal(s[0]!.id, 'github');
  assert.equal(s[0]!.state, 'outage');
  assert.equal(s[0]!.incidents[0]!.title, 'Git is down');
  const discord = s.find((x) => x.id === 'discord')!;
  assert.equal(discord.state, 'unknown');
  assert.match(discord.summary, /did not answer/);
  const x = s.find((v) => v.id === 'x')!;
  assert.equal(x.official, false);
  assert.equal(x.source, 'our probe from one location');
  assert.equal(x.probe?.answer, '403');
  assert.equal(s.find((v) => v.id === 'google')!.probe?.answer, '2xx');
  const youtube = s.find((v) => v.id === 'youtube')!;
  assert.equal(youtube.state, 'operational', 'unmatched probes get a 404 from the mock, which is still an answer');
  assert.equal(youtube.probe?.answer, '404');
  assert.equal(r.result.counts.outage + r.result.counts.degraded + r.result.counts.unknown + r.result.counts.operational, s.length);
  assert.ok(r.provenance.some((p) => p.source === 'down-probe' && /our probe from one location/.test(p.note ?? '')));

  // One service, and the probe is cached for the next call.
  const before = ctx.calls.length;
  const one = await downStatus(ctx, 'X');
  assert.equal(one.result.services.length, 1);
  assert.equal(ctx.calls.length, before, 'cached probe, no new request');
  await assert.rejects(downStatus(ctx, 'myspace'), /not a service on the board/);
});
