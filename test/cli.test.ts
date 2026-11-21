import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { COMMANDS, parseArgs } from '../src/cli/main.js';

test('argument parsing', () => {
  assert.deepEqual(parseArgs(['dossier', 'Open', 'AI', '--json']), { pos: ['dossier', 'Open', 'AI'], flags: { json: true } });
  assert.deepEqual(parseArgs(['forecast', 'slug', '--p', '0.3', '--why=because']), { pos: ['forecast', 'slug'], flags: { p: '0.3', why: 'because' } });
  assert.deepEqual(parseArgs(['footprint', 'x.com', '--no-org', '--days', '7']), { pos: ['footprint', 'x.com'], flags: { 'no-org': true, days: '7' } });
});

test('every documented command exists', () => {
  for (const c of ['case', 'scoops', 'fence', 'markets', 'launches', 'rewind', 'deployer', 'ships', 'ship', 'watch', 'brief', 'quota', 'rh', 'ask', 'radar', 'signals', 'dossier', 'hype', 'footprint', 'plane', 'mil', 'events', 'lights', 'image', 'wallet', 'token', 'space', 'air', 'search', 'read', 'entity', 'forecast', 'proof', 'serve', 'doctor']) assert.ok(COMMANDS[c], c);
});

test('cli binary: help, version, offline commands, usage errors and exit codes', () => {
  const home = mkdtempSync(join(tmpdir(), 'oculon-cli-'));
  const run = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], { encoding: 'utf8', env: { ...process.env, OCULON_HOME: home, OCULON_DB: join(home, 'o.db'), NO_COLOR: '1' } });
  try {
    const help = run('help');
    assert.equal(help.status, 0);
    assert.match(help.stdout, /oculon dossier <name>/);
    assert.doesNotMatch(help.stderr, /ExperimentalWarning/);
    assert.match(run('--version').stdout.trim(), /^\d+\.\d+\.\d+$/);
    const sig = run('signals', '--json');
    assert.equal(sig.status, 0);
    assert.deepEqual(JSON.parse(sig.stdout), []);
    const score = run('forecast', 'score', '--json');
    assert.equal(JSON.parse(score.stdout).total, 0);
    const usage = run('dossier');
    assert.equal(usage.status, 2);
    assert.match(usage.stdout, /missing name/);
    assert.equal(run('nope').status, 2);
    assert.match(run('entity', 'org:none').stdout, /No entity/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
