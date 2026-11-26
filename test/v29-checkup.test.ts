import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkup, checkupCardSvg, gradeFor, parseCard, scoreCheckup } from '../src/modules/checkup.js';
import { testContext } from './helpers.js';

const best = { password: { pwned: false }, emailDomain: { verdict: 'protected' as const }, domainBreaches: 0, habits: { passwordManager: 'yes' as const, twoFactor: 'key' as const, uniquePasswords: 'all' as const, simLock: 'yes' as const, updates: 'auto' as const, backups: 'yes' as const } };

test('checkup: full marks, grades and scaling', () => {
  const r = scoreCheckup(best);
  assert.equal(r.score, 100);
  assert.equal(r.grade, 'A');
  assert.equal(r.max, 100);
  assert.equal(r.topFixes.length, 0);
  assert.equal(scoreCheckup({ ...best, wallet: { riskyApprovals: 0 } }).max, 110);
  assert.equal(scoreCheckup({ habits: { twoFactor: 'app' } }).score, 80, 'only answered items count');
  assert.equal(gradeFor(89), 'B'); assert.equal(gradeFor(59), 'F'); assert.equal(gradeFor(70), 'C');
});

test('checkup: a leaked password and weak habits give the biggest fixes first', () => {
  const r = scoreCheckup({ password: { pwned: true, count: 12000 }, emailDomain: { verdict: 'spoofable' }, domainBreaches: 4, wallet: { riskyApprovals: 2 }, habits: { passwordManager: 'no', twoFactor: 'sms', uniquePasswords: 'most', simLock: 'unsure', updates: 'sometimes', backups: 'no' } });
  assert.equal(r.points, 0 + 0 + 0 + 5 + 0 + 6 + 8 + 5 + 2 + 0);
  assert.equal(r.grade, 'F');
  assert.equal(r.topFixes[0]!.id, 'password');
  for (let i = 1; i < r.topFixes.length; i++) assert.ok(r.topFixes[i - 1]!.gain >= r.topFixes[i]!.gain);
  assert.match(r.items.find((i) => i.id === 'password')!.answer, /12,000/);
  assert.match(r.items.find((i) => i.id === 'wallet')!.fix!, /\/guard/);
});

test('checkup: bad input is refused', () => {
  assert.throws(() => scoreCheckup({}), /nothing to score/);
  assert.throws(() => scoreCheckup({ habits: { twoFactor: 'carrier pigeon' as never } }), /twoFactor/);
  assert.throws(() => scoreCheckup({ domainBreaches: -1 }), /0 or more/);
  assert.throws(() => scoreCheckup({ emailDomain: { verdict: 'meh' as never } }), /verdict/);
});

test('checkup card: grade must fit the score, and the SVG holds nothing else', async () => {
  assert.deepEqual(parseCard('B-84'), { grade: 'B', score: 84 });
  assert.equal(parseCard('A-50'), null);
  assert.equal(parseCard('A-101'), null);
  assert.equal(parseCard('E-50'), null);
  const svg = checkupCardSvg('B', 84)!;
  assert.match(svg, /^<svg /);
  assert.match(svg, />B</);
  assert.match(svg, /84 \/ 100/);
  assert.ok(checkupCardSvg('A', 100)!.includes('<path'));
  assert.equal(checkupCardSvg('A', 12), null);
  const r = await checkup(testContext([]), best);
  assert.equal(r.module, 'checkup');
  assert.equal(r.result.score, 100);
});
