import assert from 'node:assert/strict';
import test from 'node:test';
import { otsFile, parseTimestamp } from '../src/sources/opentimestamps.js';

test('otsFile writes a standard detached OpenTimestamps file around the calendar receipts', () => {
  const digest = 'ab'.repeat(32);
  const uri = Buffer.from('https://alice.btc.calendar.opentimestamps.org');
  const payload = Buffer.concat([Buffer.from([uri.length]), uri]);
  // sha256, then a pending attestation for the calendar
  const receipt = Buffer.concat([Buffer.from([0x08, 0x00]), Buffer.from('83dfe30d2ef90c8e', 'hex'), Buffer.from([payload.length]), payload]).toString('hex');
  const file = otsFile(digest, [
    { calendar: 'a', ots: receipt },
    { calendar: 'b', ots: receipt },
  ]);
  assert.equal(file.subarray(1, 15).toString(), 'OpenTimestamps');
  const head = 31 + 2;
  assert.equal(file[31], 0x01); // version
  assert.equal(file[32], 0x08); // file hash: sha256
  assert.equal(file.subarray(head, head + 32).toString('hex'), digest);
  // the timestamp part forks into both receipts
  const atts = parseTimestamp(file.subarray(head + 32), Buffer.from(digest, 'hex'));
  assert.equal(atts.length, 2);
  assert.ok(atts.every((a) => a.kind === 'pending'));
});
