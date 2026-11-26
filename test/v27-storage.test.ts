import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { rescueFullDb, Store } from '../src/core/store.js';

test('rescue: a compacted copy keeps every table but the raw cache, and replaces the file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oculon-rescue-test-'));
  try {
    const path = join(dir, 'oculon.db');
    const s = new Store(path);
    s.cachePut('https://example.com/big', 'x'.repeat(200_000));
    s.cachePut('derived:calibration', '{"a":1}');
    s.db.prepare("INSERT INTO watchlist (kind, target, created_at) VALUES ('domain', 'example.com', 1)").run();
    const db = rescueFullDb(s.db, path, dir);
    assert.ok(existsSync(path));
    assert.equal((db.prepare('SELECT count(*) n FROM watchlist').get() as { n: number }).n, 1);
    assert.equal((db.prepare("SELECT count(*) n FROM cache WHERE key LIKE 'derived:%'").get() as { n: number }).n, 1);
    assert.equal((db.prepare("SELECT count(*) n FROM cache WHERE key NOT LIKE 'derived:%'").get() as { n: number }).n, 0);
    db.close();
    const again = new DatabaseSync(path);
    assert.equal((again.prepare('SELECT count(*) n FROM watchlist').get() as { n: number }).n, 1);
    again.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('relieve: old raw responses and large day-old ones go, derived entries stay', () => {
  const s = new Store(':memory:');
  const now = Date.UTC(2026, 10, 26);
  s.cachePut('old', 'a', now - 10 * 86_400_000);
  s.cachePut('big', 'x'.repeat(150_000), now - 2 * 86_400_000);
  s.cachePut('fresh', 'b', now - 3600_000);
  s.cachePut('derived:x', 'c', now - 90 * 86_400_000);
  const r = s.relieve(7, 60, false, now);
  assert.equal(r.cache, 2);
  assert.ok(s.cacheGet('fresh') && s.cacheGet('derived:x') && !s.cacheGet('old') && !s.cacheGet('big'));
  const rep = s.storageReport();
  assert.ok(rep.file > 0 && Array.isArray(rep.tables));
});
