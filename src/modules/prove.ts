/**
 * Prove It: timestamp any file on Bitcoin through OpenTimestamps, without the file leaving the browser.
 *   The page hashes the file with SHA-256 and sends only the 32-byte digest. The digest goes to the public
 *   OpenTimestamps calendars (free, keyless); their receipts become a standard detached `.ots` proof.
 *   A timer asks the calendars every half hour whether a pending proof has made it into a Bitcoin block.
 *   Once it has, the attested commitment is checked against that block's merkle root (Blockstream) and the
 *   upgraded `.ots` is stored, so the proof can be checked later with any OpenTimestamps tool and without us.
 * What it proves: these exact bytes existed no later than the block's time. Not who made them, not that
 * they are true, and not that they were created then (only that they existed by then).
 */
import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { bitcoinBlock, CALENDARS, matchesMerkleRoot, submit } from '../sources/opentimestamps.js';

export type ProofState = 'PENDING' | 'CONFIRMED';

export interface Proof {
  hash: string;
  label: string | null;
  createdAt: string;
  status: ProofState;
  /** The Bitcoin block whose merkle root commits to this hash, once confirmed. */
  bitcoin: { height: number; blockHash: string; time: string; url: string } | null;
  calendars: string[];
  lastCheckedAt: string | null;
  /** Download path of the standard `.ots` proof. */
  ots: string;
  permalink: string;
}

export interface ProveResult {
  found: boolean;
  /** True when this hash had already been submitted: the existing proof is returned, nothing is resubmitted. */
  existing?: boolean;
  proof: Proof | null;
  proves: string;
  doesNotProve: string;
  howToVerify: string[];
}

const PROVES = 'These exact bytes existed no later than the time of the Bitcoin block named in the proof. Change one byte of the file and the hash, and the proof, no longer match.';
const DOES_NOT = 'Who made the file, who submitted it, that its contents are true, or that it was created at that time (only that it existed by then). Oculon never sees the file, only its hash.';
const howTo = (hash: string) => [
  'Hash the file with SHA-256. The result must equal the hash on this proof.',
  `Download the proof (/prove/${hash}.ots) and run: ots verify -d ${hash} proof.ots, or drop the file and the proof on opentimestamps.org.`,
  'A confirmed proof names a Bitcoin block. Its merkle root commits to the hash, which anyone can check against a block explorer.',
];

export const LABEL_MAX = 80;
/** New proofs accepted per rolling 24 hours, across all visitors: keeps the free calendars' load sane. */
export const DAILY_CAP = Number(process.env.OCULON_PROVE_DAILY ?? 5000);
/** Calendars aggregate digests and stamp about once per block; asking sooner is wasted. */
const FIRST_CHECK_MS = 20 * 60_000;
const RECHECK_MS = 25 * 60_000;
/** Proofs still pending after three days are asked about four times a day. */
const SLOW_AFTER_MS = 3 * 86_400_000;
const SLOW_RECHECK_MS = 6 * 3600_000;

const PENDING_TAG = '83dfe30d2ef90c8e';
const BITCOIN_TAG = '0588960d73d71901';
const OTS_MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const HEADER_LEN = OTS_MAGIC.length + 2 + 32;

// ---------------------------------------------------------------------------------------------------------
// A small OpenTimestamps tree: parse a serialized timestamp, merge an upgrade into it, serialize it again.

type Item = { kind: 'att'; tag: string; payload: Buffer; msg: Buffer } | { kind: 'op'; op: number; arg?: Buffer; child: Item[] };

class Reader {
  pos = 0;
  constructor(private readonly buf: Buffer) {}
  byte(): number {
    if (this.pos >= this.buf.length) throw new Error('ots: unexpected end');
    return this.buf[this.pos++]!;
  }
  bytes(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('ots: unexpected end');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }
  varuint(): number {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      v += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return v;
      shift += 7;
      if (shift > 49) throw new Error('ots: varuint too long');
    }
  }
  varbytes(): Buffer {
    return this.bytes(this.varuint());
  }
  get done() {
    return this.pos >= this.buf.length;
  }
}

const digestOf = (alg: string, data: Buffer) => createHash(alg).update(data).digest();

function applyOp(op: number, msg: Buffer, arg: Buffer | undefined): Buffer {
  switch (op) {
    case 0xf0:
      return Buffer.concat([msg, arg!]);
    case 0xf1:
      return Buffer.concat([arg!, msg]);
    case 0x08:
      return digestOf('sha256', msg);
    case 0x02:
      return digestOf('sha1', msg);
    case 0x03:
      return digestOf('ripemd160', msg);
    case 0xf2:
      return Buffer.from(msg).reverse();
    case 0xf3:
      return Buffer.from(msg.toString('hex'), 'utf8');
    default:
      throw new Error(`ots: unsupported op 0x${op.toString(16)}`);
  }
}

function parseNode(r: Reader, msg: Buffer, depth = 0): Item[] {
  if (depth > 256) throw new Error('ots: timestamp too deep');
  const items: Item[] = [];
  for (;;) {
    const tag = r.byte();
    if (tag === 0xff) {
      items.push(parseItem(r, r.byte(), msg, depth));
      continue;
    }
    items.push(parseItem(r, tag, msg, depth));
    return items;
  }
}

function parseItem(r: Reader, tag: number, msg: Buffer, depth: number): Item {
  if (tag === 0x00) return { kind: 'att', tag: r.bytes(8).toString('hex'), payload: Buffer.from(r.varbytes()), msg };
  const arg = tag === 0xf0 || tag === 0xf1 ? Buffer.from(r.varbytes()) : undefined;
  return { kind: 'op', op: tag, ...(arg ? { arg } : {}), child: parseNode(r, applyOp(tag, msg, arg), depth + 1) };
}

/** Parse a serialized timestamp that starts at `msg`. Trailing bytes mean it is not one. */
export function parseTree(bytes: Buffer, msg: Buffer): Item[] {
  const r = new Reader(bytes);
  const node = parseNode(r, msg);
  if (!r.done) throw new Error('ots: trailing bytes');
  return node;
}

function varuintBytes(n: number): Buffer {
  const out: number[] = [];
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return Buffer.from(out);
}
const varbytesOf = (b: Buffer) => Buffer.concat([varuintBytes(b.length), b]);

export function serializeTree(node: Item[]): Buffer {
  const parts: Buffer[] = [];
  node.forEach((it, i) => {
    if (i < node.length - 1) parts.push(Buffer.from([0xff]));
    if (it.kind === 'att') parts.push(Buffer.from([0x00]), Buffer.from(it.tag, 'hex'), varbytesOf(it.payload));
    else parts.push(Buffer.from([it.op]), ...(it.arg ? [varbytesOf(it.arg)] : []), serializeTree(it.child));
  });
  return Buffer.concat(parts);
}

/** Every attestation in the tree, with the node that holds it (to merge an upgrade next to it). */
function attestations(node: Item[], out: { att: Extract<Item, { kind: 'att' }>; node: Item[] }[] = []) {
  for (const it of node) {
    if (it.kind === 'att') out.push({ att: it, node });
    else attestations(it.child, out);
  }
  return out;
}

const pendingUri = (a: Extract<Item, { kind: 'att' }>) => new Reader(a.payload).varbytes().toString('utf8');
const bitcoinHeight = (a: Extract<Item, { kind: 'att' }>) => new Reader(a.payload).varuint();

/** Only real calendars are asked for upgrades: a receipt names the URI, and we do not fetch arbitrary hosts. */
export function trustedCalendar(uri: string): boolean {
  try {
    const u = new URL(uri);
    return u.protocol === 'https:' && !u.port && !u.username && (/\.opentimestamps\.org$/.test(u.hostname) || ['finney.calendar.eternitywall.com', 'btc.calendar.catallaxy.com'].includes(u.hostname));
  } catch {
    return false;
  }
}

export function otsFromTree(digest: Buffer, node: Item[]): Buffer {
  return Buffer.concat([OTS_MAGIC, Buffer.from([0x01, 0x08]), digest, serializeTree(node)]);
}

/** The tree inside a stored `.ots` file. */
export function treeFromOts(file: Buffer): { digest: Buffer; node: Item[] } {
  if (file.length <= HEADER_LEN || !file.subarray(0, OTS_MAGIC.length).equals(OTS_MAGIC) || file[OTS_MAGIC.length] !== 0x01 || file[OTS_MAGIC.length + 1] !== 0x08) throw new Error('ots: not a SHA-256 detached timestamp');
  const digest = Buffer.from(file.subarray(OTS_MAGIC.length + 2, HEADER_LEN));
  return { digest, node: parseTree(file.subarray(HEADER_LEN), digest) };
}

// ---------------------------------------------------------------------------------------------------------
// Storage

const ready = new WeakSet<DatabaseSync>();
function db(ctx: Ctx): DatabaseSync {
  const d = ctx.store.db;
  if (!ready.has(d)) {
    d.exec(`CREATE TABLE IF NOT EXISTS prove_proofs (hash TEXT PRIMARY KEY, label TEXT, created_at INTEGER NOT NULL, ots BLOB NOT NULL, status TEXT NOT NULL, calendars TEXT NOT NULL DEFAULT '[]', bitcoin_height INTEGER, bitcoin_time INTEGER, block_hash TEXT, checked_at INTEGER, checks INTEGER NOT NULL DEFAULT 0);
      CREATE INDEX IF NOT EXISTS prove_proofs_pending ON prove_proofs (status, checked_at);
      CREATE INDEX IF NOT EXISTS prove_proofs_created ON prove_proofs (created_at);`);
    ready.add(d);
  }
  return d;
}

interface Row {
  hash: string;
  label: string | null;
  created_at: number;
  ots: Uint8Array;
  status: ProofState;
  calendars: string;
  bitcoin_height: number | null;
  bitcoin_time: number | null;
  block_hash: string | null;
  checked_at: number | null;
  checks: number;
}

const toProof = (r: Row): Proof => ({
  hash: r.hash,
  label: r.label,
  createdAt: new Date(r.created_at).toISOString(),
  status: r.status,
  bitcoin:
    r.status === 'CONFIRMED' && r.bitcoin_height != null
      ? { height: r.bitcoin_height, blockHash: r.block_hash ?? '', time: new Date((r.bitcoin_time ?? 0) * 1000).toISOString(), url: `https://blockstream.info/block/${r.block_hash ?? ''}` }
      : null,
  calendars: JSON.parse(r.calendars) as string[],
  lastCheckedAt: r.checked_at ? new Date(r.checked_at).toISOString() : null,
  ots: `/prove/${r.hash}.ots`,
  permalink: `/prove?hash=${r.hash}`,
});

const row = (ctx: Ctx, hash: string) => db(ctx).prepare('SELECT * FROM prove_proofs WHERE hash = ?').get(hash) as Row | undefined;

/** A SHA-256 in hex, lowercased, or an error a caller can show. */
export function normalizeHash(input: string): string {
  const h = String(input ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('invalid hash: expected the 64-character hex SHA-256 of the file');
  return h;
}

/** Labels are free text shown on the proof page: control characters out, whitespace collapsed, 80 characters. */
export function cleanLabel(label: unknown): string | null {
  if (label == null) return null;
  // eslint-disable-next-line no-control-regex
  const s = String(label).replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, LABEL_MAX).trim();
  return s || null;
}

const result = (ctx: Ctx, input: string, r: ProveResult, provenance: Provenance[] = []): ModuleResult<ProveResult> => ({
  module: 'prove',
  input,
  generatedAt: ctx.now().toISOString(),
  result: r,
  signals: [],
  provenance,
});

const found = (p: Proof, existing?: boolean): ProveResult => ({ found: true, ...(existing === undefined ? {} : { existing }), proof: p, proves: PROVES, doesNotProve: DOES_NOT, howToVerify: howTo(p.hash) });

// ---------------------------------------------------------------------------------------------------------
// Public API

/** Submit a file's SHA-256 to the OpenTimestamps calendars and store the pending proof. Same hash twice: the existing proof. */
export async function proveSubmit(ctx: Ctx, sha256Hex: string, label?: string | null): Promise<ModuleResult<ProveResult>> {
  const hash = normalizeHash(sha256Hex);
  const have = row(ctx, hash);
  if (have) return result(ctx, hash, found(toProof(have), true));

  const now = ctx.now().getTime();
  const recent = (db(ctx).prepare('SELECT COUNT(*) AS n FROM prove_proofs WHERE created_at > ?').get(now - 86_400_000) as { n: number }).n;
  if (recent >= DAILY_CAP) throw new Error('the daily limit for new proofs is reached; try again later');

  const { receipts, provenance } = await submit(ctx, hash);
  const digest = Buffer.from(hash, 'hex');
  const node: Item[] = [];
  const calendars: string[] = [];
  for (const rc of receipts) {
    try {
      node.push(...parseTree(Buffer.from(rc.ots, 'hex'), digest));
      calendars.push(rc.calendar);
    } catch {
      /* a receipt we cannot read is left out; the other calendar's still counts */
    }
  }
  if (!node.length) throw new Error('no OpenTimestamps calendar accepted the hash right now; try again in a few minutes');
  db(ctx)
    .prepare('INSERT INTO prove_proofs (hash, label, created_at, ots, status, calendars) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(hash) DO NOTHING')
    .run(hash, cleanLabel(label), now, otsFromTree(digest, node), 'PENDING', JSON.stringify(calendars));
  return result(ctx, hash, found(toProof(row(ctx, hash)!), false), provenance);
}

const due = (r: Row, now: number) => {
  if (r.status !== 'PENDING') return false;
  if (now - r.created_at < FIRST_CHECK_MS) return false;
  if (r.checked_at == null) return true;
  return now - r.checked_at >= (now - r.created_at > SLOW_AFTER_MS ? SLOW_RECHECK_MS : RECHECK_MS);
};

/** Ask the calendars about one pending proof; merge any upgrade and confirm it against the Bitcoin block. */
async function upgradeOne(ctx: Ctx, r: Row): Promise<{ confirmed: boolean; provenance: Provenance[] }> {
  const provenance: Provenance[] = [];
  const now = ctx.now().getTime();
  const { digest, node } = treeFromOts(Buffer.from(r.ots));
  let changed = false;

  // A calendar is asked only while the proof has no Bitcoin attestation yet.
  if (!attestations(node).some((a) => a.att.tag === BITCOIN_TAG)) {
    const seen = new Set<string>();
    for (const { att, node: holder } of attestations(node)) {
      if (att.tag !== PENDING_TAG) continue;
      let uri: string;
      try { uri = pendingUri(att); } catch { continue; }
      const commitment = att.msg.toString('hex');
      if (!trustedCalendar(uri) || seen.has(`${uri}|${commitment}`)) continue;
      seen.add(`${uri}|${commitment}`);
      const got = await ctx.http.getBytes(`${uri.replace(/\/$/, '')}/timestamp/${commitment}`, { source: 'opentimestamps', headers: { accept: 'application/vnd.opentimestamps.v1' } });
      provenance.push(got.prov);
      if (!got.data?.length) continue; // 404: still pending
      try {
        const up = parseTree(got.data, att.msg);
        if (!attestations(up).some((a) => a.att.tag === BITCOIN_TAG)) continue;
        holder.push(...up);
        changed = true;
      } catch {
        /* an unreadable upgrade is ignored; the proof stays as it was */
      }
    }
  }

  let confirmed: { height: number; time: number; hash: string } | null = null;
  for (const { att } of attestations(node)) {
    if (att.tag !== BITCOIN_TAG) continue;
    let height: number;
    try { height = bitcoinHeight(att); } catch { continue; }
    const block = await bitcoinBlock(ctx, height);
    provenance.push(block.prov);
    if (block.data && matchesMerkleRoot(att.msg.toString('hex'), block.data.merkleRoot)) {
      confirmed = { height, time: block.data.time, hash: block.data.hash };
      break;
    }
  }

  const ots = changed ? otsFromTree(digest, node) : Buffer.from(r.ots);
  if (confirmed) {
    db(ctx).prepare('UPDATE prove_proofs SET ots = ?, status = ?, bitcoin_height = ?, bitcoin_time = ?, block_hash = ?, checked_at = ?, checks = checks + 1 WHERE hash = ?').run(ots, 'CONFIRMED', confirmed.height, confirmed.time, confirmed.hash, now, r.hash);
  } else {
    db(ctx).prepare('UPDATE prove_proofs SET ots = ?, checked_at = ?, checks = checks + 1 WHERE hash = ?').run(ots, now, r.hash);
  }
  return { confirmed: Boolean(confirmed), provenance };
}

/**
 * Where a proof stands. A pending proof that is due for a check (at most every 25 minutes) is checked now,
 * so the page shows a confirmation without waiting for the timer; pass refresh: false to read only.
 */
export async function proveStatus(ctx: Ctx, sha256Hex: string, opts: { refresh?: boolean } = {}): Promise<ModuleResult<ProveResult>> {
  const hash = normalizeHash(sha256Hex);
  let r = row(ctx, hash);
  if (!r) return result(ctx, hash, { found: false, proof: null, proves: PROVES, doesNotProve: DOES_NOT, howToVerify: howTo(hash) });
  let provenance: Provenance[] = [];
  if (opts.refresh !== false && due(r, ctx.now().getTime())) {
    try {
      provenance = (await upgradeOne(ctx, r)).provenance;
    } catch {
      /* a failed check leaves the proof pending */
    }
    r = row(ctx, hash)!;
  }
  return result(ctx, hash, found(toProof(r)), provenance);
}

/** Timer pass: check a limited number of pending proofs that are due, oldest check first. */
export async function proveUpgrade(ctx: Ctx, opts: { limit?: number } = {}): Promise<{ checked: number; confirmed: number; pending: number }> {
  const now = ctx.now().getTime();
  const limit = Math.max(1, Math.min(100, opts.limit ?? 12));
  const candidates = db(ctx).prepare("SELECT * FROM prove_proofs WHERE status = 'PENDING' AND created_at <= ? ORDER BY checked_at IS NOT NULL, checked_at, created_at LIMIT ?").all(now - FIRST_CHECK_MS, limit * 4) as unknown as Row[];
  let checked = 0;
  let confirmed = 0;
  for (const r of candidates) {
    if (checked >= limit) break;
    if (!due(r, now)) continue;
    checked++;
    try {
      if ((await upgradeOne(ctx, r)).confirmed) confirmed++;
    } catch {
      db(ctx).prepare('UPDATE prove_proofs SET checked_at = ?, checks = checks + 1 WHERE hash = ?').run(now, r.hash);
    }
  }
  const pending = (db(ctx).prepare("SELECT COUNT(*) AS n FROM prove_proofs WHERE status = 'PENDING'").get() as { n: number }).n;
  return { checked, confirmed, pending };
}

/** The proof as a standard detached `.ots` file, or null for an unknown hash. */
export function proveOts(ctx: Ctx, sha256Hex: string): Buffer | null {
  let hash: string;
  try { hash = normalizeHash(sha256Hex); } catch { return null; }
  const r = row(ctx, hash);
  return r ? Buffer.from(r.ots) : null;
}

/** Calendars the proofs are submitted to (for docs and the page). */
export const PROVE_CALENDARS = CALENDARS;
