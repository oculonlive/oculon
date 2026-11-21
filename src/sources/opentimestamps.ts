/**
 * OpenTimestamps: free, keyless timestamping anchored in Bitcoin.
 * We submit a 32-byte digest to public calendars, keep their receipts, and later check
 * (a) whether a calendar has upgraded the receipt to a Bitcoin block attestation, and
 * (b) that the attested commitment equals that block's merkle root (fetched from Blockstream).
 */
import { createHash } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import type { Provenance, Sourced } from '../core/types.js';

export const CALENDARS = ['https://a.pool.opentimestamps.org', 'https://b.pool.opentimestamps.org'];

const PENDING_TAG = '83dfe30d2ef90c8e';
const BITCOIN_TAG = '0588960d73d71901';

export type Attestation =
  | { kind: 'pending'; uri: string; commitment: string }
  | { kind: 'bitcoin'; height: number; commitment: string }
  | { kind: 'unknown'; tag: string; commitment: string };

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
    }
  }
  varbytes(): Buffer {
    return this.bytes(this.varuint());
  }
}

const hash = (alg: string, data: Buffer) => createHash(alg).update(data).digest();

function applyOp(op: number, msg: Buffer, r: Reader): Buffer {
  switch (op) {
    case 0xf0:
      return Buffer.concat([msg, r.varbytes()]);
    case 0xf1:
      return Buffer.concat([r.varbytes(), msg]);
    case 0x08:
      return hash('sha256', msg);
    case 0x02:
      return hash('sha1', msg);
    case 0x03:
      return hash('ripemd160', msg);
    case 0xf2:
      return Buffer.from(msg).reverse();
    case 0xf3:
      return Buffer.from(msg.toString('hex'), 'utf8');
    default:
      throw new Error(`ots: unsupported op 0x${op.toString(16)}`);
  }
}

/** Walk a serialized timestamp (as returned by a calendar) starting from `digest`, collecting attestations. */
export function parseTimestamp(bytes: Buffer, digest: Buffer): Attestation[] {
  const r = new Reader(bytes);
  const out: Attestation[] = [];
  const item = (tag: number, msg: Buffer) => {
    if (tag === 0x00) {
      const t = r.bytes(8).toString('hex');
      const payload = new Reader(r.varbytes());
      const commitment = msg.toString('hex');
      if (t === PENDING_TAG) out.push({ kind: 'pending', uri: payload.varbytes().toString('utf8'), commitment });
      else if (t === BITCOIN_TAG) out.push({ kind: 'bitcoin', height: payload.varuint(), commitment });
      else out.push({ kind: 'unknown', tag: t, commitment });
    } else {
      walk(applyOp(tag, msg, r));
    }
  };
  const walk = (msg: Buffer) => {
    for (;;) {
      const tag = r.byte();
      if (tag === 0xff) {
        item(r.byte(), msg);
        continue;
      }
      item(tag, msg);
      return;
    }
  };
  walk(digest);
  return out;
}

export interface Receipt {
  calendar: string;
  /** Hex of the calendar's serialized timestamp for our digest. */
  ots: string;
}

export async function submit(ctx: Ctx, digestHex: string): Promise<{ receipts: Receipt[]; provenance: Provenance[] }> {
  const body = Buffer.from(digestHex, 'hex');
  const results = await Promise.all(
    CALENDARS.map((c) => ctx.http.postBytes(`${c}/digest`, body, { source: 'opentimestamps', headers: { accept: 'application/vnd.opentimestamps.v1' } })),
  );
  const receipts = results.flatMap((r, i) => (r.data ? [{ calendar: CALENDARS[i]!, ots: r.data.toString('hex') }] : []));
  return { receipts, provenance: results.map((r) => r.prov) };
}

/** Ask the calendar for the upgraded timestamp of a pending commitment. 404 means still pending. */
export async function upgrade(ctx: Ctx, att: Extract<Attestation, { kind: 'pending' }>): Promise<{ attestations: Attestation[]; prov: Provenance }> {
  const r = await ctx.http.getBytes(`${att.uri.replace(/\/$/, '')}/timestamp/${att.commitment}`, {
    source: 'opentimestamps',
    headers: { accept: 'application/vnd.opentimestamps.v1' },
  });
  if (!r.data) return { attestations: [], prov: r.prov };
  try {
    return { attestations: parseTimestamp(r.data, Buffer.from(att.commitment, 'hex')), prov: r.prov };
  } catch (e) {
    return { attestations: [], prov: { ...r.prov, status: 'ERROR', note: (e as Error).message } };
  }
}

export interface BlockInfo {
  height: number;
  hash: string;
  /** Merkle root in display (big-endian) hex, as block explorers show it. */
  merkleRoot: string;
  time: number;
}

export async function bitcoinBlock(ctx: Ctx, height: number): Promise<Sourced<BlockInfo>> {
  const h = await ctx.http.get<string>(`https://blockstream.info/api/block-height/${height}`, { source: 'blockstream', as: 'text', ttlSec: 30 * 86_400 });
  if (!h.data) return { data: null, prov: h.prov };
  const b = await ctx.http.get<{ id: string; height: number; merkle_root: string; timestamp: number }>(`https://blockstream.info/api/block/${h.data.trim()}`, {
    source: 'blockstream',
    ttlSec: 30 * 86_400,
  });
  return { data: b.data ? { height: b.data.height, hash: b.data.id, merkleRoot: b.data.merkle_root, time: b.data.timestamp } : null, prov: b.prov };
}

/** OTS commitments are in internal byte order; explorers display the merkle root reversed. */
export const matchesMerkleRoot = (commitmentHex: string, displayRootHex: string) =>
  Buffer.from(commitmentHex, 'hex').reverse().toString('hex') === displayRootHex.toLowerCase();
