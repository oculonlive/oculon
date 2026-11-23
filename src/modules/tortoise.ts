/**
 * Tortoise: tamper-evident proofs for Raven's forecasts.
 * Open forecasts are batched into a Merkle tree; the root is timestamped on Bitcoin through OpenTimestamps
 * (free, no wallet). Anyone can later recompute a forecast's hash, walk its Merkle path to the root, and
 * check the root against a Bitcoin block's merkle root. Anchoring on Robinhood Chain is a later, opt-in step
 * because it needs a funded wallet.
 */
import type { Ctx } from '../core/context.js';
import { applyPath, merkle, type PathStep } from '../core/merkle.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { bitcoinBlock, matchesMerkleRoot, otsFile, parseTimestamp, submit, upgrade, type Attestation, type Receipt } from '../sources/opentimestamps.js';
import { canonicalJson } from '../core/merkle.js';
import { getPrediction, leafOf, predictionCore } from './raven.js';

/** Everything needed to check a forecast's proof without trusting this server. */
export interface ProofBundle {
  forecast: ReturnType<typeof predictionCore>;
  canonicalJson: string;
  leaf: string;
  merklePath: PathStep[];
  root: string | null;
  batchId: string | null;
  bitcoin: { height: number; time: string } | null;
  howToVerify: string[];
}

export function proofBundle(ctx: Ctx, predictionId: string): ProofBundle {
  const p = getPrediction(ctx, predictionId);
  if (!p) throw new Error(`no prediction ${predictionId}`);
  const forecast = predictionCore(p);
  const row = ctx.store.db.prepare('SELECT merkle_path FROM predictions WHERE id = ?').get(p.id) as { merkle_path: string | null };
  const batch = p.batchId ? getBatch(ctx, p.batchId) : null;
  return {
    forecast,
    canonicalJson: canonicalJson(forecast),
    leaf: p.leaf,
    merklePath: row.merkle_path ? (JSON.parse(row.merkle_path) as PathStep[]) : [],
    root: batch?.root ?? null,
    batchId: batch?.id ?? null,
    bitcoin: batch?.bitcoinHeight ? { height: batch.bitcoinHeight, time: new Date((batch.bitcoinTime ?? 0) * 1000).toISOString() } : null,
    howToVerify: [
      'SHA-256 of canonicalJson (UTF-8) must equal leaf.',
      'Walk merklePath from leaf: for each step, hash sha256(current || sibling) when side is R, or sha256(sibling || current) when side is L. The result must equal root.',
      `Download the OpenTimestamps proof (/proof/${p.id}.ots) and run: ots verify -d ${batch?.root ?? '<root>'} ${p.id}.ots (or open it at opentimestamps.org). It names the Bitcoin block whose merkle root commits to root.`,
    ],
  };
}

/** The forecast's batch root as a standard `.ots` file, or null when it has not been stamped yet. */
export function proofOts(ctx: Ctx, predictionId: string): Buffer | null {
  const p = getPrediction(ctx, predictionId);
  const batch = p?.batchId ? getBatch(ctx, p.batchId) : null;
  return batch && batch.receipts.length ? otsFile(batch.root, batch.receipts) : null;
}

export interface Batch {
  id: string;
  root: string;
  size: number;
  createdAt: string;
  receipts: Receipt[];
  bitcoinHeight: number | null;
  bitcoinTime: number | null;
}

interface BatchRow {
  id: string;
  root: string;
  size: number;
  created_at: number;
  receipts: string;
  bitcoin_height: number | null;
  bitcoin_time: number | null;
}

const toBatch = (r: BatchRow): Batch => ({
  id: r.id,
  root: r.root,
  size: r.size,
  createdAt: new Date(r.created_at).toISOString(),
  receipts: JSON.parse(r.receipts) as Receipt[],
  bitcoinHeight: r.bitcoin_height,
  bitcoinTime: r.bitcoin_time,
});

export function getBatch(ctx: Ctx, id: string): Batch | null {
  const r = ctx.store.db.prepare('SELECT * FROM proof_batches WHERE id = ?').get(id) as BatchRow | undefined;
  return r ? toBatch(r) : null;
}

/** Batch every not-yet-stamped forecast and submit the Merkle root to the OpenTimestamps calendars. */
export async function stamp(ctx: Ctx): Promise<ModuleResult<{ batch: Batch | null; reason?: string }>> {
  const rows = ctx.store.db.prepare('SELECT id, leaf FROM predictions WHERE batch_id IS NULL ORDER BY created_at').all() as { id: string; leaf: string }[];
  const nowIso = ctx.now().toISOString();
  if (!rows.length) return { module: 'tortoise', input: 'stamp', generatedAt: nowIso, result: { batch: null, reason: 'nothing to stamp' }, signals: [], provenance: [] };

  const { root, paths } = merkle(rows.map((r) => r.leaf));
  const { receipts, provenance } = await submit(ctx, root);
  if (!receipts.length) {
    return { module: 'tortoise', input: 'stamp', generatedAt: nowIso, result: { batch: null, reason: 'no calendar accepted the digest' }, signals: [], provenance };
  }
  const id = `batch-${root.slice(0, 16)}`;
  const db = ctx.store.db;
  db.prepare('INSERT INTO proof_batches (id, root, size, created_at, receipts) VALUES (?, ?, ?, ?, ?)').run(id, root, rows.length, Date.parse(nowIso), JSON.stringify(receipts));
  const upd = db.prepare('UPDATE predictions SET batch_id = ?, merkle_path = ? WHERE id = ?');
  rows.forEach((r, i) => upd.run(id, JSON.stringify(paths[i]), r.id));
  return { module: 'tortoise', input: 'stamp', generatedAt: nowIso, result: { batch: getBatch(ctx, id) }, signals: [], provenance };
}

export type ProofStatus = 'VERIFIED' | 'PENDING' | 'NOT_STAMPED' | 'TAMPERED' | 'ERROR';

export interface Verification {
  predictionId: string;
  status: ProofStatus;
  leaf: string;
  root: string | null;
  steps: string[];
  bitcoin: { height: number; blockHash: string; time: string } | null;
}

/** Recompute everything from the stored forecast and check it all the way down to Bitcoin. */
export async function verify(ctx: Ctx, predictionId: string): Promise<ModuleResult<Verification>> {
  const provenance: Provenance[] = [];
  const steps: string[] = [];
  const nowIso = ctx.now().toISOString();
  const done = (v: Omit<Verification, 'predictionId' | 'steps'>): ModuleResult<Verification> => ({
    module: 'tortoise',
    input: predictionId,
    generatedAt: nowIso,
    result: { predictionId, steps, ...v },
    signals: [],
    provenance,
  });

  const p = getPrediction(ctx, predictionId);
  if (!p) throw new Error(`no prediction ${predictionId}`);
  const leaf = leafOf(p);
  if (leaf !== p.leaf) {
    steps.push(`hash of stored forecast ${leaf.slice(0, 16)}... does not match recorded leaf ${p.leaf.slice(0, 16)}...`);
    return done({ status: 'TAMPERED', leaf, root: null, bitcoin: null });
  }
  steps.push(`forecast hash recomputed: ${leaf.slice(0, 16)}...`);
  if (!p.batchId) return done({ status: 'NOT_STAMPED', leaf, root: null, bitcoin: null });

  const batch = getBatch(ctx, p.batchId)!;
  const pathRow = ctx.store.db.prepare('SELECT merkle_path FROM predictions WHERE id = ?').get(p.id) as { merkle_path: string };
  const root = applyPath(leaf, JSON.parse(pathRow.merkle_path) as PathStep[]);
  if (root !== batch.root) {
    steps.push(`merkle path leads to ${root.slice(0, 16)}..., batch root is ${batch.root.slice(0, 16)}...`);
    return done({ status: 'TAMPERED', leaf, root, bitcoin: null });
  }
  steps.push(`merkle path checks out to batch root ${root.slice(0, 16)}... (${batch.size} forecasts in batch ${batch.id})`);

  const attestations: Attestation[] = [];
  for (const rc of batch.receipts) {
    try {
      const atts = parseTimestamp(Buffer.from(rc.ots, 'hex'), Buffer.from(batch.root, 'hex'));
      for (const a of atts) {
        if (a.kind === 'pending') {
          const up = await upgrade(ctx, a);
          provenance.push(up.prov);
          if (up.attestations.length) attestations.push(...up.attestations);
          else steps.push(`${a.uri}: still pending (Bitcoin confirmation usually takes a few hours)`);
        } else attestations.push(a);
      }
    } catch (e) {
      steps.push(`receipt from ${rc.calendar} could not be parsed: ${(e as Error).message}`);
    }
  }

  for (const a of attestations.filter((x): x is Extract<Attestation, { kind: 'bitcoin' }> => x.kind === 'bitcoin')) {
    const block = await bitcoinBlock(ctx, a.height);
    provenance.push(block.prov);
    if (!block.data) {
      steps.push(`Bitcoin block ${a.height} could not be fetched (${block.prov.status})`);
      continue;
    }
    if (matchesMerkleRoot(a.commitment, block.data.merkleRoot)) {
      ctx.store.db.prepare('UPDATE proof_batches SET bitcoin_height = ?, bitcoin_time = ?, verified_at = ? WHERE id = ?').run(a.height, block.data.time, Date.now(), batch.id);
      steps.push(`commitment equals merkle root of Bitcoin block ${a.height} (${block.data.hash.slice(0, 16)}...)`);
      return done({ status: 'VERIFIED', leaf, root, bitcoin: { height: a.height, blockHash: block.data.hash, time: new Date(block.data.time * 1000).toISOString() } });
    }
    steps.push(`attestation claims block ${a.height} but its merkle root does not match`);
    return done({ status: 'ERROR', leaf, root, bitcoin: null });
  }
  return done({ status: 'PENDING', leaf, root, bitcoin: null });
}
