import { createHash } from 'node:crypto';

export const sha256 = (data: Uint8Array | string): Buffer => createHash('sha256').update(data).digest();

/** Deterministic JSON: object keys sorted recursively, so the same record always hashes the same. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
    .join(',')}}`;
}

export interface PathStep {
  /** Sibling hash (hex). */
  h: string;
  /** Which side the sibling is on. */
  side: 'L' | 'R';
}

/** Merkle tree over hex leaves; an odd node is paired with itself. Returns root and one path per leaf. */
export function merkle(leaves: string[]): { root: string; paths: PathStep[][] } {
  if (!leaves.length) throw new Error('merkle: no leaves');
  let level: Buffer[] = leaves.map((l) => Buffer.from(l, "hex"));
  const paths: PathStep[][] = leaves.map(() => []);
  let index = leaves.map((_, i) => i);
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1] ?? left;
      next.push(sha256(Buffer.concat([left, right])));
    }
    index = index.map((pos, leaf) => {
      const sibling = pos % 2 === 0 ? (level[pos + 1] ?? level[pos]!) : level[pos - 1]!;
      paths[leaf]!.push({ h: sibling.toString('hex'), side: pos % 2 === 0 ? 'R' : 'L' });
      return Math.floor(pos / 2);
    });
    level = next;
  }
  return { root: level[0]!.toString('hex'), paths };
}

export function applyPath(leaf: string, path: PathStep[]): string {
  let h: Buffer = Buffer.from(leaf, "hex");
  for (const s of path) {
    const sib = Buffer.from(s.h, 'hex');
    h = sha256(s.side === 'R' ? Buffer.concat([h, sib]) : Buffer.concat([sib, h]));
  }
  return h.toString('hex');
}
