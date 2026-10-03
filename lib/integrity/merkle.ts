import { createHash } from "node:crypto";

// A Merkle tree over fingerprints (hex SHA-256). Leaves are sorted and deduplicated, so
// the root depends only on the set. A parent is SHA-256 over the left then right child's
// raw bytes; an odd level pairs its last node with itself; one leaf is its own root.

export type MerkleProof = { index: number; path: string[] };

function parent(left: string, right: string) {
  return createHash("sha256").update(Buffer.concat([Buffer.from(left, "hex"), Buffer.from(right, "hex")])).digest("hex");
}

function prepare(leaves: string[]) {
  if (leaves.length === 0) throw new Error("A Merkle tree needs at least one leaf; got no leaves");
  return [...new Set(leaves.map((l) => l.toLowerCase()))].sort();
}

function nextLevel(level: string[]) {
  const out: string[] = [];
  for (let i = 0; i < level.length; i += 2) out.push(parent(level[i], level[i + 1] ?? level[i]));
  return out;
}

export function merkleRoot(leaves: string[]): string {
  let level = prepare(leaves);
  while (level.length > 1) level = nextLevel(level);
  return level[0];
}

export function merkleProof(leaves: string[], leaf: string): MerkleProof {
  let level = prepare(leaves);
  const start = level.indexOf(leaf.toLowerCase());
  if (start < 0) throw new Error(`Leaf ${leaf} is not in the tree`);
  const path: string[] = [];
  let index = start;
  while (level.length > 1) {
    const sibling = index % 2 === 0 ? index + 1 : index - 1;
    path.push(level[sibling] ?? level[index]);
    level = nextLevel(level);
    index = Math.floor(index / 2);
  }
  return { index: start, path };
}

export function verifyProof(leaf: string, proof: MerkleProof, root: string): boolean {
  let hash = leaf.toLowerCase();
  let index = proof.index;
  for (const sibling of proof.path) {
    hash = index % 2 === 0 ? parent(hash, sibling) : parent(sibling, hash);
    index = Math.floor(index / 2);
  }
  return index === 0 && hash === root.toLowerCase();
}
