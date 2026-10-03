import { fingerprintRecord } from "./canonical";
import { entryBody, entryFingerprint, verifyChain, type LogEntry } from "./log";
import { merkleProof, verifyProof, type MerkleProof } from "./merkle";
import { isTrusted, keyValidAt, serviceSigProblems, type Rotation } from "./sign-service";
import { sshsigKeyId } from "./sshsig";

// Everything needed to check one record against the log without trusting the site.
export type RecordProof = {
  id: string;
  edition: string;
  fingerprint: string;              // as approved in the latest entry holding the record
  entry: LogEntry;
  merkleProof: MerkleProof;
  versions: { seq: number; publishedAt: string; fingerprint: string; supersedes: string | null }[];
};

export type VerifyKeys = {
  rotations: Rotation[];            // every key ever used, with service public keys, by id
  // Checks an owner signature over a message; null where ssh-keygen cannot run (the web app).
  ownerCheck: ((message: string, sshsig: string) => boolean) | null;
  // Checks an entry's witness receipts offline (the build gate); without it, an entry only
  // needs a receipt reference.
  witnessCheck?: (entry: LogEntry) => string[];
};

// The latest entry holding `id` (in `edition`, when given), with its Merkle proof and every version.
export function proofFor(id: string, log: LogEntry[], edition?: string): RecordProof | null {
  const holding = log.filter((e) => (!edition || e.edition === edition) && e.records.some((r) => r.id === id));
  const entry = holding.at(-1);
  if (!entry) return null;
  const record = entry.records.find((r) => r.id === id)!;
  return {
    id, edition: entry.edition, fingerprint: record.fingerprint, entry,
    merkleProof: merkleProof(entry.records.map((r) => r.fingerprint), record.fingerprint),
    versions: holding.map((e) => {
      const r = e.records.find((x) => x.id === id)!;
      return { seq: e.seq, publishedAt: e.publishedAt, fingerprint: r.fingerprint, supersedes: r.supersedes };
    }),
  };
}

// Checks on the entry itself, shared by every record it holds.
export function entryProblems(entry: LogEntry, keys: VerifyKeys): string[] {
  const problems = serviceSigProblems(entryBody(entry), entry.serviceSig, entry.publishedAt, keys.rotations);
  if (!entry.ownerSig) {
    problems.push("missing owner signature");
  } else {
    // Key status is judged for the key that actually signed, read from the signature itself.
    const signer = sshsigKeyId(entry.ownerSig.sshsig);
    if (signer !== entry.ownerSig.keyId) {
      problems.push(`owner signature was made by ${signer ?? "an unreadable key"}, not ${entry.ownerSig.keyId}`);
    }
    if (keys.ownerCheck && !keys.ownerCheck(entryFingerprint(entry), entry.ownerSig.sshsig)) {
      problems.push("owner signature does not verify");
    }
    if (signer) {
      const owner = keyValidAt("owner", signer, entry.publishedAt, keys.rotations);
      if (!isTrusted(owner)) problems.push(`owner key ${signer} is ${owner} at ${entry.publishedAt}`);
    }
  }
  if (keys.witnessCheck) problems.push(...keys.witnessCheck(entry));
  else if (!entry.receipts.some((r) => r.ref)) problems.push("not witnessed");
  return problems;
}

function recordProblems(record: { verification?: unknown }, proof: RecordProof): string[] {
  const problems: string[] = [];
  if (fingerprintRecord(record) !== proof.fingerprint) problems.push("changed after approval");
  const inEntry = proof.entry.records.find((r) => r.id === proof.id);
  if (!inEntry || inEntry.fingerprint !== proof.fingerprint || !verifyProof(proof.fingerprint, proof.merkleProof, proof.entry.merkleRoot)) {
    problems.push("not in its log entry's Merkle tree");
  }
  return problems;
}

export function verifyRecord(record: { verification?: unknown }, proof: RecordProof, keys: VerifyKeys): { ok: boolean; problems: string[] } {
  const problems = [...recordProblems(record, proof), ...entryProblems(proof.entry, keys)];
  return { ok: problems.length === 0, problems };
}

// The build gate for one edition: every listed record must be in the log at its current
// fingerprint, in an intact chain, signed by both keys, and sent to a witness.
export function integrityProblems(
  edition: string, records: { id: string; verification?: unknown }[], log: LogEntry[], keys: VerifyKeys,
): string[] {
  const errors: string[] = [];
  const chain = verifyChain(log);
  if (!chain.ok) errors.push(`${edition}: integrity log broken at entry ${chain.seq}: ${chain.reason}`);
  const byEntry = new Map<number, string[]>();
  for (const record of records) {
    const proof = proofFor(record.id, log, edition);
    if (!proof) {
      errors.push(`${record.id}: not approved`);
      continue;
    }
    if (!byEntry.has(proof.entry.seq)) byEntry.set(proof.entry.seq, entryProblems(proof.entry, keys));
    for (const p of [...recordProblems(record, proof), ...byEntry.get(proof.entry.seq)!]) errors.push(`${record.id}: ${p}`);
  }
  return errors;
}

// Every entry the site reads a badge from, whatever edition it is for: an intact chain, a
// valid service signature and, where the owner has signed, an owner signature that
// verifies. Owner approval may still be pending (the record shows as checked); witnessing
// is the gate's job for gated editions.
export function logSignatureProblems(log: LogEntry[], keys: VerifyKeys): string[] {
  const chain = verifyChain(log);
  const errors = chain.ok ? [] : [`integrity log broken at entry ${chain.seq}: ${chain.reason}`];
  const ungated = { rotations: keys.rotations, ownerCheck: keys.ownerCheck };
  for (const entry of log) {
    for (const p of entryProblems(entry, ungated)) {
      if (p === "not witnessed" || (p === "missing owner signature" && !entry.ownerSig)) continue;
      errors.push(`integrity log entry ${entry.seq}: ${p}`);
    }
  }
  return errors;
}
