import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { entryFingerprint, type LogEntry, type Receipt } from "./log";
import { openTimestampsWitness } from "./witness-ots";
import { rfc3161Witness } from "./witness-rfc3161";

// Outside witnesses the operator does not control. Each publish sends the entry's
// fingerprint (which covers its Merkle root and the previous entry) to every active
// witness; a witness that is down leaves a "pending" receipt that a later retry fills.

export type Submission = { status: "ok" | "pending"; receiptPath: string | null };

export interface Witness {
  name: string;
  // Timestamp a SHA-256 digest; any receipt file is written under `dir`.
  submit(digestHex: string, dir: string): Promise<Submission>;
  // Turn a pending receipt into a complete one, where the witness needs that (OpenTimestamps).
  upgrade?(digestHex: string, receiptPath: string): Promise<Submission>;
  verify(digestHex: string, receiptPath: string): Promise<boolean>;
}

const ADAPTERS: Record<string, () => Witness> = {
  rfc3161: () => rfc3161Witness(),
  opentimestamps: () => openTimestampsWitness(),
};

// The witnesses named in integrity/witnesses.json, e.g. ["rfc3161", "opentimestamps"].
export function activeWitnesses(file = path.join(process.cwd(), "integrity/witnesses.json")): Witness[] {
  const names: string[] = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : [];
  return names.map((name) => {
    const make = ADAPTERS[name];
    if (!make) throw new Error(`Unknown witness ${name} in ${file}`);
    return make();
  });
}

// Receipt refs are stored relative to the repository root so the log is portable.
const toRef = (receiptPath: string | null) => (receiptPath ? path.relative(process.cwd(), receiptPath) : null);
const fromRef = (ref: string) => path.resolve(process.cwd(), ref);

async function attempt(witness: Witness, run: () => Promise<Submission>): Promise<Receipt> {
  try {
    const result = await run();
    return { witness: witness.name, status: result.status, ref: toRef(result.receiptPath) };
  } catch (error) {
    console.warn(`Witness ${witness.name} failed: ${error instanceof Error ? error.message : String(error)}`);
    return { witness: witness.name, status: "pending", ref: null };
  }
}

export async function submitAll(digestHex: string, dir: string, witnesses: Witness[]): Promise<Receipt[]> {
  return Promise.all(witnesses.map((w) => attempt(w, () => w.submit(digestHex, dir))));
}

// Witness a newly logged entry. Receipts sit outside the signed body.
export async function witnessEntry(entry: LogEntry, dir: string, witnesses: Witness[]): Promise<LogEntry> {
  return { ...entry, receipts: await submitAll(entryFingerprint(entry), dir, witnesses) };
}

// Retry every pending receipt, and add a receipt for any witness added since. Complete
// receipts and everything inside the signed body stay exactly as they were.
export async function retryEntry(entry: LogEntry, dir: string, witnesses: Witness[]): Promise<LogEntry> {
  const digest = entryFingerprint(entry);
  const receipts: Receipt[] = [];
  for (const receipt of entry.receipts) {
    const w = witnesses.find((x) => x.name === receipt.witness);
    if (!w || receipt.status === "ok") {
      receipts.push(receipt);
    } else if (receipt.ref && w.upgrade) {
      const ref = receipt.ref;
      const upgraded = await attempt(w, () => w.upgrade!(digest, fromRef(ref)));
      receipts.push(upgraded.ref ? upgraded : receipt);
    } else {
      receipts.push(await attempt(w, () => w.submit(digest, dir)));
    }
  }
  for (const w of witnesses) {
    if (!entry.receipts.some((r) => r.witness === w.name)) receipts.push(await attempt(w, () => w.submit(digest, dir)));
  }
  return { ...entry, receipts };
}

export async function verifyReceipt(entry: LogEntry, receipt: Receipt, witnesses: Witness[]): Promise<boolean> {
  const w = witnesses.find((x) => x.name === receipt.witness);
  if (!w || !receipt.ref) return false;
  try {
    return await w.verify(entryFingerprint(entry), fromRef(receipt.ref));
  } catch {
    return false;
  }
}
