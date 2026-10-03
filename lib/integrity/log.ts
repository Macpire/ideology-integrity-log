import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { fingerprint } from "./canonical";
import { merkleRoot } from "./merkle";

export type LogRecord = { id: string; kind: "content" | "judgment"; fingerprint: string; supersedes: string | null };

export type Receipt = { witness: string; status: "ok" | "pending"; ref: string | null };

// One publish of one edition. The body is what both keys sign and what the next entry's
// `prev` points at; signatures and witness receipts sit outside it, so a receipt that
// arrives later never changes a fingerprint.
export type LogEntry = {
  seq: number;
  prev: string | null;            // fingerprint of the previous entry's body; null for seq 1
  edition: string;
  publishedAt: string;            // ISO 8601
  records: LogRecord[];
  merkleRoot: string;
  serviceSig: { keyId: string; sig: string };
  ownerSig: { keyId: string; sshsig: string } | null;
  receipts: Receipt[];
};

export type EntryBody = Omit<LogEntry, "serviceSig" | "ownerSig" | "receipts">;

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export const LOG_DIR =path.join("integrity", "log");

export const entryFileName = (seq: number) => `${String(seq).padStart(6, "0")}.json`;

export function entryBody(e: EntryBody): EntryBody {
  return { seq: e.seq, prev: e.prev, edition: e.edition, publishedAt: e.publishedAt, records: e.records, merkleRoot: e.merkleRoot };
}

export function entryFingerprint(e: EntryBody): string {
  return fingerprint(entryBody(e));
}

export function verifyChain(entries: LogEntry[]): { ok: true } | { ok: false; seq: number; reason: string } {
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i + 1) return { ok: false, seq: e.seq, reason: `expected seq ${i + 1}` };
    const expectedPrev = i === 0 ? null : entryFingerprint(entries[i - 1]);
    if (e.prev !== expectedPrev) return { ok: false, seq: e.seq, reason: "prev does not match the previous entry" };
    // Key validity is judged at publishedAt, so it may never move back: a leaked key cannot
    // date a new entry before its recorded compromise.
    const at = Date.parse(e.publishedAt);
    if (!ISO_INSTANT.test(e.publishedAt) || Number.isNaN(at)) return { ok: false, seq: e.seq, reason: "publishedAt is not an ISO 8601 time" };
    if (i > 0 && at < Date.parse(entries[i - 1].publishedAt)) {
      return { ok: false, seq: e.seq, reason: "publishedAt is earlier than the previous entry's" };
    }
    if (e.records.length === 0) return { ok: false, seq: e.seq, reason: "entry has no records" };
    if (e.merkleRoot !== merkleRoot(e.records.map((r) => r.fingerprint))) {
      return { ok: false, seq: e.seq, reason: "merkleRoot does not match the records" };
    }
  }
  return { ok: true };
}

// integrity/log/*.json in seq order.
export function readLog(dir: string = path.join(process.cwd(), LOG_DIR)): LogEntry[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => /^\d+\.json$/.test(name))
    .map((name) => JSON.parse(readFileSync(path.join(dir, name), "utf8")) as LogEntry)
    .sort((a, b) => a.seq - b.seq);
}
