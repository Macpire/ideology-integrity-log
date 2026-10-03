import { createHash } from "node:crypto";

import { canonicalize, withoutBookkeeping } from "./canonical";
import type { LogEntry } from "./log";

// The public copy of every logged record: integrity/records/<seq>/<encoded id>.json holds the exact
// bytes whose SHA-256 is the fingerprint in log entry <seq>, so anyone holding the public log
// can check a record without asking the site for it. See integrity/records/SPEC.md.

export const RECORDS_DIR = "integrity/records";

// A record id as a file name every operating system accepts: A-Z, a-z, 0-9, ".", "_" and "-"
// stay as they are; every other character is percent-encoded as its UTF-8 bytes, with
// uppercase hex (":" becomes "%3A", "@" becomes "%40"). decodeURIComponent reverses it.
export const recordFileName = (id: string) =>
  encodeURIComponent(id).replace(/[!'()*~]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export const recordIdFromFileName = (name: string) => decodeURIComponent(name);

export const recordFile = (seq: number, id: string) => `${RECORDS_DIR}/${seq}/${recordFileName(id)}.json`;

// The canonical bytes of a record: no fact-check bookkeeping, sorted keys, NFC, no whitespace.
export function recordBytes(record: { verification?: unknown }): string {
  return canonicalize(withoutBookkeeping(record));
}

export const sha256Hex = (bytes: string) => createHash("sha256").update(bytes, "utf8").digest("hex");

export type RecordVersion = { id: string; verification?: unknown; [field: string]: unknown };

// Every file an entry needs, or which records could not be found at their logged fingerprint.
// `find` returns the versions of a record it knows (current content first, then history).
export function entryRecordFiles(
  entry: LogEntry, find: (edition: string, id: string, seq: number) => Iterable<RecordVersion>,
): { files: { path: string; bytes: string }[]; missing: string[] } {
  const files: { path: string; bytes: string }[] = [];
  const missing: string[] = [];
  for (const r of entry.records) {
    let bytes: string | null = null;
    for (const version of find(entry.edition, r.id, entry.seq)) {
      const candidate = recordBytes(version);
      if (version.id === r.id && sha256Hex(candidate) === r.fingerprint) {
        bytes = candidate;
        break;
      }
    }
    if (bytes === null) missing.push(`entry ${entry.seq}: ${r.id} at ${r.fingerprint}`);
    else files.push({ path: recordFile(entry.seq, r.id), bytes });
  }
  return { files, missing };
}
