import { fingerprintRecord, withoutBookkeeping } from "./canonical";
import type { LogEntry } from "./log";
import { proofFor, type RecordProof } from "./verify";

// The public record.json: a published record with its fingerprint and the proof the site
// claims for it. A verifier checks that proof against the log in the public repository,
// never against anything else the site serves. Fact-check bookkeeping (`verification`) is
// left out; it is not part of the fingerprint.

export type PublishedRecord = { id: string; record: Record<string, unknown>; fingerprint: string; proof: RecordProof | null };

export type RecordDocument = PublishedRecord & {
  edition: string;
  kind: string;
  judgments: PublishedRecord[];
};

function published(edition: string, record: { id: string; verification?: unknown }, log: LogEntry[]): PublishedRecord {
  return { id: record.id, record: withoutBookkeeping(record), fingerprint: fingerprintRecord(record), proof: proofFor(record.id, log, edition) };
}

export function recordDocument(
  resolved: { edition: string; id: string; kind: string; record: { id: string; verification?: unknown }; judgments: { id: string; verification?: unknown }[] },
  log: LogEntry[],
): RecordDocument {
  const main = published(resolved.edition, resolved.record, log);
  const judgments = resolved.judgments.map((j) => published(resolved.edition, j, log));
  return { edition: resolved.edition, kind: resolved.kind, ...main, judgments };
}
