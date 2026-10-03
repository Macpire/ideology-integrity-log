import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { entryFingerprint, type LogEntry } from "./log";
import type { Submission, Witness } from "./witness";

// RFC 3161 timestamp authority, via `openssl ts` (scripts only, never the web app).
// Until counsel names an authority, DigiCert's free service; INTEGRITY_TSA_URL swaps it, and
// each receipt's metadata file records which authority issued it.

export const DEFAULT_TSA_URL = "http://timestamp.digicert.com";

export type Rfc3161Options = {
  url?: string;
  caFile?: string;                  // trust anchors (and intermediates) for verification
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
};

const openssl = (args: string[], input?: Buffer) =>
  execFileSync("openssl", args, { input, stdio: ["pipe", "pipe", "pipe"] });

// integrity/keys/tsa-chain.pem when committed, else OpenSSL's own trust store.
function defaultCaFile(): string {
  const committed = path.join(process.cwd(), "integrity/keys/tsa-chain.pem");
  if (existsSync(committed)) return committed;
  const dir = openssl(["version", "-d"]).toString().match(/"(.*)"/)?.[1];
  return path.join(dir ?? "/etc/ssl", "cert.pem");
}

function withTemp<T>(run: (dir: string) => T): T {
  const dir = mkdtempSync(path.join(tmpdir(), "rfc3161-"));
  try {
    return run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function rfc3161Witness(options: Rfc3161Options = {}): Witness {
  const url = options.url ?? process.env.INTEGRITY_TSA_URL ?? DEFAULT_TSA_URL;
  const doFetch = options.fetch ?? globalThis.fetch;
  return {
    name: "rfc3161",
    async submit(digestHex: string, dir: string): Promise<Submission> {
      const query = withTemp((tmp) => {
        const out = path.join(tmp, "req.tsq");
        openssl(["ts", "-query", "-digest", digestHex, "-sha256", "-cert", "-out", out]);
        return readFileSync(out);
      });
      const response = await doFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/timestamp-query" },
        body: new Uint8Array(query),
        signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
      });
      if (!response.ok) throw new Error(`${url} answered ${response.status}`);
      const reply = Buffer.from(await response.arrayBuffer());
      const status = withTemp((tmp) => {
        const file = path.join(tmp, "resp.tsr");
        writeFileSync(file, reply);
        return openssl(["ts", "-reply", "-in", file, "-text"]).toString();
      });
      if (!/Status: Granted/.test(status)) throw new Error(`${url} did not grant the timestamp`);
      mkdirSync(dir, { recursive: true });
      const receiptPath = path.join(dir, "rfc3161.tsr");
      writeFileSync(receiptPath, reply);
      writeFileSync(
        path.join(dir, "rfc3161.json"),
        `${JSON.stringify({ authority: url, digest: digestHex, receivedAt: new Date().toISOString() }, null, 2)}\n`,
      );
      return { status: "ok", receiptPath };
    },
    async verify(digestHex: string, receiptPath: string): Promise<boolean> {
      return verifyRfc3161(digestHex, receiptPath, options.caFile);
    },
  };
}

// Offline check of a stored receipt against the digest and the trust anchors.
export function verifyRfc3161(digestHex: string, receiptPath: string, caFile?: string): boolean {
  try {
    openssl(["ts", "-verify", "-digest", digestHex, "-in", receiptPath, "-CAfile", caFile ?? defaultCaFile()]);
    return true;
  } catch {
    return false;
  }
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// The time the authority stamped (its genTime) as an ISO 8601 instant, or null.
export function receiptTime(receiptPath: string): string | null {
  try {
    const text = openssl(["ts", "-reply", "-in", receiptPath, "-text"]).toString();
    const m = text.match(/Time stamp: (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(\.\d+)? (\d{4}) GMT/);
    if (!m || !MONTHS.includes(m[1])) return null;
    const ms = Date.UTC(Number(m[7]), MONTHS.indexOf(m[1]), Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    return new Date(ms + Math.round(Number(m[6] ?? 0) * 1000)).toISOString();
  } catch {
    return null;
  }
}

// How long the owner may take between service signing (publishedAt) and the timestamp, and
// how far the signer's clock may run ahead of the authority's.
export const MAX_STAMP_DELAY_MS = 30 * 24 * 60 * 60 * 1000;
export const CLOCK_SKEW_MS = 5 * 60 * 1000;

// The build gate's witness check for one entry (scripts only): at least one RFC 3161
// receipt must verify offline for the entry's fingerprint, and its stamped time must come
// after publishedAt, within MAX_STAMP_DELAY_MS. A pending OpenTimestamps proof alone is
// never enough. Refs are relative to the repository root.
export function rfc3161EntryProblems(entry: LogEntry, caFile?: string): string[] {
  const digest = entryFingerprint(entry);
  const times = entry.receipts
    .filter((r) => r.witness === "rfc3161" && r.status === "ok" && r.ref)
    .map((r) => path.resolve(process.cwd(), r.ref!))
    .filter((file) => existsSync(file) && verifyRfc3161(digest, file, caFile))
    .map((file) => receiptTime(file));
  if (times.length === 0) return ["no RFC 3161 receipt verifies"];
  const stamped = times.find((t): t is string => t !== null);
  if (!stamped) return ["the RFC 3161 receipt has no readable time"];
  const gap = Date.parse(stamped) - Date.parse(entry.publishedAt);
  if (gap < -CLOCK_SKEW_MS) return [`publishedAt ${entry.publishedAt} is after its RFC 3161 time ${stamped}`];
  if (gap > MAX_STAMP_DELAY_MS) return [`publishedAt ${entry.publishedAt} is more than 30 days before its RFC 3161 time ${stamped}`];
  return [];
}

// The authority that issued a stored receipt, from its metadata file.
export function receiptAuthority(receiptPath: string): string | null {
  const meta = path.join(path.dirname(receiptPath), "rfc3161.json");
  return existsSync(meta) ? (JSON.parse(readFileSync(meta, "utf8")).authority as string) : null;
}
