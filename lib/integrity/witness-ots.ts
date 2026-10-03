import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { attestations, merge, parseTimestamp, readDetached, writeDetached, type Timestamp } from "./ots";
import type { Submission, Witness } from "./witness";

// OpenTimestamps: public calendars aggregate digests into Bitcoin transactions. A fresh proof
// is pending; once its commitment is in a block (hours), an upgrade fetches the path to the
// block header and the receipt becomes complete. Verification checks that header's Merkle
// root through a block explorer.

export const DEFAULT_CALENDARS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"];
export const DEFAULT_EXPLORER = "https://blockstream.info/api";

export type OtsOptions = {
  calendars?: string[];
  explorer?: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
};

const OTS_HEADERS = { Accept: "application/vnd.opentimestamps.v1", "User-Agent": "ideology-integrity" };

const hasBitcoin = (ts: Timestamp, digest: Buffer) => attestations(ts, digest).some((a) => a.attestation.kind === "bitcoin");

export function openTimestampsWitness(options: OtsOptions = {}): Witness {
  const calendars = options.calendars ?? DEFAULT_CALENDARS;
  const explorer = options.explorer ?? DEFAULT_EXPLORER;
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeout = () => AbortSignal.timeout(options.timeoutMs ?? 30_000);

  async function bytes(url: string, init: RequestInit = {}): Promise<Buffer | null> {
    const response = await doFetch(url, { ...init, signal: timeout() });
    if (!response.ok) return null;
    return Buffer.from(await response.arrayBuffer());
  }

  async function json<T>(url: string): Promise<T> {
    const response = await doFetch(url, { signal: timeout() });
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    return (await response.json()) as T;
  }

  return {
    name: "opentimestamps",
    async submit(digestHex: string, dir: string): Promise<Submission> {
      const digest = Buffer.from(digestHex, "hex");
      const root: Timestamp = { attestations: [], ops: [] };
      const failures: string[] = [];
      for (const calendar of calendars) {
        try {
          const body = await bytes(`${calendar}/digest`, { method: "POST", headers: OTS_HEADERS, body: new Uint8Array(digest) });
          if (body) merge(root, parseTimestamp(body));
          else failures.push(calendar);
        } catch (error) {
          failures.push(`${calendar} (${error instanceof Error ? error.message : String(error)})`);
        }
      }
      if (root.attestations.length === 0 && root.ops.length === 0) throw new Error(`No calendar answered: ${failures.join(", ")}`);
      mkdirSync(dir, { recursive: true });
      const receiptPath = path.join(dir, "opentimestamps.ots");
      writeFileSync(receiptPath, writeDetached(digest, root));
      return { status: hasBitcoin(root, digest) ? "ok" : "pending", receiptPath };
    },

    async upgrade(digestHex: string, receiptPath: string): Promise<Submission> {
      if (!existsSync(receiptPath)) throw new Error(`Missing ${receiptPath}`);
      const { digest, timestamp } = readDetached(readFileSync(receiptPath));
      if (digest.toString("hex") !== digestHex) throw new Error("Proof is for another digest");
      for (const { attestation, msg, node } of attestations(timestamp, digest)) {
        if (attestation.kind !== "pending") continue;
        if (!calendars.some((c) => attestation.uri.replace(/\/$/, "") === c.replace(/\/$/, ""))) continue; // only calendars we trust to ask
        const body = await bytes(`${attestation.uri.replace(/\/$/, "")}/timestamp/${msg.toString("hex")}`, { headers: OTS_HEADERS }).catch(() => null);
        if (!body) continue; // not in a block yet
        const upgrade = parseTimestamp(body);
        if (!hasBitcoin(upgrade, msg)) continue;
        node.attestations = node.attestations.filter((a) => a !== attestation);
        merge(node, upgrade);
      }
      writeFileSync(receiptPath, writeDetached(digest, timestamp));
      return { status: hasBitcoin(timestamp, digest) ? "ok" : "pending", receiptPath };
    },

    async verify(digestHex: string, receiptPath: string): Promise<boolean> {
      const { digest, timestamp } = readDetached(readFileSync(receiptPath));
      if (digest.toString("hex") !== digestHex) return false;
      for (const { attestation, msg } of attestations(timestamp, digest)) {
        if (attestation.kind !== "bitcoin") continue;
        const hashResponse = await doFetch(`${explorer}/block-height/${attestation.height}`, { signal: timeout() });
        if (!hashResponse.ok) continue;
        const blockHash = (await hashResponse.text()).trim();
        const block = await json<{ merkle_root: string }>(`${explorer}/block/${blockHash}`);
        // The header stores the Merkle root in internal byte order; explorers show it reversed.
        if (Buffer.from(msg).reverse().toString("hex") === block.merkle_root) return true;
      }
      return false;
    },
  };
}
