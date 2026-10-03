import { createHash } from "node:crypto";

// One serialization for every machine: sorted keys, "\n" line endings, NFC Unicode,
// no undefined fields, and JSON's own number formatting (no locale, no trailing zeros).

function normalizeString(s: string) {
  return s.replace(/\r\n?/g, "\n").normalize("NFC");
}

function sortValue(value: unknown): unknown {
  if (typeof value === "string") return normalizeString(value);
  if (typeof value === "number" && !Number.isFinite(value)) throw new Error("Non-finite number in record");
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .map(([key, v]) => [normalizeString(key), v] as const)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const out: Record<string, unknown> = {};
    for (const [key, v] of entries) {
      if (key in out) throw new Error(`Two keys normalize to "${key}"`);
      out[key] = sortValue(v);
    }
    return out;
  }
  return value;
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

export function fingerprint(value: unknown): string {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

// A record without its fact-check bookkeeping: its own `verification` and that of each
// measure link (a link's direction is vetted by its own link-direction judgment).
export function withoutBookkeeping(record: { verification?: unknown }): Record<string, unknown> {
  const rest: Record<string, unknown> = { ...record };
  delete rest.verification;
  if (Array.isArray(rest.links)) {
    rest.links = rest.links.map((link: unknown) => {
      if (!link || typeof link !== "object") return link;
      const kept: Record<string, unknown> = { ...link };
      delete kept.verification;
      return kept;
    });
  }
  return rest;
}

// A record's fingerprint covers what readers see and what scoring uses,
// never the fact-check bookkeeping that changes on every re-check.
export function fingerprintRecord(record: { verification?: unknown }): string {
  return fingerprint(withoutBookkeeping(record));
}
