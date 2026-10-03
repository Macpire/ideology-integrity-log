import { createHash, createPublicKey, sign, verify } from "node:crypto";

import { canonicalize } from "./canonical";

// The service key signs "independently checked". Its private half lives only in the CI
// secret store; this module never reads the environment.

export function serviceSign(body: unknown, privateKeyPem: string): string {
  return sign(null, Buffer.from(canonicalize(body), "utf8"), privateKeyPem).toString("base64");
}

export function serviceVerify(body: unknown, sig: string, publicKeyPem: string): boolean {
  try {
    return verify(null, Buffer.from(canonicalize(body), "utf8"), publicKeyPem, Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

// Short, stable id for a service public key: the first 16 hex digits of the SHA-256 of its DER.
export function serviceKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return `service:${createHash("sha256").update(der).digest("hex").slice(0, 16)}`;
}

export type Rotation = {
  keyId: string;
  role: "service" | "owner";
  publicKey?: string;             // service keys: the Ed25519 public key (PEM) whose id is keyId
  validFrom: string;              // ISO 8601
  retiredAt: string | null;
  compromisedAt: string | null;
};

export type KeyStatus = "valid" | "retired-ok" | "retired" | "compromised" | "not-yet-valid" | "unknown";

// Whether a signature by `keyId` made at `at` can be trusted. A retired key's earlier
// signatures stay good; anything from the recorded compromise on is flagged.
export function keyValidAt(role: Rotation["role"], keyId: string, at: string, rotations: Rotation[]): KeyStatus {
  const r = rotations.find((x) => x.role === role && x.keyId === keyId);
  const t = Date.parse(at);
  if (!r || Number.isNaN(t)) return "unknown";
  if (r.compromisedAt && t >= Date.parse(r.compromisedAt)) return "compromised";
  if (t < Date.parse(r.validFrom)) return "not-yet-valid";
  if (r.retiredAt) return t < Date.parse(r.retiredAt) ? "retired-ok" : "retired";
  return "valid";
}

export const isTrusted = (status: KeyStatus) => status === "valid" || status === "retired-ok";

// The public key listed for a service key id, only when that key really has that id.
// Every service key ever used stays listed, so entries signed before a rotation still verify.
export function servicePublicKey(keyId: string, rotations: Rotation[]): string | null {
  const row = rotations.find((r) => r.role === "service" && r.keyId === keyId);
  if (!row?.publicKey) return null;
  try {
    return serviceKeyId(row.publicKey) === keyId ? row.publicKey : null;
  } catch {
    return null;
  }
}

// What is wrong with a service signature over `body`: it is checked with the key its id
// names, and that key must have been trusted at `at`.
export function serviceSigProblems(body: unknown, serviceSig: { keyId: string; sig: string }, at: string, rotations: Rotation[]): string[] {
  const pem = servicePublicKey(serviceSig.keyId, rotations);
  if (!pem) return [`service key ${serviceSig.keyId} is not listed with its public key`];
  const problems: string[] = [];
  if (!serviceVerify(body, serviceSig.sig, pem)) problems.push("service signature does not verify");
  const status = keyValidAt("service", serviceSig.keyId, at, rotations);
  if (!isTrusted(status)) problems.push(`service key ${serviceSig.keyId} is ${status} at ${at}`);
  return problems;
}
