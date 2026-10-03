import { createHash } from "node:crypto";

// Reads the signing key out of an armored OpenSSH signature (PROTOCOL.sshsig), without
// running ssh-keygen: the blob is "SSHSIG", a version, then the public key as an SSH
// string. The key's fingerprint is what `ssh-keygen -l -E sha256` prints for it.

function sshString(buf: Buffer, offset: number): { value: Buffer; next: number } | null {
  if (offset + 4 > buf.length) return null;
  const length = buf.readUInt32BE(offset);
  const start = offset + 4;
  if (start + length > buf.length) return null;
  return { value: buf.subarray(start, start + length), next: start + length };
}

export function sshsigPublicKey(sshsig: string): Buffer | null {
  const match = sshsig.match(/-----BEGIN SSH SIGNATURE-----([\s\S]*?)-----END SSH SIGNATURE-----/);
  if (!match) return null;
  const blob = Buffer.from(match[1].replace(/\s+/g, ""), "base64");
  if (blob.subarray(0, 6).toString("latin1") !== "SSHSIG" || blob.length < 10) return null;
  const key = sshString(blob, 10);
  return key && key.value.length > 0 ? key.value : null;
}

// "SHA256:…" fingerprint of the key that made the signature, or null when it cannot be read.
export function sshsigKeyId(sshsig: string): string | null {
  const key = sshsigPublicKey(sshsig);
  return key ? `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}` : null;
}
