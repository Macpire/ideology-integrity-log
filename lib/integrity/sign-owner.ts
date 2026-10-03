import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

// The owner key signs "owner approved" with OpenSSH's SSHSIG format, so any SSH key can hold
// it: today a Secure Enclave key through Secretive's agent (Touch ID per signature), or a
// FIDO2 security key (`ed25519-sk`, touch and PIN). These run ssh-keygen as a system tool from
// scripts only, never from the web app at request time. The message always goes on stdin.

export const OWNER_NAMESPACE = "ideology-integrity";

export function ownerSign(message: string, keyPath: string): string {
  return execFileSync("ssh-keygen", ["-Y", "sign", "-n", OWNER_NAMESPACE, "-f", keyPath], {
    input: message,
    stdio: ["pipe", "pipe", "inherit"], // a security key prompts for touch and PIN on the terminal
  }).toString();
}

export function ownerVerify(message: string, sshsig: string, allowedSignersPath: string, identity: string): boolean {
  const dir = mkdtempSync(path.join(tmpdir(), "sshsig-"));
  try {
    const sigFile = path.join(dir, "message.sig");
    writeFileSync(sigFile, sshsig);
    execFileSync(
      "ssh-keygen",
      ["-Y", "verify", "-f", allowedSignersPath, "-I", identity, "-n", OWNER_NAMESPACE, "-s", sigFile],
      { input: message, stdio: ["pipe", "pipe", "pipe"] },
    );
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// The allowed signer whose key made this signature, or null.
export function ownerPrincipal(sshsig: string, allowedSignersPath: string): string | null {
  const dir = mkdtempSync(path.join(tmpdir(), "sshsig-"));
  try {
    const sigFile = path.join(dir, "message.sig");
    writeFileSync(sigFile, sshsig);
    const out = execFileSync("ssh-keygen", ["-Y", "find-principals", "-s", sigFile, "-f", allowedSignersPath], {
      stdio: ["ignore", "pipe", "pipe"],
    }).toString().trim();
    return out.split("\n")[0] || null;
  } catch {
    return null;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A check for any listed owner key: finds the signer among the allowed signers, then verifies.
export function ownerChecker(allowedSignersPath: string): (message: string, sshsig: string) => boolean {
  return (message, sshsig) => {
    const principal = ownerPrincipal(sshsig, allowedSignersPath);
    return principal !== null && ownerVerify(message, sshsig, allowedSignersPath, principal);
  };
}

// "SHA256:…" fingerprint of a public key file, used as the owner signature's key id.
export function ownerKeyFingerprint(publicKeyPath: string): string {
  const out = execFileSync("ssh-keygen", ["-l", "-E", "sha256", "-f", publicKeyPath]).toString();
  const match = out.match(/SHA256:[A-Za-z0-9+/]+/);
  if (!match) throw new Error(`No fingerprint for ${publicKeyPath}`);
  return match[0];
}

// True when ssh-keygen can be run here; the build gate reports a clear error otherwise.
export function sshKeygenAvailable(): boolean {
  try {
    execFileSync("ssh-keygen", ["-?"], { stdio: "ignore" });
    return true;
  } catch (error) {
    // ssh-keygen prints usage and exits 1 for -?; only a missing binary is a real failure
    return (error as NodeJS.ErrnoException).code !== "ENOENT";
  }
}
