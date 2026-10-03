import { createHash } from "node:crypto";

// A minimal reader and writer for OpenTimestamps detached proofs (.ots): enough to build a
// proof from calendar responses, upgrade pending attestations, and find Bitcoin attestations.
// Format: https://github.com/opentimestamps/python-opentimestamps (core/serialize, timestamp, op, notary).

export const OTS_MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
const PENDING_TAG = Buffer.from("83dfe30d2ef90c8e", "hex");
const BITCOIN_TAG = Buffer.from("0588960d73d71901", "hex");
const SHA256 = 0x08;

export type Attestation =
  | { kind: "pending"; uri: string }
  | { kind: "bitcoin"; height: number }
  | { kind: "unknown"; tag: Buffer; payload: Buffer };

export type Op = { tag: number; arg: Buffer | null };
export type Timestamp = { attestations: Attestation[]; ops: { op: Op; next: Timestamp }[] };

const UNARY: Record<number, string> = { 0x02: "sha1", 0x03: "ripemd160", 0x08: "sha256", 0xf2: "reverse", 0xf3: "hexlify" };
const BINARY: Record<number, string> = { 0xf0: "append", 0xf1: "prepend" };

class Reader {
  private pos = 0;
  constructor(private buf: Buffer) {}
  byte() {
    if (this.pos >= this.buf.length) throw new Error("Truncated proof");
    return this.buf[this.pos++];
  }
  bytes(n: number) {
    if (this.pos + n > this.buf.length) throw new Error("Truncated proof");
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return Buffer.from(out);
  }
  varuint() {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      shift += 7;
      if (shift > 49) throw new Error("varuint too long");
    }
  }
  varbytes(max = 8192) {
    const n = this.varuint();
    if (n > max) throw new Error("varbytes too long");
    return this.bytes(n);
  }
  done() {
    return this.pos === this.buf.length;
  }
}

function varuint(n: number): Buffer {
  const out: number[] = [];
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return Buffer.from(out);
}

const varbytes = (b: Buffer) => Buffer.concat([varuint(b.length), b]);

function readAttestation(r: Reader): Attestation {
  const tag = r.bytes(8);
  const payload = r.varbytes();
  const inner = new Reader(payload);
  if (tag.equals(PENDING_TAG)) return { kind: "pending", uri: inner.varbytes(1000).toString("utf8") };
  if (tag.equals(BITCOIN_TAG)) return { kind: "bitcoin", height: inner.varuint() };
  return { kind: "unknown", tag, payload };
}

function readOp(r: Reader, tag: number): Op {
  if (tag in UNARY) return { tag, arg: null };
  if (tag in BINARY) return { tag, arg: r.varbytes(4096) };
  throw new Error(`Unknown operation 0x${tag.toString(16)}`);
}

function readItem(r: Reader, ts: Timestamp, tag: number) {
  if (tag === 0x00) ts.attestations.push(readAttestation(r));
  else ts.ops.push({ op: readOp(r, tag), next: readTimestamp(r) });
}

function readTimestamp(r: Reader): Timestamp {
  const ts: Timestamp = { attestations: [], ops: [] };
  let tag = r.byte();
  while (tag === 0xff) {
    readItem(r, ts, r.byte());
    tag = r.byte();
  }
  readItem(r, ts, tag);
  return ts;
}

export function parseTimestamp(buf: Buffer): Timestamp {
  const r = new Reader(buf);
  const ts = readTimestamp(r);
  if (!r.done()) throw new Error("Trailing bytes after timestamp");
  return ts;
}

function writeAttestation(a: Attestation): Buffer {
  if (a.kind === "pending") return Buffer.concat([Buffer.from([0x00]), PENDING_TAG, varbytes(varbytes(Buffer.from(a.uri, "utf8")))]);
  if (a.kind === "bitcoin") return Buffer.concat([Buffer.from([0x00]), BITCOIN_TAG, varbytes(varuint(a.height))]);
  return Buffer.concat([Buffer.from([0x00]), a.tag, varbytes(a.payload)]);
}

const writeOp = (op: Op) => Buffer.concat([Buffer.from([op.tag]), op.arg ? varbytes(op.arg) : Buffer.alloc(0)]);

export function serializeTimestamp(ts: Timestamp): Buffer {
  const items = [
    ...ts.attestations.map(writeAttestation),
    ...ts.ops.map(({ op, next }) => Buffer.concat([writeOp(op), serializeTimestamp(next)])),
  ];
  if (items.length === 0) throw new Error("Empty timestamp");
  return Buffer.concat(items.map((item, i) => (i < items.length - 1 ? Buffer.concat([Buffer.from([0xff]), item]) : item)));
}

export function applyOp(op: Op, msg: Buffer): Buffer {
  switch (op.tag) {
    case 0xf0: return Buffer.concat([msg, op.arg!]);
    case 0xf1: return Buffer.concat([op.arg!, msg]);
    case 0xf2: return Buffer.from(msg).reverse();
    case 0xf3: return Buffer.from(msg.toString("hex"), "utf8");
    default: return createHash(UNARY[op.tag]).update(msg).digest();
  }
}

// Every attestation in the tree with the message it commits to.
export function attestations(ts: Timestamp, msg: Buffer): { attestation: Attestation; msg: Buffer; node: Timestamp }[] {
  return [
    ...ts.attestations.map((attestation) => ({ attestation, msg, node: ts })),
    ...ts.ops.flatMap(({ op, next }) => attestations(next, applyOp(op, msg))),
  ];
}

// A detached proof for a SHA-256 digest.
export function writeDetached(digest: Buffer, ts: Timestamp): Buffer {
  return Buffer.concat([OTS_MAGIC, varuint(1), Buffer.from([SHA256]), digest, serializeTimestamp(ts)]);
}

export function readDetached(buf: Buffer): { digest: Buffer; timestamp: Timestamp } {
  const r = new Reader(buf);
  if (!r.bytes(OTS_MAGIC.length).equals(OTS_MAGIC)) throw new Error("Not an OpenTimestamps proof");
  if (r.varuint() !== 1) throw new Error("Unsupported proof version");
  if (r.byte() !== SHA256) throw new Error("Proof is not over a SHA-256 digest");
  const digest = r.bytes(32);
  const timestamp = readTimestamp(r);
  if (!r.done()) throw new Error("Trailing bytes after proof");
  return { digest, timestamp };
}

// Graft one timestamp's items onto another node (same message).
export function merge(into: Timestamp, from: Timestamp) {
  into.attestations.push(...from.attestations);
  into.ops.push(...from.ops);
}
