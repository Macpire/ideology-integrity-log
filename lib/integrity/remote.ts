import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { fingerprintRecord } from "./canonical";
import type { PublishedRecord, RecordDocument } from "./document";
import { entryFileName, entryFingerprint, verifyChain, type LogEntry } from "./log";
import { verifyProof } from "./merkle";
import { ownerChecker } from "./sign-owner";
import type { Rotation } from "./sign-service";
import { recordFile } from "./records";
import { entryProblems, proofFor } from "./verify";
import type { Witness } from "./witness";

// Checks a record against the public log repository. Two modes:
// - verifyRemote: the record comes from the site; the log, the keys and the witness receipts
//   come from the public repository. The site's proof must match the repository's log entry
//   for entry, and must be the latest version the repository holds, so a rolled-back
//   correction is caught.
// - verifyFromLog: nothing comes from the site. The record is the public copy in
//   integrity/records/<seq>/<encoded id>.json, and its proof is built from the repository's log.
// The repository can be a URL or a local directory (a clone of the public log).

export const DEFAULT_REPO_BASE = "https://raw.githubusercontent.com/Macpire/ideology-integrity-log/main";

export type Check = { name: string; ok: boolean | "pending"; detail: string };

export type RemoteOptions = {
  site: string;
  edition: string;
  id: string;
  locale?: string;
  repoBase?: string;                // a URL, or a local directory holding the public log
  fetch?: typeof globalThis.fetch;
  witnesses: Witness[];
};

export type LogOnlyOptions = Omit<RemoteOptions, "site" | "locale">;

const isUrl = (base: string) => /^https?:\/\//.test(base);

// Reads `<repo>/<path>` from a URL or from a local directory, answering like fetch.
function repositoryReader(repoBase: string, doFetch: typeof fetch): typeof fetch {
  if (isUrl(repoBase)) return doFetch;
  const root = path.resolve(repoBase);
  return (async (input: string | URL | Request) => {
    const file = path.resolve(root, String(input).slice(repoBase.length).replace(/^\//, ""));
    if (!file.startsWith(`${root}${path.sep}`) || !existsSync(file)) return new Response("missing", { status: 404 });
    return new Response(readFileSync(file));
  }) as typeof fetch;
}

// Far more entries than the log will ever hold; only guards against a server that never 404s.
const MAX_ENTRIES = 100_000;

async function text(doFetch: typeof fetch, url: string): Promise<string> {
  const response = await doFetch(url);
  if (!response.ok) throw new Error(`${url} answered ${response.status}`);
  return response.text();
}

// integrity/log/000001.json, 000002.json, … until the first missing entry.
async function repositoryLog(doFetch: typeof fetch, repo: string): Promise<LogEntry[]> {
  const log: LogEntry[] = [];
  for (let seq = 1; seq <= MAX_ENTRIES; seq++) {
    const response = await doFetch(`${repo}/integrity/log/${entryFileName(seq)}`);
    if (response.status === 404) break;
    if (!response.ok) throw new Error(`${repo}/integrity/log/${entryFileName(seq)} answered ${response.status}`);
    log.push(JSON.parse(await response.text()) as LogEntry);
  }
  return log;
}

function checkPublished(label: string, p: PublishedRecord, logEdition: string, repoLog: LogEntry[]): Check[] {
  const recomputed = fingerprintRecord(p.record);
  const checks: Check[] = [{
    name: `${label}: fingerprint`, ok: recomputed === p.fingerprint,
    detail: recomputed === p.fingerprint ? recomputed : `the site says ${p.fingerprint}, the record hashes to ${recomputed}`,
  }];
  // The content and the proof must both be for the id asked about, not a neighbour's.
  const ids = [p.record.id, ...(p.proof ? [p.proof.id] : [])];
  const sameId = ids.every((id) => id === p.id);
  checks.push({ name: `${label}: id`, ok: sameId, detail: sameId ? p.id : `asked for ${p.id}, the site sent ${ids.join(" and ")}` });
  if (!p.proof) {
    checks.push({ name: `${label}: approved`, ok: false, detail: "not in the integrity log" });
    return checks;
  }
  const { entry } = p.proof;
  checks.push({
    name: `${label}: matches the approved version`, ok: recomputed === p.proof.fingerprint,
    detail: recomputed === p.proof.fingerprint ? `log entry ${entry.seq}` : `approved ${p.proof.fingerprint}, published ${recomputed}`,
  });
  const inTree = verifyProof(p.proof.fingerprint, p.proof.merkleProof, entry.merkleRoot);
  checks.push({ name: `${label}: Merkle proof`, ok: inTree, detail: inTree ? entry.merkleRoot : "the proof does not lead to the entry's root" });

  const repoEntry = repoLog.find((e) => e.seq === entry.seq);
  const logged = repoEntry?.records.find((r) => r.id === p.id);
  const latest = repoLog.filter((e) => e.edition === logEdition && e.records.some((r) => r.id === p.id)).at(-1);
  const current: Check = { name: `${label}: current in the repository log`, ok: true, detail: `entry ${entry.seq}` };
  if (entry.edition !== logEdition) {
    Object.assign(current, { ok: false, detail: `the proof's entry is for ${entry.edition}, not ${logEdition}` });
  } else if (!repoEntry || entryFingerprint(repoEntry) !== entryFingerprint(entry)) {
    Object.assign(current, { ok: false, detail: `the site's entry ${entry.seq} differs from the repository's` });
  } else if (!logged || logged.fingerprint !== p.proof.fingerprint) {
    Object.assign(current, { ok: false, detail: logged ? `the repository's entry ${entry.seq} holds ${logged.fingerprint} for ${p.id}` : `the repository's entry ${entry.seq} does not hold ${p.id}` });
  } else if (!latest || latest.seq !== entry.seq) {
    Object.assign(current, { ok: false, detail: latest ? `superseded by entry ${latest.seq}` : "not in the repository's log" });
  }
  checks.push(current);
  return checks;
}

// The subjects a record's judgments can be about: the record itself and, for a measure,
// each link it has now (a link it dropped is no longer judged).
function subjectsOf(doc: RecordDocument): string[] {
  const links = Array.isArray(doc.record.links) ? (doc.record.links as { questionId?: unknown }[]) : [];
  return [doc.id, ...links.flatMap((l) => (typeof l.questionId === "string" ? [`${doc.id}@${l.questionId}`] : []))];
}

// Each judgment the site shows must be about the record; each judgment the repository log
// holds about the record must be shown, so a site cannot quietly drop a logged decision.
function checkJudgments(doc: RecordDocument, repoLog: LogEntry[]): Check[] {
  const subjects = subjectsOf(doc);
  const isAbout = (subjectId: unknown) =>
    typeof subjectId === "string" && (subjectId === doc.id || subjectId.startsWith(`${doc.id}@`));
  const checks: Check[] = doc.judgments.map((j) => {
    const { subjectId, kind } = j.record;
    const ok = isAbout(subjectId) && j.id === `${subjectId}:${kind}`;
    return { name: `${j.id}: about ${doc.id}`, ok, detail: ok ? String(subjectId) : `the judgment is about ${String(subjectId)}` };
  });
  if (doc.kind === "judgment") return checks;
  const judgedHere = (id: string) =>
    subjects.some((s) => id.startsWith(`${s}:`) && !id.slice(s.length + 1).includes(":"));
  const logged = new Set(
    repoLog.filter((e) => e.edition === doc.edition)
      .flatMap((e) => e.records.filter((r) => r.kind === "judgment" && judgedHere(r.id)).map((r) => r.id)),
  );
  const shown = new Set(doc.judgments.map((j) => j.id));
  const missing = [...logged].filter((id) => !shown.has(id)).sort();
  checks.push({
    name: "judgments: none left out", ok: missing.length === 0,
    detail: missing.length === 0 ? `${logged.size} logged` : `the log holds ${missing.join(", ")}, the site does not show ${missing.length === 1 ? "it" : "them"}`,
  });
  return checks;
}

// Signatures and receipts, read from the repository's copy of each cited entry.
async function entryChecks(entries: LogEntry[], repo: string, doFetch: typeof fetch, witnesses: Witness[]): Promise<Check[]> {
  const checks: Check[] = [];
  if (entries.length === 0) return checks;
  const rotations = JSON.parse(await text(doFetch, `${repo}/integrity/keys/rotations.json`)) as Rotation[];
  const dir = mkdtempSync(path.join(tmpdir(), "verify-record-"));
  try {
    const allowed = path.join(dir, "owner.allowed_signers");
    writeFileSync(allowed, await text(doFetch, `${repo}/integrity/keys/owner.allowed_signers`));
    const keys = { rotations, ownerCheck: ownerChecker(allowed) };
    for (const entry of entries) {
      const problems = entryProblems(entry, keys).filter((p) => p !== "not witnessed");
      checks.push({ name: `entry ${entry.seq}: signatures`, ok: problems.length === 0, detail: problems.join("; ") || "service and owner signatures verify" });
      if (entry.receipts.length === 0) {
        checks.push({ name: `entry ${entry.seq}: witnesses`, ok: false, detail: "no witness receipts" });
      }
      for (const receipt of entry.receipts) {
        const name = `entry ${entry.seq}: witness ${receipt.witness}`;
        const witness = witnesses.find((w) => w.name === receipt.witness);
        if (!receipt.ref) {
          checks.push({ name, ok: "pending", detail: "not yet submitted" });
          continue;
        }
        if (!witness) {
          checks.push({ name, ok: false, detail: "unknown witness" });
          continue;
        }
        const file = path.join(dir, `${entry.seq}-${path.basename(receipt.ref)}`);
        const response = await doFetch(`${repo}/${receipt.ref}`);
        if (!response.ok) {
          checks.push({ name, ok: false, detail: `receipt ${receipt.ref} not found` });
          continue;
        }
        writeFileSync(file, Buffer.from(await response.arrayBuffer()));
        const ok = await witness.verify(entryFingerprint(entry), file).catch(() => false);
        checks.push({ name, ok: ok ? true : receipt.status === "pending" ? "pending" : false, detail: receipt.ref });
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return checks;
}

function chainCheck(repoLog: LogEntry[]): Check {
  const chain = verifyChain(repoLog);
  return {
    name: "repository log chain", ok: chain.ok,
    detail: chain.ok ? `${repoLog.length} entr${repoLog.length === 1 ? "y" : "ies"}` : `broken at entry ${chain.seq}: ${chain.reason}`,
  };
}

const citedEntries = (published: PublishedRecord[], repoLog: LogEntry[]) => {
  const seqs = new Set(published.flatMap((p) => (p.proof ? [p.proof.entry.seq] : [])));
  return repoLog.filter((e) => seqs.has(e.seq));
};

export async function verifyRemote(options: RemoteOptions): Promise<Check[]> {
  const repoBase = (options.repoBase ?? DEFAULT_REPO_BASE).replace(/\/$/, "");
  const doFetch = options.fetch ?? globalThis.fetch;
  const readRepo = repositoryReader(repoBase, doFetch);
  const site = options.site.replace(/\/$/, "");
  const url = `${site}/${options.locale ?? "en"}/${options.edition}/verify/${encodeURIComponent(options.id)}/record.json`;
  const doc = JSON.parse(await text(doFetch, url)) as RecordDocument;

  // Past propositions are logged under archive-<area>; everything else under the edition.
  const editionOk = doc.id === options.id && (doc.edition === options.edition || doc.edition.startsWith("archive-"));
  const checks: Check[] = [{
    name: "record", ok: editionOk,
    detail: editionOk ? `${doc.edition} ${doc.id}` : `asked for ${options.edition} ${options.id}, the site sent ${doc.edition} ${doc.id}`,
  }];

  const repoLog = await repositoryLog(readRepo, repoBase);
  checks.push(chainCheck(repoLog));

  const published = [doc, ...doc.judgments];
  checks.push(...published.flatMap((p) => checkPublished(p.id, p, doc.edition, repoLog)));
  checks.push(...checkJudgments(doc, repoLog));
  checks.push(...await entryChecks(citedEntries(published, repoLog), repoBase, readRepo, options.witnesses));
  return checks;
}

// The record as the public log holds it: the latest logged version, read from its public copy.
async function loggedRecord(readRepo: typeof fetch, repo: string, edition: string, id: string, repoLog: LogEntry[]): Promise<PublishedRecord | null> {
  const proof = proofFor(id, repoLog, edition);
  if (!proof) return null;
  // The file name is percent-encoded (see recordFileName); over HTTP its "%" must be escaped.
  const file = recordFile(proof.entry.seq, id);
  const location = `${repo}/${isUrl(repo) ? encodeURI(file) : file}`;
  const response = await readRepo(location);
  if (!response.ok) throw new Error(`${location} answered ${response.status}`);
  const record = JSON.parse(await response.text()) as Record<string, unknown>;
  // The fingerprint claimed for the copy is the log's, so an edited copy fails its own check.
  return { id, record, fingerprint: proof.fingerprint, proof };
}

// Checks a record from the public log alone: no request goes to the site. `edition` is the
// edition id; a past proposition is found under its archive-<area> log edition.
export async function verifyFromLog(options: LogOnlyOptions): Promise<Check[]> {
  const repoBase = (options.repoBase ?? DEFAULT_REPO_BASE).replace(/\/$/, "");
  const readRepo = repositoryReader(repoBase, options.fetch ?? globalThis.fetch);
  const repoLog = await repositoryLog(readRepo, repoBase);
  const checks: Check[] = [chainCheck(repoLog)];

  const holds = (edition: string) => repoLog.some((e) => e.edition === edition && e.records.some((r) => r.id === options.id));
  const edition = holds(options.edition)
    ? options.edition
    : [...new Set(repoLog.map((e) => e.edition))].find((e) => e.startsWith("archive-") && holds(e));
  if (!edition) {
    checks.push({ name: "record", ok: false, detail: `the public log holds no ${options.id} for ${options.edition}` });
    return checks;
  }
  const main = await loggedRecord(readRepo, repoBase, edition, options.id, repoLog);
  if (!main) return checks;
  checks.push({ name: "record", ok: true, detail: `${edition} ${options.id}, public copy from entry ${main.proof!.entry.seq}` });

  // The judgments about the record: the latest logged version of each, for the record's subjects.
  const doc: RecordDocument = { ...main, edition, kind: repoLog.flatMap((e) => e.records).find((r) => r.id === options.id)!.kind, judgments: [] };
  if (doc.kind !== "judgment") {
    const subjects = subjectsOf(doc);
    const ids = [...new Set(repoLog.filter((e) => e.edition === edition).flatMap((e) => e.records)
      .filter((r) => r.kind === "judgment" && subjects.some((s) => r.id.startsWith(`${s}:`) && !r.id.slice(s.length + 1).includes(":")))
      .map((r) => r.id))].sort();
    for (const id of ids) {
      const judgment = await loggedRecord(readRepo, repoBase, edition, id, repoLog);
      if (judgment) doc.judgments.push(judgment);
    }
  }

  const published = [doc, ...doc.judgments];
  checks.push(...published.flatMap((p) => checkPublished(p.id, p, edition, repoLog)));
  checks.push(...await entryChecks(citedEntries(published, repoLog), repoBase, readRepo, options.witnesses));
  return checks;
}
