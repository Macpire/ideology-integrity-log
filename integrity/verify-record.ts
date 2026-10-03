// Checks one record against the public integrity log: recomputes its fingerprint, checks the
// Merkle proof, the log chain, both signatures (owner via ssh-keygen) against the keys in the
// public log, and each witness receipt.
//
// From the public log alone (no request to the site; the record is the log's public copy):
//   npx tsx verify-record.ts --log <edition> <id> [--repo <raw base url or local clone>]
//
// Comparing what the site serves with the public log:
//   npx tsx verify-record.ts <site-url> <edition> <id> [--locale en] [--repo <raw base url or local clone>]
//
// The repository defaults to https://raw.githubusercontent.com/Macpire/ideology-integrity-log/main.
// In a clone of the public log, pass --repo . to read everything from disk.
import { DEFAULT_REPO_BASE, verifyFromLog, verifyRemote, type Check } from "../lib/integrity/remote.ts";
import { openTimestampsWitness } from "../lib/integrity/witness-ots.ts";
import { rfc3161Witness } from "../lib/integrity/witness-rfc3161.ts";

const USAGE = [
  "Usage:",
  "  verify-record.ts --log <edition> <id> [--repo <raw base url or local directory>]",
  "  verify-record.ts <site-url> <edition> <id> [--locale en] [--repo <raw base url or local directory>]",
].join("\n");

const VALUE_FLAGS = new Set(["--locale", "--repo"]);
const args = process.argv.slice(2);
const positional: string[] = [];
const options: Record<string, string> = {};
let logOnly = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--log") logOnly = true;
  else if (VALUE_FLAGS.has(args[i])) options[args[i]] = args[++i];
  else if (args[i].startsWith("--")) {
    console.error(`Unknown option ${args[i]}\n${USAGE}`);
    process.exit(2);
  } else positional.push(args[i]);
}

const repoBase = options["--repo"] ?? DEFAULT_REPO_BASE;
const witnesses = [rfc3161Witness(), openTimestampsWitness()];

async function run(): Promise<Check[]> {
  if (logOnly) {
    const [edition, id] = positional;
    if (!edition || !id || positional.length !== 2) throw new Error(USAGE);
    return verifyFromLog({ edition, id, repoBase, witnesses });
  }
  const [site, edition, id] = positional;
  if (!site || !edition || !id || positional.length !== 3) throw new Error(USAGE);
  return verifyRemote({ site, edition, id, locale: options["--locale"], repoBase, witnesses });
}

run()
  .then((checks) => {
    for (const c of checks) {
      const mark = c.ok === true ? "PASS" : c.ok === "pending" ? "PENDING" : "FAIL";
      console.log(`${mark.padEnd(8)} ${c.name} — ${c.detail}`);
    }
    const failed = checks.filter((c) => c.ok === false).length;
    console.log(failed === 0 ? "\nEvery check passed." : `\n${failed} check(s) failed.`);
    process.exit(failed === 0 ? 0 : 1);
  })
  .catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(error instanceof Error && error.message === USAGE ? 2 : 1);
  });
