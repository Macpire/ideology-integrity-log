# Public record copies

`integrity/records/<seq>/<id>.json` holds the exact bytes of record `<id>` as it was approved
in log entry `<seq>` (`integrity/log/<seq as six digits>.json`). The SHA-256 of the file is the
`fingerprint` that entry lists for `<id>`. Every record and judgment in the log has a copy,
including versions that a later entry replaced.

Record ids use `a-z`, `0-9`, `-` and `.`; judgment ids add `@` and `:`
(`<subject>:<kind>`, where a measure link's subject is `<measure>@<question>`).

## File names

`<id>` in the file name is the id with every character outside `A-Z`, `a-z`, `0-9`, `.`, `_`
and `-` percent-encoded as its UTF-8 bytes in uppercase hex, so that the repository can be
checked out on every operating system (Windows does not allow `:` in a file name):

| id | file |
| --- | --- |
| `allen` | `allen.json` |
| `allen:inclusion` | `allen%3Ainclusion.json` |
| `ca-1978-prop-13@believe.tax-threshold:link-direction` | `ca-1978-prop-13%40believe.tax-threshold%3Alink-direction.json` |

The encoding is reversible: percent-decoding the name (JavaScript `decodeURIComponent`) gives
the id. The reference implementation is `recordFileName` in `lib/integrity/records.ts`. When
fetching a copy over HTTP, escape the `%` itself (`%3A` becomes `%253A` in the URL), for
example with JavaScript `encodeURI`.

## Canonical serialization

A record's fingerprint covers what readers see and what scoring uses. Before hashing:

1. **Leave out fact-check bookkeeping.** Remove the record's top-level `verification` field
   and, when the record has a `links` array, the `verification` field of each link. Nothing
   else is removed.
2. **Strings.** Replace every `\r\n` and lone `\r` with `\n`, then normalize to Unicode NFC.
   This applies to object keys as well as string values.
3. **Objects.** Drop fields whose value is `undefined` (JSON has none, so this only matters
   when serializing from code). Sort keys by UTF-16 code unit order (JavaScript's default
   string comparison). Two keys that become equal after step 2 are an error.
4. **Arrays** keep their order.
5. **Numbers** use JSON's shortest round-trip form (JavaScript `JSON.stringify`); non-finite
   numbers are an error.
6. **Output** is `JSON.stringify` of the result: no whitespace between tokens, no trailing
   newline, UTF-8 encoded.

The reference implementation is `canonicalize` and `withoutBookkeeping` in
`lib/integrity/canonical.ts`.

Each file in this directory is already in canonical form, so its fingerprint is simply the
SHA-256 of its bytes.

## Recomputing a fingerprint

From a clone of the public log:

```sh
shasum -a 256 integrity/records/2/allen.json        # or: sha256sum
grep -A2 '"id": "allen"' integrity/log/000002.json  # the fingerprint entry 2 lists for it
```

The two must be equal. To check a copy of a record taken from somewhere else (the site's
`…/verify/<id>/record.json` serves it as `record`), serialize it by the rules above and hash
the result; `verify-record.ts` does this.

## From a fingerprint to a signed entry

1. **Merkle root.** An entry's `merkleRoot` is computed over the fingerprints of its
   `records`: lowercase hex, deduplicated, sorted. A parent is the SHA-256 of the left child's
   32 raw bytes followed by the right child's; a level with an odd count pairs its last node
   with itself; a single leaf is its own root. (`lib/integrity/merkle.ts`)
2. **Entry fingerprint.** The SHA-256 of the canonical serialization (rules 2 to 6 above) of
   the entry body: `seq`, `prev`, `edition`, `publishedAt`, `records`, `merkleRoot`. The next
   entry's `prev` is this value, so the entries form a chain. (`lib/integrity/log.ts`)
3. **Service signature.** `serviceSig.sig` is a base64 Ed25519 signature over the canonical
   entry body itself (UTF-8 bytes), checked with the public key whose id is
   `serviceSig.keyId` in `integrity/keys/rotations.json`.
4. **Owner signature.** `ownerSig.sshsig` is an OpenSSH signature (namespace
   `ideology-integrity`) over the entry fingerprint as a 64-character hex string, checked with
   `ssh-keygen -Y verify` against `integrity/keys/owner.allowed_signers`.
5. **Witnesses.** Each receipt in `integrity/receipts/<seq>/` timestamps the entry
   fingerprint: `rfc3161.tsr` (check with
   `openssl ts -verify -digest <entry fingerprint> -in rfc3161.tsr -CAfile <trusted roots>`)
   and `opentimestamps.ots` (check with the `ots` client once the Bitcoin attestation has
   confirmed; until then its receipt status is `pending`).

## The script

`integrity/verify-record.ts` runs every check above for one record, with its judgments:

```sh
npx tsx integrity/verify-record.ts --log ca-2026 allen --repo .
```

`--log` reads only the public log (here the clone in the current directory; without `--repo`
it reads `raw.githubusercontent.com/Macpire/ideology-integrity-log/main`). It needs Node.js
20 or later, `ssh-keygen` and `openssl`. Without `--log`, the script also fetches the record
from a site and checks that it matches the log:

```sh
npx tsx integrity/verify-record.ts https://<site> ca-2026 allen
```

What a passing check shows: the record in the public log is exactly the one both keys signed,
in a chain no one changed afterwards, timestamped no later than the receipts say. It does not
show that the page you read displays that record faithfully; compare the text, or use the
second form, which compares the site's data with the log.
