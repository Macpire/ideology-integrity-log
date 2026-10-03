# Ideology integrity log

This repository is the public copy of the integrity log for the Ideology civic voter guide.

It holds everything needed to check a published record **without trusting the site**:

- `integrity/log/` — hash-chained entries. Each lists record fingerprints with a Merkle root, signed by the service key (“independently checked”) and the owner key (“owner approved”).
- `integrity/records/<seq>/` — the **canonical signed bytes** of every logged record and judgment (the exact text each fingerprint is the hash of), plus `SPEC.md` describing how fingerprints are computed.
- `integrity/receipts/<entry>/` — an RFC 3161 timestamp (`rfc3161.tsr`) and an OpenTimestamps proof anchored in Bitcoin (`opentimestamps.ots`).
- `integrity/keys/` — `owner.allowed_signers` and `rotations.json` (every key ever used, with validity dates).
- `integrity/verify-record.ts` and `lib/integrity/` — the verify script and the modules it runs on.

**No personal data** is published here: no accounts, answers, notes, demographics, reviewer identities, or identity documents. The record copies are the published civic content (quotes, summaries, judgments) that readers already see on the site.

It is updated automatically from the site’s private repository after each owner-approved publish. To check a record from this log alone:

```sh
npx tsx integrity/verify-record.ts --log <edition-id> <record-id> --repo .
```

To also check that a live site serves the same bytes, pass the site URL first (see the script’s header comments).
