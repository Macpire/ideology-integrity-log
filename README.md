# Ideology integrity log

This repository is the public copy of the integrity log for the Ideology civic voter guide.
It holds only fingerprints, signatures, witness receipts and public keys — no content and no personal data.

- `integrity/log/` — hash-chained entries. Each lists record fingerprints with a Merkle root, signed by the service key (independently checked) and the owner's hardware key (owner approved).
- `integrity/receipts/<entry>/` — an RFC 3161 timestamp (`rfc3161.tsr`) and an OpenTimestamps proof anchored in Bitcoin (`opentimestamps.ots`).
- `integrity/keys/` — `owner.allowed_signers` and `rotations.json` (every key ever used, with validity dates).

It is updated automatically from the site's repository after each owner-approved publish. Anyone can check a published record against it with the verify script, which trusts nothing served by the site.
