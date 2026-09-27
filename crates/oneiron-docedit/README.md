# oneiron-docedit

Storage-independent document edit core (ARTL). The crate owns office-file
inspection, narrow edit proposals, OPC validation, typed anchor replay, version
planning, and proposal freshness. It does not open a vault or run office binaries.

A host implements [`ArtifactStorage`](src/lib.rs) to return a consistent head,
media type, and byte snapshot. The first host is `oneiron`: it reads that
snapshot in one LMDB read transaction. The host owns its write transaction,
including the claim ledger, version append, re-anchor sweep, consume-once
settlement, consent recheck, and receipt. This keeps a select atomic and a
failed or stale proposal from mutating the document.

The host must not use an edit session's self-reported diff as proof: the core
re-parses the output OPC package and validates its actual parts before it
returns a proposal. External edit and recalculation binaries remain in host
session images, behind `EditSession`; none is a crate dependency.

## Admission budgets

`DocumentLimits` is supplied by the host with the snapshot. The organ has no
compiled customer admission threshold. It rejects ZIP64 sentinel sizes and
invalid (zero or non-ZIP32) budgets regardless of policy. Both the input and
every intermediate/final session output use the same resolved limits; size and
CRC checks remain mandatory.

The `oneiron` host seeds `document_limits: {entry_bytes: 268435456,
package_bytes: 1073741824}` in its default POLICY_MANIFEST. A trusted holder-
authored manifest row replaces the seeded fallback and may widen it within the
ZIP32 representation bound. Other trusted authored rows combine by minimum;
untrusted peer contributions only narrow. A nested request can narrow the
vault result but never widen it. Missing or malformed policy refuses a stored
document proposal. The host reads the manifest and document under one LMDB
read transaction before passing the budget here.
