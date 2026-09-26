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
