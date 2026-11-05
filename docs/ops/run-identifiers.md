# Run identifiers

Queue run identifiers and the HTTP run-tree query accept nonempty UTF-8 strings
without a byte-length cap. The HTTP query still requires `run_id`; it never
turns an omitted identifier into an unfiltered read.

The run and pending-consent run/group indexes use a fixed-size BLAKE3 bucket
for the full identifier. Each reader joins the stored primary row and compares
the full identifier. A digest is a lookup location, not identity or authority.
An actual hash collision is filtered by the full string. A key that points to
a row in a different hash bucket, a missing primary, malformed data, or an
inconsistent pending-consent index state still returns the existing error.
Writes, reads, deletes, alias refresh, and index reconstruction use the same
key builders. The three index namespaces use key format v2 under storage ABI
27. Opening a vault in the older storage ABI is not supported; deployments use
fresh ABI-27 vaults. No old-key reader, backfill, or migration is provided.

A Dreamer skill-edit cycle label still has its existing 128-byte bound. A run
identifier that fits after `run:` keeps the literal `run:<identifier>` label.
A longer identifier uses `run-hash:<BLAKE3 digest of the full UTF-8 identifier>`
(73 bytes). These label namespaces are distinct. The identifier is never
truncated, and the same run still shares one cycle's accounting across attempts.
An attempt without a run keeps `attempt:<attempt id>`; a missing attempt row
still does not prove a cycle.
