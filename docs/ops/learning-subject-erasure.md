# Learning after a subject's hard deletion

A native hard deletion removes the subject's registered learning cells,
evidence, stored priors and subject-index entries. It closes the subject's
active engine-observed learning heads, including heads no longer connected
by a ClaimOf edge. Existing closed history and the other subjects' measurements
are not rewritten by the late-write rule below.

Outcome and receipt records can outlive the subject. A later projection of
those records must not register the hard-deleted subject again or abort the
transaction carrying another subject's outcome.

The shared learning write doors consult the existing permanent local hard-delete
marker in their own write transaction. Recording evidence, capturing a borrowed
or reliability prior, storing an explicit cell prior, and projecting a registered
cell skip that subject and log the reason. They use the existing successful
empty result; the carrying team outcome, offer check or judge conversion can
still commit. PERSON and SKILL use the same subject-id rule.

This is not an entity-presence or visibility rule. Soft deletion, archive and
an id that has never been materialized do not create this hard-delete marker.
Their previous behavior is unchanged. The ordinary claim subject check still
reports an absent subject when a non-skipped writer needs it. Read-only prior
backoff and owner-written setting seeds are unchanged.

The rule adds no marker format, table, migration, default, limit or public API.
The separate nightly snapshot race still needs its missing-cell skip. This
record describes the source contract, not runtime or global erasure proof.
