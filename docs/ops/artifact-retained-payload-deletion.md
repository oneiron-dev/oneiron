# Artifact deletion and retained work

Deleting an artifact removes three kinds of retained payload in the same
write transaction as its existing blob lifecycle cleanup:

- pending edit/native-output proposals (`PENDING`);
- stale-base stranded proposals (`STRANDED`);
- held organ calls, including failed rows (`WAITS`).

Each purge scans only its table prefix plus the exact artifact id. It
collects keys without decoding row values, then deletes those keys. Other
artifacts, the consume-once settlement ledger (`RECORD`), version/history
rules and the existing deletion/hold decisions are unchanged. A storage
error aborts the caller's whole transaction, including these purges.

Every new-payload writer checks the existing durable deletion markers in
its own write transaction before publication. This uses the native soft
delete fence / hard delete marker predicate, including its existing
protected-record exceptions. It is not a new presence requirement: an edit
proposal for a never-created artifact id without a deletion marker remains
accepted as before. A held organ call already required an artifact; that
check is also repeated inside its publication transaction. A delete and a
concurrent publication therefore serialize at the writer instead of leaving
a new retained row after cleanup. The existing update-only wait path still
cannot recreate a missing row.

Before redriving a RAM snapshot, the organ host calls the native
`Vault::organ_wait_is_current` read port. One read transaction checks that
the exact retained call still waits, that its artifact is present, and that
the artifact is not durably deletion-marked. The transaction closes before
decode, routing or any callback. A released, superseded, failed or erased
held call is not dispatched and returns the existing `Redrive::Failed`
channel without recreating its removed row. Live calls retain their old
read sight, submitter, grant, clocks, resource handling and proposal landing.

This is retained-storage cleanup plus a fresh pre-dispatch check, not
global erasure or cancellation of already-running work. A delete can race
after the read transaction closes; no lock or transaction spans an organ
call, and already-issued external effects are not undone. Existing read
snapshots and independently owned byte copies are not a whole-memory
erasure claim. Producer fences prevent post-delete retained publication
while the native deletion marker remains effective.

No count/byte cap, default, timeout, wire/schema, SDK verb, dependency or
configuration changes. Existing settlement consent, Keep/Discard and
restore semantics remain unchanged. The new read port is internal native
engine/organ-host coordination, not a new HTTP or SDK door.
