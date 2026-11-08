# Retained-shell verb-hook binding cache

Forward recovery can replace a live local CLAIM body with a retained soft-delete
header. The entity pass leaves a tombstoned row alone; the dedicated retained-shell
writer runs after that pass, before the edge and ordinary tombstone passes.

`recovery::materialize_retained_shells` publishes the existing verb-hook binding
cache generation after each successfully committed CLAIM-shell restoration.
It uses `with_write_txn_grouped_after_commit`, so publication happens after the
root commit is durable and before fallible postcommit work. An error after that
commit does not undo either the restored shell or the cache publication.

The notification is deliberately coarse. An admitted CLAIM shell invalidates the
cache even when the row was already header-only or absent. A local hard-delete
marker skips restoration and notification. A failed base write publishes nothing.
Non-CLAIM shells retain their existing behavior.

The batch restoration primitive and its aborted bridge preflight do not publish
this notification. The forward caller owns the durable write. Existing shell
validation, delete semantics, later replay, and hook admission remain unchanged.
An invocation that already selected a binding is not cancelled by this refresh.
The existing two-second cache age is unchanged; the next cache lookup after
publication observes the new generation instead of waiting for that age.
