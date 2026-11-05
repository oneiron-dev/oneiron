# Executor continuation seed state

A prompt continuation first proves the failed predecessor's captured start,
source replay prefix and effect cut. It then keeps the frozen task, model,
locality, effort, tier, soft step limit, clock and teaching fingerprint as
content owned by the child run. This exists before the child's first step.
It does not copy the teaching package or another full replay prefix.

On reopening, the child reads that exact owned occurrence, with its body
digest, secret and taint marks, and actor erasure checked. A released,
withheld, erased or changed seed is not a witness. The config marker alone
cannot reconstruct the task or authorize a continuation. Marker validation uses
the caller's transaction and custody guard, with its own body pin. It never
re-enters the public reader while holding that guard or a seed writer.

The leased-successor binding, approved continuation, failed predecessor,
source replay row, selected capsule generation and start digest stay live
checks. The seed records the identity of the exact admitted source prefix;
reopening compares the current source prefix with it. Later masking of the
child's inherited replies does not replace that original prefix witness.
An effect after a model-step cut still refuses. A final-row cut still checks
the original final-row digest and terminal markers. Removing only the parent
start body's occurrence no longer removes the child's independent config.
Erasing the actor still releases the child's seed like its other reply bodies.

A seed is published in the same write transaction as the child's replay row,
with the current source and actor checked inside that writer. Actual actor
ownership is stamped before the native erase fence. The two body instances
are reserved before the writer opens; their file pins last through commit.
No descriptor is republished after the fence releases it.

The seed path contains the child run's id under `executor/repl/continuation/`.
It is internal content, not a guest result path or an authority token. A
fork of a fork keeps inherited occurrences and adds its own distinct seed;
it does not discard an output just because its path resembles a seed.
A child with no independent seed can still reopen through the original full
source-start proof when that proof succeeds.

No migration, new setting, cap, timeout, protocol or artifact change is needed.
Deploy only the normal matching engine/server when authorized.
