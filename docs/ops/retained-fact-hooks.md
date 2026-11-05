# Retained background fact hooks

`FactHookRunner::spawn` owns fact-hook evaluations independently of its pass
caller. The synchronous `run_pass`, verb-hook and replay APIs remain synchronous.
This is an in-memory continuation, not a new public Pending outcome or vault row.

## Ownership and progress

Before a body starts, its job owns the vault, runtime, verdict host, binding,
grant, input, fact position and run key. It carries the **original admitted
ScopedReadActorKey**, not a later read key reconstructed from the actor's current
grants. The job builds its scoped lane from that key with `Recorded` status.
The original pass admission remains held through the job and its completion.

A pending evaluation owns its binding's next cursor position in both sources.
The pass never advances that binding through the rest of a batch. Other bindings
read from their own cursors, so an old pending position does not hold their batch
floor back. Bindings start in the existing priority/body-hash order; independent
bindings may finish in a different order. After a completed evaluation, the next
scan prefers the other existing fact source, so a continuous claim feed does not
starve settlement delivery. The source-order choice lives in
`runner::retained::RetainedRuns::sources`.

## Eventual completion

The owned job runs the native sandbox and its admitted read/verdict callbacks to
their ends. There is no timeout, cancellation, late-answer discard, budget-based
refusal or re-entry of that body while its job is pending. Verdict ordinals and
pins retain their ordinary order. Usage that was not reported stays unavailable;
budget overruns remain accounting beside the actual outcome.

Once the body ends, the retained result contains its input, read/verdict pins,
judgement, measured accounting and runtime identity. The parent resumes the
existing record, commit and intent-drain tail. Its memo, receipt, lineage,
erasure fence, intent and exact fact cursor still land through the original
writer. A record/commit error retains this result and retries completion, not
body execution. Each retained intent drain, retries included, reads the current
hook switch and live bindings and uses the native refusal for a disabled or
revoked hook. The run record still keeps its original binding and grant. After
a successful commit, a drain retry cannot recommit or recount that run. A panic from the owned runtime is an actual failed outcome
with the context and pins reported so far, not a reason to re-enter the body.

A completion wakes the background loop. Its existing change notices and tick
remain. Shutdown starts no new evaluation and keeps the original admissions and
continuations until pending jobs and completion tails finish. An admitted
callback that never answers can therefore keep shutdown pending; it is not
silently cancelled. This change does not provide crash/restart durability for
an unfinished callback, nor retained-async verb or replay callers.
