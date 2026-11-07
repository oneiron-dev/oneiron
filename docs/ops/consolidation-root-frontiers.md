# Typed consolidation frontiers

The owner pins a root with `consolidation_pin_as_owner`, then submits typed
child judgements through `consolidation_frontier_as_owner`. The root keeps
reference pins and judgement digests, not another copy of proposal text.

A newly accepted child whose complete evidence set consists of corroborating
CLAIM/TURN references now enters a standard Micro queue attempt. All eligible
new children in one bucket submission share the attempt and the existing
conflict resolver. Repeating the same accepted child does not enqueue it again.
NOTE-containing and non-corroborating children keep their existing accounting
behavior. No citation is removed to make a child eligible.

The queued judgement keeps the public frontier's JSON value. Candidate creation
uses the native claim conversion and derives identities from the actual queued
attempt. The root owner is ownership metadata, not the Dreamer actor or an
approval. Current Dreamer reads, exact prior admission, conflict decisions,
verified evidence and the existing sealed promotion sink still decide writes.
A CLAIM-only root has no synthetic TURN, conversation or partition.

The output writer rechecks the live root, its accepted child subset and the
original source pins after model/checker work. Erasure of the root during that
work cannot produce a later write. The root owner's erase also empties this
bridge's queued proposal payloads in the same transaction, without touching
other Micro jobs. A hard erase of any captured selector, cited source, pinned
ancestor or MESSAGE also empties each affected bridge payload through the
native queue eraser, including its archived-row and run-snapshot copies. The
producer captures these dependency ids in the same transaction as the accepted
frontier and queue row, so removing the root first does not hide a dependency.
Ordinary soft-delete history is unchanged. Consolidation claims retain the
normal evidence and erasure rules; this slice does not establish full RUNS-07
or NOTE promotion support.

When this attempt's own native grant closes a pinned CLAIM, the same grant
transaction records the original retained revision and the exact closed-row
revision in the private root. A later pass can recover only that attempt's
original bytes through the existing entity revision ledger, after current
Recorded read authority and the full root fence pass. No source bodies are
copied into the root. Native source erasure, stale checks and history retirement
still govern those retained revisions. Another attempt or an external change
cannot use the own-close exception.

There is no new queue kind, wake timer, public request field, model setting,
budget, numeric limit, migration or deployment requirement.
