# Nested result readers

A native Read job can use `self.spawn` to queue another Read job over one
of its own stored outputs, then use `tasks.wait` for those children. An
inherited `src` is not the child's own output and cannot be forwarded by
this path. Scoped-agent jobs and summary jobs keep their existing doors.

The nested seat uses the current child's attempt scope, or the same host
meter when no scope exists. It keeps the caller destination and inherited
model list. Its window is bounded by the child's remaining time, with a
fold reserve inside that time. It borrows no ancestor attempt lease and
opens no new default window. Both the native per-rung backend and its
fallback publish settled generation spend on the same lease ledger before
returning the answer or error. Final settlement books only the remaining
unbooked spend. A booking fault keeps the existing warn-and-retry behavior.

A durable peer wait drops the native executor and guest heap before
releasing the shared code-run execution permit. The child keeps its model
seat, configuration, backend, budget guard and per-parent resident count.
The existing reader-runner ticks observe the exact routed wait delivery.
The child then reacquires a permit from the same pool within its remaining
cutoff, verifies the same active job generation and binding, and restores
its committed replay through the native executor. No model call polls an
unsettled wait. Other kinds of child waits keep their previous refusal.

The worker advances a separate in-memory queue cursor for the canonical
store and each live session. A full parent's queued siblings cannot keep
later grandchildren hidden behind the same queue page on every tick. The
existing per-tick page size and per-parent resident limits stay in force.
At the end of a queue, one empty-page wrap checks the head before deciding
that a session has no queued work. A restart resets only this scan position.

Each level still uses native stored-source admission, committed-output
checks, range and row checks, taint checks, current job generation and its
original canonical or off-record participant route. A nested door supplies
no credential and does not admit ordinary agent verbs or ambient writes.

This change needs matching engine/server binaries when deployed. It adds
no setting, storage format, guest protocol change or image-build step.
