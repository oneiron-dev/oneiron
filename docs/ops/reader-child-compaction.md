# Reader-child compaction

Ordinary host-metered code-reader children use the host's configured compaction
factory. Their existing model-seat and code-check hooks are unchanged. A factory
that is absent or off keeps the raw window, as on the other native run paths.
Summary-only jobs do not create a compaction seat.

The binding uses the child's actual dispatcher actor, the locality already noted
for its parent's reads, and the child spend scope its runner already opened. A
host-metered child with no scope keeps the host meter. The child carries no parent
credential or verified read slip; compaction home reads use the existing actor's
Grant and that locality, without inventing a proof. The queue label
`reader:<parent-run>` only gives siblings one parent's turn in the existing pass
queue. It proves no identity or authority. Summary placement keeps the native
factory's default, like pumped runs; no credential world or facet is guessed.

One compaction seat stays with the child across its yielded entries. Session
executors bind it to their existing recording route. Anonymous recording routes
keep the window raw. An accepted result still passes through the executor's
original admission, validation and landing path on the next entry.

When a full window reports an in-flight pass, the blocking reader worker waits on
that pass's existing channel for at most the child's remaining cutoff, including
its existing parent-clock/fold-reserve bound. The received result stays on the
same seat until the next entry takes it. No polling interval, retry count or new
clock is added. The cutoff and borrowed parent lease are checked again before
that entry can read or call a model. A wait that expires settles at the existing
cutoff. A disconnected pass goes through its original refusal path. A full
window with no pass in flight keeps the existing `window_full` disposition.

## Remaining scope

A host-profiled scoped child keeps its existing profile backend and parent guard.
The standard host compaction factory cannot represent that custom guard. This
change does not substitute the host's payer or claim to provide profiled-child
compaction. That part of FIX 1841 remains open.

The nested-reader implementation in PR #5403 is separate. At their source join,
keep the same compaction seat outside its outer nested-wait/executor-rebuild loop;
do not construct a fresh seat after each nested wait. Existing private-session
routing, retained results, explicit-speech denial, replay and settlement rules
remain independent of compaction.

No guest protocol, image, configuration or deployment change is required beyond
an ordinary engine/server update. This document describes source behavior, not
an observed runtime or memory bound.
