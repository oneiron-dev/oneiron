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

## Host-profiled children

A host-profiled scoped child keeps its own generation backend. Its compaction
uses the ordinary house or agent memory profile, prompt and compaction route,
but spends on the same parent guard as its generation. It never substitutes a
reader-attempt scope or the host's code-mode meter.

The host supplies an interface to its original generation count. Each compaction
call admits once while that generation is open and not stopped, then settles
its response's input plus output units once. An error, an unsent warm-prefix
call or a dropped ticket settles zero, matching the existing generation
accounting. The original session alone closes the count. Calls still in flight
at that close remain owed and settle against the original attempt's line.
The call carries the same work deadline, cancellation identity, task and parent
admission as the original generation. An admitted call can finish after a stop;
no new call is admitted after it.

An agent's self-written live fork is admitted on the role the profiled host
actually supplied for its generation, both when capturing the live rung and
when sending the fork. The extraction backend is not reused as a compaction
backend. An absent generation interface or provider factory keeps the existing
raw window. No second counter, clock or queue is created.

## Source integration

The nested-reader implementation in PR #5403 is separate. At their source join,
keep the same compaction seat outside its outer nested-wait/executor-rebuild loop;
do not construct a fresh seat after each nested wait. Existing private-session
routing, retained results, explicit-speech denial, replay and settlement rules
remain independent of compaction.

No guest protocol, image, configuration or deployment change is required beyond
an ordinary engine/server update. This document describes source behavior, not
an observed runtime or memory bound.
