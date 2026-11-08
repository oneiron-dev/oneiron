# Captured task-refusal reasons

A fresh native `tasks.refuse` decline can retain its readable reason as an output of the
executor run that made the call. The reason comes from the actual post-hook request,
under the read key already admitted for that call. A replayed decline publishes nothing.

A claim is a Full-profile JSON row. It uses the normal claim projection and context-pack
field-release rules, including credential and secret filtering. A turn is a JSON row
containing the released text of its readable messages in `txt`. The row's `id` is the
accepted claim or turn reference. These outputs do not contain raw MessagePack rows.
No ranking, live-support, token-budget or character-budget filter is added by this path.

A missing read key, an unreadable or empty reason, a failed read, or a failed output
publication leaves the output unknown. It does not change the accepted decline into a
failed call. The original refusal receipt, settlement and replay classification remain.
The output uses the run's existing routed body spool and publication door, at the exact
bridge-result path for the recorded call's sequence.

Agent-result attribution still prefers the run's complete nonempty observation. An
empty REPL observation does not shadow a retained decline reason: the resolver may use
only the retained, digest-checked output of the latest fresh native decline of that
attempt's own TASK. Without that reason, the existing empty observation remains the
answer. It joins the recorded accepted outcome to the same sequence's complete output;
a pointer, receipt, unrelated file or another TASK is not body evidence.
The existing result TURN and body-holder write stay in the same transaction. This slice
does not establish output entities for every opaque workflow result or other self-settled
TASK report, or prove every later source-erasure effect on copied result occurrences.
