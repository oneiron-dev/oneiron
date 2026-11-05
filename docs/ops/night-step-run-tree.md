# Night-step run-tree projection

A run-tree read displays the parent attempt carried by native night-step maintenance
payloads. It does not infer parentage from a shared run id. An explicit placement
parent still takes precedence; otherwise a retry belongs beneath the attempt it
replaces, before the payload's parent is considered.

An unreadable maintenance payload leaves that row as a bare job rather than failing
the whole tree read. Missing parents and parent cycles use the existing tree repair
records.

This is a read-only projection. It does not change queue parent indexes, placement,
retry scheduling or cancellation. In particular, cancelling the night-step plan does
not gain a new cascade over its maintenance jobs.
