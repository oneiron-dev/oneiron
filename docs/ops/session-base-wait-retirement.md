# Session wait resume after a flip to on-record

A Session code run captures its write route at each entry. After a flip to
on-record, it can still read the waiting replay record and delivered reply
from the sealed room while its new writes go to base.

The base-route resume now commits the replay record and its generation-bound
wait cleanup in one writer. It validates the replay generation and the holder
and delivery erasure state against the composed view. It keeps the existing
base replay fence and route, participant and saver checks.

After the base commit is durable, the existing Session publication guard
retires only the changed full VaultMeta keys from the sealed overlay: the
replay record, the waiter index only when its composed generation matches,
and the delivery and trap for that exact wait generation. It compares the
captured preview and current row and preserves a changed mode or row. An
aborted writer retires nothing. The old post-generation cleanup remains
idempotent.

Overlay-route resume, public wait cleanup, settled replies, holder records,
observed-change cursors, consent handling, heal counters and fold receipts
retain their existing behavior. No new table, timer, cap or setting is added.
The ordinary engine/server update is sufficient; no guest image or protocol
change is required. This change does not make a closed room restart-durable.
