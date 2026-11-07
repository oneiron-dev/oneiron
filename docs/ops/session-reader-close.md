# Session reader spend at explicit close

Reader jobs, waits and findings follow their parent's recording route. An
off-record session keeps them in its in-memory overlay. Their spend scopes are
already base records containing units and ids, not private request or result
bodies.

An explicit session close drains all existing overlay leases and makes its
routes terminal before removing the final overlay state. The close visits the
actual final live reader-job rows only after that drain and after releasing the
lifecycle lock. Each matching metered queued or active job settles its existing
attempt's child scope through the ordinary idempotent spend-settlement method.
This releases an unused parent hold even when the runner can no longer record a
completion in the evaporated overlay. Queued jobs never claimed have no child
scope to settle. Already settled jobs keep their existing settlement.

The visit borrows one row at a time. It creates no whole-map or body copy and
writes no private job, finding or wait into base. A retained-state hold keeps the
same final overlay state charged through its last borrowed use, including when
another plan drops concurrently. It is not a read or segment lease, so it cannot
hold up the close's lease drain. Normal overlay close without a visitor does not
walk these rows.

An in-flight call may report usage after the close. The existing closed-scope
spend path records that usage on the original scope and its ancestors. It does
not reserve a replacement scope or charge the same completed spend twice.
A decode or settlement error is reported and does not undo or refuse the user's
close. Such an error is not reported as a successful settlement.

This is the live explicit-close spend slice of FIX 1835. It is not session-child
restart durability. The current session registry and overlay are in memory;
this change adds no persistent session store, restart-restorer or canonical
private-body fallback. Base-routed jobs remain visible to the existing canonical
recovery and cutoff sweep. Full FIX 1835 remains open.

No configuration, numeric cap, default, format, migration, guest protocol or
image change is needed. An ordinary engine/server update carries the change.
The behavior above is a source contract, not a runtime or memory-bound claim.
