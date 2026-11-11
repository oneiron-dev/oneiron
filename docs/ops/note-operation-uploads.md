# NOTE operation uploads

NOTE editor commands keep one durable `QN_E` envelope per request. It holds the
input digest and the complete command frame after the ordinary text admission.
Retries replay that exact admitted command. They do not re-admit its text or
replace its input digest.

A command that fits a node batch keeps the ordinary batch path. A command past
the batch's framing room is sent directly on the same socket. When it also
exceeds the existing document wire bound, the sender releases ordered PART13
frames. Each part fits that unchanged wire bound. It is never nested inside a
node batch that would add its own framing overhead.

The sender retains the whole logical command while it sends its parts. Each part
rechecks the original whole command's release policy and active subscription,
and gives way to the existing connection stop. If release changes after a
prefix was sent, the socket closes and drops the receiver's incomplete assembly.
The durable request remains owed for the normal reconnect and replay path.

The server keeps assembly on that socket only. It checks the current bound
credential and admitted NOTE subscription before retaining each part. Continuity and the whole payload digest must match
before the original complete NOTE operation decoder and admission run. A digest
is integrity evidence, not a grant. The original current credential, selector or
owner authority, destination, idempotency and state-before-receipt behavior stay
at their ordinary complete-command doors. No prefix imports or settles anything.

The receipt is checked against the complete admitted command, not a part digest.
Only the existing receipt acceptance retires the durable request. Disconnecting
mid-upload does not replace that receipt with an acknowledgment.

Both endpoints must use the same source for PART13. There is no old-format
reader, migration, new logical-size cap or new authority field. Existing wire
bounds and explicit server frame settings remain unchanged. Assembly and command
decoding still hold a whole logical payload; this is not bounded-total-memory or
full-duplex progress proof. The pre-existing read/write backpressure follow-up is
tracked separately in FIX20959.
