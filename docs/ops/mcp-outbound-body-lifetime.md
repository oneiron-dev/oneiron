# MCP socket request body lifetime

The stdio bridge keeps a request's original body only while it can still be
needed for the existing HTTP fallback. The encoded socket frame is a separate
owned value in the driver's existing outbound queue.

When the driver's existing socket send returns success, it posts an internal
`Sent` marker on that request's existing answer channel. On reading that marker,
the waiting caller releases the original body vector's backing. The marker is
not a server execution or delivery receipt and does not change any wire frame.

A true unsent outcome returns the exact original body to the existing HTTP
path, with its fresh holder proof. A send error after dequeue remains a cut,
not an unsent retry. Owner calls still never fall back to HTTP.

The marker does not start or refresh the reply idle clock, change the absolute
deadline, or consume any reply-byte allowance. A caller timeout still drops its
original body immediately; the driver still sends already admitted queued calls.
No original-body owner is added to the outbound queue or pending map.

This is a backing-lifetime change, not a queue bound or end-to-end streaming.
The encoded queue, in-flight socket buffers, parsed request values, pending-call
metadata, reply chunks and decoded values remain. Existing input/reply limits,
worker count, credentials, invocation tracking and transport fallback stay unchanged.
