# MCP socket request body lifetime

The stdio bridge queues a prepared request with its original UTF-8 body, chosen
id, surface and signed binding. It does not keep a second encoded frame beside
a caller-held fallback body. Before enqueue, the same native primitive-only
MessagePack struct map serializes to an I/O sink; framing errors still return
before the request enters the queue.

Only the driver encodes the full Binary frame when it dequeues that request.
The original body remains alive through the actual socket write. After that
write succeeds, the driver releases the original body and posts the existing
`Sent` marker. The waiting caller still releases its parsed request fields on
reading that marker. It is not a server execution or delivery receipt and does
not change any wire frame.

A true unsent outcome returns the exact original body to the existing HTTP
path, with its fresh holder proof. A failed queue send recovers it from the
unsent item; a queued-but-unwritten drain returns it on the existing answer
channel. A send error after dequeue remains a cut, not an unsent retry. Owner
calls still never fall back to HTTP.

The marker does not start or refresh the reply idle clock, change the absolute
deadline, or consume any reply-byte allowance. A caller timeout does not cancel
an already admitted queued call: its original body stays with the queued item
until the driver sends or drains it. The pending reply map holds no body.

This removes the queued encoded duplicate, not the unbounded queue or the
full-frame write allocation. Original queued bodies, the active writer's frame,
in-flight socket buffers, parsed request values, pending-call metadata, reply
chunks and decoded values remain. Existing input/reply limits, worker count,
credentials, invocation tracking and transport fallback stay unchanged.
