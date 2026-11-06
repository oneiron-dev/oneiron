# MCP socket request body lifetime

The stdio bridge queues a prepared request with its original UTF-8 body, chosen
id, surface and signed binding. It does not keep a second encoded frame beside
a caller-held fallback body. Before enqueue, the same native primitive-only
MessagePack struct map serializes to an infallible byte counter; framing errors
still return before the request enters the queue. The recorded length includes
the RPC tag and is not a separate encoded body.

Only the driver prepares the Binary frame when it dequeues that request. For
an eligible own-link frame, the same native writer feeds a fresh zstd encoder
without a full uncompressed MessagePack buffer. Compression errors or a result
that does not shrink fall back to the ordinary full-frame encoder and codec.
The existing codec threshold, level, maximum inner size and strict shrink check
are unchanged. Segmented writes preserve the decoded frame, not a promised
byte-for-byte compressed representation.

Once the final wire bytes are complete, the driver releases the original body
before the socket masks or writes the frame. Only a successful socket write
posts the existing `Sent` marker. The waiting caller still releases its parsed
request fields on reading that marker. It is not a server execution or delivery
receipt and does not change any wire frame.

A true unsent outcome returns the exact original body to the existing HTTP
path, with its fresh holder proof. A failed queue send recovers it from the
unsent item; a queued-but-unwritten drain returns it on the existing answer
channel. A send error after dequeue remains a cut, not an unsent retry. Owner
calls still never fall back to HTTP.

The marker does not start or refresh the reply idle clock, change the absolute
deadline, or consume any reply-byte allowance. A caller timeout does not cancel
an already admitted queued call: its original body stays with the queued item
until the driver sends or drains it. The pending reply map holds no body.

The prepared send retains the original inner tag and length for link counters;
readiness, attempted-send accounting, start-send and flush keep their order.
`Sent` still follows a successful local flush, not server execution.

This removes the queued encoded duplicate and the raw full-frame staging on a
successful streaming compression, not the unbounded queue or physical socket
staging. Original queued bodies, the active writer's compressed or plain frame,
in-flight socket buffers, parsed request values, pending-call metadata, reply
chunks and decoded values remain. Existing input/reply limits, worker count,
credentials, invocation tracking and transport fallback stay unchanged.
