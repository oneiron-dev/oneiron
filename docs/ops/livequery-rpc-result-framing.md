# Live-query RPC result framing

RPC success replies keep the existing 32 MiB packed-result limit and 64 KiB
fragment boundaries. Each `rpc.res` fragment carries the original request id,
sequence, terminal flag and call receipt. Delivery still passes through the
existing per-chunk release door.

The server first serializes the owned JSON result into a byte counter and an
incremental BLAKE3 hasher. This pass retains no packed result bytes. A result over
the existing limit becomes the same refusal before the call receipt is recorded.
The unmasked receipt digest is the lowercase, unprefixed BLAKE3 of the same
MessagePack bytes; masked reveal replies keep their existing JSON digest.

After recording the receipt, the server serializes that same immutable JSON
value again with the same MessagePack settings. A writer retains at most one raw
fragment and writes each completed fragment through the existing stamped-frame
encoder. It keeps a full fragment until another byte arrives, or serialization
ends, so an exact multiple of 64 KiB has the same terminal fragment and no extra
empty one. The old generic packing and subscription framing paths are unchanged.

This removes the server RPC path's contiguous packed-result buffer. Batch
callers use two serialization passes and still retain all encoded frames before
returning them. The ordinary asynchronous facade RPC sender uses the three
passes described below instead. The parsed JSON value stays alive through its
last serialization, and the client still collects the whole result before
decoding it. No runtime latency, total retained-memory bound, or end-to-end
streaming claim follows from this change. No result limits, wire formats or
configuration settings change, and no result is spooled to disk.

## Client result chunks

The opened-item RPC client moves each received binary or string payload's bytes
into a chunk list instead of copying them into one assembled buffer. It checks
the same cumulative 32 MiB limit and the same request id, sequence, reply kind and
collection deadline. A home refusal remains separate from a failed call.

Decoding still starts only after the terminal reply, so parser work does not add
backpressure inside the existing collection deadline. A consuming reader supplies
the chunks in order and releases each exhausted raw chunk as decoding advances.
The MessagePack reader, like the prior slice decoder, decodes one value without
requiring trailing EOF. No task, channel or clock policy is added.

All raw chunks remain retained until the terminal reply. The decoder can also
allocate a field-sized scratch buffer and the parsed JSON value. Removing the
assembled concatenation is not a total memory or peak-allocation guarantee, and
it does not complete end-to-end streaming.

## Routing queued frames

The ordinary asynchronous facade RPC path keeps the prepared JSON value, its
receipt stamp and its rows rather than an encoded result batch. After the
count-and-hash pass and receipt creation, it validates every stamped frame while
dropping each completed frame. A framing failure produces the original single
bare refusal before any success frame is enqueued.

On validation success, the sender serializes the same immutable value again with
the same stamp. It routes and enqueues each completed frame on the existing reply
channel. These are three serialization passes in total: count/hash, validate/drop,
and send. Both framed passes use the same encoder and fragment boundaries. The
answer's encode holds remain alive through all three passes and enqueue.

Delivery errors remain separate from encoding errors. If the existing reply
channel closes, the sender returns the same channel-closed protocol error; it
does not turn that error into a byte-limit refusal or send a refusal after a
queued success prefix. The per-request frame order, routing rows and downstream
release checks are unchanged. Batch and own-machine callers retain their eager
frame APIs.

The sender retains one raw fragment plus transient encoding and routing buffers,
not a complete encoded result batch. During routing, the encoded frame and its
routed copy can coexist. The existing reply channel is still unbounded, so
enqueued frames can accumulate. The owned value, routing rows, answer-owned holds
and client collection also remain. This is not a queue bound, a total-memory
bound, or completed end-to-end streaming.
