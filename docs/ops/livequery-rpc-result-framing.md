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

This removes the server RPC path's contiguous packed-result buffer. It does not
make the complete path streaming: the parsed JSON value stays alive through the
second serialization, all encoded frames are still queued together, and the
client still assembles the result before decoding it. There are two serialization
passes. No runtime latency, total retained-memory bound, or end-to-end streaming
claim follows from this change. No result limits, wire formats or configuration
settings change, and no result is spooled to disk.
