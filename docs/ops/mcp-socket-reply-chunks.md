# MCP socket reply chunks

The stdio bridge keeps the socket answer payloads as the owned byte chunks it
receives. It does not concatenate those chunks into a second complete
MessagePack buffer. After the final chunk arrives, a private reader presents the
chunks in order to the existing `SocketAnswer` decoder. Exhausted chunks drop
before the reader advances to the next one.

Collection still ends before decoding starts. The existing absolute deadline,
idle timeout, channel-close and revocation errors keep their order. The same
aggregate limit includes the existing answer-envelope allowance, and the decoded
body still has its original reply-body limit. The JSON-RPC validation and stdout
paths are unchanged. No task, channel, queue bound, cancellation rule, refusal or
configuration value is added. The existing crossing-chunk forwarding stays in
place.

This removes the assembled MessagePack concatenation and its copies. It is not
end-to-end streaming: all raw chunks remain until the final chunk, the decoder
can allocate field scratch, and the decoded body is still an owned `String`
converted to bytes. Queued chunks, parsed JSON values and stdout waiting remain
separate retained storage. This change makes no total-heap, latency or runtime
bound claim. The stdin frame limit, whole HTTP-response assembler and outbound
queue lifecycle remain separate work.
