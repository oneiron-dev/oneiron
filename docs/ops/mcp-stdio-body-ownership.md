# MCP stdio body ownership

The stdio bridge keeps its existing bounded line reader, oversize drain,
UTF-8 and JSON errors, notification behavior, deadlines and worker limit.
The owned input string moves into the worker's request handler. A passthrough
request uses `String::into_bytes` to keep the client's exact original bytes
without making another raw-body vector. Rewritten requests still serialize
the same invocation/session changes as before.

A successful validated JSON-RPC response stays a `serde_json::Value` until it
is serialized directly to stdout. Serialization, the newline and flush hold
the existing stdout mutex, so another response cannot interleave. Refusal
strings keep their existing output path and wording. Client-output failures
are still ignored as a closed client; there is no new timeout or refusal.
The parsed reply remains alive until output finishes; this is not a bound
on retained memory while the client is slow.

The 2 MiB input and 16 MiB reply limits remain unchanged. Input lines and
parsed values still allocate. This is not a total heap, output-time or
performance bound, and it does not complete the input STREAM or queued
outbound lifecycle work. No private or off-record body is spooled to disk.
