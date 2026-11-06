# MCP bridge HTTP reply chunks

`oneiron mcp --transport http` and the socket carrier's existing unsent
fallback keep the owned HTTP chunks returned by reqwest. Their combined byte
length is checked against the same reply limit after each chunk. The existing
content-length precheck, response status, idle timeout, deadline, and broken-body
diagnostics are unchanged. There is no JSON parsing during collection.

After HTTP EOF, `Reply::answer_to` parses the completed body through a buffered
reader over those chunks. A valid JSON body does not need a concatenated byte
vector. JSON-RPC response matching and all HTTP status classifications still run
after decoding. Probes, wake delivery, notifications, pending-call memory, and
client-session tracking keep their existing paths.

If JSON decoding fails, the original chunks are joined before the existing
whole-body UTF-8-lossy diagnostic conversion. This preserves diagnostics when a
multibyte character crosses chunk boundaries. A socket reply still uses its
existing owned byte vector and `serde_json::from_slice` at this stage.

This removes the HTTP concatenation for valid JSON, not all reply allocations.
All HTTP chunks remain held through collection and parsing; their backing
allocations may exceed their visible lengths. The chunk list, reader buffer,
JSON decoder's field scratch, and owned JSON value also remain. Invalid JSON
still uses a concatenated diagnostic buffer. The bridge's input/reply limits,
worker count, socket queues, and outbound lifecycle are not changed here.
