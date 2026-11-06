# MCP diagnostic envelope ownership

The bridge builds its JSON-RPC error envelope and diagnostic metadata before
inserting an owned server diagnostic into the final `error.data` object. The
insertion moves the diagnostic `Value`; it does not pass that value through
`json!` and materialize a second diagnostic tree.

The response ID, error code, message, diagnostic keys, and server diagnostic
content are unchanged. A missing server diagnostic still omits `server_error`.
The final JSON serialization still allocates its output string. This change
does not make a streaming, queue-size, or runtime memory-bound guarantee.

An initialize refusal with an `error` field moves that terminal answer's original
field value into the final JSON-RPC envelope. A present null field stays present;
a missing field or non-object answer still uses the existing full-answer fallback.
The probe cache retains its own stored refusal and its existing clones.

Wake handoff decoding borrows the parsed JSON `result` while constructing the
same owned delivery type. The original complete answer stays available for the
existing malformed-handoff error. Delivery strings and vectors still allocate;
only the intermediate cloned JSON result tree is removed.
