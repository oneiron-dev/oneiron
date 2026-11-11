# MCP diagnostic envelope ownership

The bridge builds its JSON-RPC error envelope and diagnostic metadata before
inserting an owned server diagnostic into the final `error.data` object. The
insertion moves the diagnostic `Value`; it does not pass that value through
`json!` and materialize a second diagnostic tree.

The response ID, error code, message, diagnostic keys, and server diagnostic
content are unchanged. A missing server diagnostic still omits `server_error`.
The final JSON serialization still allocates its output string. This change
does not make a streaming, queue-size, or runtime memory-bound guarantee.
