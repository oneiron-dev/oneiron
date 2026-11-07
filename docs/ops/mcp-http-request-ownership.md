# MCP HTTP request ownership

The stdio MCP bridge's HTTP sender passes the request body to the existing
`encode_http_body` selector. That selector returns an owned zstd buffer only
when the existing size threshold is met and compression produces fewer bytes.

When the selector returns a compressed buffer, the sender releases the original
uncompressed `Vec<u8>` before moving the same compressed bytes into the HTTP
request. When it returns `None`, the original body still moves directly into
the request without a copy. Compression failure keeps that same plain path.

The content-encoding header, request signatures, endpoint, socket-to-HTTP
fallback, send, reply collection, idle limit and absolute deadline are unchanged.
Owner-mode calls still never use HTTP. No new task, channel or callback is added.

Both buffers still coexist while compression runs. The parsed request remains
alive during the post, and transport or reply buffers can still be retained.
This is a narrow lifetime change, not a total heap, streaming or runtime bound.
