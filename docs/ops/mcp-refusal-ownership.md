# MCP terminal refusal ownership

The request-answer and wake-reporting paths own the terminal refusal they pass
to the JSON-RPC error conversion. The conversion consumes that refusal and moves
its authentication body, server body, or initialize answer without an `error`
field into the existing error builder. It does not clone those diagnostic values
at this step.

The probe cache still retains its own refusal and clones it for each returned
failure. An initialize answer that has an `error` field still uses the original
field-only response conversion, including arbitrary fields in that error value.
Authentication advice, error codes, raw bodies, response IDs and all transport
behavior stay unchanged. The existing JSON error builder and serialization
still allocate; this is not a zero-copy or runtime memory-bound claim.
