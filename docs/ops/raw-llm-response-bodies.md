# Raw-LLM HTTP response bodies

The SDK's `RemoteLlmClient` uses its existing authenticated async HTTP client
for `/v1/llm/generate` and `/v1/llm/stream`. Holder proofs, budget-lease headers,
request serialization, client timeouts and cancellation custody are unchanged.

## JSON replies

Generate replies and non-success replies from either endpoint feed existing
HTTP chunks through a one-slot internal channel into a blocking JSON decoder.
There is no concatenated raw-body buffer and no temporary-file staging. The
reader consumes each chunk in place; it does not add a direct `bytes`
dependency or copy the chunks into another byte vector.

The async producer remains the sole aggregate-byte limit check: 32 MiB for
successful generate replies and 64 KiB for non-success replies. It continues
reading after a JSON error, so a later network failure or size violation still
precedes the JSON result. Network timeouts remain `Timeout`; other network
read failures remain `StreamCut`; oversize replies remain `InvalidRequest`.
Malformed non-success JSON still falls back to status classification with a
null value. Typed server failures and all status classifications are unchanged.

JSON decoding, including typed allocations, starts before the complete body
size is known. The decoder requires EOF and rejects trailing non-whitespace.
Dropping the producer closes the channel, so a decoder waiting for another
chunk can finish. The runtime still owns the blocking task until it exits.
A failed decoder task is reported as `StreamCut`. This is not a total heap,
allocator, cancellation-latency or performance bound. Network chunks and the
parsed result still own memory; the size limits have not been lifted.

## Successful NDJSON replies

Successful streaming replies use the same decoder with a separate channel
lifetime for each newline-terminated frame. The producer passes slices of the
existing HTTP chunk; it does not concatenate a raw line. The same 32 MiB
per-frame byte limit, ASCII-whitespace-line handling, typed error/event order,
one-event backpressure and `Done` handling remain in place. A malformed frame
is reported only after its newline; network and size failures before that
newline still take precedence. EOF without a final newline remains `StreamCut`.

Frame decoding and typed allocations can begin before the full frame size is
known. Parsed values and their conversion to typed events still allocate.
Limits have not been lifted, and full STREAM completion for FIX 154 or FIX 155
is not claimed. Neither path spools private or off-record data to disk.
