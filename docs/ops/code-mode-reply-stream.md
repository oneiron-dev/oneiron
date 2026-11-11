# Code-mode provider reply transport

Each code-mode step keeps its generated-call admission and settlement. On a
rung that advertises streaming and passes the stream preflight, the native
step request consumes that rung's `LlmBackend` stream instead of its buffered
provider response. The request digest is admitted for the selected transport
before it leaves. Only the terminal `Done` becomes the generated reply.

Native seat `reasoning_effort` and the host's cache descriptor namespace may
accompany the stream. Other custom parameters or provider options retain buffered
generation. In particular, `Done` has no token-score field, so requests for token
scores keep their existing buffered response shape. A rung without streaming, or whose stream preflight
cannot take the request, also keeps buffered generation. Neither case skips a
working rung or introduces another refusal.

The existing generated-call walk still owns each permit, source admission,
physical work context, live spend look, deadline, provider retry and owner
fallback. A picked model still has no fallback. The answering rung supplies the
same binding for model-call evidence, planned-child receipts and browser handoff.
Transient events do not escape this private consumer; failed calls keep the
generated-call retry behavior.

This is the provider supplier slice of FIX 448, not the full streamed-evidence
implementation. The adapter still assembles the terminal `LlmMessage`. The
executor still stores its existing terminal JSON with its existing PERSON and
custody substitutions, output owner and source provenance. This change does not
capture raw transport bytes or publish transient event bodies. Those remaining
parts of FIX 448 stay open.

No new configuration, operating limit, protocol or rollout step is required.
