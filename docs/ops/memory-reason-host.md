# Production memory reasoning

`POST /v1/companion/memory/reason` uses the configured `generative_reasoner`
and `reranker` roles for paid retrieval efforts. Light and medium remain
model-free. An explicitly injected deep-retrieval host still takes precedence.
With no injection, the server creates a host for this request, not a shared
host identity or a host-wide budget.

The request retains its original authenticated caller, off-record session,
locality and session narrowing. Native role admission chooses models and routes.
The role's configured rung prompt supplies its instruction; the host sends
machine-readable `decompose` and `compose` operations with a typed JSON response
schema. No model id, endpoint, persona or prose instruction is built into the
host. Reranking uses the native indexed-scores transport and its batch line.

Each model destination must admit the exact pinned source cohort before it is
sent. The same sources are read again after any wait and before dispatch. A
missing or changed pin is never replaced with the live row or a text lookup.
The response includes the host's destination-bound read receipts alongside the
retrieval and evidence-projection receipts. The existing answer boundary still
checks every returned citation.

The explicit request token budget remains the whole read's budget. Its capacity
lease and native per-rung policy meter have separate state, so native permits
are not charged twice. `tokensUsed` is derived from reported usage, never from
reservations, billing-unit conversion or the paid meter's balance. When physical
reports overlap, the host does not add them twice. When coverage is incomplete,
`tokensUsageComplete` is false and `tokensUsed` is a lower bound from the reports.
A usable answer is not discarded just because usage is incomplete.

Run receipts and budget-hit notifications are held until the request ends.
They reach neither the durable sink nor a surrounding settlement capture when
the session was anonymous at arrival or is anonymous at completion. Calls that
start anonymously use the existing traceless native rung and worker path.

This host sends all admitted evidence; it does not impose another row cap or
silently truncate a model request. Provider-frame tiling and multi-pass
composition are not implemented by this change. The configured evidence and
token rows therefore remain partial for model-sized passes and fair resource
accounting. This change does not attach a production host to the raw search or
deadline-search doors, and makes no runtime or speed claim.
