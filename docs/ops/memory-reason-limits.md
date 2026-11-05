# Memory reasoning request limits

`POST /v1/companion/memory/reason` accepts a positive `limit` (default 10)
and a positive `tokenBudget` (default 4,000). Both are whole numbers that fit
the HTTP `usize` fields. Zero is a bad request; omitting either field keeps
its request default.

The following `[limits]` settings are question boundaries, not ceilings:

| Setting | Default | Measured work |
| --- | ---: | --- |
| `memory_reason_evidence_rows` | 1,048,576 | The requested evidence count |
| `memory_reason_tokens` | 16,777,216 | The offered total token budget |

Each setting accepts a positive integer override. After the route validates
the request, session narrowing, deep-backend availability and actor read
credentials, it measures each effective value once through the vault's
owner-aware limit-question port. Crossing a boundary asks and still serves
the full value. The measure runs outside a held read transaction.

The former 1,000-row serve clamp and 65,536-token request ceiling are removed.
The response keeps its `limitClamped` field; a full-count read leaves it
false (and therefore omitted by the existing serializer). The separate
1,000-row candidate-fetch floor for narrowed reads is unchanged.

The total token budget is not reported spend. Retrieval and composition
still use the same budget lease, report actual backend usage, enforce the
remaining budget and settle spent tokens on success or failure. Model-free
depths still spend zero tokens. These settings do not change provider
context windows or promise that a large request fits one model call.

Actor projection, session narrowing, revision-pinned evidence, citation
admission, query-byte checks and the projection-body budget are unchanged.
The existing body budget can omit bodies; asking for more rows does not
bypass it.

## Remaining work

These settings and the HTTP ask-and-serve path do not complete FIX 60 or
FIX 61. Resident-memory and fair-work admission for a large evidence read
remain unbuilt on this route. Evidence collection and composition still
have their existing single-pass shape. Processing evidence and composing
answers in model-sized passes under actual provider frame limits also
remain unbuilt. No native, binding or MCP memory-reason terminal is added.
