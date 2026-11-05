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
are not charged twice. Each native call's reservation is sized to the remaining
request allowance and nonzero line headroom, not the original full reservation.
An exhausted paid line still fails its native admission; it is not given a zero
reservation to bypass the line. `tokensUsed` is derived from reported usage, never from
reservations, billing-unit conversion or the paid meter's balance. The answer's
aggregate is reconciled with its matched physical token reports before overlaps
are removed, so absent aggregate counters cannot erase known token use.
Additional physical observations are added once. When coverage is incomplete,
`tokensUsageComplete` is false and `tokensUsed` is a lower bound from the reports.
A usable answer is not discarded just because usage is incomplete.

Run receipts and budget-hit notifications are held until the request ends.
They reach neither the durable sink nor a surrounding settlement capture when
the session was anonymous at arrival or is anonymous at completion. Calls that
start anonymously use the existing traceless native rung and worker path.

This host sends all admitted evidence; it does not impose another row cap or
silently truncate a model request. When every sampled primary and fallback model
has current context, output-reserve and measured token-ratio metadata, composition
can partition whole evidence rows into estimated-size map passes. It reduces only
pairs of valid drafts that fit that estimate. Each reduction consumes two drafts
and produces at most one, so free or unmeasured usage cannot leave a reduction
loop running without progress.

A draft's declared `sourceShortIds` must belong to that pass's actual inputs.
Prose record links remain display-only under the existing final answer boundary;
this check does not claim complete semantic grounding or refuse display links. An invalid, blank,
declined or malformed intermediate is never forwarded as model input. Producer
cohorts are tracked separately: each destination checks every original pin that
could have influenced a draft, including inputs not cited by that draft. Whole
source text and pinned-body validation are unchanged. Map and reduction calls
use the same request budget and retain earlier usage on any later error.

Frame sizing is an estimate, not a provider bound. The host counts serialized
operation data, response schema and configured rung prompts with the existing
o200k tokenizer and measured per-model ratio. Missing, stale or unmeasured
metadata, or a manifest route outside the inventoried seat, preserves the existing whole-send path and reports that gap. An atomic
row that exceeds the estimate is still sent whole and reported; it is never
clipped. If remaining drafts cannot be combined, the existing declined path
renders all original evidence extractively and says why. Configured rung prompts
must support `compose` operations carrying either `evidence` rows or `drafts`
with the same answer/citation schema.

Provider framing, route changes after sampling, reranker wire windows and fair
resource accounting remain unproved. These rows therefore remain partial. This
change does not attach a production host to raw search or deadline search, and
makes no runtime or speed claim.

## Retained evidence storage

The route keeps the collected citable evidence in a private owner through
extractive rendering, deep composition and the answer boundary. Its process
memory lease records the actual evidence-vector backing capacity and the
`short_id`, `kind` and `text` string capacities once. The rows and their strings
drop before this charge is released, including on projection, pin or composition
errors. Neither the public evidence value nor the response DTO carries a lease.

This is accounting after allocation, not before-growth admission. It uses an
empty native lease and names the retained capacities allocated without joining
the memory wait queue, reserving more room or adding a refusal. It does not
estimate capacity from text length, projected-body length or the requested count.
The source/projection buffers, omitted markers, derived answer and sources,
composition frames and pins, provider scratch and allocator overhead are not
covered by this owner. Full working-set admission and Q remain open; no runtime,
peak-memory or no-hang result is claimed.
