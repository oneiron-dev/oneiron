# Budget-hit hook scope context

`host.budget.hit` runs one hook chain for one actual budget hit. The host
keeps the actual model call's world, facet and project axes when its request
carries them. It does not choose one axis or run the chain once per axis.

The hook input's `scope` is:

- `null` when the producer knows no hook axis;
- the existing `"axis:32-lowercase-hex"` string for one known axis;
- an array of those names when several independent axes are set.

The array uses world, facet, project order for stable serialization. That
order is not a priority. A scoped selector matches any actual member through
the same native per-member predicate. Each binding is still selected and
charged once. Room-only call inputs keep their original string form and room
ceiling, facet and project checks. Invalid names match nothing. Storage errors
from a visited predicate still propagate.

Scope context is not authority. Hook reads still use the caller's read key
and the hook's grant. Matching a world, facet or project does not grant access
to its rows. Relationship and readable/writable resource bounds are not hook
scope axes and are not converted to scope names.

The durable model-step, review-explainer and voice-generation budget-refusal
callers use their actual request envelope. Producers without that context keep
`None`, including pass-global wake hits, owner budget-hit calls, guard-only
receipts, the default-scope voice extractor, recall reranking, safeguard
classification and deep-retrieval admission. No room is inferred from a run
label, subject, payer or caller-supplied reference text. Other host/session,
compaction and wake scope gaps remain outside this slice.

The receipt's scalar `scope` metadata keeps a single name as raw text and
stores multiple names as a JSON-array string. This metadata is not a token,
read grant or parseable authority proof. Held pre-state snapshots and pending
asks retain the same native context value.

This change requires matching engine/server binaries when rollout is
authorized. It adds no setting, numerical limit, SDK verb, guest protocol,
image change or migration. The open owner-review call is
`L11-D28-FIX2009` in the engine calls ledger.
