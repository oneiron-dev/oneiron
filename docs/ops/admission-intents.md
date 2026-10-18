# Durable admission receipts

A named typed facade call uses its existing `x-oneiron-invocation` value as its
admission `intent_key`. Use 32 hex digits and keep the key before waiting for the
call. The SDK transport already supplies an invocation id; an injected
`facadeTree` transport receives that id before sending the request. A direct
HTTP caller can author the header itself. This is not a new submit or execute
endpoint: send work to its original typed verb with the original credential.

The generated HTTP and SDK reads are:

- `POST /v1/core/facade/self.admission.status`, input
  `{ "intent_key": "<32hex>" }`, returns `AdmissionReceipt | null`.
- `POST /v1/core/facade/self.admission.receipts`, input
  `{ "intent_keys": ["<32hex>"] }`, returns `AdmissionReceipt[]` in requested
  order, deduplicated. The existing query limit admits 1 to 1,000 keys. Missing
  keys stay absent; reconcile the returned keys against the authored set.

Each receipt names its stable `receipt_ref`, `intent_key`, original `verb`,
canonical `request_digest`, `accepted_at`, `updated_at`, and typed `state`:

- `queued`: waiting in the existing fair admission line.
- `held`: executing, or waiting on the verb's own pending ask (`reason`).
- `completed`: the typed call answered, with its `result_digest`.
- `refused`: the original door's error `code` and `reason`.
- `interrupted`: the host could not observe settlement, with a `reason`.
  Effects might already have committed. Inspect them before creating a new
  intent. The receipt is not authority to replay the old intent.

These reads use the credential's bound actor and class, like call receipts.
They expose no other actor's intents and require the ordinary read scope.
A receipt reports the original typed call's result, not a second commit. Inspect
that verb's own memory/effect receipts to determine what actually landed.

The host keeps the receipt before executing the original generated dispatch.
The original door retains its scope checks, credential, context, gates and
hooks. Active and terminal intents cannot start another worker. A pending hook
ask may resume only through the existing hook continuation gate. Client
cancellation does not stop the worker or release the permit it still holds.
Host restart keeps unfinished active work as `interrupted`, without replay.
The side table is LIVE on checkpoint restore, like call receipts.

The existing `Admission::admit` and vault task-work line report queued/held
transitions through a shared observer; their scheduling, bounds, deadlines and
health questions are unchanged. A held HEALTH CHECK never holds its triggering
act. No threshold is changed by these observation verbs.

Coverage is named, actor-bound HTTP/SDK facade calls and facade calls over a
held socket. Session-bound calls are excluded to preserve the off-record
no-record boundary. Direct MCP tool execution is not wrapped by this ledger;
the generated MCP tools can read the same typed receipts. The reads themselves
are not admitted as new work in this ledger.

ARCH-0044 C5 specifies the admission semantics but no explicit admission verb
spelling. This door uses the `self.admission.status` and
`self.admission.receipts` family, with the existing invocation id as the intent
identity; it adds no generic work-submission verb.
