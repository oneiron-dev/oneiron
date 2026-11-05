# Decision and chat model-call evidence

This page describes the current decision and chat capture sites. It does not
claim that every model call in the engine is recorded.

## Captured decision calls

A completed generative Big-rung call keeps best-effort model-call evidence before
the typed answer is parsed. A provider response that becomes a typed abstention
still has a record. A located Big call abstains before any provider call and does
not create one.

The capture uses the actual caller at each entry:

- Live `ai.verdict`, `vault.graph.ask`, `vault.artifacts.ask` and
  `vault.artifacts.review_slides` carry the session from their authenticated
  request. Artifact calls use the principal on the engine's unit call.
- Standing graph and artifact work, including a manual refresh, runs as the
  stored question's principal, not the person requesting the refresh. It does
  not borrow that person's session.
- Run-host calls have no bound session at this seam. A run id or attempt label
  is not substituted for one. Existing payer and spend handling stay unchanged.
- A generative hook verdict uses its grant's reader as principal and has no
  bound request session.

The caller context is one thread-local scope on the blocking decision thread.
It restores the entire previous context on return or panic. It is not authority,
a payer, or an async context propagated to another thread.

## Captured chat calls

Whole and streamed chat replies, including queued Continue and Retry, keep
best-effort evidence from the independent answer producer's actual terminal.
The answering leg forwards its admitted request, sourced run and actual ladder
binding before yielding `Done`. A captured-prefix attempt that fails before it
speaks leaves no terminal record; today's fallback carries its own context.
Quota fallbacks retain the binding of the rung that actually answered.

The row's actor is the authenticated request's actual principal or native host
actor, or the queued action's verified requester. It is not inferred from the
answering agent or the payer. The existing turn credential continues to own
liveness. Caller attribution is added to an evidence-only run clone after the
provider terminal. The live run keeps its original initiator, resident-share
admission and charging; the evidence clone grants no authority.

The native evidence NoRecord check uses that same caller and the request's
authenticated session, before generation and again at the terminal. The actual
resolved room and the answer's container are checked before generation and
at the terminal too. Either retention exception suppresses the optional base
write. Unknown session bindings keep the native helper's existing behavior;
no raw session key or response-bus id becomes proof. Capture never adds an
execution refusal or changes settlement, cancellation or delivery.

Full terminal parts reach the existing writer, including signed reasoning and
its whole-part custody handling below. These are inline call-record parts,
not references to MESSAGE parts that the text-only chat sink did not retain.
Missing issuing-login and provider fields remain unknown. This does not enable
HTTP off-record assistant storage, reasoning replay or new MESSAGE persistence.

## Decision recording and privacy

For a bound session, the existing NoRecord/off-record check runs both before the
provider call and at its terminal response. Either check suppresses the evidence
write. The same principal is used for the check and the row's actor. Room privacy
is resolved by that existing session check; no room id is invented.

The evidence-only initiator is added to a clone of the run after the provider
returns. It does not change the live run, admission, route, meter, payer, reply,
or typed decision. A failed evidence write is logged and never fails the answer.
An unbound call records as usual; a call outside every capture scope is not
assigned a guessed actor.

## Signed parts containing secrets

For an inline capture, the writer keeps the original typed provider part before
selecting the call record's display representation. If that signed or opaque
part contains a secret found by the existing write policy, the writer seals the
whole original part in existing secret custody. It never masks its text or
edits its signature or data. The encoding is canonical MessagePack of the
captured `ContentPart`, not a claim to preserve the provider's HTTP wire bytes.

The call record contains only the custody handle for that part. The handle is
not permission to read it. The existing reveal and grant doors still authorize
the current consumer. The custody origin names this exact call record and
reasoning position, so the existing actor erase revokes it before erasing the
record. A failed evidence write rolls back both the new custody and its
reference; it does not fail the model answer.

This enables no upstream reasoning replay. A viewer's reveal grant and a
provider configuration name do not prove the actual issuing login. MESSAGE
parts, other plaintext copies such as step memos, live response serving and the
issuing-login producer remain separate work.

## Limits of this coverage

This is not MESSAGE/chat reasoning delivery, replay admission, or complete
issuing-login and read-world capture. It adds no retrieval, Dreamer-mining,
training, or export reader. Native label reads use their separate settled-read
capture path. Whole-engine model-call coverage remains work in progress.

## Ordered MESSAGE Continue parts

The existing Base Continue writer can keep a signed reasoning part whole in
secret custody when mask-on-write is on and the current known-value or shape
scan finds a secret. The stored part then contains only a custody handle.
The canonical typed part, including its kind, text, data and signature, is
sealed unchanged. This is not a claim about original provider HTTP bytes.

Only new suffix parts are converted. The stored prefix keeps its existing
representation and order. The normal stream generation, actor, topology,
document grant, full-envelope ceiling and terminal receipt stay in one write
transaction with custody registration. A completed generation returns its
existing receipt before any suffix is sealed again. MESSAGE erasure revokes
custody under its actual origin and owner act; a restorable delete does not.

Base MESSAGE birth and DAG MESSAGE append use the same whole-part policy.
Base birth runs its original guards before sealing, then authorizes and stages
one local plan with the converted parts. The original author, topology,
assertion, quote, thread, full-envelope ceiling and final route checks remain.
An exact birth retry never mints again: it reuses a stored reference only after
matching the actual MESSAGE, part position, custody origin and handle, and the
original whole value's existing keyed fingerprint at that unit's birth
generation. It then passes the original full-body and topology comparison.
This identity proof opens no value and gives no reveal or replay permission.
The on-record room copy keeps the exact admitted stored bodies, not the
unsealed draft bodies, so its body digests describe what was committed.

Off-record staging keeps inline parts and never mints durable custody. An
explicit promote or later room copy applies the same whole-part policy to
fresh MESSAGE rows in the promotion's existing base transaction. An id base
already holds keeps the offered bytes for the ordinary replay's equality
check, and a durable retry receipt returns before sealing. Custody, replay
and the save receipt therefore commit or roll back together. A room's kept
message digests come from the actual stored MESSAGE bodies in that writer
and are published only after commit, not from the unsealed journal copies.

This is a storage path, not reasoning delivery. No production caller currently
supplies parts to the model-stream finalize door. Scan-off preserves the
MESSAGE writer's existing inline behavior; it does not implement the generic
batch door's known-only placement policy. Inline parts must not be assumed
public or secret-free. Chat wiring, scan-off whole-part marks, actual
issuing-login replay and whole MESSAGE privacy remain separate work. A custody
handle is not a reveal grant or provider replay permission.

Generic MESSAGE reads use the caller's ordinary scoped read and its existing
secret redaction. If that projection changes an inline Reasoning part, the
read withholds that whole part as JSON `null` at its original array position,
rather than returning edited text, data or a signature. It does not restore a
parts field already withheld by the existing projection, or change other
parts or the ordinary message text. Stored bytes stay unchanged.

A stored custody part remains an opaque handle in that view. Its whole value
leaves only through the existing secret reveal and wait doors, under their
current grant and T1 lease, or through the owner's authenticated reveal door.
Those doors return the canonical typed part bytes sealed by the writer. This
is not automatic upstream replay or proof of an issuing login.
