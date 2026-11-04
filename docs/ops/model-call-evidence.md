# Decision model-call evidence

This page describes the current decision capture sites. It does not claim that
every model call in the engine is recorded.

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

## Recording and privacy

For a bound session, the existing NoRecord/off-record check runs both before the
provider call and at its terminal response. Either check suppresses the evidence
write. The same principal is used for the check and the row's actor. Room privacy
is resolved by that existing session check; no room id is invented.

The evidence-only initiator is added to a clone of the run after the provider
returns. It does not change the live run, admission, route, meter, payer, reply,
or typed decision. A failed evidence write is logged and never fails the answer.
An unbound call records as usual; a call outside every capture scope is not
assigned a guessed actor.

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

This is a narrow storage path, not reasoning delivery. No production caller
currently supplies parts to the model-stream finalize door. Birth and overlay
promotion still keep inline parts. Scan-off preserves the direct parts
writer's existing inline behavior; it does not implement the generic batch
door's known-only placement policy. Inline parts must not be assumed public
or secret-free. Chat wiring, scan-off whole-part marks, authorized part serving,
actual issuing-login replay and whole MESSAGE privacy remain separate work.
A custody handle is not a reveal grant or provider replay permission.
