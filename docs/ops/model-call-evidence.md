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
