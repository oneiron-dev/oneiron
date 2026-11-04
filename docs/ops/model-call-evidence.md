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
- A generative eval arm uses the registered judge's principal with no bound
  request session. It records only an actual successful terminal response and
  its answering binding. The job's shared run, exact-model call and wait
  deadline stay unchanged.

The Big-rung caller context is one thread-local scope on the blocking decision
thread. It restores the entire previous context on return or panic. It is not
authority, a payer, or an async context propagated to another thread. Generative
eval arms pass their recording principal directly.

## Native house reads

A house escalation read with a caller-supplied run uses the same caller context
on the blocking decision thread. Only a bound context can write evidence; a
missing context skips evidence, not the read. The run-less house gate, System
One, Local-vision, embedder and tagger paths are not covered by this hook.

The engine lends the exact admitted native request and its terminal result to
an optional observer after the gate has attempted settlement. The observer
never reads or settles again. It records a completed read only after the
existing distribution validation succeeds. A malformed reply keeps its actual
usage; a raw reader error keeps only its typed failure class and unknown usage.
Readout probabilities and raw reader errors are not copied to the record. An
unmapped failure skips evidence without changing the original error.

The owner probe and this hook share one native record initializer and request
canonicalizer. They record the actual reader model, opaque revision and
connector locality. The probe retains its existing per-attempt retry indices;
house reads use the caller run's shared evidence sequence. No generative request,
finish reason, route, issuer or read-world identity is invented.

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

Each raw/Big/generative-eval/observed-house evidence row takes a distinct record
stamp from its shared run. This is an evidence-key sequence, not an admission or receipt
number. Cloned handles share it and declaration revisions do not reset it.
A failed or suppressed write does not require a dense sequence.

## Limits of this coverage

This is not MESSAGE/chat reasoning delivery, replay admission, or complete
issuing-login and read-world capture. It adds no retrieval, Dreamer-mining,
training, or export reader. Native label reads use their separate settled-read
capture path. Whole-engine model-call coverage remains work in progress.

## Provider signature retention

The Anthropic whole-response decoder retains a thinking block's actual signature
when its visible text is empty or absent. The Gemini whole and stream decoder
retains a standalone `thoughtSignature` as its own signature-only reasoning part
at that position. It does not assign that signature to an earlier part or
replace an earlier signature. Neither change requests thinking or rewrites the
provider's bytes.

Signature-only streamed terminals also need the shared terminal-acceptance fix;
retaining a provider field alone does not prove every path accepts the terminal.
MESSAGE custody, replay permission and issuing-login identity remain separate.
