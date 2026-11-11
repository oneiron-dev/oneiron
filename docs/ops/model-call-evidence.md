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
- A generative eval arm uses the registered judge's principal with no bound
  request session. It records only an actual successful terminal response and
  its answering binding. The job's shared run, exact-model call and wait
  deadline stay unchanged.

The Big-rung caller context is one thread-local scope on the blocking decision
thread. It restores the entire previous context on return or panic. It is not
authority, a payer, or an async context propagated to another thread. Generative
eval arms, the Coach distill and code-fix drafts pass their recording principal directly.
Router and Decision eval reads scope the same registered judge principal around
their existing run-aware ladder call, without changing the question or scoring.

## Native house reads

A house escalation read uses the same caller context on the blocking decision
thread. Only a bound context can write evidence; a missing context skips
evidence, not the read. A read with a caller-supplied run records that run. A
read without one carries the house gate's actual funded run to the observer
only after its existing settlement attempt. The run stays in that decision
frame and never enters the typed answer. System One, Local-vision, embedder
and tagger paths are not covered by this hook.

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
house reads use their actual run's shared evidence sequence. Each native row
explicitly records its run source: `probe`, `caller`, or `house_gate`. These
are required current-format tags, not inferred identities or replay permission;
erasure keeps the nonpersonal source tag. No generative request, finish reason,
route, issuer or read-world identity is invented.

## Native System One calls

A System One call with an actual caller-supplied run records a `seat_decision`
row after its original settlement attempt. A settlement error still propagates
as before; recording the provider outcome does not claim settlement succeeded.
The no-run branch is unchanged and is not captured.

The adapter builds, sends and parses once through the same implementation used
by its ordinary call. Its separate recorded result carries a canonical JSON-tree
fingerprint of the actual built request body, not a hash of wire bytes or of the
logical pre-transform request. No body, image pixels, headers or credentials are
stored. Other remote seats default to returning no fingerprint, not an invented
one. A missing fingerprint or unmapped error skips evidence only.

The same bound principal/session and arrival-or-terminal NoRecord check apply.
Completed calls retain actual usage; failures retain only a typed class with
unknown usage. Answer probabilities and error text are not stored. The shared
native initializer writes the actual model, revision and connector locality,
with required `caller` run provenance. It invents no generative finish reason,
route, issuer, reasoning part or read-world identity. The run's shared evidence
sequence is allocated only after privacy, fingerprint and model checks.

## Local-vision calls

Local-vision records actual successful generative terminals before its unchanged
text and typed-answer projection. A provider response that later fails typed JSON
parsing still has its raw call evidence, as on the Big rung. Provider errors and
timeouts create no success record. The outer timeout, Waits deadline, role/model
checks, full existing rung/fallback traversal and last-usage mapping are unchanged.

Capture uses only a bound model-call principal and its owned optional session.
An absent context skips evidence, never the call. Both the caller-sourced run
and the pre-existing host run stay unchanged. The existing raw writer receives
the actual admitted request, full response and actual answering binding; the
requested rung is never substituted for a fallback's binding. The same actor
and session are checked at arrival and terminal, and NoRecord on either suppresses
the write. Evidence uses only a post-terminal initiated-by clone and the shared
run sequence. No new call, run, receipt, store or replay permission is created.

## Coach session distill

The standing Coach session distill records successful provider terminals before
its unchanged text and notes parsing. Its caller is the execution actor on the
admitted attempt's validated authority stamp, with an exact `coach.skill_distill`
facet match. The enqueue path stamps that actor; the core distill door validates
it against the Coach authority it uses for the drain's writes before invoking
the model. Budget authority, input speakers and the sitting being read are not
used to infer the caller. The standing execution has no calling session.

A missing, mismatched or unreadable stamp suppresses only evidence; the existing
core door and distill retain their behavior. The explicit actor reaches only the
distill's recorded call. Other Coach calls and exact replays stay uncaptured by
this hook. The shared model call keeps its existing run, host wait, full fallback
walk, settlement, text result and error mapping. It retains the actual admitted
request, terminal response and answering binding for the existing raw writer.

The same actor is checked for NoRecord before and after the call, with either
check suppressing evidence. Only a post-terminal run clone carries that actor
for evidence. A successful provider answer that later fails notes parsing can
still have evidence; provider errors add no record or retry.

## Coach code-fix drafts

Only the generative draft of an admitted `coach.code_fix` attempt uses the same
recorded-call path. Its explicit actor comes from that attempt's validated
execution stamp with an exact facet match. The core code-fix door validates the
stamp against the Coach authority before invoking the draft. The separate owner
principal used for the code-fix judgments stays unchanged and is not substituted
for the generative worker's actor.

The draft's source rows, messages, budget, route, full fallback walk, host wait,
text and parsed result stay unchanged. A provider success is recorded before
draft parsing; an unusable draft can therefore still have raw call evidence.
The standing execution has no calling session and uses the same actor's arrival
or terminal NoRecord check. Missing identity suppresses only evidence. Replies,
exact replays, shadow runs and other Coach calls are not captured by this hook.

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
A call without a bound session can still record when an actual caller context
is present; a call outside every capture scope is not assigned a guessed actor.

Each captured raw, Big, generative-eval, Coach-distill/draft, Local-vision, house or caller-System-One
evidence row takes a distinct record
stamp from its shared run. This is an evidence-key sequence, not an admission or receipt
number. Cloned handles share it and declaration revisions do not reset it.
A failed or suppressed write does not require a dense sequence.

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

## Provider signature retention

The Anthropic whole-response decoder retains a thinking block's actual signature
when its visible text is empty or absent. The Gemini whole and stream decoder
retains a standalone `thoughtSignature` as its own signature-only reasoning part
at that position. It does not assign that signature to an earlier part or
replace an earlier signature. Neither change requests thinking or rewrites the
provider's bytes.

The shared terminal predicates also accept signature-only parts (the separate
terminal-acceptance fix). Retaining a provider field does not prove that the
provider emits that shape in every call. MESSAGE custody, replay permission and
issuing-login identity remain separate.

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
