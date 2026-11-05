# Caller-bound native session witnesses

`Memory::session_witness_context()` captures the session named on the caller's
actual bound Memory surface. `SessionWitnessContext::witness(author, turn)` keeps
that caller separate from the MESSAGE author. It is a native one-shot witness
API, not a new SDK request field, a code-run capability or a message-stream door.

The context keeps the exact live session instance and its mode-generation route.
A retained witness uses the existing witness program and its author/envelope
checks. The caller's proof, holder, class and current room membership are checked
again in every owning transaction. The author must independently belong to a
session's room. A human caller's credential never becomes an agent author's proof.
A mode change or close invalidates the captured route rather than silently re-minting it.
Session instance metadata is captured before the owning transaction opens.
Admission rechecks live caller proof, room membership, the exact instance's
published open state and the captured route in that transaction without acquiring
the session-state mutex. This preserves the
session-state-before-base-writer lock order used by promotion and close.
The shared overlay sink also captures its immutable room before the writer opens;
its in-transaction guard reads that value without taking session state.

- OffRecord witnesses retain only session-local rows and return
  `SessionWitnessOutcome::Retained` with the session-local witness receipt.
- OnRecord witnesses use the existing continuation shell and saver checks.
- Anonymous witnesses return `SessionWitnessOutcome::Unretained`. Admission is
  read-only: no MESSAGE, custody, ACTIVE checkpoint, receipt or replay row is
  created. The caller already owns its input; the outcome invents no saved ids.

Bind a verified slip, an authenticated owner proof, or the native host action on
transport caller surfaces. A credential flag or actor label alone is not proof.
Native in-process surfaces keep their existing host trust boundary. A roomless
session must belong to the actual entering principal/creator, or, for an ordinary
owner stretch, its caller must still satisfy the existing owner check. Anonymous
sessions entered without a principal bind nobody.

## Native asynchronous work

`SessionWitnessContext::into_binding()` consumes the borrowed context and returns
an opaque `SessionWitnessBinding` with no Vault or Memory borrow. Move the binding
into the native task, then call `binding.witness(&author_memory, &turn)` there.
The binding keeps the actual verified caller instrument, the resolved live
session name and the original mode-generation route. It never mints a new route.

Each use resolves the session in the author's Vault and requires the exact same
in-process overlay instance as the captured route. A different Vault, or a closed
and reopened session with the same name, cannot reuse it. Caller revocation,
current membership and author admission are still checked in the owning witness
transaction. A failed instrument never falls back to native-host authority.
The binding holds no Vault reference, so keeping it beside a producer or runtime
entry cannot create a Vault ownership cycle. It is not serializable or recoverable.

This is a native lifetime bridge, not a routed message-stream implementation.
The ordinary message-stream opener, ACTIVE rows, custody, partial publication,
terminal receipts and HTTP delivery still do not consume this binding.

## Session-owned invocation claims

`SessionWitnessContext::claim_invocation(id, body)` and
`SessionWitnessBinding::claim_invocation(vault, id, body)` claim a request under
that exact caller and session. The native hash binds the actual caller actor and
class as well as the door's canonical body hash. Successful outcomes stay in the
session's existing RAM keep; no durable invocation intent or reply is opened.
Ordinary vault claims retain their existing concurrent-only lifetime.

All active claims still occupy the original vault-wide in-flight index, so a
hook cannot mistake a concurrent request for nested work. The session index and
the volatile index share one outcome slot. Finish removes the volatile entry and
keeps a successful session outcome for a later duplicate. `finish_unkept` shares
a failure with current waiters but releases its session entry. A drop without a
reply releases both entries. Removal requires the same slot instance.

Session close force-clears completed outcomes as well as pending ones, wakes
waiters without a reply and fences a late finish on the old slot. A new captured
mode generation replaces the old RAM owner only after a typed stale-route check.
The original caller binding must be revalidated after a wait and after replay's
current destination release; neither an invocation id nor a kept reply is authority.

The named-invocation path of `POST /v1/ai/chat` selects this keep for a positively
bound Anonymous caller before opening the ordinary durable claim. Managed owner
proof is attached only to the actual Human requester's caller Memory, never the
assistant author. Unmatched session headers and ordinary OnRecord calls keep
their existing durable path. The chat call hash includes the request's session
context. This is the invocation-storage slice only: user/assistant witness and
stream routing, Continue/Retry and completed-but-unretained delivery remain open.
It is not a whole HTTP privacy guarantee or a cross-mode transition guarantee.

## Integration boundary

This API does not route the HTTP chat user witness or assistant producer yet.
Those paths still need a cohesive integration before any chat privacy fix can be
claimed. Select the route before opening any durable seed, custody, invocation,
receipt or broadcast state. Carry it through append, flush, cancellation, idle and
terminal transitions, and add truthful completed-but-unretained delivery. Keep
ordinary OnRecord, Continue and Retry behavior. A terminal-only reroute is not a
privacy fix. The one-shot context does not grant stable TURN ids, continuation,
regeneration or CodeRun authority.
