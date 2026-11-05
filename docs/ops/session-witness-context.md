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

This is the native lifetime bridge used by the private assistant stream below.
The ordinary message-stream opener, ACTIVE rows, custody and partial publication
remain unchanged. HTTP delivery still does not consume this binding.

## Native caller-private assistant streams

`binding.begin_assistant_stream(vault, agent, sitting, turn)` consumes the actual
caller binding and opens one fresh Companion reply. Its author is the native
assistant handle: `vault.memory(agent, Agent)` with the optional sitting key.
The native host supplies its actually selected assistant agent. This is not a
snapshot of an arbitrary credential-bound author Memory, and the sitting key
is context, not authority. The caller's human identity never becomes the agent.

The opaque, non-serializable `SessionMessageStream` shares the existing live
registry, fair permit and idle pump. It buffers in RAM without ACTIVE rows,
custody or partial broadcasts. `append`, `partial` and `flush` recheck the
original caller and independent author; partial text projects known secrets
through the caller's own sight. A write-only credential sees masked keys, not
an extra requirement to read base records. Legacy actor-only stream handles
cannot access a caller-private entry, even if they name the same agent.

`finalize`, `finalize_model` and `cancel` keep their actual finality and model
finish reason. The existing policy idle interval ends a quiet stream as Partial.
The native token's `completion` exposes that state after an explicit or idle end.
Anonymous returns `SessionStreamOutcome::Unretained` with no MESSAGE id or
receipt reference. No row, checkpoint, custody or receipt is written.

A retained terminal uses the existing witness program. Its native plan supplies
the actual newly staged MESSAGE id. That same transaction writes the existing
stream receipt and per-generation reference into the selected base or session
sink, after MESSAGE staging and before its effect. Canonical text bytes and
reply-assertion types are read from that same staged view. No latest-row guess,
caller-chosen MESSAGE id, second writer or base sidecar for an overlay is used.
A post-commit hook error is recognized only by the exact immutable generation
receipt in that same captured route, never by its RAM candidate alone.

A revoked caller or invalidated session retires private RAM state. An author
policy refusal or storage error does not discard its accepted text. A terminal
releases its fair permit and removes the resident entry. No private stream is
recoverable after process exit: its accepted text was never checkpointed.
This new native door does not change ordinary OnRecord, Continue or Retry APIs.

## Integration boundary

This API does not route the HTTP chat user witness or assistant producer yet.
Those paths still need a cohesive integration before any chat privacy fix can be
claimed. Select the route before opening any durable seed, custody, invocation,
receipt or broadcast state. Carry it through append, flush, cancellation, idle and
terminal transitions, and add truthful completed-but-unretained delivery. Keep
ordinary OnRecord, Continue and Retry behavior. A terminal-only reroute is not a
privacy fix. The one-shot context does not grant stable TURN ids, continuation,
regeneration or CodeRun authority.
