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
A mode change invalidates the captured route rather than silently re-minting it.

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

## Integration boundary

This API does not route the HTTP chat user witness or assistant producer yet.
Those paths still need a cohesive integration before any chat privacy fix can be
claimed. Select the route before opening any durable seed, custody, invocation,
receipt or broadcast state. Carry it through append, flush, cancellation, idle and
terminal transitions, and add truthful completed-but-unretained delivery. Keep
ordinary OnRecord, Continue and Retry behavior. A terminal-only reroute is not a
privacy fix. The one-shot context does not grant stable TURN ids, continuation,
regeneration or CodeRun authority.
