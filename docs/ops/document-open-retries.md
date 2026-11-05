# Per-document open retries on the shared sync socket

A live-document open that reaches its existing wait deadline does not close
unrelated subscriptions. The server answers that REQUEST or UPDATE on the same
connection with `DOCUMENT / WAITED_OUT`.

The current frame is `[DOCUMENT=11][entity:16][WAITED_OUT=8][initiator:1]`.
The initiator is exactly REQUEST (2) or UPDATE (0). No other byte or payload
length is valid. It carries no text, vector, acknowledgement, admission result
or settlement. Clients cannot send this server-only answer as an update.
Other document errors keep their existing socket behavior.

The answer retains the initiating wire entity, including a copy alias. A
server may resolve that alias to open its source, but the client retries the
actual `ds:e:` subscription key, not that source identity. The client rebuilds
the current selector/owner REQUEST and current vector on the existing ephemeral
housekeeping tick. It uses the existing host batch admission, document buffer,
debounce and last release checks. There is no new timer or retry limit.

Retry IDs are transient connection scheduling state. Subscriptions and pending
edits remain in their existing durable stores. Missing subscriptions or deleted
rows retire only the retry ID. Read and open failures retain it and report the
error without closing unrelated socket traffic. Reconnect clears scheduling
state and replays the durable subscriptions and journals as before.

A successful STATE or UPDATE ends a retry only when no local pending work
remains. Otherwise it resends the existing pending frames and keeps retrying
until an ACK covers the current document and its journal is empty. An old or
partial ACK cannot retire newer pending work. NOTE semantic requests keep their
existing receipt handling. A wait answer itself never clears a journal, moves
a delivery cursor or claims that an update landed.

Only a strictly validated no-body wait answer bypasses document-subscription
and body-withholding filters on its direct reply path. Existing authentication,
credential revocation and final transport-stop checks still apply. Artifact
refusal receipts and owner-body requests retain their separate semantics.
