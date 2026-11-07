# Code-result secret lift proposals

Stored code results that the secret scan marks keep their original bytes. Their
occurrence-specific secret and taint marks continue to control redacted reads and
exports. A lift proposal contains only the body handle, occurrence id, detector
reason and suggested custody name. It never contains the body or a secret value.

The vault owner can read proposals with
`GET /v1/owner/secrets/code-run-lifts`. To dismiss one, send its exact `handle` and
`occurrence` to `POST /v1/owner/secrets/code-run-lifts/dismiss`. Both routes use the
normal owner proof. The engine rechecks that proof in the deciding transaction.
The response contains the remaining proposals and, for a dismissal, its author,
time and Gate receipt. Repeating the same dismissal returns its original receipt.

The HTTP facade and MCP expose the same operation as
`vault.secrets.code_run_lifts`. Its input is `{}` for a list, or
`{"dismiss":{"handle":"<body handle>","occurrence":"<occurrence id>"}}`.
The verb has Write scope because it can dismiss a proposal. Its host preflight
checks the owner proof before verb hooks run. Embedded use requires the embedded
owner proof as well.

Dismissing a proposal is not lifting a secret, untainting a result, approving an
export, or erasing a body. Its secret and taint marks stay intact. Another
occurrence of the same bytes has its own proposal and decision. Existing erase
and collection paths remove a decision only with that exact occurrence's marks;
a MESSAGE erase also removes the marks of result occurrences that MESSAGE held.
A delete preserves its existing restore-window behavior.

The original list and dismissal routes above read the base-vault proposal
family; they do not export room bodies.

## Selected room overlay

`GET /v1/owner/secrets/code-run-room-lifts?room_ref=<room id>&session_ref=<stretch name>`
and the Read verb `vault.secrets.code_run_room_lifts` take a room id and its
named stretch. The verb input is
`{"room_ref":"<room id>","session_ref":"<stretch name>"}`. Both return an array
of the same value-free proposal fields. The host checks owner proof before
hooks; embedded calls use the embedded owner proof. The engine rechecks live
owner proof, actual room binding and current roster membership in the serving
transaction. It applies membership windows and the private-thread turn read
rule to each journal MESSAGE it considers.

This list includes positive secret marks reached through a current, visible
MESSAGE result reference in that selected overlay snapshot: its exact producer
occurrence, and its MESSAGE-owned occurrence when present. Off-record MESSAGEs
use room-held producer bodies rather than creating a separate retained hold.
The list does not include base-vault marks, runs with no such visible MESSAGE,
or messages already kept only in base. No result body,
MESSAGE content or result preview is decoded into a string. The scanner borrows
the current overlay MESSAGE and selectively decodes its visibility and result
reference; journal entries supply only candidate ids, turn bindings and times.
Deleted, stale and replaced rows cannot be revived from an old journal body.
The ordinary deletion/stale admission can still copy an opaque encoded entity
row internally. The journal itself also holds the original MESSAGE bytes.
The journal, current rows, exact mark lookup and composed private-thread read
share one overlay snapshot.

An empty list is not a clean result or a clearance decision. Existing producer
and MESSAGE secret/taint checks on reads, redaction and exports stay unchanged.
The room list performs no dismissal, base copy, receipt write or export. Room
proposal dismissal and non-MESSAGE occurrence mapping remain follow-ups to
FIX590.
