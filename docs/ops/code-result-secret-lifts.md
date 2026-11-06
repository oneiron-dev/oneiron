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

Off-record room proposal filing is a separate follow-up (FIX590). These routes
list the existing base-vault proposal family; they do not export room bodies.
