# Re-review a resolved repository proposal

A standalone Approved proposal can hold at landing when replacing its secret handles
and re-redacting the result does not reproduce its reviewed content. The old proposal
stays Approved and unconsumed; its critiques do not approve different redacted bytes.

Trusted engine hosts can call `Vault::propose_repo_rereview(original, request, catalog)`
to submit a fresh review. The request supplies a new actor, session, provenance,
message and current checkout pin. It must name the original repository and ordinary
operation target. Its content field is replaced with the verified redacted resolution.
This native API has the same trusted-host authority as `propose_repo_mutation`; it is
not an authenticated owner or leased-run door. HTTP, SDK and run adapters are not added.

The engine resolves only the original's handles under their existing `repo:landing`
bindings. A candidate is kept only if resolving its handles reproduces the exact bytes
and every raw occurrence of each authorized value is fully covered by its handle
replacement spans. Matching reads the original resolved bytes, never inserted handle
text. Encoded spellings are not substituted as raw values. The fresh row's handle order
must also pass the existing landing equality rule. Non-representable overlap or handle
syntax cases retain the existing typed hold rather than exposing resolved bytes.

The checked proposer captures the ordinary current base and admits its custody. Before
persisting anything, its writer verifies the original row is unchanged and revalidates
every source handle's current binding and value. The new row is Proposed, has empty
critique collections and no `resolves` link. The original row is not changed or closed.
Critics judge the fresh redacted file through the ordinary review doors. Landing still
requires the usual review, current custody, snapshot and secret-landing authority; this
API grants no secret export or landing exception.
