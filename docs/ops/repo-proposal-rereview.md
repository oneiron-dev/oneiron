# Re-review a resolved repository proposal

A standalone Approved proposal can hold at landing when replacing its secret handles
and re-redacting the result does not reproduce its reviewed content. The old proposal
stays Approved and unconsumed; its critiques do not approve different redacted bytes.

Trusted engine hosts can call `Vault::propose_repo_rereview(original, request, catalog)`
to submit a fresh review. The request supplies a new actor, session, provenance,
message and current checkout pin. It must name the original repository and ordinary
operation target. Its content field is replaced with the verified redacted resolution.
This native API has the same trusted-host authority as `propose_repo_mutation`; it is
not an authenticated owner or leased-run door.

Native Memory callers can use `code_proposal_rereview_as(owner, original, input)`
or `repo_proposal_rereview_for_run(binding, original, input, policy, sources)`.
These use their existing ordinary submission input and return records. The input's
content is replaced internally. These two callers submit CommitFile changes only, as
their ordinary submission counterparts do.

For an owner-submitted conflict resolution, use
`code_proposal_resolve_rereview_as(owner, original, input)` with the existing
`CodeProposalResolveRequest`. It retains the ordinary branch-subject, conflict-claim
and conflict-task checks before reading the original through the current credential.
The original must name the same repository, path, branch and conflict subject before
any handle is resolved. Fresh actor/session/provenance and the same owner writer
revalidation remain in force. The existing resolve door is unchanged for submissions
without an original. A leased-run resolution caller, HTTP and SDK surfaces are not
added here; the trusted core still accepts both ordinary operations.

The owner caller validates the actual owner, repository and attribution sources, and
reads the original through its current credential. The run caller admits the current
work's target edit, checks its publication declaration, reads the original through
its current read lane, and captures its actual pinned base before resolving handles.
The host still supplies review policy and fresh provenance. A readable original need
not belong to the current run, work or lease: none of those old fields grants authority.
Both callers retain ordinary admission and revalidate it in the same writer as the
original-row and live-handle checks. No caller copies the original's actor or critiques.

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
