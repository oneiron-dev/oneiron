# Held connector calls and owner reasons

A live scoped-MCP call that reaches an approvable Gate hold can carry the Gate's
actual consent effect and action requirement into its owner question. These are
captured after contact hydration and policy matching. The question does not
rebuild them from the pending call, its tool name, or its endpoint.

Adding a reason to that question drafts a **Proposed** standing grant for the
attached action bound. The answer does not release the call or activate the
standing grant. The authenticated owner's later confirmation uses the existing
decision-ask grant confirmation door. The existing connector consent and
approve-once doors remain available.

Actor erasure clears an ask's consent attachment when its typed action subject
or disclosure audience names that actor. It does not rewrite the bound or reopen
an answered or withdrawn question. Attachments that name no erased actor stay.

The pending call keeps the attachment alongside its current approval metadata.
A changed attachment is a new approval question, even when the request digest is
unchanged. Its question version distinguishes an attached consent effect from a
generic hold. If the approval changes while a question is queued, that stale
question is withdrawn rather than recorded as the current approval's question.

This first caller covers live first admissions only. Administrative holds,
code-owned consent waits, frozen-intent resumes, and recovery sweeps keep their
existing question paths. A composition that cannot ride the typed ask keeps its
generic question; it does not gain a new refusal or admission rule. No request
arguments or credentials are copied into the attachment.

The existing consent queue may pre-fill a reason from its recorded reason
lookup. This change does not complete the separate typed nearest-reason judgment
remainder of FIX2975, or make any new runtime or end-to-end proof claim.

## Code-owned stop-asking answers

A code consent wait's authenticated **approve and stop asking** answer keeps
its original approve-once for the frozen call and mints a separate native
standing consent grant. Following DEC-0006 line 106, its default is **this
connection × this class × this project**, not the requesting agent. The
connection is the actual native catalog key of a derived per-grant key, or
the actual key itself when it is not derived. The class is the prepared
call's payload data class. The server, tool and current settings act remain
pinned. Every caller still needs its own baseline scoped-MCP grant; a
remembered answer does not replace that authority.

`vault.code.waits.resolve` accepts an optional `remember_scope` on a
stop-asking answer. Omitted or `connection` uses the default above.
`asking_lineage` narrows the same bound to the original caller's verified
credential delegation lineage. It is never the default, and it cannot be
selected when that credential lineage was not available. The confirm still
has three answers: approve once, approve and stop asking, deny.

The answer receipt returns the first answer's actual `remember_scope` and
`remembered_grant_ref`. A later request for a different scope returns that
first answer with `already_answered`; it does not replace the grant.

The engine resolves the project from the dispatch record named by the code
run, not from tool arguments or a server label. An actual no-project call
has an exact no-project bound; it is not a vault-wide grant. The native
context is frozen with the request and the wait's digest. If that optional
context cannot be resolved, the ordinary per-call consent path remains.
A vault-wide grant, when the owner wants one, is an explicit registry row.
For the same connection, class, server and tool, an owner can widen to all
projects by leaving that row's target unpinned. The settings-act selector
still ends it when the owner explicitly changes that tool's setting.

The answer does not set the shared catalog row to `auto` or clear holder
narrows. Preparation, the current Gate and the final send boundary all check
the live remembered grant. `never allow`, scope, manifest, authority and the
catastrophe floor keep their existing checks. Ordinary non-code questions
keep their existing paths.

Every new tool row and every explicit owner override of that row receives a
fresh native `settings_act`, including an override that repeats the same
setting. That later act ends prior remembers for the row. An override of a
different row does not end them. Unchanged rows carry their identity through
delta slates, forced revisions and pack rebounds. The grant is visible and
revocable through the existing consent registry.
