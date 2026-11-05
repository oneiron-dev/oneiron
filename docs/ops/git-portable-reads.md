# Portable selection for Git reads and pushes

A Git HTTP read can select a portable repository in a project with these
request headers, sent together on both the advertisement and upload-pack RPC:

- `oneiron-repo-portable`: the manifest's 64-character lowercase hexadecimal portable id.
- `oneiron-repo-project`: the project's entity id, parsed by the normal entity-id parser.
- `oneiron-repo-reveal-why`: the reader's reason, when it wants marked files' real bytes.

Stock Git can send each header with `-c http.extraHeader="name: value"`.
Use the portable id from the repo manifest. Do not substitute a store hash,
repository name, folder path or CODE entity id.

The two selection headers are optional. An incomplete or malformed pair is
HTTP 400, not an absent selection. With neither header, reads and pushes keep
their existing behavior. A valid but unknown portable id also keeps the old
lookup: reads keep the old recipient-project/served-anchor lookup; pushes keep
the old native first-in-id-order decision.

The selection is not authentication or authority. The server keeps the agent
from the verified credential. The selected live CODE must belong to the
requested live project, and its stored local folder must identify the very
canonical Git store being served. A known id that fails that binding stays
masked; it cannot fall through to another private anchor. The existing live
per-file standing grants still decide which marked files can be released,
and upload-pack delivers each released file afresh with its existing receipts.
A project or repo id alone grants nothing. A task-bound grant still needs its
actual run; these headers do not create one.

An admitted checkout's recipient binding takes precedence over the read
selection. An already host-proved recipient project is retained; the checked
requested project fills only an unknown project. Exact reads, unnamed
recipients and reads without a valid reveal reason are unchanged. The portable
selection does not change a Git CGI field or affect the canonical repository's
refs.

## Push selection (same headers)

A Git HTTP push can select a portable repository in a project with the same
`oneiron-repo-portable` and `oneiron-repo-project` headers, sent together on
each HTTP request: both the receive-pack advertisement and the receive-pack RPC.
Each request carries its own pair; the preflight and the serving-plane decision
for that request see the same value.

The selection narrows only the non-owner Grant and checkout arms to the
user-named pair. The owner's implicit admission and the in-process owner-only
refusal stay as before; there is no new owner restriction. A `None` selection
and a valid but unknown portable id keep the old native first-in-id-order
decision.

A known portable id resolves to its live CODE in the same admission
transaction, and the requested project must match that same existing grant's
project while its stored local folder identifies the very canonical Git store
being served, in both the Grant and the checkout arms. A known id that matches
no live grant for this pusher and store is refused with the existing served-repo
error string and the current typed reasons; it never falls through to another
grant's CODE. The admitted stamp, the final writer's same-grant recheck and the
checkout per-ref and changed-path checks are unchanged.
