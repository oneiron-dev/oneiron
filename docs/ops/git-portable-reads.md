# Portable selection for Git reads

A Git HTTP read can select a portable repository in a project with these
request headers, sent together on both the advertisement and upload-pack RPC:

- `oneiron-repo-portable`: the manifest's 64-character lowercase hexadecimal portable id.
- `oneiron-repo-project`: the project's entity id, parsed by the normal entity-id parser.
- `oneiron-repo-reveal-why`: the reader's reason, when it wants marked files' real bytes.

Stock Git can send each header with `-c http.extraHeader="name: value"`.
Use the portable id from the repo manifest. Do not substitute a store hash,
repository name, folder path or CODE entity id.

The two selection headers are optional. An incomplete or malformed pair is
HTTP 400, not an absent selection. With neither header, reads keep their
existing behavior. A valid but unknown portable id also keeps the old
recipient-project/served-anchor lookup.

The selection is not authentication or authority. The server keeps the agent
from the verified credential. The selected live CODE must belong to the
requested live project, and its stored local folder must identify the very
canonical Git store being served. A known id that fails that binding stays
masked; it cannot fall through to another private anchor. The existing live
per-file standing grants still decide which marked files can be released,
and upload-pack delivers each released file afresh with its existing receipts.
A project or repo id alone grants nothing. A task-bound grant still needs its
actual run; these headers do not create one.

An admitted checkout's recipient binding takes precedence over the selection.
An already host-proved recipient project is retained; the checked requested
project fills only an unknown project. Exact reads, unnamed recipients, reads
without a valid reveal reason and push admission are unchanged. The portable selection does not choose a push Grant,
change a Git CGI field or affect the canonical repository's refs.
