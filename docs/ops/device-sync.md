# Sync a machine to its home

Every machine in a vault except its home keeps its vault in sync with the home
(ARCH-0023b); the home dials no one. `oneiron serve`, and an app's embedded engine, dial the home
this machine enrolled with, or the one the config file's `[device_sync]` section names by hand.
With neither, a machine dials no one.

## Enrol a machine

1. On the home, while it runs, the owner makes a machine pairing link with an owner-grade
   credential (the one `token bootstrap` paired):

   ```sh
   oneiron token pair --principal-ref <owner PERSON from `oneiron whoami`> --actor-class human \
     --machine yours > link.txt
   ```

   Omit `--scope`: `/ws` admits only an owner-grade slip. `--machine` takes `yours`,
   `work_school` or `rented`; only the owner, in person, answers for a machine. The link lasts
   an hour and is spent once redeemed.

2. On the machine, with its vault stopped:

   ```sh
   oneiron device enrol <vault path> [--config <file>] < link.txt
   ```

   It redeems the link with this machine's signed enrolment request. The home adds the machine
   and answers with the paired credential, its MACHINE id and its sync node id, and the
   authority checkpoint pin the link named. The pin must be exactly the one the link names, or
   enrolment is refused. Two files are kept beside this install's key directory, outside the
   vault, so a copy of the vault never carries the credential:
   `<state>/oneiron/device-sync/<vault id>.json` (the home, its URL, node id and pin) and
   `<vault id>.cred` (the credential, mode 600). `<state>` is `$XDG_STATE_HOME`, else
   `$HOME/.local/state`, or the parent of `keystore.dir` when that is set. Remove both to enrol
   again with a new link.

3. Start `oneiron serve`. It dials the enrolled home with no `[device_sync]` section. The
   connection's first authority catch-up adopts the pinned checkpoint, and it brings this
   machine's own profile and the home's, which the home logged at enrolment.

The machine's vault must be a copy of the home's (restored from its backup or recovery kit). A
fresh vault has another authority root, and the home refuses it.

## What it needs

- This install's machine enrolled: live in the vault, or enrolled at the home by `device enrol`.
- The home a live machine of the vault, or one this machine enrolled with.
- A credential the home's `/ws` upgrade admits, in a file that only its owner can read.
- A way to the home:
  - over the mesh, when the home's MACHINE row carries a paired mesh address here and the mesh
    listener runs (a server built with the `mesh` feature, `ONEIRON_MESH_BIND=<addr:port>`, plus
    `ONEIRON_MESH_RELAYS` for private relays). A managed vault reads no environment: its supervisor
    passes them as `--mesh-bind <addr:port>` and `--mesh-relays <url>,<url>`, and without a bind its
    mesh is off. The machine dials from the listener's own endpoint and never binds a second one;
  - otherwise at `home_url` itself, which must be `wss://` (or `ws://` to a loopback address):
    the same `/ws` upgrade every SDK client makes.

## The section

```toml
[device_sync]
worlds = ["<world id>"]
# Only to name a home by hand, instead of the enrolled one:
home_machine = "<the home's MACHINE id, 32 hex characters>"
home_url = "wss://home.example/ws"
credential_file = "/absolute/path/to/home.cred"
home_node_id = 1234567890123456789   # the home's sync_node_id, from `oneiron whoami` there
# Only to make this machine a MACRO home candidate:
always_on = true
primary = false
```

- `worlds`: the worlds this machine follows, by id. Absent, it follows none until some are named.
- `home_machine`, `home_url`, `credential_file`: a home named by hand, all three or none. Absent,
  the enrolled home. A hand-named home that is the enrolled one keeps the enrolment's pin.
  - `home_machine`: the home's MACHINE id. The mesh dials this machine.
  - `home_url`: the URL the upgrade names, `ws://` or `wss://` with the path `/ws`. Over the mesh
    the host part only names the home.
  - `credential_file`: one line, `v2.cred.<slip>.<seed>`. That is the slip without its
    `v2.slip.` prefix, then the 64-hex seed of the key the slip is bound to. This is the form the
    MCP bridge's `--credential-file` reads. The file must be mode 600; on macOS it must also carry
    no ACL entry (`chmod -N`). `/ws` admits only a logged, holder-bound owner-grade slip, so it
    refuses the scoped slips that `token agent` and `token read` mint.
- `home_node_id`: the home's sync node id, which `oneiron whoami` prints on the home as
  `sync_node_id`. This is not its MACHINE id. Absent, the enrolled home's. Named (or enrolled),
  the connection publishes that node, with `home_url` as its endpoint, as its home-node
  topology, so residence reads go to `home_url` while that node is the elected MACRO home. This
  machine keeps that node as its own always-on candidate for the home, so with no declaration it
  elects the home it dials; once the home's own declaration names the node, the declared facts
  rule (below). A hand-named home without it publishes no endpoint, and this machine elects over
  the declarations alone. A node id that is this machine's own is refused.
- `always_on`, `primary`: what this machine declares itself as a MACRO home candidate (below).
  Both are off by default, so a machine that syncs to a home is no candidate until its owner
  says so.

## The MACRO home candidacy

One node of the vault runs its MACRO consolidation: the elected home node (ARCH-0026). Each
machine declares itself to the election, signed by its own install key into the vault's
authority log, so every linked machine sees the same declarations. It writes a declaration
only when its facts change, never one per start.

- A served host that dials no home declares itself always on, and ready for MACRO work while
  its Dreamer runs. A managed host's hosted node also declares itself the cloud node.
- A machine that dials a home, by this section or by its enrolment, declares what `always_on`
  and `primary` say, ready for MACRO work while its own Dreamer runs.

Every election, on every machine, reads each machine's newest declaration again. It counts one
only while its machine stands here under the key that signed it, as one of the owner's
machines: his own, work/school or rented, or a hosted node. An execution node, a machine whose
owner has not answered, and a removed, held or key-conflicted machine are no candidates. Of
those that can take MACRO work, the owner's pick wins (`vault.consolidation.home.pick`).
Without an eligible pick, the order is the cloud node, then an always-on machine, then the
primary device; the lowest node id breaks a tie. A pick of a node no declaration names stays
recorded, and wins once that node declares itself. Two machines that declare one node id
refuse the election, and the last elected home stands. `vault.consolidation.home.get` lists the
candidates every election ranks.

A served host also keeps itself as its own candidate. Alone, it elects itself, and with its
Dreamer off it still claims a vault no other candidate stands for, so its standing questions
run. A machine that dials a home keeps that home's node as its own candidate the same way. Such
a kept candidate gives way to a declaration that names its node, and stands no more once only
removed, held or key-conflicted machines declare that node. Being elected moves no dial: an
elected machine that syncs to a home keeps dialing it, and syncs every window it may read. A
lost connection is no removal and moves no election.

The section is file-only: no environment variable or flag sets it.

## The credential renews itself

The paired credential's slip has a lifetime. serve renews it at the home once at start, then at
half each new slip's lifetime (`POST /v1/core/slips/renew`, at the http(s) origin of
`home_url`: `wss` becomes `https`, `ws` becomes `http`, and `/ws` is dropped). The lifetime comes
from the new slip itself, never from the home's clock against this machine's. The request
carries the slip, a holder proof with its key, and this machine's own proof.

- On success the replacement, bound to the same seed, is written over the credential file (the
  enrolled `.cred` or the hand-named `credential_file`): to a new owner-only file beside it,
  synced, then renamed over it. The connection then stops and starts again on the new slip.
- The connection's own loop writes the replacement, never the request that fetched it. A stop
  that comes first leaves the file as it was, and the old slip works until it runs out; a write
  already under way ends before serve stops, and stays. A request still waiting on the home at
  stop writes nothing.
- On failure, of the request or of the write, the file and the connection stay as they are, and
  the renewal is tried again after 30 seconds, doubling up to 15 minutes. The old slip works
  until it runs out.
- A refusal (an expired or revoked slip, or a machine the home no longer counts as the owner's)
  stands until serve starts again. Pair the machine again: with the vault stopped, remove both
  device-sync files and run `oneiron device enrol` with a new link.

## Publication diagnostics

For a pending sealed-bundle publication, the executor's
`GET /v1/owner/owner-work/{request}/diagnostics` reply includes
`device_sync_start` once a device-sync start outcome was observed on this open
vault session. Clones of that session share the observation. Closing it loses the
observation; it is not restored or synced. An absent field means no outcome was
recorded, not that device sync is unconfigured.

Its `state` is one of:

- `not_configured`: neither a device-sync section nor an enrolled home was found.
- `configuration_failed`: resolving the configuration or enrolment failed.
- `frozen_for_reap`: reap preparation did not admit that managed start.
- `open_failed`: opening the sync connection failed. Its
  `archive_receiver_running` boolean says only whether the archive receiver had
  started before that failure; it does not report current receiver health.
- `started`: opening succeeded then. It does not prove that the connection still
  runs, is connected, or has reached this publication's home.

The existing `relay` field separately reports what each pass observed for this
request. `relay.state: "unknown"` still means no pass has observed it on this
session. A recorded start outcome now distinguishes that from a start which found
no home, was not admitted, or failed. Neither field changes publication admission,
the named executor, pending work, or relay behavior. Full failure details stay in
the existing operator logs; this reply carries only closed reasons, not paths,
URLs or credentials.

## What the log shows

- `device sync started` with this machine's id, the home's, and `over` (`mesh` or `url`).
- `device sync disabled: <reason>` when a condition above fails. It appears once, and serve runs
  on without the connection.
- `device sync` warnings for connection errors. The connection retries with backoff up to a
  minute.
- `device credential renewed`, with the seconds until the next renewal; `device sync reconnects
  on its renewed credential` after it.
- `device credential renewal failed (<reason>)` with the seconds until it tries again, and
  `device credential renewal refused (<reason>)` (pair again) or `renewal off (<reason>)` when
  it will not try again before the next start.
- `mesh model catalog kept the vault's own routes`, with the model ids, when another node
  offers a model that this vault already routes another way (a pack or a local row). That row
  wins.
- `mesh model catalog refresh failed` or `unavailable` when a row could not be read or written.
- At stop, serve closes the connection before the mesh listener.

Lines carry machine ids, never a slip or a key.

## Residence reads

In the default Opened mode, a machine reads the home's index, fetches an item on first touch, and
promotes a window on its first edit. The paired credential binds each socket's NOTE session, as
the actor its holder names. The mesh is a private carrier, so `ws://` is enough there; off the
mesh the bind needs `wss://`. What those reads may return is the own-device member grant that the
credential names (`grant_ref`): the home provisions it when a live owner pairs, which `device
enrol` does. A credential that names no grant leaves residence
reads off. The log says so once at start, and the home refuses those reads.

A search the machine cannot answer alone asks the home. An owner-grade caller is the machine's
paired owner, so the home answers it within the machine's own grant. For a narrower caller, the
machine forwards that caller's own holder proof: its slip and the `x-oneiron-binding` fields it
sent, unchanged. The machine adds its install key's signature over the proof and the request.
The home checks both, then answers within the caller's own reach and the machine's grant. If the
home refuses, or cannot be reached, the caller gets no home hits; the machine never answers for it
from its own scan. The `/api` search door still admits only owner-grade callers.

## The owner's other models

While the connection is synced over the mesh, the machine asks each of the owner's other nodes whose MACHINE
grant admits model calls (`oneiron/llm/1`) which models they serve. It asks each time the
connection syncs and then every 30 seconds while it stays synced: no mesh signal says that a
node's offer changed. Each model a node serves on its own compute becomes an own-server row in
the vault registry, routed to that node. A row the vault already holds another way is kept, and
the node's offer is skipped. A node that does not answer keeps the rows it had. Nothing is
deleted when a node stops offering a model.

The rows feed the own-server backend. The configured model router is built from `[models]` at
start, so serve does not route a discovered model by itself yet.

## Shared environments

A host can retain dedicated shared-vault environments beside its personal vault. Declare each
one explicitly; serve does not scan directories or discover them through `HOME` or XDG paths:

```toml
[[shared_env]]
path = "/absolute/path/to/the/shared-env"
vault_id = 1234567890123456789
member = "<the membership's 32-hex person id>"
home_url = "wss://home.example/ws"
credential_file = "/absolute/path/to/the/membership.cred"
```

`path` is the environment's own existing vault directory; serve does not create a new vault there.
`vault_id` and `member` name the membership the leave check verifies, and `home_url` plus
`credential_file` give its own sync lane the same inputs as a personal `[device_sync]` connection.
As with direct sync, `ws://` is allowed only to a loopback host; any other network home uses
`wss://`. On plain serve the section is file-only. On managed
serve it arrives in the supervisor-selected settings file, and both paths must pass the same
vault/configuration-root containment check as other owner paths. No environment variable or flag
sets it.

At start, serve opens every entry and keeps its handle. Each active membership gets its own
window manager and sync connection; one bad environment is logged and skipped without stopping
the others. Once an hour, the lifecycle tick asks the engine's verified leave door for each
active membership. A refusal or failed check is not a leave. Only a verified notice detaches the
lane. The environment's own durable leave receipt is the record; there is no second registry in
the vault and no new side table.

The handle stays open after a confirmed leave. The person can still read retained removal
archives, and the deferred orphan-body collection written by the leave purge can finish. The
ordinary housekeeping tick and the owner's "run now" cover every retained environment, active or
left, sequentially with an independent budget per handle. A managed wake takes the earliest wake
of the personal vault and all retained environments, so a left environment's collection does not
sleep past its deadline. At stop, lanes drop before handles; in-flight checks and passes finish
first.

## How it fits

- The connection runs on the server's own window manager. Its outbound channel sits beside the
  server's relay to its own clients, and each local update reaches both. Neither replaces the
  other.
- Not yet built:
  - binding mesh addresses: no command pairs the home and this machine on the mesh yet, so a
    machine dials the home at `home_url`;
  - bootstrapping a fresh vault from the home, rather than a copy of it;
  - moving to a new home when the election changes;
  - the apps.

## Federation selector reads

A federation selector fetch is separate from the full-window device sync above. Its
rows must pass both the selector's live grant and the credential admitted on that
socket. The same credential scope bounds source-backed text, NOTE review
attachments, tombstones and base-window edge endpoints. Prompt sources in
born-with text use that scope too, even when the source row is not in the window.
A bundle remains whole when all its members pass; otherwise the existing NOTE
projection keeps only its admitted members.

By-reference bodies use the same bound when a held selector copy is rebuilt and
when a dropped copy is rebuilt lazily. The scope comes from the socket's live
bound authentication, not from a second stored scope registry. Grant, selector,
pact, peer-world and facet-read checks still run. Grant-only engine callers keep
their existing behavior; this adds no setting, expiry or transfer limit.

## Optional CLAIM copies on promotion replies

A `residence.promote` reply keeps its original JSON result, snapshot envelope,
chunk sequence and call receipt. Optional home CLAIM copies travel in a separate
`home_claim_copies` MessagePack binary field on the last `rpc.res` frame, only
when they fit in the unused space of that result chunk. They never add a frame
or change the result digest.

The existing socket reply queue keeps the native source and recipient evidence,
not just serialized copy bytes. After the socket is ready, owed control frames
have drained, and its credential is rechecked, the sender rechecks every selected
copy against that socket's vault and proved machine. A changed source, key,
release row, required reply, or a preparation/encoding/space miss drops only the
optional metadata. The required response still follows its original release,
revocation, engine-stop and send behavior.

The receiving machine collects and decodes the required result in the original
order. It opens optional metadata against the promotion envelope's original
window and payload before translating the snapshot for import. These copies use
the existing native copy scope for validation and import. They do not authenticate
the raw snapshot or grant a read. Missing or malformed optional copy data leaves
the ordinary import intact. This does not provide immediate vector fill when no
eligible native home copy is available.

## Optional CLAIM copies on window updates

The home's direct and broadcast `UPDATE` and `REPLACEMENT` sends can carry
optional home CLAIM copies in their existing window-pad envelope. Preparation
uses that envelope's actual projected payload and the current window document
as partial-update context. It walks carried CLAIM occurrences, not the context's
current winners.

Client and server window sends share the native copy holder and required-prefix
logic. The server adds copies only when the complete encoded copy blob fits in
spare space in the original required frames. Frame count and every required
prefix length remain unchanged; no copy-only frame or send is added. Receipt
bindings still describe the canonical payload and required pads, not the copies.

Native source and recipient evidence stays with the selected frames through the
existing socket wait. After readiness, control-frame drain and fresh revocation
checks, the final send rechecks the actual vault, proved peer, source rows and
keys. A miss discards only the optional suffix. The required envelope id and part
offsets remain consistent even when that suffix is omitted. Raw deliveries,
including those to an unknown peer, keep their existing behavior.

The existing receiver opens copies against the original envelope before native
import. Missing or malformed copies do not delay or repeat canonical delivery.
This path reuses eligible native copies; it does not provide immediate vector
fill when no such copy exists and does not change any timer, limit or setting.

## Completing retained CLAIM copies after import

After a native copy scope's canonical import call returns, the receiver attempts
vector completion for each distinct CLAIM whose copy was retained in that call.
It reopens that CLAIM's copy from the existing pending job and uses the same
retained-copy opener and vector writer as background catch-up. Source, model,
peer, custody, lease and job-token checks still run. No live home or embedder is
needed for an eligible retained copy.

A savepoint result is not a durability receipt, and a returned writer error is
not proof of rollback. Completion checks the persisted job and current source;
its optional errors never replace the original import result. Existing
housekeeping can revisit pending work, including active and left shared vaults.
