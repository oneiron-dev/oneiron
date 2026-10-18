# Sync a machine to its home

Every machine in a vault except the elected home keeps its vault in sync with the home
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
- This machine not being the elected home.
- A credential the home's `/ws` upgrade admits, in a file that only its owner can read.
- A way to the home:
  - over the mesh, when the home's MACHINE row carries a paired mesh address here and the mesh
    listener runs (a server built with the `mesh` feature, `ONEIRON_MESH_BIND=<addr:port>`, plus
    `ONEIRON_MESH_RELAYS` for private relays). The machine dials from the listener's own endpoint
    and never binds a second one;
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
  this machine holds that node as its elected home before anything reads the election. A Dreamer
  here that claimed this machine at start then yields, and the connection publishes the home,
  with `home_url` as its endpoint, as its home-node topology. The home stands as an always-on
  local node. A hand-named home without it keeps the home this machine holds. If its own Dreamer
  has claimed it, device sync stays off ("this machine is the elected home").

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
- On failure the file and the connection stay as they are, and the renewal is tried again after
  30 seconds, doubling up to 15 minutes. The old slip works until it runs out.
- A refusal (an expired or revoked slip, or a machine the home no longer counts as the owner's)
  stands until serve starts again. Pair the machine again: with the vault stopped, remove both
  device-sync files and run `oneiron device enrol` with a new link.

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

## How it fits

- The connection runs on the server's own window manager. Its outbound channel sits beside the
  server's relay to its own clients, and each local update reaches both. Neither replaces the
  other.
- Not yet built:
  - binding mesh addresses: no command pairs the home and this machine on the mesh yet, so a
    machine dials the home at `home_url`;
  - bootstrapping a fresh vault from the home, rather than a copy of it;
  - moving to a new home when the election changes;
  - managed (Hypnos) serve;
  - the apps.
