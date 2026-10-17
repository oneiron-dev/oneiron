# Sync a machine to its home

Every machine in a vault except the elected home keeps its vault in sync with the home
(ARCH-0023b); the home dials no one. `oneiron serve`, and an app's embedded engine, dial the home
the config file's `[device_sync]` section names. Without the section a machine dials no one.

For now the home is named by hand. Enrolment that records the home, so that a machine connects
the moment it is enrolled, comes later.

## What it needs

- A server built with the `mesh` feature, with the mesh listener on: `ONEIRON_MESH_BIND=<addr:port>`,
  plus `ONEIRON_MESH_RELAYS` for private relays. The machine dials from the listener's own endpoint
  and never binds a second one.
- This install enrolled as a live machine in the vault.
- The home a live machine that is paired on the mesh: its MACHINE row carries a mesh address.
- This machine not being the elected home.
- A credential the home's `/ws` upgrade admits, in a file that only its owner can read.

## The section

```toml
[device_sync]
home_machine = "<the home's MACHINE id, 64 hex characters>"
home_url = "ws://home/ws"
credential_file = "/absolute/path/to/home.cred"
worlds = ["<world id>"]
```

- `home_machine`: the home's MACHINE id. The mesh dials this machine.
- `home_url`: the URL the upgrade names, `ws://` or `wss://` with the path `/ws`. The mesh carries
  the socket, so the host part only names the home.
- `credential_file`: one line, `v2.cred.<slip>.<seed>`. That is the slip without its `v2.slip.`
  prefix, then the 64-hex seed of the key the slip is bound to. This is the form the MCP bridge's
  `--credential-file` reads. The file must be mode 600; on macOS it must also carry no ACL entry
  (`chmod -N`). `/ws` admits only a logged, holder-bound owner-grade slip, so it refuses the
  scoped slips that `token agent` and `token read` mint. No command writes this file yet. Until
  enrolment delivers it, redeem an owner pairing link from the home (`oneiron token pair`
  without `--scope`) and store the slip and its key's seed in this form.
- `worlds`: the worlds this machine follows, by id. Absent, it follows none until some are named.

The section is file-only: no environment variable or flag sets it.

## What the log shows

- `device sync started` with this machine's id and the home's.
- `device sync disabled: <reason>` when a condition above fails. It appears once, and serve runs
  on without the connection.
- `device sync` warnings for connection errors. The connection retries with backoff up to a
  minute.
- `mesh model catalog kept the vault's own routes`, with the model ids, when another node
  offers a model that this vault already routes another way (a pack or a local row). That row
  wins.
- `mesh model catalog refresh failed` or `unavailable` when a row could not be read or written.
- At stop, serve closes the connection before the mesh listener.

Lines carry machine ids, never a slip or a key.

## The owner's other models

While the connection is synced, the machine asks each of the owner's other nodes whose MACHINE
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
  - residence reads (index, first touch, promotion), which need a grant selector and a NOTE
    session that the section cannot name yet;
  - a home-node topology feed;
  - moving to a new home when the election changes;
  - managed (Hypnos) serve;
  - the apps.
