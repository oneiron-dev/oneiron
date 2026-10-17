# Mesh transport (ONE-2648, binding and grant cut)

This crate keeps the engine's connection seam separate from storage and the read plane.
`MeshTransport` dials a MACHINE by entity id, accepts a connection, and opens bounded
bidirectional streams, and exposes the authenticated ALPN on each accepted
connection for host dispatch. The generic conformance laws in `tests/conformance.rs` run
against the in-memory test transport and, with `--features iroh`, iroh on loopback.
Sync rides the mesh only where a host opts in (OF-535, below); managed cloud
HTTP/WebSocket paths remain separate. There is no automatic production migration to the mesh.

## Sync over the mesh (OF-535)

- **ALPN `oneiron/sync/1`** carries the sync server's own HTTP/1.1 routes and their
  WebSocket upgrades, one long-lived bidirectional stream (`MeshConnection::open_duplex`)
  per HTTP connection. The upgrade, its slip, the machine proof and every grant check
  are the bytes they are on TCP; the mesh adds the paired-machine admission under them.
- **Admission.** `PairedMachineGrants` admits a key only when `Vault::mesh_peer_machine`
  proves the paired machine: the host-signed binding names the key the machine stands
  on, and the live ALPN grant admits it. Both ends use it.
- **Server.** `oneiron-server` built with `--features mesh` starts the listener when
  `ONEIRON_MESH_BIND` names a socket address (`ONEIRON_MESH_RELAYS`: comma-separated
  private relay URLs, none by default). The install must be enrolled as a machine: its
  transport key derives from the machine key (`TransportKey::for_install`). Routes are
  one row per ALPN in `handler/mesh.rs` `mesh_routes`; a route may add a tick. A mesh
  caller is always off-device: its requests carry a `fd00::/8` peer address made from
  its endpoint key.
- **Client.** Set `SyncClientConfig::mesh_dialer` to a `MeshSyncDialer` (feature `sync`;
  `MeshSyncDialer::bind_for_install` with `iroh`). The steady socket and the residence
  sockets to the configured home ride it; an elected home elsewhere is dialed at its URL.

## Trust boundary

The device holds its pairing signing seed in platform protected custody. A
`TransportKey` derives a distinct Ed25519 seed using
`oneiron/mesh-transport-ed25519/v1`, zeroizes the derived seed on drop, and
provides the EndpointId and possession proofs for the paired MACHINE binding.
The host never stores that seed in a MACHINE or grant record; on restart the
device re-derives it from its protected signing seed. `bind_paired` consumes the
derived key. The raw `bind` seam remains for the conformance lab and explicit
transport hosts, but cannot itself grant admission.

`Vault::bind_mesh_machine` requires a live pairing slip naming this MACHINE,
plus signatures from both the paired device key and its transport key over the
same domain-separated MACHINE/EndpointId transcript. A live, previously created
MACHINE can be paired through the public pairing route first. The host-authorized
binding then replaces its body with the typed address envelope; wrong-kind,
deleted, already-bound, duplicate-key, and conflicting tagged endpoint rows
fail closed. The envelope and host-signed local binding projection commit
atomically with no ALPN grants. `set_mesh_alpn_grant` requires the live host authority root,
appends a scoped `SlipMint` or `SlipRevoke` to AUTHORITY_LOG and updates its
local pointer in the same transaction. `revoke_mesh_machine` revokes every
listed grant and seals the local binding. The live read checks the current
MACHINE key, the host signature and roster, live pairing slip, and exact
MACHINE/key/ALPN grant **from the authority fold** in one snapshot. The local
projection is not an independent trust root, nor is it portable authorization:
peers need their own admitted authority history and local binding before they
can serve this ALPN. A public MACHINE rewrite or stale address hint cannot
mint a grant.

`VaultMachineRoster` reads type, liveness and body from one vault snapshot.
Other MACHINE actors are not automatically transport peers. `VaultMachineGrants`
implements the mandatory live `MachineGrants` verifier. The iroh adapter uses
`presets::Minimal` and a private `AddressLookup`, never public DNS/pkarr. A
relay is disabled unless the caller supplies a private relay map, and the
MACHINE relay URL must be in that map. Incoming TLS keys, queued accepts, new
streams and stream messages recheck the grant. The lab tests both transports
against queued and established revocation and the exact/over 1 MiB boundary.
No 0-RTT application traffic is exposed. The managed WebSocket sync path and
federation request-grant revalidation remain independent: a mesh ALPN grant
never authorizes a federation request or widens its scope.

A transport bound with `bind_paired` leaves a path receipt in the vault
(`VaultPathReceipts`, `Vault::record_mesh_path_receipt`) for every connection,
inbound and outbound. It writes the receipt when the connection is admitted
and again when it closes. The receipt names the MACHINE, the endpoint key and
the ALPN, which paths were open (direct, relayed, mixed), which ones carried
data (from `Connection::paths` and `path_events`), the times, and the close
reason. Refused and failed attempts leave one too. Refusals from one machine,
or from keys no MACHINE names, fold into one receipt per 60 s window with an
attempt count. Receipts stay local and are kept 90 days. A refusal before the
TLS identity is known (in the iroh router) leaves none.

## Next cuts

1. Entry-node relay: deploy our pinned `iroh-relay` with owned TLS hostname,
   network/abuse policy, health checks and outbound address distribution. The
   relay forwards encrypted packets only; locker and mobile push remain separate.
2. Fork upkeep/fleet job: pin tested fork commits, automate each upstream-tag
   refresh on a staging branch, run the conformance lab across tag/version pairs
   and LAN/hotspot/relay-only hosts, then send narrowly scoped patches upstream.
