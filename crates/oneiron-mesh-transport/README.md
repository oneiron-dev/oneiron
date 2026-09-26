# Mesh transport (ONE-2648, binding and grant cut)

This crate keeps the engine's connection seam separate from storage and the read plane.
`MeshTransport` dials a MACHINE by entity id, accepts a connection, and opens bounded
bidirectional streams, and exposes the authenticated ALPN on each accepted
connection for host dispatch. The generic conformance laws in `tests/conformance.rs` run
against the in-memory test transport and, with `--features iroh`, iroh on loopback.
The current WebSocket sync client is unchanged; managed cloud HTTP/WebSocket paths
remain separate. There is no automatic production migration to the mesh.

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
same domain-separated MACHINE/EndpointId transcript. It atomically writes the
public MACHINE address envelope and a host-signed local binding projection with
no ALPN grants. `set_mesh_alpn_grant` requires the live host authority root,
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

## Next cuts

1. Path receipt: observe iroh `Connection::paths` / `path_events`, classify the
   selected path as direct or relayed, and persist a per-connection receipt with
   the MACHINE, ALPN, endpoint keys, time and outcome. Include refused attempts.
2. Entry-node relay: deploy our pinned `iroh-relay` with owned TLS hostname,
   network/abuse policy, health checks and outbound address distribution. The
   relay forwards encrypted packets only; locker and mobile push remain separate.
3. Fork upkeep/fleet job: pin tested fork commits, automate each upstream-tag
   refresh on a staging branch, run the conformance lab across tag/version pairs
   and LAN/hotspot/relay-only hosts, then review and send narrowly scoped patches
   upstream. Keep the final bump human-reviewed before changing Cargo.lock.
