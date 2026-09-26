# Mesh transport (ONE-2648, first slice)

This crate keeps the engine's connection seam separate from storage and the read plane.
`MeshTransport` dials a MACHINE by entity id, accepts a connection, and opens bounded
bidirectional streams, and exposes the authenticated ALPN on each accepted
connection for host dispatch. The generic conformance laws in `tests/conformance.rs` run
against the in-memory test transport and, with `--features iroh`, iroh on loopback.
The current WebSocket sync client is unchanged; managed cloud HTTP/WebSocket paths
remain separate. There is no automatic production migration to the mesh.

## Trust boundary

An endpoint is bound with an explicitly supplied iroh Ed25519 `SecretKey`.
`iroh_transport::IrohTransport::bind` uses only `presets::Minimal`, a private
`AddressLookup`, and a disabled relay unless a **caller-supplied** relay map is
provided. A roster relay URL must belong to that supplied map. Loopback tests
bind only a loopback IP transport and disable port-mapping and network probes. It neither publishes to nor queries n0 DNS/pkarr. A relay has no say
in admission. Each incoming TLS-authenticated key is checked against the live
roster and a mandatory `MachineGrants` implementation for its ALPN before
any stream is dispatched. Queued connections and newly opened streams are
rechecked, so a revoke does not leave a queued accept as an admission bypass.
No 0-RTT application traffic is exposed.

`VaultMachineRoster` reads only explicitly tagged/versioned MACHINE address
envelopes. Existing MACHINE entities have varied unrelated bodies, so an
ordinary MACHINE row must not silently become a mesh peer. Address hints are
**not authority**: production hosts must provide a trusted `MachineGrants`
implementation that verifies the current, separately granted
MACHINE/key/ALPN tuple and revocation. There is no canonical MACHINE transport
record writer or per-ALPN grant record in the engine today. The bundled
conformance test grants are in-memory fixtures, not a production grant source.
Until a trusted grant provider is wired, the adapter cannot be used to admit
production peers. Authentication at this transport layer also does not replace
the existing sync/federation authorization check on each request.

## Next cuts

1. Pairing-derived transport key: derive a distinct Ed25519 seed using a domain-
   separated KDF over device-key material at pairing; securely store it and
   cryptographically bind its EndpointId to the MACHINE/authority record. Add a
   single-snapshot, typed MACHINE roster/ALPN grant read door and a signed
   admission/write door. The transport adapter must not invent this authority.
2. Path receipt: observe iroh `Connection::paths` / `path_events`, classify the
   selected path as direct or relayed, and persist a per-connection receipt with
   the MACHINE, ALPN, endpoint keys, time and outcome. Include refused attempts.
3. Entry-node relay: deploy our pinned `iroh-relay` with owned TLS hostname,
   network/abuse policy, health checks and outbound address distribution. The
   relay forwards encrypted packets only; locker and mobile push remain separate.
4. Fork upkeep/fleet job: pin tested fork commits, automate each upstream-tag
   refresh on a staging branch, run the conformance lab across tag/version pairs
   and LAN/hotspot/relay-only hosts, then review and send narrowly scoped patches
   upstream. Keep the final bump human-reviewed before changing Cargo.lock.
