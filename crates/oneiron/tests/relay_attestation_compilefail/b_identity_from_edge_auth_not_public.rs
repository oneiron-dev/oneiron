//! (b.2) ONE-1572 H1: ordinary downstream code must NOT be able to mint a
//! `CloudVault` witness from public labels. The edge-auth constructor's
//! entire authority is the caller-supplied `(service_identity, class)` pair
//! checked against a caller-supplied registry, so it is `pub(crate)` until
//! real connector-edge wiring lands — a name is not a capability boundary.
//! If this file ever COMPILES from the external integration-test position,
//! the seal is gone: the strongest registered identity
//! (`connector-edge:cloud-vault` + `CloudVaultPeer`) would be mintable by
//! anyone, and `from_connection_identity` turns it into the exact floor-skip
//! witness this ticket exists to prevent.

fn main() {
    // The full public-labels mint chain, attempted from outside the crate.
    // The registry itself is inert data — the capability under test is the
    // crate-private constructor.
    let mut registry = oneiron::EdgeServiceRegistry::new();
    registry
        .register("cloud-vault", oneiron::ConnectionClass::CloudVaultPeer)
        .expect("fixture registration must succeed");
    let identity = oneiron::AuthenticatedConnectionIdentity::from_edge_auth(
        "connector-edge:cloud-vault",
        oneiron::ConnectionClass::CloudVaultPeer,
        &registry,
    )
    .expect("crate-private constructor must not be callable here");
    let witness = oneiron::AttestedRelayDomain::from_connection_identity(&identity);
    assert_eq!(witness.domain(), oneiron::RelayTrustDomain::CloudVault);
}
