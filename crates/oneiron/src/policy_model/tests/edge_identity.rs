//! Sealed edge identity, service registry, attested relay witnesses and domains.

use super::*;

#[test]
fn from_edge_auth_rejects_malformed_service_identity_grammar() {
    let registry = fixture_edge_service_registry();
    for malformed in [
        "",
        "slack-hosted",
        "connector-edge",
        "connector-edge:",
        "Connector-edge:slack-hosted",
        " connector-edge:slack-hosted",
    ] {
        let err = AuthenticatedConnectionIdentity::from_edge_auth(
            malformed,
            ConnectionClass::LocalVaultViaHostedConnector,
            &registry,
        )
        .expect_err("malformed service identity must be rejected");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity,
            "input: {malformed:?}"
        );
    }
}

#[test]
fn from_edge_auth_rejects_unregistered_service_identity() {
    // Fail-closed registry: an identity the deployment never registered can
    // never mint a witness, whatever class it claims. An EMPTY registry
    // rejects even the names the fixture registry knows — the engine ships no
    // implicit registrations.
    let registry = EdgeServiceRegistry::new();
    for service_identity in [
        CLOUD_EDGE_IDENTITY,
        HOSTED_EDGE_IDENTITY,
        "connector-edge:totally-unknown-edge",
    ] {
        for class in [
            ConnectionClass::CloudVaultPeer,
            ConnectionClass::LocalVaultViaHostedConnector,
        ] {
            let err =
                AuthenticatedConnectionIdentity::from_edge_auth(service_identity, class, &registry)
                    .expect_err("unregistered service identity must be rejected");
            assert_eq!(
                err.kind(),
                crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity,
                "input: {service_identity:?}"
            );
        }
    }
}

#[test]
fn edge_service_registry_rejects_conflicting_re_registration() {
    // Fail-closed registration data: re-registering a name to a DIFFERENT
    // class is a manifest error, never a silent re-standing of the edge.
    let mut registry = EdgeServiceRegistry::new();
    registry
        .register("edge-one", ConnectionClass::CloudVaultPeer)
        .expect("first registration succeeds");
    registry
        .register("edge-one", ConnectionClass::CloudVaultPeer)
        .expect("identical re-registration is idempotent");
    let err = registry
        .register("edge-one", ConnectionClass::LocalVaultViaHostedConnector)
        .expect_err("conflicting re-registration must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationEdgeServiceConflict
    );
    let identity = AuthenticatedConnectionIdentity::from_edge_auth(
        "connector-edge:edge-one",
        ConnectionClass::CloudVaultPeer,
        &registry,
    )
    .expect("original registration still governs after the rejected conflict");
    assert_eq!(identity.connection_class(), ConnectionClass::CloudVaultPeer);
}

#[test]
fn the_relay_takes_its_hosted_policy_from_the_attested_identity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The policy is bound to `push-relay`. The pass runs under `slack-hosted`,
    // so nothing applies to it — the caller has no way to reach for another
    // service's jurisdiction, because it never names one.
    let mut registry = fixture_edge_service_registry();
    registry.register_hosted_legal_policy(
        "push-relay",
        hosted_policy_with_rules(vec![decide_rule("hosted.bomb", "(?i)bomb")]),
    )?;

    let request = || PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let unbound = block_on(vault.relay_boundary_pass(
        request(),
        &hosted_witness(),
        &registry,
        &PolicyModelConfig::default(),
        None,
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(
        unbound.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!unbound.must_halt_relay());

    // The same content under the identity the policy IS bound to blocks.
    let bound_witness = AttestedRelayDomain::for_testing(
        RelayTrustDomain::LocalViaHostedConnector,
        "connector-edge:push-relay",
    );
    let bound = block_on(vault.relay_boundary_pass(
        request(),
        &bound_witness,
        &registry,
        &PolicyModelConfig::default(),
        None,
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert!(bound.must_halt_relay());
    Ok(())
}

#[test]
fn from_edge_auth_rejects_identity_class_mismatch() {
    // The hosted connector is registered as a local-vault relay edge; it may
    // never claim cloud-vault peer standing (which would skip the hosted pass).
    let registry = fixture_edge_service_registry();
    let err = AuthenticatedConnectionIdentity::from_edge_auth(
        HOSTED_EDGE_IDENTITY,
        ConnectionClass::CloudVaultPeer,
        &registry,
    )
    .expect_err("hosted connector claiming cloud-vault peer must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationClassMismatch,
    );

    // The mirror: the cloud-vault peer may not present as a hosted connector
    // (which would force a redundant re-run on already-classified content).
    let err = AuthenticatedConnectionIdentity::from_edge_auth(
        CLOUD_EDGE_IDENTITY,
        ConnectionClass::LocalVaultViaHostedConnector,
        &registry,
    )
    .expect_err("cloud-vault peer claiming hosted-connector class must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationClassMismatch,
    );
}

#[test]
fn witness_and_identity_never_implement_deserialize() {
    // Ambiguity-based negative trait check: each `marker()` call resolves ONLY
    // while `T` does NOT implement `DeserializeOwned`. If a `Deserialize` impl
    // ever lands on either type, both blanket impls apply and this test stops
    // compiling.
    trait AmbiguousIfImpl<A> {
        fn marker() {}
    }
    impl<T> AmbiguousIfImpl<()> for T {}
    struct NotDeserialize<T>(std::marker::PhantomData<T>);
    impl<T: serde::de::DeserializeOwned> AmbiguousIfImpl<u8> for NotDeserialize<T> {}

    NotDeserialize::<AttestedRelayDomain>::marker();
    NotDeserialize::<AuthenticatedConnectionIdentity>::marker();
}

#[test]
fn attested_witness_drives_the_relay_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The hosted connector edge attests its validated identity; the minted
    // witness then drives the pass exactly like a bare domain would.
    let identity = edge_auth_identity(
        HOSTED_EDGE_IDENTITY,
        ConnectionClass::LocalVaultViaHostedConnector,
    );
    let witness = HostedEdgeAttestation::new().attest(&identity);
    let backend = blocking_backend();
    let budget = lease("attested-witness");
    let pass = block_on(vault.relay_boundary_pass(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &witness,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict()
            .expect("hosted relay runs a pass")
            .decision,
        PolicyClassifyDecision::Block
    );
    Ok(())
}
