//! Sealed edge identity, service registry, attested relay witnesses and domains.

use super::*;

#[test]
fn from_edge_auth_accepts_every_registered_pair() {
    let registry = fixture_edge_service_registry();
    for (service, class) in fixture_edge_services() {
        let service_identity = format!("connector-edge:{service}");
        let identity =
            AuthenticatedConnectionIdentity::from_edge_auth(&service_identity, class, &registry)
                .expect("registered (service, class) pair must validate");
        assert_eq!(identity.service_identity(), service_identity);
        assert_eq!(identity.connection_class(), class);
    }
}

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
fn edge_service_registry_rejects_empty_service_name() {
    let mut registry = EdgeServiceRegistry::new();
    let err = registry
        .register("", ConnectionClass::CloudVaultPeer)
        .expect_err("empty service name must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity
    );
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
        crate::error::ErrorKind::RelayAttestationClassMismatch
    );
    let message = format!("{err}");
    assert!(message.contains(HOSTED_EDGE_IDENTITY));
    assert!(message.contains("cloud_vault_peer"));
    assert!(message.contains("local_vault_via_hosted_connector"));

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
        crate::error::ErrorKind::RelayAttestationClassMismatch
    );
}

#[test]
fn witness_mint_maps_every_connection_class() {
    // Exhaustive over ConnectionClass: the general mint can only produce the
    // two hosted domains — never `LocalViaByoConnector`.
    for (service_identity, class, expected) in [
        (
            CLOUD_EDGE_IDENTITY,
            ConnectionClass::CloudVaultPeer,
            RelayTrustDomain::CloudVault,
        ),
        (
            HOSTED_EDGE_IDENTITY,
            ConnectionClass::LocalVaultViaHostedConnector,
            RelayTrustDomain::LocalViaHostedConnector,
        ),
    ] {
        let identity = edge_auth_identity(service_identity, class);
        let witness = AttestedRelayDomain::from_connection_identity(&identity);
        assert_eq!(witness.domain(), expected);
    }
}

#[test]
fn hosted_edge_attestation_can_never_reach_byo() {
    // Type-level BYO unconstructibility: `HostedDomain` has no BYO arm, so
    // attesting over EVERY ConnectionClass yields only the two hosted
    // domains — a hosted edge can never conclude "not relayed by us".
    let attestation = HostedEdgeAttestation::new();
    let mut seen = Vec::new();
    for (service_identity, class) in [
        (CLOUD_EDGE_IDENTITY, ConnectionClass::CloudVaultPeer),
        (
            HOSTED_EDGE_IDENTITY,
            ConnectionClass::LocalVaultViaHostedConnector,
        ),
    ] {
        let identity = edge_auth_identity(service_identity, class);
        let witness = attestation.attest(&identity);
        assert!(matches!(
            witness.domain(),
            RelayTrustDomain::CloudVault | RelayTrustDomain::LocalViaHostedConnector
        ));
        seen.push(witness.domain());
    }
    assert_eq!(
        seen,
        vec![
            RelayTrustDomain::CloudVault,
            RelayTrustDomain::LocalViaHostedConnector
        ]
    );
}

#[test]
fn hosted_domain_variant_set_is_exactly_two_hosted_arms() {
    // Security tripwire: an in-crate EXHAUSTIVE, no-wildcard match over the
    // module-private `HostedDomain`. Adding a variant (a BYO arm, say) breaks
    // THIS match at compile time — the variant-set pin the external
    // compile-fail fixture cannot provide (its E0603 fires regardless of the
    // variant set). The expected mapping is checked against the production
    // `from_hosted_domain` arm-for-arm, so the two cannot drift apart either.
    fn expected_domain(hosted: HostedDomain) -> RelayTrustDomain {
        match hosted {
            HostedDomain::CloudVault => RelayTrustDomain::CloudVault,
            HostedDomain::LocalViaHostedConnector => RelayTrustDomain::LocalViaHostedConnector,
        }
    }
    for hosted in [
        HostedDomain::CloudVault,
        HostedDomain::LocalViaHostedConnector,
    ] {
        assert_eq!(
            AttestedRelayDomain::from_hosted_domain(hosted, HOSTED_EDGE_IDENTITY.to_owned())
                .domain(),
            expected_domain(hosted),
            "hosted-edge mapping drifted from the pinned two-variant set"
        );
    }
}

#[test]
fn attested_relay_domain_serializes_domain_and_identity() {
    // The witness emits BOTH halves of its evidence: which trust domain, and
    // which attested service identity that domain was established for. A
    // receipt naming only the domain could not be traced back to the edge that
    // presented it.
    let witness = &hosted_witness();
    assert_eq!(
        serde_json::to_value(witness).expect("witness serializes"),
        serde_json::json!({
            "domain": serde_json::to_value(RelayTrustDomain::LocalViaHostedConnector)
                .expect("inner domain serializes"),
            "service_identity": HOSTED_EDGE_IDENTITY,
        })
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

#[test]
fn attested_cloud_vault_witness_short_circuits_the_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = edge_auth_identity(CLOUD_EDGE_IDENTITY, ConnectionClass::CloudVaultPeer);
    let witness = AttestedRelayDomain::from_connection_identity(&identity);
    assert_eq!(witness.service_identity(), CLOUD_EDGE_IDENTITY);
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            binding,
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        )
        .attesting_hosted_plane(
            &registered_policy(&registry),
            &PolicyModelConfig::default(),
            &answered_pass(),
        ),
        requested_hash: Mutex::new(None),
    };
    let pass = block_on(vault.relay_boundary_pass(
        request,
        &witness,
        &registry,
        &PolicyModelConfig::default(),
        None,
        &source,
    ))?;
    assert_eq!(pass, RelayBoundaryPass::TrustedVaultSide);
    assert!(!pass.ran_relay_classify());
    Ok(())
}
