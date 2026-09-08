//! Cloud-vault receipt trust/attestation, trust domains, degrade halts, dual-plane passes and enforce doors.

use super::*;

#[test]
fn cloud_vault_receipt_without_hosted_attestation_reruns_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // A clean vault-side Allow that verifies on content, frontier and safeguard
    // selector — and says nothing about the hosted plane. Trusting it would
    // hand this payload straight through the hosted service's own legal policy.
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            binding,
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        ),
        requested_hash: Mutex::new(None),
    };
    let backend = blocking_backend();
    let budget = lease("cloud-unattested");

    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict().expect("hosted pass ran").decision,
        PolicyClassifyDecision::Block
    );
    assert!(pass.must_halt_relay());
    assert_eq!(
        *source.requested_hash.lock().expect("requested hash lock"),
        Some(binding.content_hash)
    );
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.hosted_plane_unattested"
    ));
    Ok(())
}

#[test]
fn cloud_vault_receipt_with_hosted_attestation_trusts_without_rerunning() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The same payload, but the vault-side pass says it ran THIS hosted policy.
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
    let backend = CountingPolicyBackend::clean();
    let budget = lease("cloud-attested");

    let pass = cloud_pass(
        &vault,
        request,
        &registry,
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(pass, RelayBoundaryPass::TrustedVaultSide);
    assert_eq!(backend.calls(), 0);
    assert_eq!(
        *source.requested_hash.lock().expect("requested hash lock"),
        Some(binding.content_hash)
    );
    Ok(())
}

#[test]
fn cloud_vault_attestation_of_another_policy_version_is_not_evidence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Attestation names a policy the relay is not enforcing, so it proves
    // nothing about the one it is: the hosted pass runs and blocks.
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let superseded = registered_policy(&hosted_edge_registry(HostedLegalPolicy {
        version: "2020-01-01".to_owned(),
        ..hosted_serious_crime_block()
    }));
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            binding,
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        )
        .attesting_hosted_plane(
            &superseded,
            &PolicyModelConfig::default(),
            &answered_pass(),
        ),
        requested_hash: Mutex::new(None),
    };
    let backend = blocking_backend();
    let budget = lease("cloud-superseded");

    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_unattested_warn_receipt_cannot_relay_past_the_hosted_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The mild version of the same hole: a stored WARN does not halt, so
    // trusting it verbatim would relay this payload with the hosted plane never
    // consulted. The attestation check sits ahead of the decision branch.
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::new(
            PolicyClassifyDecision::Warn,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: "owner:vault-side".to_owned(),
            },
            PolicyConfidence::HIGH,
            binding,
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        ),
        requested_hash: Mutex::new(None),
    };
    let backend = blocking_backend();
    let budget = lease("cloud-warn");

    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(
        pass.boundary_verdict().expect("hosted pass ran").decision,
        PolicyClassifyDecision::Block
    );
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_missing_receipt_falls_back_to_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let err = vault
        .cloud_vault_verified_trust(
            &request,
            None,
            &PolicyModelConfig::default(),
            &EMPTY_VAULT_SIDE_VERDICTS,
        )
        .expect_err("missing receipt must be untrusted");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted { reason: "missing" }
    ));

    let backend = blocking_backend();
    let budget = lease("cloud-missing");
    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &EMPTY_VAULT_SIDE_VERDICTS,
        Some(tier(&backend, &budget)),
    )?;
    // Missing evidence cannot create a skip: the hosted pass runs and blocks.
    assert!(pass.ran_relay_classify());
    assert!(pass.must_halt_relay());
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.missing"
    ));
    Ok(())
}

#[test]
fn in_memory_vault_side_verdicts_hit_trusts_cloud_vault_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let binding = vault.relay_verify_binding(&request, &config)?;
    let mut verdicts = InMemoryVaultSideVerdicts::new();
    verdicts.insert(
        binding.content_hash,
        PolicyClassifyVerdict::clean_allow(binding, &config, PolicyPlane::OwnerPolicy),
    );

    let pass = cloud_pass(
        &vault,
        request,
        &no_hosted_policy_registry(),
        &verdicts,
        None,
    )?;
    assert_eq!(pass, RelayBoundaryPass::TrustedVaultSide);
    Ok(())
}

#[test]
fn in_memory_vault_side_verdicts_miss_uses_hosted_fallback() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let verdicts = InMemoryVaultSideVerdicts::new();

    let pass = cloud_pass(
        &vault,
        request,
        &no_hosted_policy_registry(),
        &verdicts,
        None,
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict()
            .expect("hosted fallback verdict")
            .decision,
        PolicyClassifyDecision::Allow
    );
    Ok(())
}

#[test]
fn in_memory_vault_side_verdicts_wrong_hash_family_is_a_miss() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let verify_binding = vault.relay_verify_binding(&request, &config)?;
    let skip_binding = relay_skip_content_binding(&request);
    assert_ne!(verify_binding.content_hash, skip_binding.content_hash);

    let mut verdicts = InMemoryVaultSideVerdicts::new();
    verdicts.insert(
        skip_binding.content_hash,
        PolicyClassifyVerdict::clean_allow(verify_binding, &config, PolicyPlane::OwnerPolicy),
    );
    let pass = cloud_pass(
        &vault,
        request,
        &no_hosted_policy_registry(),
        &verdicts,
        None,
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict()
            .expect("wrong-family miss fallback")
            .decision,
        PolicyClassifyDecision::Allow
    );
    Ok(())
}

#[test]
fn cloud_vault_receipt_binding_mismatch_fails_closed_to_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let mut binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    binding.read_frontier_hash = [7; 32];
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            binding,
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        ),
        requested_hash: Mutex::new(None),
    };

    let err = vault
        .cloud_vault_verified_trust(&request, None, &PolicyModelConfig::default(), &source)
        .expect_err("frontier mismatch must be rejected by the CloudVault arm");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted {
            reason: "binding_mismatch"
        }
    ));
    let backend = blocking_backend();
    let budget = lease("cloud-binding-mismatch");
    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_content_hash_mismatch_audits_exact_cause() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let mut binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    binding.content_hash = [9; 32];
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            binding,
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        ),
        requested_hash: Mutex::new(None),
    };
    let err = vault
        .cloud_vault_verified_trust(&request, None, &PolicyModelConfig::default(), &source)
        .expect_err("stored content hash mismatch must be untrusted");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted {
            reason: "binding_mismatch"
        }
    ));
    cloud_pass(&vault, request, &no_hosted_policy_registry(), &source, None)?;
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.binding_mismatch"
    ));
    Ok(())
}

#[test]
fn cloud_vault_safeguard_binding_mismatch_falls_back_and_audits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let mut receipt = PolicyClassifyVerdict::clean_allow(
        binding,
        &PolicyModelConfig::default(),
        PolicyPlane::OwnerPolicy,
    );
    receipt.safeguard_binding = "stale-safeguard".to_owned();
    let source = StaticVaultSideVerdicts {
        verdict: receipt,
        requested_hash: Mutex::new(None),
    };

    let pass = cloud_pass(&vault, request, &no_hosted_policy_registry(), &source, None)?;
    assert_eq!(
        pass.boundary_verdict().expect("fallback verdict").decision,
        PolicyClassifyDecision::Allow
    );
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.safeguard_binding_mismatch"
    ));
    Ok(())
}

#[test]
fn cloud_vault_non_allow_receipts_halt_and_record_real_decisions() -> Result<()> {
    for (decision, outcome) in [
        (PolicyClassifyDecision::Block, "relay_boundary_block"),
        (
            PolicyClassifyDecision::RouteToHelp,
            "relay_boundary_route_to_help",
        ),
        (PolicyClassifyDecision::Warn, "relay_boundary_warn"),
    ] {
        let (_tmp, vault) = temp_vault();
        let request = PolicyClassifyRequest::outbound_content("ordinary content");
        let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
        let source = StaticVaultSideVerdicts {
            verdict: PolicyClassifyVerdict::new(
                decision,
                PolicyVerdictCategory::OwnerPolicy {
                    row_ref: "owner:vault-side".to_owned(),
                },
                PolicyConfidence::HIGH,
                binding,
                &PolicyModelConfig::default(),
                PolicyPlane::OwnerPolicy,
            ),
            requested_hash: Mutex::new(None),
        };

        let pass = cloud_pass(&vault, request, &no_hosted_policy_registry(), &source, None)?;
        assert!(matches!(pass, RelayBoundaryPass::Classified(_)));
        assert_eq!(
            pass.must_halt_relay(),
            decision != PolicyClassifyDecision::Warn
        );
        // The relay verified WHAT was judged, never HOW. No hosted policy is
        // bound here, so the attestation check never ran and the vault-side
        // verdict may well have been decided by a `Decide` pattern with no
        // model call at all — recording `model_decided` would assert a model
        // ran on no evidence.
        assert_eq!(pass.resolution(), Some(RelayResolution::VaultSideDecided));
        let receipts = gate_receipts(&vault)?;
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, outcome);
        assert!(has_trace(
            &receipts[0],
            "gate.relay.resolution.vault_side_decided"
        ));
        assert!(!has_trace(
            &receipts[0],
            "gate.relay.resolution.model_decided"
        ));
        assert!(
            !receipts
                .iter()
                .any(|receipt| receipt.outcome == "relay_trusted_vault_side")
        );
    }
    Ok(())
}

#[test]
fn relay_skips_write_audit_receipts_with_trust_domain() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let content = || PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&content(), &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            binding,
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        ),
        requested_hash: Mutex::new(None),
    };
    cloud_pass(
        &vault,
        content(),
        &no_hosted_policy_registry(),
        &source,
        None,
    )?;
    block_on(vault.relay_boundary_pass(
        content(),
        &byo_witness(),
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        None,
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 2);
    let outcomes = receipts
        .iter()
        .map(|receipt| receipt.outcome.as_str())
        .collect::<Vec<_>>();
    assert!(outcomes.contains(&"relay_trusted_vault_side"));
    assert!(outcomes.contains(&"relay_not_relayed"));
    assert!(
        receipts
            .iter()
            .all(|receipt| has_trace(receipt, "gate.relay.classify.skipped"))
    );
    Ok(())
}

#[test]
fn relay_verify_binding_ignores_world_ref_while_content_binding_does_not() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let plain = PolicyClassifyRequest::outbound_content("same content");
    let scoped =
        PolicyClassifyRequest::outbound_content("same content").with_world_ref("world:other");
    assert_eq!(
        vault
            .relay_verify_binding(&plain, &PolicyModelConfig::default())?
            .content_hash,
        vault
            .relay_verify_binding(&scoped, &PolicyModelConfig::default())?
            .content_hash,
    );
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert_ne!(
        content_binding(&plain, &policy, &PolicyModelConfig::default())?.content_hash,
        content_binding(&scoped, &policy, &PolicyModelConfig::default())?.content_hash,
    );
    Ok(())
}

#[test]
fn relay_verify_binding_is_distinct_from_skip_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("same content");
    let verify = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    assert_ne!(
        verify.content_hash,
        relay_skip_content_binding(&request).content_hash
    );
    Ok(())
}

#[test]
fn a_degraded_pass_halts_only_where_a_hosted_policy_was_in_play() {
    // The contract stated directly, both sides of the line. A hosted policy in
    // play means the fail-closed plane lost coverage, so the relay stops; with
    // no hosted policy there was never anything for the outage to uncover, and
    // the owner plane is sovereign — it never gains a halt it did not ask for.
    let binding = relay_skip_content_binding(&PolicyClassifyRequest::outbound_content("candidate"));
    let verdict = PolicyClassifyVerdict::clean_allow(
        binding,
        &PolicyModelConfig::default(),
        PolicyPlane::OwnerPolicy,
    );
    for degrade in [
        RelayBoundaryDegrade::SafeguardModelUnavailable,
        RelayBoundaryDegrade::SafeguardModelResponseUnusable,
        RelayBoundaryDegrade::SafeguardModelTierAbsent,
        RelayBoundaryDegrade::OutputContractUndeclared,
    ] {
        assert!(
            !classified_pass(verdict.clone(), Some(degrade), false).must_halt_relay(),
            "owner-plane-only degrade must not halt: {degrade:?}"
        );
        assert!(
            classified_pass(verdict.clone(), Some(degrade), true).must_halt_relay(),
            "hosted-plane degrade must halt: {degrade:?}"
        );
    }
    // Undegraded, a clean allow still relays whichever plane was in play.
    for hosted_policy_in_play in [false, true] {
        assert!(!classified_pass(verdict.clone(), None, hosted_policy_in_play).must_halt_relay());
    }
}

#[test]
fn a_relay_with_no_hosted_policy_bound_never_degrades_at_all() -> Result<()> {
    // With nothing bound to the attested identity the safeguard model is never
    // called, so a downed model cannot even produce a degrade, let alone a halt.
    let (_tmp, vault) = temp_vault();
    let budget = lease("relay-unbound-no-degrade");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert!(pass.degraded().is_none());
    assert!(!pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_untrusted_receipt_with_backend_runs_and_degrades() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            PolicyContentBinding {
                content_hash: [9; 32],
                read_frontier_hash: [9; 32],
            },
            &PolicyModelConfig::default(),
            PolicyPlane::OwnerPolicy,
        ),
        requested_hash: Mutex::new(None),
    };
    let budget = lease("cloud-fallback-backend-down");

    let pass = cloud_pass(
        &vault,
        PolicyClassifyRequest::outbound_content("a clean span"),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        pass.boundary_verdict().expect("fallback verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable)
    );
    Ok(())
}

#[test]
fn both_planes_are_called_concurrently_each_under_its_own_document() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;

    // The rendezvous backend refuses to answer EITHER caller until both have
    // arrived, so completing at all is the proof that the two calls were in
    // flight together. Sequentially the first would wait forever.
    let backend = RendezvousBackend::new();
    let budget = lease("both-planes");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    // Each plane was asked under ITS OWN document.
    let documents = backend.documents();
    assert_eq!(documents.len(), 2, "both planes issued a call");
    assert!(documents.contains(&OWNER_DOCUMENT.to_owned()));
    assert!(documents.contains(&HOSTED_DOCUMENT.to_owned()));

    // ... and each verdict landed in its own plane's machinery.
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Warn);
    assert_eq!(
        pass.owner.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    assert!(!pass.owner_model_skipped);

    let relay_verdict = pass.relay.boundary_verdict().expect("relay ran");
    assert_eq!(relay_verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(relay_verdict.plane(), Some(PolicyPlane::HostedLegal));
    assert!(pass.relay.must_halt_relay());
    Ok(())
}

#[test]
fn a_dual_plane_pass_receipts_both_planes() -> Result<()> {
    // The dual-plane entry hands the owner verdict back RAW — it never routes
    // through enforcement, which is where an owner verdict is normally
    // receipted. Without a row written here a vault owner reading their own
    // ledger would find only the hosted service's verdict about their content
    // and no trace that their own plane ran at all.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x71),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;
    let backend = RendezvousBackend::new();
    let budget = lease("both-planes-receipted");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Warn);

    let receipts = gate_receipts(&vault)?;
    let owner_row = receipts
        .iter()
        .find(|receipt| receipt.outcome == "owner_plane_warn")
        .expect("the owner plane's own row");
    assert!(has_trace(owner_row, "gate.relay.owner_plane.classify.ran"));
    assert!(has_trace(owner_row, "gate.policy_model.plane.owner_policy"));
    assert!(has_trace(owner_row, "gate.policy_model.warn"));
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.outcome == "relay_boundary_block"),
        "the hosted plane's row is still written"
    );
    Ok(())
}

/// An attestation is evidence only under the OUTAGE POSTURE that authorized
/// the pass it records.
///
/// Under `ProceedReceipted` a vault-side hosted pass may proceed through an
/// availability degrade. Identity and dial say nothing about that, so a
/// receipt minted that way attested cleanly to a vault now running `Halt` —
/// and the relay, trusting it, skipped its own hosted pass and released
/// exactly what `Halt` exists to stop. F98's twin, on the field beside it.
#[test]
fn an_attestation_is_evidence_only_under_the_posture_that_made_it() {
    let policy = hosted_serious_crime_block();
    let proceed = PolicyModelConfig {
        hosted_outage_policy: HostedOutagePolicy::ProceedReceipted,
        ..PolicyModelConfig::default()
    };
    let halt = PolicyModelConfig {
        hosted_outage_policy: HostedOutagePolicy::Halt,
        ..PolicyModelConfig::default()
    };
    let binding = PolicyContentBinding {
        content_hash: [0x11; 32],
        read_frontier_hash: [0x22; 32],
    };
    // A pass that PROCEEDED THROUGH A DEGRADE: the posture that tolerated it
    // is exactly the question, so it is evidence only under that posture.
    let degraded = PolicyClassifyVerdict::clean_allow(binding, &proceed, PolicyPlane::HostedLegal)
        .attesting_hosted_plane(&policy, &proceed, &degraded_pass());
    assert!(
        degraded.attests_hosted_plane(&policy, &proceed),
        "the posture that tolerated it is the posture it attests under"
    );
    assert!(
        !degraded.attests_hosted_plane(&policy, &halt),
        "a pass that proceeded through an outage is not evidence for a vault that halts on one"
    );

    // A pass the MODEL ANSWERED reached the same verdict under either posture,
    // so posture is not evidence about it. Refusing it would force a re-run —
    // and a re-run under `ProceedReceipted` whose model is now unavailable
    // degrades to a NON-HALTING allow, releasing what the attested verdict
    // blocked. Strictly worse than the staleness being guarded against.
    let answered = PolicyClassifyVerdict::clean_allow(binding, &halt, PolicyPlane::HostedLegal)
        .attesting_hosted_plane(&policy, &halt, &answered_pass());
    assert!(
        answered.attests_hosted_plane(&policy, &proceed),
        "an answered pass survives a posture change; no outage was tolerated to reach it"
    );
    assert!(answered.attests_hosted_plane(&policy, &halt));

    // A degrade minted under HALT is not a posture mismatch — it is a pass
    // that never yielded a reusable verdict, because under `Halt` a degrade
    // stops the relay. The persisted verdict is a clean `Allow` all the same
    // (the halt lives on the pass), so trusting it would convert a stopped
    // pass into one whose `must_halt_relay` is false.
    let halted = PolicyClassifyVerdict::clean_allow(binding, &halt, PolicyPlane::HostedLegal)
        .attesting_hosted_plane(&policy, &halt, &degraded_pass());
    assert!(
        !halted.attests_hosted_plane(&policy, &halt),
        "a degrade under Halt halted the relay; there is no allow to reuse"
    );
    assert!(!halted.attests_hosted_plane(&policy, &proceed));

    // And the flag is DERIVED, not asserted: the constructor reads the pass,
    // so a caller cannot mark a degraded pass as model-answered.
    let derived = PolicyClassifyVerdict::clean_allow(binding, &proceed, PolicyPlane::HostedLegal)
        .attesting_hosted_plane(&policy, &proceed, &degraded_pass());
    assert_eq!(
        derived
            .hosted_attestation
            .as_deref()
            .and_then(|attestation| attestation.degraded),
        Some(true),
        "the degrade comes from the pass, not from the caller's word for it"
    );

    let attested = degraded;

    // And an attestation predating the field says nothing about posture, so it
    // is not evidence about posture — the same fail direction `classifier_mode`
    // beside it takes.
    let mut legacy = attested;
    if let Some(attestation) = legacy.hosted_attestation.as_deref_mut() {
        attestation.outage_policy = None;
    }
    assert!(
        !legacy.attests_hosted_plane(&policy, &proceed),
        "an attestation that cannot name its posture is not trusted by omission"
    );
}

/// The case the category and attestation markers each miss: a hosted CLEAN
/// ALLOW, minted by a real pass, handed to the owner door.
///
/// It carries no `HostedLegal` category (nothing decided) and no attestation
/// (only the cloud-vault verification path mints one), and
/// `relay_policy_binding` derives its binding from the SAME `content_binding`
/// against the SAME manifest as the owner path — so the staleness check has
/// nothing to catch either. If the door accepts it, a caller who passed
/// `pass.relay` when the owner verdict was a Block gets an allow.
#[test]
fn the_owner_enforce_door_and_a_production_minted_hosted_clean_allow() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = clean_backend();
    let budget = lease("hosted-clean-allow");
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let pass = block_on(vault.classify_both_planes(
        request.clone(),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &config,
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let hosted = pass
        .relay
        .boundary_verdict()
        .expect("the hosted pass ran")
        .clone();
    assert_eq!(hosted.decision, PolicyClassifyDecision::Allow);
    assert_eq!(hosted.category, PolicyVerdictCategory::None);
    assert!(hosted.hosted_attestation.is_none());

    let outcome = vault.enforce_policy_model_verdict(request.clone(), &config, hosted, false);
    assert!(
        matches!(outcome, Err(Error::PolicyVerdictNotInForce)),
        "a hosted verdict is not this door's to enforce, whatever it decided; got {outcome:?}"
    );

    // The owner half of the same pass still enforces: the door refuses a
    // PLANE, not a decision.
    assert!(
        vault
            .enforce_policy_model_verdict(request.clone(), &config, pass.owner.clone(), false)
            .is_ok()
    );

    // A verdict predating the field is REFUSED, not assumed. The fail
    // direction is the one F86 and F98 take: a refusal costs one
    // re-derivation, trusting a plane nobody wrote down costs the separation.
    let mut legacy = pass.owner;
    legacy.plane_minted = None;
    let refused_legacy = vault.enforce_policy_model_verdict(request, &config, legacy, false);
    assert!(
        matches!(refused_legacy, Err(Error::PolicyVerdictNotInForce)),
        "an unstamped verdict is not trusted by omission; got {refused_legacy:?}"
    );
    Ok(())
}

#[test]
fn the_owner_enforce_door_refuses_a_production_minted_hosted_verdict() -> Result<()> {
    // The sibling test below builds its hosted verdict with
    // `attesting_hosted_plane`, and that constructor is reached ONLY on the
    // cloud-vault verification path — the relay's own hosted passes return
    // UNATTESTED verdicts. So the sibling proves the attestation branch and
    // nothing about the mistake the door actually exists to catch.
    //
    // This one takes BOTH halves from one real `classify_both_planes` call and
    // hands over the wrong one. No test-only constructor anywhere: this is the
    // slip as a caller would make it, one field apart.
    //
    // It is a CONTRACT test, not a regression test, and the difference is
    // recorded deliberately: it still passes with both plane markers disabled,
    // because the two planes bind against different documents and the
    // staleness check refuses the verdict on its binding. That is the fact the
    // door's old comment got wrong. What this pins is the door's promise — a
    // hosted verdict never enforces here — by whichever check is holding it.
    let (_tmp, vault) = temp_vault();
    let backend = blocking_backend();
    let budget = lease("production-hosted-verdict");
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let config = PolicyModelConfig::default();
    let pass = block_on(vault.classify_both_planes(
        request.clone(),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &config,
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let hosted_verdict = pass
        .relay
        .boundary_verdict()
        .expect("the hosted pass ran")
        .clone();
    assert!(
        hosted_verdict.hosted_attestation.is_none(),
        "production hosted verdicts are unattested — that is why the attestation check alone missed this"
    );
    assert_eq!(hosted_verdict.decision, PolicyClassifyDecision::Block);

    let refused =
        vault.enforce_policy_model_verdict(request.clone(), &config, hosted_verdict, false);
    assert!(
        matches!(refused, Err(Error::PolicyVerdictNotInForce)),
        "a hosted Block must not be enforced as the owner's own; got {refused:?}"
    );

    // And the door still refuses a PLANE, not a shape: the owner half of the
    // very same pass enforces.
    assert!(
        vault
            .enforce_policy_model_verdict(request, &config, pass.owner, false)
            .is_ok(),
        "the owner half of the same pass is this door's business"
    );
    Ok(())
}

#[test]
fn the_owner_enforce_door_refuses_an_attested_hosted_verdict() -> Result<()> {
    // Covers the ATTESTATION belt specifically, and nothing wider.
    //
    // `attesting_hosted_plane` is reached only on the cloud-vault verification
    // path, so this shape is the one a VERIFIED vault-side verdict has. Built
    // by hand here because no local pass mints it — which also means this test
    // says nothing about the locally minted `pass.relay` slip. That case is
    // `the_owner_enforce_door_refuses_a_production_minted_hosted_verdict`,
    // and the two are kept apart on purpose: the version of this test that
    // claimed to cover both is what let F106 ship believing it had.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    // Built from the OWNER verdict for this very request, then marked as
    // hosted-attested. Binding, selector and frontier are therefore identical
    // to what the door would derive — the staleness check has nothing to catch,
    // and the attestation is the only thing separating the two. That is the
    // real shape of the mistake: one field of a `DualPlanePass` instead of the
    // other.
    let owner_verdict = vault.classify_policy_model_with_config(request.clone(), &config)?;
    let hosted_verdict = owner_verdict.clone().attesting_hosted_plane(
        &registered_policy(&registry),
        &config,
        &answered_pass(),
    );
    assert!(
        !vault.policy_model_verdict_is_stale_with_config(&hosted_verdict, &request, &config)?,
        "the staleness check cannot tell the planes apart — that is why this door must"
    );

    let refused =
        vault.enforce_policy_model_verdict(request.clone(), &config, hosted_verdict, false);
    assert!(matches!(refused, Err(Error::PolicyVerdictNotInForce)));

    // The owner's own verdict for the same request still enforces. The door
    // refuses a PLANE, not a shape.
    assert!(
        vault
            .enforce_policy_model_verdict(request, &config, owner_verdict, false)
            .is_ok()
    );
    Ok(())
}

#[test]
fn the_documented_dual_plane_flow_receipts_one_owner_decision() -> Result<()> {
    // `classify_both_planes` decides, then hands the owner half back for the
    // vault to enforce, and `enforce_policy_model_verdict` is the door it
    // hands it to. One decision, so one row: two would count the same warn
    // twice in the pattern-tuning totals those rows exist for, under two
    // different outcome names.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x73),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;
    let backend = RendezvousBackend::new();
    let budget = lease("one-owner-receipt");
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let pass = block_on(vault.classify_both_planes(
        request.clone(),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Warn);

    let enforcement = vault.enforce_policy_model_verdict(
        request,
        &PolicyModelConfig::default(),
        pass.owner,
        pass.owner_model_skipped,
    )?;
    assert_eq!(enforcement.action, PolicyEnforcementAction::Warn);
    assert_eq!(
        enforcement.receipt_ref, None,
        "the producing door owns the row, so enforcement returns no receipt of its own",
    );

    let receipts = gate_receipts(&vault)?;
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.outcome == "owner_plane_warn")
            .count(),
        1,
        "the deciding door writes the owner plane's one row",
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.outcome == "warn")
            .count(),
        0,
        "enforcement must not re-record the decision under its own outcome",
    );
    Ok(())
}

#[test]
fn enforcing_a_verdict_about_other_content_is_refused() -> Result<()> {
    // Request, config and verdict arrive here as three independent arguments,
    // so nothing but this check stops a caller enforcing one question's answer
    // against another question's content. A verdict decided about a blocked
    // string would otherwise halt an unrelated reply — and be receipted
    // against that reply's metadata.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x74),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers.",
                "block",
            )]),
            owner_patterns(vec![owner_pattern(
                "owner.spoilers",
                "(?i)spoiler",
                "owner:spoilers",
                Some("decide"),
            )]),
        ]),
    )?;
    let spoiler_request = PolicyClassifyRequest::outbound_content("This reply contains spoilers.");
    let blocked = vault.classify_policy_model(spoiler_request.clone())?;
    assert_eq!(blocked.decision, PolicyClassifyDecision::Block);

    // Its own request still enforces.
    let honest = vault.enforce_policy_model_verdict(
        spoiler_request,
        &PolicyModelConfig::default(),
        blocked.clone(),
        false,
    )?;
    assert_eq!(honest.action, PolicyEnforcementAction::Block);

    // Another request's content does not.
    let other_request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let refused = vault.enforce_policy_model_verdict(
        other_request,
        &PolicyModelConfig::default(),
        blocked,
        false,
    );
    assert!(
        matches!(refused, Err(Error::PolicyVerdictNotInForce)),
        "a verdict about other content must be refused, not enforced",
    );
    Ok(())
}

#[test]
fn enforcing_a_verdict_the_manifest_moved_under_is_refused() -> Result<()> {
    // The other half of the same check: the verdict IS this request's, but the
    // owner edited the policy since it was decided. This door has no model to
    // re-derive with, so it sends the caller back rather than enforcing a rule
    // that may no longer say what it said.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x75),
        &enabled_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")]),
    )?;
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let verdict = vault.classify_policy_model(request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    put_policy_manifest_bytes(
        &vault,
        test_id(0x75),
        &enabled_owner_manifest(vec![
            owner_row("owner:jargon", "Avoid jargon."),
            owner_row_with_action("owner:spoilers", "Block spoilers.", "block"),
        ]),
    )?;
    let refused =
        vault.enforce_policy_model_verdict(request, &PolicyModelConfig::default(), verdict, false);
    assert!(
        matches!(refused, Err(Error::PolicyVerdictNotInForce)),
        "a verdict the manifest moved under must be refused, not enforced",
    );
    Ok(())
}

#[test]
fn a_dual_plane_owner_model_failure_leaves_a_fail_open_row() -> Result<()> {
    // The owner plane is sovereign, so a downed model resolves to `Allow` and
    // the content flows. Recording nothing would make that indistinguishable
    // from a clean allow the model actually examined — the ledger has to say
    // the plane fell open.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "block",
            )],
            Vec::new(),
        ),
    )?;
    let budget = lease("owner-fail-open");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        Some(tier(&FailingPolicyBackend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Allow);
    assert!(pass.owner_model_skipped);

    let receipts = gate_receipts(&vault)?;
    let owner_row = receipts
        .iter()
        .find(|receipt| receipt.outcome == "owner_plane_allow")
        .expect("a fail-open allow is still a row");
    assert!(has_trace(owner_row, "gate.relay.owner_plane.model_skipped"));
    assert!(has_trace(owner_row, "gate.relay.owner_plane.fail_open"));
    Ok(())
}

#[test]
fn both_planes_stay_separate_when_only_one_is_configured() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // No owner plane at all: the hosted plane still decides the relay, and the
    // owner's verdict is a clean allow rather than a borrowed hosted one.
    let backend = blocking_backend();
    let budget = lease("one-plane");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Allow);
    assert_eq!(pass.owner.category, PolicyVerdictCategory::None);
    assert!(pass.relay.must_halt_relay());
    Ok(())
}
