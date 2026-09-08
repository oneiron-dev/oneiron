//! Receipt-time binding rechecks, manifest movement mid-call, citations/parse bounds, streaming rationale audit.

use super::*;

#[test]
fn an_oversized_rule_id_array_cannot_flood_the_ledger() -> Result<()> {
    // The array is model-supplied and nobody validated it, and every id
    // becomes a reason code. What holds the flood off is no longer a number
    // the engine picked: it is that none of these ids name a rule the plane
    // resolved, so none of them earn a row. The count of what went does.
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let flood: Vec<String> = (0..1_280).map(|index| format!("\"SC-{index}\"")).collect();
    let body = format!(
        r#"{{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":[{}],"confidence":"high","rationale":"flood"}}"#,
        flood.join(",")
    );
    let backend = StaticPolicyBackend { body };
    let budget = lease("rule-id-flood");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    assert!(audit.model_rule_ids.is_empty(), "none of them resolved");
    assert_eq!(audit.model_rule_ids_dropped, 1_280);
    // Dropped, not refused: a model that cites rules nobody wrote is a model
    // to fix, and the verdict it carried still stands.
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    let receipts = gate_receipts(&vault)?;
    assert_eq!(
        trace_count(&receipts[0], "gate.policy_model.model_rule."),
        0,
        "1280 unresolvable citations bought zero ledger rows",
    );
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.model_rule_ids_dropped.1280"
    ));
    Ok(())
}

#[test]
fn an_answer_citing_past_the_parse_bound_is_unreadable_rather_than_materialized() -> Result<()> {
    // The resolvable-set filter is what keeps junk out of the ledger, but it
    // runs AFTER the reader has built the vector. This bound is the flood stop
    // in front of that: past it the answer is refused, not truncated, so no
    // valid citation is silently dropped and no unbounded allocation happens
    // on a model's say-so. An unreadable answer degrades the hosted pass,
    // which is a case the plane already handles.
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let flood: Vec<String> = (0..=super::contract::POLICY_MODEL_RULE_IDS_PARSE_MAX)
        .map(|index| format!("\"SC-{index}\""))
        .collect();
    let body = format!(
        r#"{{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":[{}],"confidence":"high","rationale":"flood"}}"#,
        flood.join(",")
    );
    let backend = StaticPolicyBackend { body };
    let budget = lease("rule-id-parse-bound");

    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelResponseUnusable),
        "an answer past the bound is unreadable, not a verdict"
    );
    // One under the bound still reads, so the bound refuses only the flood.
    let ok_flood: Vec<String> = (0..super::contract::POLICY_MODEL_RULE_IDS_PARSE_MAX)
        .map(|index| format!("\"SC-{index}\""))
        .collect();
    let readable = StaticPolicyBackend {
        body: format!(
            r#"{{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":[{}],"confidence":"high","rationale":"verbose"}}"#,
            ok_flood.join(",")
        ),
    };
    let (_tmp2, vault2) = temp_vault();
    let budget2 = lease("rule-id-parse-bound-edge");
    let readable_pass = relay_pass(
        &vault2,
        BOMB_CONTENT,
        &hosted_edge_registry(HostedLegalPolicy {
            output_contract: Some(PolicyOutputContract::RationaleJson),
            ..hosted_serious_crime_block()
        }),
        &PolicyModelConfig::default(),
        Some(tier(&readable, &budget2)),
    )?;
    assert_eq!(readable_pass.degraded(), None);
    assert_eq!(
        readable_pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    Ok(())
}

#[test]
fn a_citation_naming_no_resolved_rule_is_dropped_and_the_loss_is_visible() -> Result<()> {
    // Half the ruling: a citation the engine cannot resolve is a claim about a
    // rule that does not exist, and carrying it into a receipt as though the
    // engine had checked it is the thing being fixed. The other half is that
    // the loss must be readable, so the count lands in the audit and the
    // ledger.
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let backend = static_backend(
        r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["serious_crime","EU-AI-ACT-5","serious_crime","hallucinated"],"confidence":"high","rationale":"cited"}"#,
    );
    let budget = lease("unresolvable-citations");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    assert_eq!(
        audit.model_rule_ids,
        vec!["serious_crime".to_owned()],
        "the resolvable one survives, once, in the order the model gave it",
    );
    assert_eq!(
        audit.model_rule_ids_dropped, 2,
        "the two invented ids; the repeat lost nothing and is not counted",
    );

    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.model_rule.serious_crime"
    ));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.model_rule_ids_dropped.2"
    ));
    assert!(
        !has_trace(&receipts[0], "gate.policy_model.model_rule.eu-ai-act-5"),
        "an unresolvable citation never becomes a ledger key",
    );
    Ok(())
}

#[test]
fn an_owner_answer_citing_a_row_it_was_shown_keeps_the_citation() -> Result<()> {
    // The owner plane publishes its rows as `row_ref`, so that is what
    // resolves there. Pinned separately because the two planes name their
    // rules differently and a check written for one could silently drop
    // everything on the other.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x81),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:jargon", "Avoid nautical jargon.")]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("rationale_json"),
        ]),
    )?;
    let backend = static_backend(
        r#"{"violation":1,"policy_category":"owner:jargon","rule_ids":["owner:jargon","owner:invented"],"confidence":"high","rationale":"nautical"}"#,
    );

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing."),
        &PolicyModelConfig::default(),
        &backend,
        &lease("owner-citations"),
    ))?;

    let audit = verdict.audit.as_deref().expect("audit");
    assert_eq!(audit.model_rule_ids, vec!["owner:jargon".to_owned()]);
    assert_eq!(audit.model_rule_ids_dropped, 1);
    Ok(())
}

#[test]
fn the_receipt_write_refuses_a_binding_that_moved_after_the_pass() -> Result<()> {
    // The pass re-checks its binding and returns; the row is written in a
    // SEPARATE transaction afterwards. Nothing in the relay entry point can
    // inject a manifest move into that gap, so the unit that closes it is
    // driven directly: a pass carrying a binding that is already stale by the
    // time the row is written.
    //
    // Without the re-check the row would assert that stale binding, and a
    // later CloudVault verification recomputing the hash locally would find a
    // receipt attesting policy state nobody can reproduce.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let hosted = hosted_serious_crime_block();
    let stale = PolicyContentBinding {
        content_hash: [0x5a; 32],
        read_frontier_hash: [0x5a; 32],
    };
    let pass = RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(stale, &config, PolicyPlane::HostedLegal),
        None,
        true,
        RelayResolution::ModelDecided,
    );
    let verdict = pass.boundary_verdict().expect("verdict").clone();

    let replacement = vault.append_relay_receipt_binding_checked(
        &super::relay::RelayReceipt {
            request: &request,
            domain: &hosted_witness(),
            pass: &pass,
            receipt_breach: None,
            hosted: Some(&hosted),
            config: &config,
        },
        &verdict,
        "relay_boundary_allow",
        vec!["gate.relay.classify.ran".to_owned()],
        Vec::new(),
        super::relay::RelayReceiptRow::Always,
    )?;

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(
        has_trace(
            &receipts[0],
            "gate.relay.degraded.policy_binding_moved_mid_pass"
        ),
        "the row records the degrade rather than the dead binding"
    );

    // The row is only half of it. A receipt that says the relay stopped, on a
    // pass that says it may proceed, is a record nobody honours — so the write
    // hands BACK the degraded pass and the caller relays that one.
    let replacement = replacement.expect("a moved binding replaces the caller's pass");
    assert_eq!(
        replacement.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass)
    );
    assert!(
        replacement.must_halt_relay(),
        "a binding move is not an availability degrade, so it halts under either outage policy"
    );
    assert!(
        !pass.must_halt_relay(),
        "the pass handed IN did not halt — which is exactly why the replacement has to travel"
    );
    Ok(())
}

/// No hosted policy bound means no receipt-time binding check, in parity with
/// the mid-pass seam.
///
/// `hosted_relay_pass` skips its own comparison whenever `hosted.is_none()` —
/// with nothing bound to the attested identity there is nothing to pin. The
/// receipt write has to skip on the same condition or the SAME event produces
/// a degrade one seam later than it possibly could, and a `NoPolicyInPlay`
/// fallback (reachable through a receipt breach) comes back HALTING on a
/// hosted plane that was never in play — `must_halt_relay` turns on exactly
/// that flag.
#[test]
fn a_pass_with_no_hosted_policy_skips_the_receipt_time_recheck() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let stale = PolicyContentBinding {
        content_hash: [0x5a; 32],
        read_frontier_hash: [0x5a; 32],
    };
    // No hosted policy in play, and a vault receipt that failed verification —
    // the CloudVault fallback shape.
    let pass = RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(stale, &config, PolicyPlane::HostedLegal),
        None,
        false,
        RelayResolution::NoPolicyInPlay,
    );
    let verdict = pass.boundary_verdict().expect("verdict").clone();
    assert!(!pass.hosted_policy_in_play());

    let replacement = vault.append_relay_receipt_binding_checked(
        &super::relay::RelayReceipt {
            request: &request,
            domain: &cloud_witness(),
            pass: &pass,
            receipt_breach: Some("missing"),
            hosted: None,
            config: &config,
        },
        &verdict,
        "relay_boundary_allow",
        vec![
            "gate.relay.classify.ran".to_owned(),
            "gate.relay.vault_receipt_untrusted.missing".to_owned(),
        ],
        Vec::new(),
        super::relay::RelayReceiptRow::Always,
    )?;

    // PARITY with the mid-pass seam, which skips its own comparison whenever
    // `hosted.is_none()`. With nothing bound to the attested identity there is
    // nothing to pin, so a stale-looking binding is not a move — and the pass
    // must come back exactly as it went in, never as a halting replacement for
    // a hosted plane that was never in play.
    assert!(
        replacement.is_none(),
        "no hosted policy means no re-check, so no replacement"
    );

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(
        has_trace(&receipts[0], "gate.relay.vault_receipt_untrusted.missing"),
        "the breach that caused the fallback is on the row"
    );
    // Derived from the pass rather than hardcoded. It reads `ran` here because
    // `ran_relay_classify` is true for every `Classified` pass, and only a
    // classified pass can reach this branch at all — a pass with no boundary
    // verdict pins nothing, so the re-check never fires for one.
    assert!(
        has_trace(&receipts[0], "gate.relay.classify.ran"),
        "the classify code is derived from the pass"
    );
    Ok(())
}

/// The replacement row keeps the evidence that explains why the pass ran.
///
/// Replacing the VERDICT does not replace the reason the pass took the shape
/// it did. An untrusted vault receipt is why the hosted fallback happened at
/// all, and the first version of this branch rebuilt the row's codes from
/// scratch and dropped it — leaving a ledger that could no longer say a vault
/// receipt had failed.
#[test]
fn a_replacement_row_keeps_the_breach_that_caused_the_fallback() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let hosted = hosted_serious_crime_block();
    let stale = PolicyContentBinding {
        content_hash: [0x5a; 32],
        read_frontier_hash: [0x5a; 32],
    };
    let audit = PolicyPassAudit {
        model_rationale: Some(RATIONALE_TEXT.to_owned()),
        ..PolicyPassAudit::default()
    };
    let pass = RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(stale, &config, PolicyPlane::HostedLegal)
            .with_audit(audit),
        None,
        true,
        RelayResolution::ModelDecided,
    );
    let verdict = pass.boundary_verdict().expect("verdict").clone();

    let replacement = vault
        .append_relay_receipt_binding_checked(
            &super::relay::RelayReceipt {
                request: &request,
                domain: &cloud_witness(),
                pass: &pass,
                receipt_breach: Some("missing"),
                hosted: Some(&hosted),
                config: &config,
            },
            &verdict,
            "relay_boundary_allow",
            vec!["gate.relay.classify.ran".to_owned()],
            Vec::new(),
            super::relay::RelayReceiptRow::Always,
        )?
        .expect("a hosted pass whose binding moved is replaced");
    assert_eq!(
        replacement.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass)
    );

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(
        has_trace(&receipts[0], "gate.relay.vault_receipt_untrusted.missing"),
        "the breach survives the verdict being replaced: {:?}",
        receipts[0]
    );

    // The other carrier of the same rule. The model's RATIONALE has no reason
    // code — its only durable form is the audit notice — so a replacement row
    // built with an empty notice list threw away what the model said about the
    // substrate owner's rules, which is the loop the whole design turns on.
    assert!(
        receipts[0]
            .fields
            .get("system_notice")
            .is_some_and(|notice| notice.contains(RATIONALE_TEXT)),
        "the model's rationale survives the verdict being replaced: {:?}",
        receipts[0]
    );
    Ok(())
}

/// A signalless clean allow writes no row — but it still holds a pinned binding
/// the relay is about to act on, so it takes the re-check anyway. If the
/// binding moved, the move IS the signal and earns the degrade row it would
/// otherwise never write.
#[test]
fn a_signalless_allow_still_takes_the_receipt_time_binding_check() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let hosted = hosted_serious_crime_block();

    // Unmoved: a fresh binding, nothing to catch, and still no row.
    let policy = vault.with_write_txn(|wtxn| gate::resolve_policy_manifest(&vault.store, wtxn))?;
    let live = super::binding::content_binding(&request, &policy, &config)?;
    let clean = RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(live, &config, PolicyPlane::HostedLegal),
        None,
        true,
        RelayResolution::ModelDecided,
    );
    let unmoved = vault.record_relay_receipt_for_test(
        &request,
        &hosted_witness(),
        &clean,
        Some(&hosted),
        &config,
    )?;
    assert!(
        unmoved.is_none(),
        "an unmoved signalless allow is left alone"
    );
    assert!(
        gate_receipts(&vault)?.is_empty(),
        "and still writes no row — the ledger contract is unchanged"
    );

    // Moved: the same shape, a stale binding. Now it degrades and says so.
    let stale = PolicyContentBinding {
        content_hash: [0x5a; 32],
        read_frontier_hash: [0x5a; 32],
    };
    let signalless = RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(stale, &config, PolicyPlane::HostedLegal),
        None,
        true,
        RelayResolution::ModelDecided,
    );
    assert!(!signalless.must_halt_relay());
    let moved = vault
        .record_relay_receipt_for_test(
            &request,
            &hosted_witness(),
            &signalless,
            Some(&hosted),
            &config,
        )?
        .expect("a moved binding replaces even a signalless allow");
    assert_eq!(
        moved.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass)
    );
    assert!(moved.must_halt_relay());
    assert_eq!(gate_receipts(&vault)?.len(), 1);
    Ok(())
}

#[test]
fn a_manifest_moving_after_the_pass_is_caught_by_the_receipt_write() -> Result<()> {
    // The pass re-checks its binding and returns; the row is written in a
    // separate transaction afterwards. A manifest that moves in THAT gap would
    // otherwise be receipted under a binding nobody can reproduce — the same
    // hole the mid-pass re-check closes one seam earlier.
    //
    // The move is staged between the two by writing the manifest from the
    // backend, which returns after the pass's own re-check has run: the pass
    // settles, and the receipt write is the next thing to look.
    let (_tmp, vault) = temp_vault();
    // The moving backend rewrites THIS id, so the seed must use it too — a
    // second manifest id would duplicate the row_ref across manifests and the
    // resolver would drop the rows instead of moving the frontier.
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("receipt-binding-recheck");

    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    // The pass itself already degrades here — that is the mid-pass re-check
    // doing its job. What this pins is that the ROW says so, written under a
    // binding the ledger can reproduce rather than the dead one.
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass)
    );
    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| has_trace(receipt, "gate.relay.degraded.policy_binding_moved_mid_pass")),
        "the degrade names itself in the ledger"
    );
    Ok(())
}

#[test]
fn a_manifest_that_moved_mid_call_is_not_enforced_stale() -> Result<()> {
    // The pass snapshots the manifest, then awaits a round trip. An owner who
    // tightens `warn` to `block` during that await must not have the
    // pre-change verdict enforced against post-change policy: the engine would
    // be acting on a rule that no longer exists.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":1,"policy_category":"owner:spoilers"}"#,
        keep_moving: false,
        calls: AtomicUsize::new(0),
    };
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("a reply with spoilers"),
        &PolicyModelConfig::default(),
        &backend,
        &lease("stale-manifest"),
    ))?;

    // Re-derived against what is in force: the row is a block now.
    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.outbound_halted);
    assert!(outcome.final_content.is_none());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn a_relay_manifest_that_moved_mid_call_is_derived_again() -> Result<()> {
    // The hosted plane's half of the same window. Its pass binds a verdict to
    // the vault's policy state, then awaits a round trip; state that moves
    // during that await leaves the pass about to receipt under a frontier
    // nobody could recompute. Derived again, ONCE, exactly as the owner plane
    // does at its enforcement door.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: false,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("relay-stale-manifest");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        2,
        "derived again, once"
    );
    assert_eq!(pass.degraded(), None, "the second derivation settled");
    assert_eq!(pass.resolution(), Some(RelayResolution::ModelDecided));
    assert!(!pass.must_halt_relay());
    Ok(())
}

#[test]
fn a_relay_manifest_that_will_not_settle_degrades_the_hosted_pass() -> Result<()> {
    // Derived twice and stale twice. Here the two planes part: the owner plane
    // is sovereign and fails OPEN, the hosted plane is fail-CLOSED. A verdict
    // it cannot pin to a policy is exactly the unexamined allow this plane
    // exists to refuse, so it degrades — and a degrade with a hosted policy in
    // play halts the relay.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("relay-unsettled-manifest");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        2,
        "derived twice, no more"
    );
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass),
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::Unresolved));
    assert!(
        pass.must_halt_relay(),
        "the hosted plane is fail-closed: an unpinnable verdict stops the relay",
    );

    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| has_trace(receipt, "gate.relay.degraded.policy_binding_moved_mid_pass")),
        "the degrade names itself in the ledger",
    );
    Ok(())
}

#[test]
fn a_manifest_that_will_not_settle_fails_the_owner_plane_open_with_a_receipt() -> Result<()> {
    // Derived twice and stale twice: the manifest is moving faster than a pass
    // can be taken. The owner plane is sovereign, so it lets the content
    // through — and leaves a row saying that is what happened, rather than
    // enforcing a rule it cannot name.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":1,"policy_category":"owner:spoilers"}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let original = "a reply with spoilers";
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content(original),
        &PolicyModelConfig::default(),
        &backend,
        &lease("unsettled-manifest"),
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.final_content.as_deref(), Some(original));
    assert!(outcome.custom_tier_skipped);
    assert!(outcome.receipt_ref.is_some());
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts[0].outcome, "owner_plane_stale_fail_open");
    assert!(has_trace(&receipts[0], "gate.policy_model.stale_manifest"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.owner_plane_fail_open"
    ));
    Ok(())
}

#[test]
fn an_answer_split_across_content_parts_is_read_whole() -> Result<()> {
    // Reading only the first non-blank part parses a fragment, a fragment is
    // an unreadable answer, and an unreadable answer HALTS the hosted relay —
    // so a provider that chunks its output would take the plane down for a
    // reason that was never about the content.
    let (_tmp, vault) = temp_vault();
    let backend = SplitAnswerBackend {
        parts: vec![
            r#"{"violation":1,"#,
            "  ",
            r#""policy_category":"hosted_legal/serious_crime"}"#,
        ],
    };
    let budget = lease("split-answer");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert!(pass.degraded().is_none(), "a split answer is not a degrade");
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::ModelDecided));
    Ok(())
}

#[test]
fn the_model_rationale_is_an_audit_row_not_a_reader_notice() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let backend = static_backend(
        r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":[],"confidence":"high","rationale":"model reasoning the reader is not shown"}"#,
    );
    let budget = lease("rationale-audience");
    relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let receipts = gate_receipts(&vault)?;
    let receipt = &receipts[0];
    // The FIRST notice — the one a caller surfaces — is the reader's, and it
    // does not carry the model's reasoning.
    let body = receipt.fields.get("system_notice").expect("notice body");
    assert!(!body.contains("model reasoning"));
    assert_eq!(
        receipt
            .fields
            .get("system_notice_audience")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL)
    );
    // The audit row rides in the same receipt, named for what it is.
    assert!(has_trace(
        receipt,
        &format!("gate.system_notice.{SYSTEM_NOTICE_TYPE_MODEL_RATIONALE}")
    ));
    Ok(())
}

#[test]
fn a_clean_allow_keeps_the_rationale_for_the_pattern_that_fired() -> Result<()> {
    // The row the design turns on: an `Escalate` pattern fired, the model
    // looked and said `violation: 0`, and its stated reason is exactly the
    // data that tells the substrate owner their pattern is too wide. A clean
    // allow attributes itself to no plane, so deriving the plane from the
    // verdict's category dropped the audit row precisely here — the calling
    // plane is passed instead, because both call sites know it statically.
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_policy_with_rules(vec![escalate_rule("hosted.bomb", "(?i)bomb")])
    };
    let backend = static_backend(
        r#"{"violation":0,"policy_category":null,"rule_ids":[],"confidence":"high","rationale":"the passage discusses policy history, not method"}"#,
    );
    let budget = lease("clean-allow-rationale");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    let verdict = pass.boundary_verdict().expect("verdict");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    assert_eq!(verdict.plane(), None);

    let notice = super::notice::policy_model_rationale_notice(
        verdict,
        PolicyPlane::HostedLegal,
        Some(HOSTED_VERSION),
    )
    .expect("a clean allow with a rationale still files its audit row");
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_AUDIT);
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::HostedLegal.as_str())
    );
    assert_eq!(
        notice.body,
        "the passage discusses policy history, not method"
    );

    // And it reaches the ledger, not just the caller.
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        &format!("gate.system_notice.{SYSTEM_NOTICE_TYPE_MODEL_RATIONALE}")
    ));
    Ok(())
}

#[test]
fn the_audit_notice_names_its_own_channel_and_audience() {
    let binding = relay_skip_content_binding(&PolicyClassifyRequest::outbound_content("candidate"));
    let verdict = PolicyClassifyVerdict::new(
        PolicyClassifyDecision::Warn,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:row".to_owned(),
        },
        PolicyConfidence::MEDIUM,
        binding,
        &PolicyModelConfig::default(),
        PolicyPlane::OwnerPolicy,
    )
    .with_audit(PolicyPassAudit {
        model_rationale: Some("because the policy says so".to_owned()),
        ..PolicyPassAudit::default()
    });
    let notice =
        super::notice::policy_model_rationale_notice(&verdict, PolicyPlane::OwnerPolicy, None)
            .expect("a rationale produces an audit row");
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_AUDIT);
    assert_eq!(notice.channel, SYSTEM_NOTICE_CHANNEL_AUDIT);
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_MODEL_RATIONALE);
    assert_eq!(notice.body, "because the policy says so");
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    // The owner plane publishes no versioned document, so it names no version.
    assert_eq!(notice.policy_version, None);

    // No rationale, no row.
    let bare = PolicyClassifyVerdict::clean_allow(
        binding,
        &PolicyModelConfig::default(),
        PolicyPlane::OwnerPolicy,
    );
    assert!(
        super::notice::policy_model_rationale_notice(&bare, PolicyPlane::OwnerPolicy, None)
            .is_none()
    );
}
