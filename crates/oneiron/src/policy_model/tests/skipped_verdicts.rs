//! A policy the owner's model never read is SKIPPED, never a clean allow.
//!
//! Security pack 2, F14 (H121, H122) and F26 (H383): no backend, a failed or
//! unreadable model answer and an exhausted classifier budget each used to come
//! back as a high-confidence `Allow` that looked exactly like a real answer.

use super::*;
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};
use crate::off_record::OffRecordBackendClass;
use crate::off_record::anonymous_chat::{
    AnonymousChatResponder, AnonymousChatSkippedCheck, AnonymousChatTarget, AnonymousChatTurn,
};

/// An owner plane with a written policy and no pattern rule: only the model
/// can classify against it.
fn documented_vault() -> Result<(TempDir, Vault)> {
    let (tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0xb7),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;
    Ok((tmp, vault))
}

fn exhausted_budget() -> BudgetGuard {
    // A reserve above the limit: admission is refused before any model call.
    BudgetGuard::with_reserve_units("skipped-exhausted", 0, 10, BudgetExhaustionPolicy::Suspend)
}

struct EchoResponder;

impl AnonymousChatResponder for EchoResponder {
    fn respond<'a>(
        &'a self,
        _target: AnonymousChatTarget,
        _text: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async { Ok("a plain answer".to_owned()) })
    }
}

#[test]
fn a_policy_no_model_read_is_never_a_clean_allow() -> Result<()> {
    let (_tmp, vault) = documented_vault()?;
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();

    // H121: no model in reach at all.
    let bare = vault.classify_policy_model(request.clone())?;
    assert_ne!(
        bare.decision,
        PolicyClassifyDecision::Allow,
        "H121: the bare door had no model and still certified the content"
    );
    assert_eq!(
        bare.decision,
        PolicyClassifyDecision::Skipped(PolicySkipReason::NoBackend)
    );
    assert_eq!(bare.confidence.calibrated, 0.0, "nothing examined it");
    let enforced = vault.enforce_policy_model(request.clone())?;
    assert_ne!(
        enforced.action,
        PolicyEnforcementAction::Allow,
        "H121: the bare enforce door"
    );
    assert_skipped_delivery(&enforced, PolicySkipReason::NoBackend);

    // H122: the model failed, or answered something unreadable.
    let unreadable = static_backend("not json at all");
    for (leg, backend, reason) in [
        (
            "failed",
            &FailingPolicyBackend as &dyn LlmBackend,
            PolicySkipReason::BackendUnavailable,
        ),
        (
            "unreadable",
            &unreadable as &dyn LlmBackend,
            PolicySkipReason::ResponseUnusable,
        ),
    ] {
        let verdict = block_on(vault.classify_policy_model_with_backend(
            request.clone(),
            &config,
            backend,
            &lease(leg),
        ))?;
        assert_ne!(
            verdict.decision,
            PolicyClassifyDecision::Allow,
            "H122 ({leg}): classify"
        );
        assert_eq!(verdict.decision, PolicyClassifyDecision::Skipped(reason));
        let outcome = block_on(vault.enforce_policy_model_with_backend(
            request.clone(),
            &config,
            backend,
            &lease(leg),
        ))?;
        assert_ne!(
            outcome.action,
            PolicyEnforcementAction::Allow,
            "H122 ({leg}): enforce"
        );
        assert_skipped_delivery(&outcome, reason);
        // A caller re-enforcing the verdict cannot erase the skip with its flag.
        let reenforced =
            vault.enforce_policy_model_verdict(request.clone(), &config, verdict, false)?;
        assert_eq!(reenforced.action, PolicyEnforcementAction::Skipped);
        assert!(reenforced.custom_tier_skipped);
    }
    let receipts = gate_receipts(&vault)?;
    for code in [
        "gate.policy_model.skip_reason.no_backend",
        "gate.policy_model.skip_reason.backend_unavailable",
        "gate.policy_model.skip_reason.response_unusable",
    ] {
        assert!(
            receipts.iter().any(|receipt| has_trace(receipt, code)),
            "every skip is receipted with its cause: {code}"
        );
    }

    // H383: the classifier budget is exhausted.
    let backend = CountingPolicyBackend::clean();
    let (decision, _) = block_on(crate::policy_model::stateless_owner_classification(
        &vault,
        CLEAN_CONTENT,
        &config,
        &backend,
        &exhausted_budget(),
    ))?;
    assert_eq!(backend.calls(), 0, "admission was refused before any call");
    assert_ne!(
        decision,
        PolicyClassifyDecision::Allow,
        "H383: an exhausted budget is not a clean answer"
    );
    let session = vault.open_anonymous_chat("skipped", OffRecordBackendClass::Local)?;
    let turn = block_on(session.chat(
        "an ordinary question",
        AnonymousChatTarget::HouseMind,
        &EchoResponder,
        &backend,
        &exhausted_budget(),
        &config,
    ))?;
    assert!(
        matches!(turn, AnonymousChatTurn::Reply { .. }),
        "the owner's own chat continues"
    );
    assert_eq!(
        decision,
        PolicyClassifyDecision::Skipped(PolicySkipReason::BudgetExhausted)
    );
    let AnonymousChatTurn::Reply { skipped_checks, .. } = turn else {
        panic!("the owner's own chat continues");
    };
    assert_eq!(
        skipped_checks,
        [true, false].map(|input| AnonymousChatSkippedCheck {
            input,
            reason: PolicySkipReason::BudgetExhausted,
        }),
        "H383: the reply says neither direction was checked"
    );
    assert_eq!(backend.calls(), 0);
    Ok(())
}

/// The owner's content still goes out — that plane is sovereign — but as a
/// skip the caller can see, never as an allow.
fn assert_skipped_delivery(outcome: &PolicyModelEnforcement, reason: PolicySkipReason) {
    assert_eq!(outcome.action, PolicyEnforcementAction::Skipped);
    assert_eq!(
        outcome.verdict.decision,
        PolicyClassifyDecision::Skipped(reason)
    );
    assert!(outcome.custom_tier_skipped);
    assert!(!outcome.outbound_halted);
    assert_eq!(outcome.final_content.as_deref(), Some(CLEAN_CONTENT));
    assert!(outcome.receipt_ref.is_some(), "a skip is never silent");
}

/// The positive control: a model that answered "no violation" is a real allow.
#[test]
fn a_clean_model_answer_is_still_a_clean_allow() -> Result<()> {
    let (_tmp, vault) = documented_vault()?;
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        request,
        &PolicyModelConfig::default(),
        &clean_backend(),
        &lease("answered"),
    ))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.verdict.decision, PolicyClassifyDecision::Allow);
    assert!(!outcome.custom_tier_skipped);
    assert_eq!(outcome.final_content.as_deref(), Some(CLEAN_CONTENT));
    Ok(())
}

/// A clean answer whose generation did not finish.
struct UnfinishedBackend(FinishReason);

impl LlmBackend for UnfinishedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let mut response = text_response(r#"{"violation":0,"policy_category":null}"#.to_owned());
        response.finish_reason = self.0.clone();
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// H122, partial answer: a cut, filtered, cancelled, paused or tool-pending
/// answer is not a verdict, however cleanly its text parses, and neither is a
/// fallback runner's reply. The finished answer is the control above.
#[test]
fn an_unfinished_model_answer_is_never_a_clean_allow() -> Result<()> {
    let (_tmp, vault) = documented_vault()?;
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    for finish in [
        FinishReason::Length,
        FinishReason::ContentFiltered,
        FinishReason::Cancelled,
        FinishReason::ToolCalls,
        FinishReason::Other {
            name: "pause_turn".to_owned(),
        },
        FinishReason::Other {
            name: "model_context_window_exceeded".to_owned(),
        },
        FinishReason::Other {
            name: "fallback:fail_closed:Unavailable".to_owned(),
        },
    ] {
        let verdict = block_on(vault.classify_policy_model_with_backend(
            request.clone(),
            &PolicyModelConfig::default(),
            &UnfinishedBackend(finish.clone()),
            &lease("unfinished"),
        ))?;
        assert_eq!(
            verdict.decision,
            PolicyClassifyDecision::Skipped(PolicySkipReason::ResponseUnusable),
            "H122: an unfinished answer ({finish:?}) became a verdict"
        );
    }
    Ok(())
}

/// H121, caller-reported state: a caller that says the owner model was skipped
/// cannot have the same verdict enforced as an Allow.
#[test]
fn a_reported_skip_never_rides_an_allow() -> Result<()> {
    let (_tmp, vault) = documented_vault()?;
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let verdict = block_on(vault.classify_policy_model_with_backend(
        request.clone(),
        &config,
        &clean_backend(),
        &lease("answered"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert!(
        vault
            .enforce_policy_model_verdict(request.clone(), &config, verdict.clone(), true)
            .is_err(),
        "H121: a reported skip was enforced as an Allow"
    );
    let answered = vault.enforce_policy_model_verdict(request, &config, verdict, false)?;
    assert_eq!(answered.action, PolicyEnforcementAction::Allow);
    Ok(())
}

/// H122, receipt reuse: a hosted pass that halted because the manifest kept
/// moving left nothing to reuse. A vault-side runner attesting it under
/// `ProceedReceipted` used to give a later cloud relay a trusted Allow and
/// no hosted pass. So did an outage that halted under `Halt` (the runner
/// supplied the posture), and passes that never ran a hosted policy at all:
/// BYO, a trusted replay, and a pass with no hosted policy in play. A real
/// outage the host tolerated under `ProceedReceipted` is still reusable, the
/// control.
#[test]
fn a_halted_hosted_pass_is_never_a_reusable_attestation() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let proceed = PolicyModelConfig {
        hosted_outage_policy: HostedOutagePolicy::ProceedReceipted,
        ..PolicyModelConfig::default()
    };
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let moving = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("halted-reuse");
    let halted = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &proceed,
        Some(tier(&moving, &budget)),
    )?;
    assert_eq!(
        halted.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass)
    );
    assert!(halted.must_halt_relay());

    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let binding = vault.relay_verify_binding(&request, &proceed)?;
    let reuse = |pass: &RelayBoundaryPass, backend: &CountingPolicyBackend| {
        let source = StaticVaultSideVerdicts {
            verdict: PolicyClassifyVerdict::clean_allow(
                binding,
                &proceed,
                PolicyPlane::OwnerPolicy,
            )
            .attesting_hosted_plane(&registered_policy(&registry), &proceed, pass),
            requested_hash: Mutex::new(None),
        };
        block_on(vault.relay_boundary_pass(
            request.clone(),
            &cloud_witness(),
            &registry,
            &proceed,
            Some(tier(backend, &budget)),
            &source,
        ))
    };

    let backend = CountingPolicyBackend::clean();
    let replayed = reuse(&halted, &backend)?;
    assert_ne!(
        replayed,
        RelayBoundaryPass::TrustedVaultSide,
        "H122: a halted hosted pass was reused as a trusted Allow"
    );
    assert_eq!(backend.calls(), 1, "the reuse runs its own hosted pass");

    let outage_under_halt = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        outage_under_halt.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable)
    );
    assert!(outage_under_halt.must_halt_relay());
    let no_hosted_policy = RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(binding, &proceed, PolicyPlane::HostedLegal),
        None,
        false,
        RelayResolution::NoPolicyInPlay,
    );
    let tolerated = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &proceed,
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        tolerated.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable)
    );
    assert!(!tolerated.must_halt_relay());
    // The relay replays a non-Allow carrier as a classified pass with no
    // degrade of its own; minted again, it would erase the outage.
    let carrier = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::skipped(
            PolicySkipReason::NoBackend,
            binding,
            &proceed,
            PolicyPlane::OwnerPolicy,
        )
        .attesting_hosted_plane(&registered_policy(&registry), &proceed, &tolerated),
        requested_hash: Mutex::new(None),
    };
    let replayed_carrier = block_on(vault.relay_boundary_pass(
        request.clone(),
        &cloud_witness(),
        &registry,
        &proceed,
        Some(tier(&CountingPolicyBackend::clean(), &budget)),
        &carrier,
    ))?;
    assert_eq!(
        replayed_carrier.resolution(),
        Some(RelayResolution::VaultSideDecided)
    );
    // A pattern-gated pass called no model; it is no evidence for the
    // classify-all dial the caller hands in now.
    let pattern_gated = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig {
            hosted_classifier_mode: RelayClassifierMode::PatternGated,
            ..proceed.clone()
        },
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        pattern_gated.resolution(),
        Some(RelayResolution::PatternGatedAllow)
    );
    for (leg, pass) in [
        ("an outage that halted under Halt", &outage_under_halt),
        ("a BYO path", &RelayBoundaryPass::NotRelayedByUs),
        ("a trusted replay", &RelayBoundaryPass::TrustedVaultSide),
        ("a replayed carrier", &replayed_carrier),
        ("a pass with no hosted policy", &no_hosted_policy),
        ("a pattern-gated pass", &pattern_gated),
    ] {
        let backend = CountingPolicyBackend::clean();
        assert_ne!(
            reuse(pass, &backend)?,
            RelayBoundaryPass::TrustedVaultSide,
            "H122: {leg} was attested as a hosted pass"
        );
        assert_eq!(
            backend.calls(),
            1,
            "{leg}: the reuse runs its own hosted pass"
        );
    }

    let backend = CountingPolicyBackend::clean();
    assert_eq!(
        reuse(&tolerated, &backend)?,
        RelayBoundaryPass::TrustedVaultSide
    );
    assert_eq!(backend.calls(), 0);
    Ok(())
}

/// H122, receipt reuse, what the pass decided and what it examined: a real
/// hosted Block attested onto the owner's Allow carrier, a real pass over one
/// hosted policy attested under the policy registered after it, and a real
/// pass over one message attested onto a carrier for another, used to give a
/// later cloud relay a trusted Allow. The same answered pass attested
/// under its own policy is still reused, the control.
#[test]
fn a_hosted_pass_attests_only_its_own_policy_and_never_its_halt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let config = PolicyModelConfig::default();
    let budget = lease("attested-reuse");
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let amended = hosted_edge_registry(HostedLegalPolicy {
        version: "2099-01-01".to_owned(),
        ..hosted_serious_crime_block()
    });
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let binding = vault.relay_verify_binding(&request, &config)?;
    let reuse = |registry: &EdgeServiceRegistry,
                 pass: &RelayBoundaryPass,
                 backend: &CountingPolicyBackend| {
        let source = StaticVaultSideVerdicts {
            verdict: PolicyClassifyVerdict::clean_allow(binding, &config, PolicyPlane::OwnerPolicy)
                .attesting_hosted_plane(&registered_policy(registry), &config, pass),
            requested_hash: Mutex::new(None),
        };
        block_on(vault.relay_boundary_pass(
            request.clone(),
            &cloud_witness(),
            registry,
            &config,
            Some(tier(backend, &budget)),
            &source,
        ))
    };

    let blocked = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &config,
        Some(tier(&blocking_backend(), &budget)),
    )?;
    assert_eq!(
        blocked.boundary_verdict().map(|verdict| verdict.decision),
        Some(PolicyClassifyDecision::Block)
    );
    assert_eq!(blocked.degraded(), None);
    let backend = CountingPolicyBackend::clean();
    assert_ne!(
        reuse(&registry, &blocked, &backend)?,
        RelayBoundaryPass::TrustedVaultSide,
        "H122: a hosted Block was attested onto an Allow"
    );
    assert_eq!(backend.calls(), 1, "the reuse runs its own hosted pass");

    let answered = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &config,
        Some(tier(&clean_backend(), &budget)),
    )?;
    assert_eq!(answered.resolution(), Some(RelayResolution::ModelDecided));
    let backend = CountingPolicyBackend::clean();
    assert_ne!(
        reuse(&amended, &answered, &backend)?,
        RelayBoundaryPass::TrustedVaultSide,
        "H122: a pass over one hosted policy attested the policy registered after it"
    );
    assert_eq!(backend.calls(), 1, "the reuse runs its own hosted pass");

    // A pass over one message is no evidence about another.
    let other = PolicyClassifyRequest::outbound_content("a different message");
    let other_source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            vault.relay_verify_binding(&other, &config)?,
            &config,
            PolicyPlane::OwnerPolicy,
        )
        .attesting_hosted_plane(&registered_policy(&registry), &config, &answered),
        requested_hash: Mutex::new(None),
    };
    let backend = CountingPolicyBackend::clean();
    assert_ne!(
        block_on(vault.relay_boundary_pass(
            other,
            &cloud_witness(),
            &registry,
            &config,
            Some(tier(&backend, &budget)),
            &other_source,
        ))?,
        RelayBoundaryPass::TrustedVaultSide,
        "H122: a pass over one message attested another"
    );
    assert_eq!(backend.calls(), 1, "the reuse runs its own hosted pass");

    let backend = CountingPolicyBackend::clean();
    assert_eq!(
        reuse(&registry, &answered, &backend)?,
        RelayBoundaryPass::TrustedVaultSide
    );
    assert_eq!(backend.calls(), 0);
    Ok(())
}

/// H121, the bare door: the owner tightens a row while the model is
/// answering, and the model's clean answer is about the policy it replaced.
/// The bare classify door used to return that `Allow` and receipt it against
/// the new frontier. Derived again it answers the policy in force; a manifest
/// that will not settle is `Skipped(PolicyMoving)`, never the old Allow.
#[test]
fn a_bare_classify_never_answers_with_a_replaced_policys_allow() -> Result<()> {
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    for keep_moving in [true, false] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
        let backend = ManifestMovingBackend {
            vault: &vault,
            manifest: spoilers_manifest("block"),
            body: r#"{"violation":0,"policy_category":null}"#,
            keep_moving,
            calls: AtomicUsize::new(0),
        };
        let verdict = block_on(vault.classify_policy_model_with_backend(
            request.clone(),
            &config,
            &backend,
            &lease("bare-moving"),
        ))?;
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            2,
            "derived again, once"
        );
        if keep_moving {
            assert_eq!(
                verdict.decision,
                PolicyClassifyDecision::Skipped(PolicySkipReason::PolicyMoving),
                "H121: a moving manifest answered with the replaced policy's Allow"
            );
            let receipts = gate_receipts(&vault)?;
            assert_eq!(receipts.len(), 1, "the fail-open is receipted");
        } else {
            // The control: the second pass read the policy in force, and the
            // model's clean answer about it is a real Allow.
            assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
        }
        assert!(
            !vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &config)?,
            "the answer is bound to the frontier in force"
        );
    }
    Ok(())
}

/// H121, the bare door's last window: the pass is pinned, then the owner
/// edits the policy before the row that hands the verdict out. Neither a
/// clean Allow nor a warn for the replaced policy is handed out, and neither
/// is stamped with the new frontier, where the enforcement door would take it
/// as current: both are `Skipped(PolicyMoving)`.
#[test]
fn a_bare_classify_never_hands_out_a_verdict_the_policy_moved_under() -> Result<()> {
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    for body in [
        r#"{"violation":0,"policy_category":null}"#,
        r#"{"violation":1,"policy_category":"owner:spoilers"}"#,
    ] {
        let (_tmp, vault) = temp_vault();
        let vault = std::rc::Rc::new(vault);
        put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
        move_policy_before(
            &vault,
            SettlingDoor::BareClassify,
            spoilers_manifest("block"),
        );
        let verdict = block_on(vault.classify_policy_model_with_backend(
            request.clone(),
            &config,
            &static_backend(body),
            &lease("receipt-moving"),
        ))?;
        assert_eq!(
            verdict.decision,
            PolicyClassifyDecision::Skipped(PolicySkipReason::PolicyMoving),
            "H121: {body} was handed out for a replaced policy"
        );
        assert!(!vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &config)?);
        let receipts = gate_receipts(&vault)?;
        assert_eq!(receipts.len(), 1, "{body}: the fail-open is receipted");
        assert!(has_trace(
            &receipts[0],
            "gate.policy_model.owner_plane_frontier_moved"
        ));
    }
    Ok(())
}

/// Answers `body`, and on each listed call moves the owner's manifest.
struct MovesOnCall<'v> {
    vault: &'v Vault,
    moves: Vec<(usize, Vec<u8>)>,
    body: &'static str,
    calls: AtomicUsize,
}

impl LlmBackend for MovesOnCall<'_> {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((_, manifest)) = self.moves.iter().find(|(on_call, _)| *on_call == call) {
            put_policy_manifest_bytes(self.vault, test_id(0x48), manifest)
                .expect("mid-call manifest write");
        }
        let body = self.body.to_owned();
        Box::pin(async move { Ok(text_response(body)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// H121, the dual-plane door: the owner half settles first and then waits on
/// the hosted half, and the owner tightens the policy during that wait (the
/// hosted half's model call moves it). The owner verdict the door hands out
/// answers the policy in force, not the one the owner half read.
#[test]
fn a_dual_plane_owner_verdict_answers_the_policy_in_force_after_the_join() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = MovesOnCall {
        vault: &vault,
        moves: vec![(1, spoilers_manifest("block"))],
        body: r#"{"violation":0,"policy_category":null}"#,
        calls: AtomicUsize::new(0),
    };
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let budget = lease("dual-moving");
    let pass = block_on(vault.classify_both_planes(
        request.clone(),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &config,
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert!(
        backend.calls.load(Ordering::SeqCst) >= 2,
        "the hosted half moved the manifest after the owner half settled"
    );
    assert!(
        !vault.policy_model_verdict_is_stale_with_config(&pass.owner, &request, &config)?,
        "H121: the dual-plane door handed out a replaced policy's verdict"
    );
    Ok(())
}

/// H122, the dual-plane door's hosted half: it settles, then the owner half
/// pins again after the join and the manifest moves during that call too. The
/// hosted verdict bound to the frontier in between used to be handed back as
/// a relayable Allow; it is the halting binding-moved degrade.
#[test]
fn a_dual_plane_hosted_half_never_relays_on_a_binding_the_owner_repin_moved() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    // Call 0 is the owner half. Call 1 is the hosted half, which moves the
    // manifest and settles at call 2. Call 3 is the owner pinning again after
    // the join, which moves it once more.
    let backend = MovesOnCall {
        vault: &vault,
        moves: vec![
            (1, spoilers_manifest("block")),
            (3, spoilers_manifest("warn")),
        ],
        body: r#"{"violation":0,"policy_category":null}"#,
        calls: AtomicUsize::new(0),
    };
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let budget = lease("dual-hosted-moving");
    let pass = block_on(vault.classify_both_planes(
        request.clone(),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &config,
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert!(
        backend.calls.load(Ordering::SeqCst) >= 4,
        "the owner half pinned again after the hosted half settled"
    );
    assert_eq!(
        pass.relay.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass),
        "H122: the hosted half was handed back on a binding no longer in force"
    );
    assert!(pass.relay.must_halt_relay());
    assert!(!vault.policy_model_verdict_is_stale_with_config(&pass.owner, &request, &config)?);
    Ok(())
}

/// H121, the classify-and-enforce doors' last window: the pass is pinned,
/// then the owner edits the policy before the row the door writes. The doors
/// used to record and return the decision reached for the replaced policy: a
/// warn, a clean Allow, and the model-less door's verdict under the old
/// frontier. Each records and returns the plane's fail-open at the frontier
/// in force.
#[test]
fn an_enforce_door_never_records_a_verdict_the_policy_moved_under() -> Result<()> {
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    for body in [
        Some(r#"{"violation":0,"policy_category":null}"#),
        Some(r#"{"violation":1,"policy_category":"owner:spoilers"}"#),
        None,
    ] {
        let (_tmp, vault) = temp_vault();
        let vault = std::rc::Rc::new(vault);
        put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
        move_policy_before(
            &vault,
            SettlingDoor::RecordAndEnforce,
            spoilers_manifest("block"),
        );
        let enforcement = match body {
            Some(body) => block_on(vault.enforce_policy_model_with_backend(
                request.clone(),
                &config,
                &static_backend(body),
                &lease("enforce-moving"),
            ))?,
            None => vault.enforce_policy_model_with_config(request.clone(), &config)?,
        };
        assert_eq!(
            enforcement.verdict.decision,
            PolicyClassifyDecision::Skipped(PolicySkipReason::PolicyMoving),
            "H121: {body:?} was enforced for a replaced policy"
        );
        assert_eq!(enforcement.action, PolicyEnforcementAction::Skipped);
        assert!(!vault.policy_model_verdict_is_stale_with_config(
            &enforcement.verdict,
            &request,
            &config
        )?);
        let receipts = gate_receipts(&vault)?;
        assert_eq!(receipts.len(), 1, "{body:?}: the fail-open is receipted");
        assert!(has_trace(
            &receipts[0],
            "gate.policy_model.owner_plane_frontier_moved"
        ));
    }
    Ok(())
}

/// H121, the owner opting out before the row: the owner switches the plane
/// off while a warn is on its way out. The doors used to hand out a skip no
/// enforcement door would take from an off plane, so the opt-out stranded the
/// content. They answer as an off plane does, with the inert clean allow, and
/// the content goes out.
#[test]
fn an_owner_opt_out_before_the_row_releases_the_content() -> Result<()> {
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let warn = r#"{"violation":1,"policy_category":"owner:spoilers"}"#;
    let opted_out = base_policy_manifest(vec![
        owner_policy_enabled(false),
        owner_rows(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
            "warn",
        )]),
        owner_document(OWNER_DOCUMENT),
        owner_contract("category_json"),
    ]);

    // The bare door, then the enforcement door on what it handed out.
    let (_tmp, vault) = temp_vault();
    let vault = std::rc::Rc::new(vault);
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    move_policy_before(&vault, SettlingDoor::BareClassify, opted_out.clone());
    let verdict = block_on(vault.classify_policy_model_with_backend(
        request.clone(),
        &config,
        &static_backend(warn),
        &lease("opt-out"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    let enforced = vault.enforce_policy_model_verdict(request.clone(), &config, verdict, false)?;
    assert_eq!(
        enforced.action,
        PolicyEnforcementAction::Allow,
        "H121: an opted-out owner's verdict was refused"
    );

    // The classify-and-enforce door.
    let (_tmp, vault) = temp_vault();
    let vault = std::rc::Rc::new(vault);
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    move_policy_before(&vault, SettlingDoor::RecordAndEnforce, opted_out);
    let enforcement = block_on(vault.enforce_policy_model_with_backend(
        request,
        &config,
        &static_backend(warn),
        &lease("opt-out-enforce"),
    ))?;
    assert_eq!(enforcement.action, PolicyEnforcementAction::Allow);
    assert_eq!(enforcement.final_content.as_deref(), Some(CLEAN_CONTENT));
    Ok(())
}

/// H122, the dual-plane door's CloudVault reuse: the owner edits the policy
/// after the reuse was verified and before the door's last transaction. The
/// reused verdict answers the replaced policy; it used to be handed back as a
/// trusted Allow, because the final check skipped a pass this edge did not
/// run. Checked at the binding it was verified at, it is the halting
/// binding-moved degrade.
#[test]
fn a_dual_plane_cloud_reuse_is_checked_in_the_last_transaction() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let vault = std::rc::Rc::new(vault);
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let config = PolicyModelConfig::default();
    let budget = lease("dual-cloud-reuse");
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let hosted_pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &config,
        Some(tier(&clean_backend(), &budget)),
    )?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
            vault.relay_verify_binding(&request, &config)?,
            &config,
            PolicyPlane::OwnerPolicy,
        )
        .attesting_hosted_plane(&registered_policy(&registry), &config, &hosted_pass),
        requested_hash: Mutex::new(None),
    };
    move_policy_before(&vault, SettlingDoor::DualPlane, spoilers_manifest("block"));
    let backend = clean_backend();
    let pass = block_on(vault.classify_both_planes(
        request.clone(),
        &cloud_witness(),
        &registry,
        &config,
        Some(tier(&backend, &budget)),
        &source,
    ))?;
    assert_eq!(
        pass.relay.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass),
        "H122: a CloudVault reuse was handed out for a replaced policy"
    );
    assert!(pass.relay.must_halt_relay());
    assert!(!vault.policy_model_verdict_is_stale_with_config(&pass.owner, &request, &config)?);
    Ok(())
}
