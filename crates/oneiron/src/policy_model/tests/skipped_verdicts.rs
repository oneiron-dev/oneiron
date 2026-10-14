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
