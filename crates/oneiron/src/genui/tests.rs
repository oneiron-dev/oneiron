use super::*;

mod failure_integrity;
mod project_proposal;

fn ask_card() -> Result<ConsentAskCard> {
    ConsentAskCard::new(
        "ask-1",
        "owner",
        "Want me to invite Yuki?",
        "Invite text preview",
        "invite",
        Vec::new(),
    )
    .map(|card| {
        card.with_counterparty_ref("contact:yuki")
            .with_channel("slack")
            .with_origin_receipt_ref("intent:invite-yuki")
    })
}

fn authenticated_person(
    vault: &crate::Vault,
    seed: u8,
    principal_ref: &str,
) -> crate::consent::AuthenticatedOwner {
    let actor = crate::test_util::entity(seed);
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            principal_ref.as_bytes(),
        )
        .expect("seed authenticated person");
    vault
        .authenticate_owner(
            actor,
            principal_ref,
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("authenticate person")
}

fn owner_context() -> (
    tempfile::TempDir,
    crate::Vault,
    crate::consent::AuthenticatedOwner,
) {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = authenticated_person(&vault, 0x71, "owner");
    (dir, vault, owner)
}

fn evaluate_ask_action(
    card: &ConsentAskCard,
    request: &ConsentActionRequest,
) -> Result<ConsentActionEvaluation> {
    let (_dir, _vault, owner) = owner_context();
    card.evaluate_action(request, &owner)
}

#[test]
fn beneficiary_cannot_confirm_always_this_verb_class() -> Result<()> {
    let card = ask_card()?.with_counterparty_ref("owner");
    let request = ConsentActionRequest::new(
        "ask-1",
        "escalate_always_this_verb_class",
        ConsentActionKind::Escalate(ConsentScopeEscalator::AlwaysThisVerbClass),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::CompanionConversation,
        102,
    )?;

    let evaluation = evaluate_ask_action(&card, &request)?;
    assert_eq!(
        evaluation.decision,
        ConsentActionDecision::NoopBeneficiaryConfirm
    );
    assert!(evaluation.grant_mint_intent.is_none());
    assert_eq!(evaluation.receipt.outcome, "no_op_beneficiary_confirm");
    assert_eq!(
        evaluation.receipt.fields.get("reason").map(String::as_str),
        Some("consent_beneficiary:self_grant")
    );
    assert!(
        evaluation
            .receipt
            .policy_trace
            .contains(&"consent_beneficiary:self_grant".to_owned())
    );

    Ok(())
}

#[test]
fn forged_typed_action_mismatch_is_rejected_before_grant_mint() -> Result<()> {
    let card = ask_card()?;
    let request = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Escalate(ConsentScopeEscalator::AlwaysThisVerbClass),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::CompanionConversation,
        103,
    )?;

    assert!(matches!(
        evaluate_ask_action(&card, &request),
        Err(Error::InvalidConfig(_))
    ));

    Ok(())
}

#[test]
fn voice_path_cannot_borrow_a_store_authenticated_owner_handle() -> Result<()> {
    let card = ask_card()?;
    let (_dir, vault, owner) = owner_context();
    let attacker = authenticated_person(&vault, 0x72, "attacker");
    let request = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Approve,
        ConsentActorIdentity::VoicePath {
            speaker_ref: "owner".to_owned(),
        },
        ConsentSurface::Voice,
        103,
    )?;

    assert_eq!(
        card.evaluate_action(&request, &attacker)
            .expect_err("caller voice claim must not authenticate another principal")
            .kind(),
        crate::error::ErrorKind::ConsentUnauthenticatedActor
    );
    assert_eq!(
        card.evaluate_action(&request, &owner)
            .expect_err("voice claim cannot borrow a device-authenticated handle")
            .kind(),
        crate::error::ErrorKind::ConsentUnauthenticatedActor
    );
    Ok(())
}

/// TARGET B pin: identical caller text is refused under the wrong authenticated
/// principal and succeeds only under the FIX2 store-resolved owner handle.
#[test]
fn principal_self_attestation_is_refused_and_store_authenticated_actor_succeeds() -> Result<()> {
    let card = ask_card()?;
    let (_dir, vault, owner) = owner_context();
    let attacker = authenticated_person(&vault, 0x72, "attacker");
    let request = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Approve,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::CompanionConversation,
        104,
    )?;

    assert_eq!(
        card.evaluate_action(&request, &attacker)
            .expect_err("self-attested owner text must not authenticate")
            .kind(),
        crate::error::ErrorKind::ConsentUnauthenticatedActor
    );
    assert_eq!(
        card.evaluate_action(&request, &owner)?.decision,
        ConsentActionDecision::ApprovedOnce,
        "the same actor text succeeds only with the store-authenticated owner"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ONE-1812 [BK-01] — the calendar grant-mint seam
// ---------------------------------------------------------------------------

#[test]
fn calendar_scope_is_not_an_outbound_grant_scope() {
    use crate::outbound_grant::StandingOutboundGrantScope;

    // A read grant must never become a standing permission to send.
    let scope = GrantMintIntentScope::Calendar {
        calendar_ref: "calendar:work".to_owned(),
        rung: DisclosureRung::Slots,
    };
    assert!(StandingOutboundGrantScope::from_grant_mint_scope(&scope).is_err());
}

// ── ONE-1887 surfaced-failure card ──────────────────────────────────────────

/// The witnessed message body the card must NEVER copy inline.
const QA_MESSAGE_BODY: &str = "witnessed-qa-body";

/// One terminally failed attempt plus the run tree that renders it.
fn failed_run(vault: &crate::Vault) -> Result<(AttemptId, RunTree)> {
    use crate::attempt_queue::{ClaimAttempt, ClaimOutcome, FailAttempt, FailOutcome};
    use crate::dreamer_runner::{
        DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
    };

    let EnqueueDreamerAttemptOutcome::Enqueued(status) =
        DreamerRunnerStore::new(vault).enqueue(EnqueueDreamerAttempt {
            attempt_type: "failing.worker".to_owned(),
            input: rmpv::Value::from("input"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-card".to_owned()),
            now: 10,
        })?
    else {
        panic!("expected a fresh enqueue");
    };
    let queue = crate::AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "card-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected a claim");
    };
    assert_eq!(claimed.id, status.attempt.id);
    let FailOutcome::Failed(failed) = queue.fail(FailAttempt {
        id: claimed.id,
        lease_owner: "card-worker".to_owned(),
        attempt_count: claimed.attempt_count,
        reason: "detector.stable_code".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected a terminal failure");
    };
    assert_eq!(failed.state, crate::attempt_queue::AttemptState::Failed);
    assert_eq!(queue.get(failed.id)?, Some(failed.clone()));
    let tree = crate::run_tree::RunTreeAdapter::new(vault).read_run("run-card")?;
    Ok((failed.id, tree))
}

fn put_container(vault: &crate::Vault, seed: u8, entity_type: u8) -> Result<EntityId> {
    let id = crate::test_util::entity(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(Vec::new()))
        .expect("encode empty container map");
    vault.put_entity(
        &id,
        entity_type,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    Ok(id)
}

fn put_actor(vault: &crate::Vault, seed: u8) -> Result<EntityId> {
    let id = crate::test_util::entity(seed);
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"qa-actor",
    )?;
    Ok(id)
}

fn card_input(
    failing_attempt_id: AttemptId,
    tree: RunTree,
    qa: HealerQaFeed,
) -> SurfacedFailureCardInput {
    SurfacedFailureCardInput {
        failure_class: FailureClass::Permanent,
        consecutive_transients: 0,
        pathology: None,
        retry_lineage_limit: crate::failure_ladder::DEFAULT_MAX_CONSECUTIVE_TRANSIENTS,
        tree,
        failing_attempt_id,
        pre_fail_checkpoint_ref: crate::test_util::entity(0x75),
        diagnosis: FailureDiagnosisState::ReservedHealerSlot,
        blocked_reports: Vec::new(),
        qa,
    }
}

fn qa_entry(message_ref: EntityId, actor_ref: EntityId, occurred_at: u64) -> HealerQaEntryRef {
    HealerQaEntryRef {
        message_ref: message_ref.to_hex(),
        actor_ref: actor_ref.to_hex(),
        occurred_at,
    }
}
