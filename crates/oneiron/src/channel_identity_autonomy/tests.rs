use std::collections::BTreeMap;

use super::*;
use crate::channel_identity::{ChannelIdentity, ChannelIdentityFulfillment, SelfHeldShape};
use crate::edge::EdgeActorClass;
use crate::receipt::{ReceiptRecord, SendReceiptOutcome, persist_send_receipt};
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

fn fixture(
    rung: ChannelIdentityAutonomyRung,
) -> (
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    ChannelIdentityAutonomyRequest,
) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), embedding_test_config()).unwrap();
    let owner_id = entity(0x51);
    vault
        .put_entity(
            &owner_id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let identity_ref = entity(0x61);
    let actor_ref = entity(0x71);
    let identity = ChannelIdentity::requested(
        "email",
        "agent@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(actor_ref),
        1,
    )
    .transition(
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Manual),
        2,
        None,
    )
    .unwrap()
    .transition(ChannelIdentityState::Active, None, 3, None)
    .unwrap();
    vault
        .create_channel_identity(&identity_ref, &identity)
        .unwrap();
    let request = ChannelIdentityAutonomyRequest {
        actor_ref,
        relationship_context: RelationshipContext::WorkDeal,
        rung,
        read_envelope: MailboxReadEnvelope {
            identity_ref,
            label_allowlist: vec!["inbox".to_owned()],
            thread_allowlist: vec!["thread:1".to_owned()],
            not_before: None,
            not_after: None,
        },
        action_envelope: rung.verb().map(|_| ChannelIdentityActionEnvelope {
            identity_ref,
            relationship_context: RelationshipContext::WorkDeal,
            counterparty_class: Some("known".to_owned()),
            max_actions: 3,
            window_secs: 86_400,
        }),
    };
    (dir, vault, owner, request)
}

fn candidate(request: &ChannelIdentityAutonomyRequest, n: u8) -> ChannelIdentityEffectCandidate {
    ChannelIdentityEffectCandidate {
        identity_ref: request.read_envelope.identity_ref,
        relationship_context: request.relationship_context,
        verb_class: "mail.send".to_owned(),
        counterparty_class: Some("known".to_owned()),
        effect_key: [n; 32],
    }
}

fn review_scope(request: &ChannelIdentityAutonomyRequest) -> GraduationScopeKey {
    GraduationScopeKey {
        actor_ref: request.actor_ref,
        identity_ref: request.read_envelope.identity_ref,
        relationship_context: request.relationship_context,
        verb_class: "mail.send".to_owned(),
        counterparty_class: Some("known".to_owned()),
    }
}

fn review_receipt(
    scope: &GraduationScopeKey,
    at: u64,
    outcome: &DraftReviewOutcome,
) -> ReceiptRecord {
    let (review_outcome, distance) = match outcome {
        DraftReviewOutcome::ApprovedUntouched => ("approved_untouched", None),
        DraftReviewOutcome::ApprovedAmended {
            edit_distance_millis,
        } => ("approved_amended", Some(*edit_distance_millis)),
        DraftReviewOutcome::Rejected => ("rejected", None),
        DraftReviewOutcome::Undone => ("undone", None),
    };
    let mut fields = BTreeMap::from([
        (
            "channel_identity_ref".to_owned(),
            scope.identity_ref.to_hex(),
        ),
        (
            "relationship_context".to_owned(),
            scope.relationship_context.as_str().to_owned(),
        ),
        ("verb_class".to_owned(), scope.verb_class.clone()),
        ("review_outcome".to_owned(), review_outcome.to_owned()),
    ]);
    if let Some(class) = &scope.counterparty_class {
        fields.insert("counterparty_class".to_owned(), class.clone());
    }
    if let Some(distance) = distance {
        fields.insert("edit_distance_millis".to_owned(), distance.to_string());
    }
    ReceiptRecord {
        receipt_id: format!("outbound-review:{}", EntityId::now().to_hex()),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: at,
        actor: Some(scope.actor_ref.to_hex()),
        on_behalf_of: None,
        outcome: "failed".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields,
    }
}

fn persist_review(
    vault: &Vault,
    scope: &GraduationScopeKey,
    at: u64,
    outcome: DraftReviewOutcome,
) -> GraduationEvidence {
    persist_review_for_task(vault, scope, EntityId::now(), at, outcome)
}

fn persist_review_for_task(
    vault: &Vault,
    scope: &GraduationScopeKey,
    task_ref: EntityId,
    at: u64,
    outcome: DraftReviewOutcome,
) -> GraduationEvidence {
    let receipt = review_receipt(scope, at, &outcome);
    let evidence = GraduationEvidence {
        scope: scope.clone(),
        outcome,
        receipt_ref: receipt.receipt_id.clone(),
        occurred_at: at,
    };
    assert!(
        persist_send_receipt(
            vault,
            task_ref,
            receipt,
            SendReceiptOutcome::Failed,
            false,
            None
        )
        .unwrap()
    );
    evidence
}

fn review(
    vault: &Vault,
    scope: &GraduationScopeKey,
    n: u64,
    outcome: DraftReviewOutcome,
) -> String {
    let evidence = persist_review(vault, scope, n, outcome);
    let reference = evidence.receipt_ref.clone();
    vault
        .record_graduation_evidence(
            evidence,
            &WriteActor::new(scope.actor_ref, EdgeActorClass::Agent),
        )
        .unwrap();
    reference
}

fn snapshot(vault: &Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    let txn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .vault_meta
        .iter(&txn)
        .unwrap()
        .map(|row| {
            let (key, value) = row.unwrap();
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

#[test]
fn read_and_action_grants_are_disjoint() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::ScopedRead);
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    assert!(state.action_grant.is_none());
    assert_eq!(
        state.read_grant.capability,
        AccessGrantCapability::ChannelIdentityScopedRead
    );
    assert!(
        crate::consent::disclosure_grant_from_access_grant(&state.read_grant).is_err(),
        "static adapters must not bypass mailbox envelope resolution"
    );
    let bound = read_bound(
        request.actor_ref,
        request.read_envelope.identity_ref,
        address(
            PREDICATE_MAILBOX_READ_ENVELOPE,
            &read_value(&request.read_envelope).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(crate::consent::ActionGrant::new(bound).is_err());
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(
                &state.mode.read_grant_ref.unwrap(),
                &candidate(&request, 1)
            )
            .is_err()
    );
}

#[test]
fn draft_grant_cannot_send() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let reference = state.mode.action_grant_ref.unwrap();
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 1))
            .unwrap()
    );
    let mut draft = candidate(&request, 1);
    draft.verb_class = " MAIL.DRAFT ".to_owned();
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &draft)
            .unwrap()
    );
    assert!(
        !state
            .action_grant
            .unwrap()
            .scope
            .matches_effect("mail.send", "email", None, None)
    );
}

#[test]
fn owner_auto_envelope_matches_exactly() {
    let (_dir, vault, owner, request) =
        fixture(ChannelIdentityAutonomyRung::AutonomousWithinEnvelope);
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let reference = state.mode.action_grant_ref.unwrap();
    let good = candidate(&request, 1);
    let mut wrong = good.clone();
    wrong.identity_ref = entity(0x62);
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &wrong)
            .unwrap()
    );
    wrong = good.clone();
    wrong.relationship_context = RelationshipContext::PersonalFriends;
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &wrong)
            .unwrap()
    );
    wrong = good.clone();
    wrong.counterparty_class = None;
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &wrong)
            .unwrap()
    );
    wrong.counterparty_class = Some("stranger".to_owned());
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &wrong)
            .unwrap()
    );
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &good)
            .unwrap()
    );
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &good)
            .unwrap(),
        "retry shares slot"
    );
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 2))
            .unwrap()
    );
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 3))
            .unwrap()
    );
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 4))
            .unwrap()
    );
}

#[test]
fn concurrent_volume_window_never_overruns() {
    let (_dir, vault, owner, request) =
        fixture(ChannelIdentityAutonomyRung::AutonomousWithinEnvelope);
    let reference = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap()
        .mode
        .action_grant_ref
        .unwrap();
    let barrier = std::sync::Barrier::new(20);
    let accepted = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..20)
            .map(|n| {
                let vault = &vault;
                let request = &request;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    vault
                        .authorize_and_consume_channel_identity_grant(
                            &reference,
                            &candidate(request, n),
                        )
                        .unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(accepted, 3);
}

#[test]
fn twelve_distinct_tasks_untouched_offer_graduation() {
    let (dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::SendWithApproval);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    let mut evidence_refs: Vec<_> = (1..12)
        .map(|n| review(&vault, &scope, n, DraftReviewOutcome::ApprovedUntouched))
        .collect();
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
    evidence_refs.push(review(
        &vault,
        &scope,
        12,
        DraftReviewOutcome::ApprovedUntouched,
    ));
    let before = vault
        .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
        .unwrap()
        .unwrap();
    assert_eq!(before.unchanged_streak, 12);
    assert_eq!(before.evidence_refs, evidence_refs);
    assert_eq!(
        Some(before.proposed_envelope.clone()),
        request.action_envelope
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
    let after = reopened
        .evaluate_graduation_offer(&scope, 12, crate::unix_seconds_now())
        .unwrap()
        .unwrap();
    assert_eq!(before.evidence_refs, after.evidence_refs);
}

#[test]
fn twelve_receipts_for_one_task_do_not_offer_graduation() {
    for owner_authenticated in [false, true] {
        let (dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::SendWithApproval);
        vault
            .apply_channel_identity_autonomy(&request, &owner)
            .unwrap();
        let scope = review_scope(&request);
        let task_ref = EntityId::now();
        let actor = WriteActor::new(scope.actor_ref, EdgeActorClass::Agent);
        let mut latest_ref = String::new();
        for at in 1..=12 {
            let evidence = persist_review_for_task(
                &vault,
                &scope,
                task_ref,
                at,
                DraftReviewOutcome::ApprovedUntouched,
            );
            latest_ref = evidence.receipt_ref.clone();
            if owner_authenticated {
                vault
                    .record_graduation_evidence_as_owner(evidence, &owner)
                    .unwrap();
            } else {
                vault.record_graduation_evidence(evidence, &actor).unwrap();
            }
        }
        let scan = vault
            .scan_receipts(ReceiptQuery::new(12).with_kind(ReceiptKind::Outbound))
            .unwrap();
        assert!(scan.complete);
        assert_eq!(
            scan.records.len(),
            12,
            "distinct attempts remain in durable history"
        );
        assert!(
            scan.records
                .iter()
                .all(|r| r.fields.get(crate::receipt::FIELD_TASK_REF) == Some(&task_ref.to_hex()))
        );
        assert!(
            vault
                .evaluate_graduation_offer(&scope, 12, crate::unix_seconds_now())
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
                .unwrap()
                .is_none()
        );
        drop(vault);
        let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
        assert!(
            reopened
                .evaluate_graduation_offer(&scope, 12, crate::unix_seconds_now())
                .unwrap()
                .is_none()
        );
        let offer = reopened
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .unwrap();
        assert_eq!(offer.unchanged_streak, 1);
        assert_eq!(offer.evidence_refs, [latest_ref]);
    }
}

#[test]
fn latest_task_correction_replaces_the_prior_review_outcome() {
    for reset in [
        DraftReviewOutcome::ApprovedAmended {
            edit_distance_millis: 1,
        },
        DraftReviewOutcome::Rejected,
        DraftReviewOutcome::Undone,
    ] {
        let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
        vault
            .apply_channel_identity_autonomy(&request, &owner)
            .unwrap();
        let scope = review_scope(&request);
        let task_ref = EntityId::now();
        let actor = WriteActor::new(scope.actor_ref, EdgeActorClass::Agent);
        let first = persist_review_for_task(
            &vault,
            &scope,
            task_ref,
            1,
            DraftReviewOutcome::ApprovedUntouched,
        );
        vault.record_graduation_evidence(first, &actor).unwrap();
        let mut expected: Vec<_> = (2..=12)
            .map(|at| review(&vault, &scope, at, DraftReviewOutcome::ApprovedUntouched))
            .collect();
        assert_eq!(
            vault
                .evaluate_graduation_offer(&scope, 12, crate::unix_seconds_now())
                .unwrap()
                .unwrap()
                .unchanged_streak,
            12
        );
        let correction = persist_review_for_task(&vault, &scope, task_ref, 13, reset.clone());
        vault
            .record_graduation_evidence_as_owner(correction, &owner)
            .unwrap();
        assert!(
            vault
                .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
                .unwrap()
                .is_none()
        );
        let latest = persist_review_for_task(
            &vault,
            &scope,
            task_ref,
            14,
            DraftReviewOutcome::ApprovedUntouched,
        );
        expected.push(latest.receipt_ref.clone());
        vault.record_graduation_evidence(latest, &actor).unwrap();
        // A late admission of an older correction cannot override the newest review.
        let stale = persist_review_for_task(&vault, &scope, task_ref, 12, reset);
        vault
            .record_graduation_evidence_as_owner(stale, &owner)
            .unwrap();
        let offer = vault
            .evaluate_graduation_offer(&scope, 12, crate::unix_seconds_now())
            .unwrap()
            .unwrap();
        assert_eq!(offer.unchanged_streak, 12);
        assert_eq!(
            offer.evidence_refs, expected,
            "old approvals and corrections are superseded, not counted"
        );
    }
}

#[test]
fn equal_time_task_reviews_use_receipt_id_order_not_admission_order() {
    for reverse in [false, true] {
        let (dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
        vault
            .apply_channel_identity_autonomy(&request, &owner)
            .unwrap();
        let scope = review_scope(&request);
        let task_ref = EntityId::now();
        let actor = WriteActor::new(scope.actor_ref, EdgeActorClass::Agent);
        let mut reviews = [
            ("outbound-review:z", 0, DraftReviewOutcome::Rejected),
            ("outbound-review:a", 1, DraftReviewOutcome::Rejected),
            (
                "outbound-review:b",
                1,
                DraftReviewOutcome::ApprovedUntouched,
            ),
        ];
        if reverse {
            reviews.reverse();
        }
        for (reference, at, outcome) in reviews {
            let mut receipt = review_receipt(&scope, at, &outcome);
            receipt.receipt_id = reference.to_owned();
            assert!(
                persist_send_receipt(
                    &vault,
                    task_ref,
                    receipt,
                    SendReceiptOutcome::Failed,
                    false,
                    None
                )
                .unwrap()
            );
            vault
                .record_graduation_evidence(
                    GraduationEvidence {
                        scope: scope.clone(),
                        outcome,
                        receipt_ref: reference.to_owned(),
                        occurred_at: at,
                    },
                    &actor,
                )
                .unwrap();
        }
        let offer = vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .unwrap();
        assert_eq!(offer.unchanged_streak, 1);
        assert_eq!(offer.evidence_refs, ["outbound-review:b"]);
        drop(vault);
        let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
        assert_eq!(
            reopened
                .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
                .unwrap()
                .unwrap()
                .evidence_refs,
            offer.evidence_refs
        );
    }
}

#[test]
fn amendment_resets_streak() {
    for reset in [
        DraftReviewOutcome::ApprovedAmended {
            edit_distance_millis: 1,
        },
        DraftReviewOutcome::Rejected,
        DraftReviewOutcome::Undone,
    ] {
        let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
        vault
            .apply_channel_identity_autonomy(&request, &owner)
            .unwrap();
        let scope = review_scope(&request);
        for n in 1..=12 {
            review(&vault, &scope, n, DraftReviewOutcome::ApprovedUntouched);
        }
        review(&vault, &scope, 13, reset);
        for n in 14..=24 {
            review(&vault, &scope, n, DraftReviewOutcome::ApprovedUntouched);
        }
        assert!(
            vault
                .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
                .unwrap()
                .is_none()
        );
        review(&vault, &scope, 25, DraftReviewOutcome::ApprovedUntouched);
        assert_eq!(
            vault
                .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
                .unwrap()
                .unwrap()
                .unchanged_streak,
            12
        );
    }
}

#[test]
fn offer_never_mints_grant() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::SendWithApproval);
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    for n in 1..=12 {
        review(&vault, &scope, n, DraftReviewOutcome::ApprovedUntouched);
    }
    let grant_count = vault.active_standing_consent_grants().unwrap().len();
    let consent_records = || {
        vault
            .store
            .gate_decisions(usize::MAX)
            .unwrap()
            .into_iter()
            .map(|row| (row.decision_id, row.outcome, row.grant_ref))
            .collect::<Vec<_>>()
    };
    let before = consent_records();
    let offer = vault
        .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
        .unwrap()
        .unwrap();
    assert_eq!(
        vault.active_standing_consent_grants().unwrap().len(),
        grant_count
    );
    assert_eq!(consent_records(), before);
    let verified = vault
        .verify_channel_identity_autonomy(&request, &owner)
        .unwrap();
    assert_eq!(verified.mode.identity_ref, state.mode.identity_ref);
    assert_eq!(
        verified.mode.relationship_context,
        state.mode.relationship_context,
    );
    assert_eq!(verified.mode.rung, state.mode.rung);
    assert_eq!(verified.mode.read_grant_ref, state.mode.read_grant_ref);
    assert_eq!(verified.mode.action_grant_ref, state.mode.action_grant_ref);
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(
                &state.mode.action_grant_ref.unwrap(),
                &candidate(&request, 1),
            )
            .unwrap()
    );
    let envelope_ref = vault
        .put_channel_identity_action_envelope(offer.proposed_envelope, &owner, 1)
        .unwrap();
    let grant_ref = vault
        .mint_channel_identity_action_grant(&envelope_ref, "mail.send", &owner)
        .unwrap();
    let mut mode = state.mode;
    mode.rung = ChannelIdentityAutonomyRung::AutonomousWithinEnvelope;
    mode.action_grant_ref = Some(grant_ref);
    vault
        .set_channel_identity_autonomy_mode(mode, &owner, crate::unix_seconds_now())
        .unwrap();
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&grant_ref, &candidate(&request, 1))
            .unwrap()
    );
}

#[test]
fn authenticated_apply_verify_is_exact_and_idempotent() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    let first = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let consent_records = || {
        vault
            .store
            .gate_decisions(usize::MAX)
            .unwrap()
            .into_iter()
            .map(|row| (row.decision_id, row.outcome, row.grant_ref))
            .collect::<Vec<_>>()
    };
    let before = consent_records();
    let assert_exact = |state: &ChannelIdentityAutonomyState| {
        assert_eq!(state.mode.identity_ref, request.read_envelope.identity_ref);
        assert_eq!(
            state.mode.relationship_context,
            request.relationship_context
        );
        assert_eq!(state.mode.rung, request.rung);
        assert_eq!(state.mode.read_grant_ref, first.mode.read_grant_ref);
        assert_eq!(state.mode.action_grant_ref, first.mode.action_grant_ref);
        assert_eq!(
            state.read_envelope.identity_ref,
            request.read_envelope.identity_ref,
        );
        assert_eq!(
            state.read_envelope.label_allowlist,
            request.read_envelope.label_allowlist,
        );
        assert_eq!(
            state.read_envelope.thread_allowlist,
            request.read_envelope.thread_allowlist,
        );
        let action = state.action_envelope.as_ref().unwrap();
        let desired = request.action_envelope.as_ref().unwrap();
        assert_eq!(action.identity_ref, desired.identity_ref);
        assert_eq!(action.relationship_context, desired.relationship_context);
        assert_eq!(action.counterparty_class, desired.counterparty_class);
        assert_eq!(action.max_actions, desired.max_actions);
        assert_eq!(action.window_secs, desired.window_secs);
    };
    assert_exact(&first);
    assert_exact(
        &vault
            .apply_channel_identity_autonomy(&request, &owner)
            .unwrap(),
    );
    assert_exact(
        &vault
            .verify_channel_identity_autonomy(&request, &owner)
            .unwrap(),
    );
    assert_eq!(consent_records(), before);
    let mut wrong = request.clone();
    wrong.action_envelope.as_mut().unwrap().max_actions += 1;
    assert!(
        vault
            .apply_channel_identity_autonomy(&wrong, &owner)
            .is_err()
    );
    assert!(
        vault
            .verify_channel_identity_autonomy(&wrong, &owner)
            .is_err()
    );
    assert_exact(
        &vault
            .verify_channel_identity_autonomy(&request, &owner)
            .unwrap(),
    );
    assert_eq!(consent_records(), before);
    assert!(
        vault
            .authenticate_owner(request.actor_ref, "agent", true, GateDecisionId::now())
            .is_err()
    );
    assert!(
        vault
            .authenticate_owner(
                owner.actor(),
                owner.principal_ref(),
                false,
                GateDecisionId::now(),
            )
            .is_err()
    );
    let (_other_dir, other) = open_test_vault_with(embedding_test_config());
    assert!(
        other
            .put_mailbox_read_envelope(request.read_envelope.clone(), &owner, 1)
            .is_err()
    );
    assert!(
        other
            .apply_channel_identity_autonomy(&request, &owner)
            .is_err()
    );
}

#[test]
fn revoked_read_action_and_unified_grants_fail_closed() {
    for which in 0..3 {
        let (_dir, vault, owner, request) =
            fixture(ChannelIdentityAutonomyRung::AutonomousWithinEnvelope);
        let state = vault
            .apply_channel_identity_autonomy(&request, &owner)
            .unwrap();
        let reference = state.mode.action_grant_ref.unwrap();
        let now = crate::unix_seconds_now();
        match which {
            0 => {
                vault
                    .revoke_access_grant(&state.mode.read_grant_ref.unwrap(), now)
                    .unwrap();
            }
            1 => {
                vault
                    .revoke_standing_outbound_grant(&reference, now)
                    .unwrap();
            }
            _ => {
                let grant = state.action_grant.unwrap();
                let bound_ref = crate::entity_id::bytes_to_hex_lower(&grant.binding_diff_handle);
                vault.revoke_consent_grant(&owner, &bound_ref).unwrap();
            }
        }
        assert!(
            vault
                .resolve_channel_identity_autonomy_mode(
                    &request.read_envelope.identity_ref,
                    &request.relationship_context,
                    now
                )
                .is_err()
        );
        assert!(
            vault
                .verify_channel_identity_autonomy(&request, &owner)
                .is_err()
        );
        assert!(
            vault
                .apply_channel_identity_autonomy(&request, &owner)
                .is_err()
        );
        assert!(
            !vault
                .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 1))
                .unwrap()
        );
    }
}

#[test]
fn rungs_and_relationship_contexts_round_trip_exactly() {
    for (rung, wire) in [
        (ChannelIdentityAutonomyRung::ScopedRead, "scoped_read"),
        (ChannelIdentityAutonomyRung::DraftOnly, "draft_only"),
        (
            ChannelIdentityAutonomyRung::SendWithApproval,
            "send_with_approval",
        ),
        (
            ChannelIdentityAutonomyRung::AutonomousWithinEnvelope,
            "autonomous_within_envelope",
        ),
    ] {
        assert_eq!(rung.as_str(), wire);
        assert_eq!(ChannelIdentityAutonomyRung::parse(wire), Some(rung));
        for relationship_context in RelationshipContext::ALL {
            let mode = ChannelIdentityAutonomyMode {
                identity_ref: entity(1),
                relationship_context,
                rung,
                read_grant_ref: Some(entity(2)),
                action_grant_ref: Some(entity(3)),
            };
            assert_eq!(
                mode_from(&decode(&encode(&mode_value(&mode)).unwrap()).unwrap()).unwrap(),
                mode
            );
        }
    }
    assert!(ChannelIdentityAutonomyRung::parse("full_auto").is_none());
    assert!(context(&Value::from("unknown")).is_err());
}

#[test]
fn evidence_is_attributed_deduplicated_and_scope_isolated() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    let evidence = persist_review(&vault, &scope, 1, DraftReviewOutcome::ApprovedUntouched);
    let consent_records = || {
        vault
            .store
            .gate_decisions(usize::MAX)
            .unwrap()
            .into_iter()
            .map(|row| (row.decision_id, row.outcome, row.grant_ref))
            .collect::<Vec<_>>()
    };
    let before_wrong_actor = consent_records();
    assert!(
        vault
            .record_graduation_evidence(
                evidence.clone(),
                &WriteActor::new(entity(9), EdgeActorClass::Agent),
            )
            .is_err()
    );
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
    assert_eq!(consent_records(), before_wrong_actor);
    let actor = WriteActor::new(scope.actor_ref, EdgeActorClass::Agent);
    vault
        .record_graduation_evidence(evidence.clone(), &actor)
        .unwrap();
    let admitted = vault
        .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
        .unwrap()
        .unwrap();
    assert_eq!(
        admitted.evidence_refs,
        std::slice::from_ref(&evidence.receipt_ref)
    );
    let before = consent_records();
    for _ in 0..12 {
        assert!(
            vault
                .record_graduation_evidence(evidence.clone(), &actor)
                .is_err()
        );
    }
    assert!(
        vault
            .record_graduation_evidence_as_owner(evidence, &owner)
            .is_err()
    );
    let after = vault
        .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
        .unwrap()
        .unwrap();
    assert_eq!(after.evidence_refs, admitted.evidence_refs);
    assert_eq!(consent_records(), before);
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
    for class in [Some("other".to_owned()), None] {
        let mut other = scope.clone();
        other.counterparty_class = class;
        for n in 1..=12 {
            review(&vault, &other, n, DraftReviewOutcome::ApprovedUntouched);
        }
        assert!(
            vault
                .evaluate_graduation_offer(&other, 0, crate::unix_seconds_now())
                .unwrap()
                .is_none()
        );
    }
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 0, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
}

/// `WriteActor` can never stand in for owner authentication at an envelope or mode door.
/// ```compile_fail
/// use oneiron::{Vault, write_envelope::WriteActor};
/// use oneiron::channel_identity_autonomy::{MailboxReadEnvelope, ChannelIdentityAutonomyMode};
/// fn cannot_escalate(vault: &Vault, actor: &WriteActor, envelope: MailboxReadEnvelope, mode: ChannelIdentityAutonomyMode) {
///     vault.put_mailbox_read_envelope(envelope, actor, 1).unwrap();
///     vault.set_channel_identity_autonomy_mode(mode, actor, 1).unwrap();
/// }
/// ```
#[test]
fn owner_write_signatures_require_authenticated_owner() {
    let _: fn(&Vault, MailboxReadEnvelope, &AuthenticatedOwner, u64) -> Result<EntityId> =
        Vault::put_mailbox_read_envelope;
    let _: fn(&Vault, ChannelIdentityActionEnvelope, &AuthenticatedOwner, u64) -> Result<EntityId> =
        Vault::put_channel_identity_action_envelope;
    let _: fn(&Vault, ChannelIdentityAutonomyMode, &AuthenticatedOwner, u64) -> Result<EntityId> =
        Vault::set_channel_identity_autonomy_mode;
    let _: fn(&Vault, &EntityId, &ChannelIdentityEffectCandidate) -> Result<bool> =
        Vault::authorize_and_consume_channel_identity_grant;
    let _: fn(
        &Vault,
        &ChannelIdentityAutonomyRequest,
        &AuthenticatedOwner,
    ) -> Result<ChannelIdentityAutonomyState> = Vault::apply_channel_identity_autonomy;
    let _: fn(
        &Vault,
        &ChannelIdentityAutonomyRequest,
        &AuthenticatedOwner,
    ) -> Result<ChannelIdentityAutonomyState> = Vault::verify_channel_identity_autonomy;
    let _: fn(&Vault, GraduationEvidence, &AuthenticatedOwner) -> Result<EntityId> =
        Vault::record_graduation_evidence_as_owner;
}

#[test]
fn generic_grant_writes_cannot_reactivate_or_replace_owner_read_authority() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let reference = state.mode.read_grant_ref.unwrap();
    assert!(
        vault
            .put_access_grant(&reference, &state.read_grant)
            .is_err()
    );
    assert!(
        vault
            .create_access_grant(&entity(0x85), &state.read_grant)
            .is_err()
    );
    let unrelated =
        AccessGrant::companion_profile_read(request.actor_ref, entity(0x86), entity(0x87), 1);
    assert!(vault.put_access_grant(&reference, &unrelated).is_err());
    vault
        .revoke_access_grant(&reference, crate::unix_seconds_now())
        .unwrap();
    assert!(
        vault
            .put_access_grant(&reference, &state.read_grant)
            .is_err()
    );
    assert!(
        vault
            .verify_channel_identity_autonomy(&request, &owner)
            .is_err()
    );
}

#[test]
fn volume_clock_rollback_fails_closed_and_elapsed_window_resets() {
    let (_dir, vault, owner, mut request) =
        fixture(ChannelIdentityAutonomyRung::AutonomousWithinEnvelope);
    request.action_envelope.as_mut().unwrap().max_actions = 1;
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let reference = state.mode.action_grant_ref.unwrap();
    let StandingOutboundGrantScope::ChannelIdentityEnvelope { envelope_ref, .. } =
        state.action_grant.unwrap().scope
    else {
        panic!("identity action");
    };
    let mut key = crate::outbound_grant::CHANNEL_IDENTITY_GRANT_USAGE_PREFIX.to_vec();
    key.extend_from_slice(envelope_ref.as_bytes());
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 1))
            .unwrap()
    );
    let now = crate::unix_seconds_now();
    // Simulate an engine clock rollback by making its last persisted window
    // start lie in the future. There is no clock field in the public candidate.
    {
        let mut txn = vault.store.env.write_txn().unwrap();
        let mut bytes = vault
            .store
            .vault_meta
            .get(&txn, &key)
            .unwrap()
            .unwrap()
            .to_vec();
        bytes[..8].copy_from_slice(&(now + 86_400).to_be_bytes());
        vault.store.vault_meta.put(&mut txn, &key, &bytes).unwrap();
        txn.commit().unwrap();
    }
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 2))
            .unwrap()
    );
    {
        let mut txn = vault.store.env.write_txn().unwrap();
        let mut bytes = vault
            .store
            .vault_meta
            .get(&txn, &key)
            .unwrap()
            .unwrap()
            .to_vec();
        bytes[..8].copy_from_slice(&(now - 86_400).to_be_bytes());
        vault.store.vault_meta.put(&mut txn, &key, &bytes).unwrap();
        txn.commit().unwrap();
    }
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 2))
            .unwrap()
    );
    assert!(
        !vault
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 3))
            .unwrap()
    );
}

#[test]
fn owner_can_apply_another_context_without_reminting_shared_read_authority() {
    let (_dir, vault, owner, mut request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    let first = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    request.relationship_context = RelationshipContext::PersonalFriends;
    request
        .action_envelope
        .as_mut()
        .unwrap()
        .relationship_context = request.relationship_context;
    let second = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    assert_eq!(first.mode.read_grant_ref, second.mode.read_grant_ref);
    assert_ne!(first.mode.action_grant_ref, second.mode.action_grant_ref);
    let verified = vault
        .verify_channel_identity_autonomy(&request, &owner)
        .unwrap();
    assert_eq!(
        verified.mode.relationship_context,
        RelationshipContext::PersonalFriends,
    );
    assert_eq!(verified.mode.rung, ChannelIdentityAutonomyRung::DraftOnly);
    assert_eq!(verified.mode.read_grant_ref, second.mode.read_grant_ref);
    assert_eq!(verified.mode.action_grant_ref, second.mode.action_grant_ref);
}

#[test]
fn scoped_read_checks_identity_principal_labels_threads_and_item_time() {
    let (_dir, vault, owner, mut request) = fixture(ChannelIdentityAutonomyRung::ScopedRead);
    request.read_envelope.not_before = Some(10);
    request.read_envelope.not_after = Some(20);
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let reference = state.mode.read_grant_ref.unwrap();
    let item = MailboxReadCandidate {
        identity_ref: request.read_envelope.identity_ref,
        label: Some("inbox".to_owned()),
        thread_ref: Some("thread:1".to_owned()),
        occurred_at: 15,
    };
    assert!(
        vault
            .authorize_channel_identity_scoped_read(&reference, &request.actor_ref, &item)
            .unwrap()
    );
    let mut wrong = item.clone();
    wrong.label = Some("private".to_owned());
    assert!(
        !vault
            .authorize_channel_identity_scoped_read(&reference, &request.actor_ref, &wrong)
            .unwrap()
    );
    wrong = item.clone();
    wrong.thread_ref = None;
    assert!(
        !vault
            .authorize_channel_identity_scoped_read(&reference, &request.actor_ref, &wrong)
            .unwrap()
    );
    wrong = item.clone();
    wrong.occurred_at = 21;
    assert!(
        !vault
            .authorize_channel_identity_scoped_read(&reference, &request.actor_ref, &wrong)
            .unwrap()
    );
    wrong = item.clone();
    wrong.identity_ref = entity(0x62);
    assert!(
        !vault
            .authorize_channel_identity_scoped_read(&reference, &request.actor_ref, &wrong)
            .unwrap()
    );
    assert!(
        !vault
            .authorize_channel_identity_scoped_read(&reference, &entity(0x72), &item)
            .unwrap()
    );
    vault
        .revoke_access_grant(&reference, crate::unix_seconds_now())
        .unwrap();
    assert!(
        !vault
            .authorize_channel_identity_scoped_read(&reference, &request.actor_ref, &item)
            .unwrap()
    );
}

#[test]
fn posture_never_authorizes_missing_or_mismatched_grants() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    let state = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let consent_records = || {
        vault
            .store
            .gate_decisions(usize::MAX)
            .unwrap()
            .into_iter()
            .map(|row| (row.decision_id, row.outcome, row.grant_ref))
            .collect::<Vec<_>>()
    };
    let before = consent_records();
    let assert_unchanged = || {
        let resolved = vault
            .resolve_channel_identity_autonomy_mode(
                &request.read_envelope.identity_ref,
                &request.relationship_context,
                crate::unix_seconds_now(),
            )
            .unwrap();
        assert_eq!(resolved.identity_ref, state.mode.identity_ref);
        assert_eq!(
            resolved.relationship_context,
            state.mode.relationship_context
        );
        assert_eq!(resolved.rung, state.mode.rung);
        assert_eq!(resolved.read_grant_ref, state.mode.read_grant_ref);
        assert_eq!(resolved.action_grant_ref, state.mode.action_grant_ref);
        assert_eq!(consent_records(), before);
    };
    let mut mode = state.mode.clone();
    mode.rung = ChannelIdentityAutonomyRung::AutonomousWithinEnvelope;
    assert!(
        vault
            .set_channel_identity_autonomy_mode(mode, &owner, crate::unix_seconds_now())
            .is_err()
    );
    assert_unchanged();
    let mut mode = state.mode.clone();
    mode.action_grant_ref = Some(entity(0x88));
    assert!(
        vault
            .set_channel_identity_autonomy_mode(mode, &owner, crate::unix_seconds_now())
            .is_err()
    );
    assert_unchanged();
    let mut mode = state.mode.clone();
    mode.read_grant_ref = None;
    assert!(
        vault
            .set_channel_identity_autonomy_mode(mode, &owner, crate::unix_seconds_now())
            .is_err()
    );
    assert_unchanged();
}

#[test]
fn effect_key_reservation_survives_reopen_without_double_consumption() {
    let (dir, vault, owner, mut request) =
        fixture(ChannelIdentityAutonomyRung::AutonomousWithinEnvelope);
    request.action_envelope.as_mut().unwrap().max_actions = 1;
    let reference = vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap()
        .mode
        .action_grant_ref
        .unwrap();
    let effect = candidate(&request, 1);
    assert!(
        vault
            .authorize_and_consume_channel_identity_grant(&reference, &effect)
            .unwrap()
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
    assert!(
        reopened
            .authorize_and_consume_channel_identity_grant(&reference, &effect)
            .unwrap()
    );
    assert!(
        !reopened
            .authorize_and_consume_channel_identity_grant(&reference, &candidate(&request, 2))
            .unwrap()
    );
}

#[test]
fn owner_review_exception_requires_authentication_and_preserves_attribution() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    let evidence = persist_review(&vault, &scope, 1, DraftReviewOutcome::ApprovedUntouched);
    let reference = evidence.receipt_ref.clone();
    let consent_records = || {
        vault
            .store
            .gate_decisions(usize::MAX)
            .unwrap()
            .into_iter()
            .map(|row| (row.decision_id, row.outcome, row.grant_ref))
            .collect::<Vec<_>>()
    };
    let before_unauthenticated = consent_records();
    assert!(
        vault
            .record_graduation_evidence(
                evidence.clone(),
                &WriteActor::new(owner.actor(), EdgeActorClass::Human),
            )
            .is_err()
    );
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
    assert_eq!(consent_records(), before_unauthenticated);
    vault
        .record_graduation_evidence_as_owner(evidence.clone(), &owner)
        .unwrap();
    let admitted = vault
        .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
        .unwrap()
        .unwrap();
    assert_eq!(admitted.scope.actor_ref, request.actor_ref);
    assert_eq!(admitted.evidence_refs, std::slice::from_ref(&reference));
    let before = consent_records();
    assert!(
        vault
            .record_graduation_evidence_as_owner(evidence.clone(), &owner)
            .is_err()
    );
    assert!(
        vault
            .record_graduation_evidence(
                evidence,
                &WriteActor::new(scope.actor_ref, EdgeActorClass::Agent),
            )
            .is_err()
    );
    assert_eq!(consent_records(), before);
    let offer = vault
        .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
        .unwrap()
        .unwrap();
    assert_eq!(offer.scope.actor_ref, request.actor_ref);
    assert_eq!(offer.evidence_refs, [reference]);
}

fn assert_review_rejected(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    evidence: &GraduationEvidence,
) {
    let before = snapshot(vault);
    let actor = WriteActor::new(evidence.scope.actor_ref, EdgeActorClass::Agent);
    assert!(
        vault
            .record_graduation_evidence(evidence.clone(), &actor)
            .is_err()
    );
    assert!(
        vault
            .record_graduation_evidence_as_owner(evidence.clone(), owner)
            .is_err()
    );
    assert_eq!(
        snapshot(vault),
        before,
        "rejection must not change evidence or grants"
    );
}

#[test]
fn graduation_evidence_requires_a_persisted_review_for_both_writers() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    let receipt = review_receipt(&scope, 1, &DraftReviewOutcome::ApprovedUntouched);
    let evidence = GraduationEvidence {
        scope: scope.clone(),
        outcome: DraftReviewOutcome::ApprovedUntouched,
        receipt_ref: receipt.receipt_id.clone(),
        occurred_at: receipt.occurred_at,
    };
    // A plausible review object and a caller-created agent attribution prove nothing.
    assert_review_rejected(&vault, &owner, &evidence);
    let (_other_dir, other) = open_test_vault_with(embedding_test_config());
    persist_send_receipt(
        &other,
        EntityId::now(),
        receipt.clone(),
        SendReceiptOutcome::Failed,
        false,
        None,
    )
    .unwrap();
    assert_review_rejected(&vault, &owner, &evidence);
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
    persist_send_receipt(
        &vault,
        EntityId::now(),
        receipt,
        SendReceiptOutcome::Failed,
        false,
        None,
    )
    .unwrap();
    vault
        .record_graduation_evidence(
            evidence,
            &WriteActor::new(scope.actor_ref, EdgeActorClass::Agent),
        )
        .unwrap();
    assert_eq!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .unwrap()
            .unchanged_streak,
        1
    );
}

#[test]
fn graduation_evidence_binds_every_scope_axis_outcome_and_time() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    // A second live identity for the same actor passes identity admission but
    // must not borrow the first identity's persisted review.
    let mut other_identity = vault
        .get_channel_identity(&scope.identity_ref)
        .unwrap()
        .unwrap();
    other_identity.address_or_handle = "other@example.test".to_owned();
    vault
        .create_channel_identity(&entity(0x62), &other_identity)
        .unwrap();
    let evidence = persist_review(&vault, &scope, 1, DraftReviewOutcome::ApprovedUntouched);
    for axis in 0..10 {
        let mut wrong = evidence.clone();
        match axis {
            0 => wrong.scope.identity_ref = entity(0x62),
            1 => wrong.scope.actor_ref = entity(0x72),
            2 => wrong.scope.relationship_context = RelationshipContext::PersonalFriends,
            3 => wrong.scope.verb_class = "mail.draft".to_owned(),
            4 => wrong.scope.counterparty_class = Some("other".to_owned()),
            5 => wrong.scope.counterparty_class = None,
            6 => {
                wrong.outcome = DraftReviewOutcome::ApprovedAmended {
                    edit_distance_millis: 1,
                }
            }
            7 => wrong.outcome = DraftReviewOutcome::Rejected,
            8 => wrong.outcome = DraftReviewOutcome::Undone,
            _ => wrong.occurred_at = 2,
        }
        assert_review_rejected(&vault, &owner, &wrong);
    }
    let amended = persist_review(
        &vault,
        &scope,
        2,
        DraftReviewOutcome::ApprovedAmended {
            edit_distance_millis: 25,
        },
    );
    for outcome in [
        DraftReviewOutcome::ApprovedUntouched,
        DraftReviewOutcome::ApprovedAmended {
            edit_distance_millis: 24,
        },
    ] {
        let mut wrong = amended.clone();
        wrong.outcome = outcome;
        assert_review_rejected(&vault, &owner, &wrong);
    }
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
    vault
        .record_graduation_evidence_as_owner(evidence.clone(), &owner)
        .unwrap();
    // A caller may not overwrite that approval with an invented correction.
    let mut correction = evidence;
    correction.outcome = DraftReviewOutcome::Rejected;
    assert_review_rejected(&vault, &owner, &correction);
    vault
        .record_graduation_evidence_as_owner(amended, &owner)
        .unwrap();
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
}

#[test]
fn graduation_rejects_ineligible_and_incompletely_bound_receipts() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    for missing in [
        "channel_identity_ref",
        "relationship_context",
        "verb_class",
        "counterparty_class",
        "review_outcome",
    ] {
        let mut receipt = review_receipt(&scope, 1, &DraftReviewOutcome::ApprovedUntouched);
        receipt.fields.remove(missing);
        let evidence = GraduationEvidence {
            scope: scope.clone(),
            outcome: DraftReviewOutcome::ApprovedUntouched,
            receipt_ref: receipt.receipt_id.clone(),
            occurred_at: 1,
        };
        persist_send_receipt(
            &vault,
            EntityId::now(),
            receipt,
            SendReceiptOutcome::Failed,
            false,
            None,
        )
        .unwrap();
        assert_review_rejected(&vault, &owner, &evidence);
    }
    for case in 0..6 {
        let mut receipt = review_receipt(&scope, 1, &DraftReviewOutcome::ApprovedUntouched);
        match case {
            0 => {
                receipt.actor = None;
                receipt.on_behalf_of = Some(scope.actor_ref.to_hex());
            }
            1 => {
                receipt.actor = Some(owner.actor().to_hex());
                receipt.on_behalf_of = Some(scope.actor_ref.to_hex());
            }
            2 => {
                receipt
                    .fields
                    .insert("review_outcome".to_owned(), "allow".to_owned());
            }
            3 => {
                receipt
                    .fields
                    .insert("edit_distance_millis".to_owned(), "0".to_owned());
            }
            4 => {
                receipt
                    .fields
                    .insert("edit_distance_millis".to_owned(), "invalid".to_owned());
            }
            _ => {
                receipt.fields.remove("review_outcome");
            }
        }
        // Delivery is not evidence that a human approved a draft untouched.
        receipt.outcome = "delivered_to_channel".to_owned();
        let evidence = GraduationEvidence {
            scope: scope.clone(),
            outcome: DraftReviewOutcome::ApprovedUntouched,
            receipt_ref: receipt.receipt_id.clone(),
            occurred_at: 1,
        };
        persist_send_receipt(
            &vault,
            EntityId::now(),
            receipt,
            SendReceiptOutcome::Delivered,
            true,
            None,
        )
        .unwrap();
        assert_review_rejected(&vault, &owner, &evidence);
    }
    for distance in [None, Some("bad"), Some("4294967296"), Some("-1")] {
        let outcome = DraftReviewOutcome::ApprovedAmended {
            edit_distance_millis: 1,
        };
        let mut receipt = review_receipt(&scope, 1, &outcome);
        receipt.fields.remove("edit_distance_millis");
        if let Some(distance) = distance {
            receipt
                .fields
                .insert("edit_distance_millis".to_owned(), distance.to_owned());
        }
        let evidence = GraduationEvidence {
            scope: scope.clone(),
            outcome,
            receipt_ref: receipt.receipt_id.clone(),
            occurred_at: 1,
        };
        persist_send_receipt(
            &vault,
            EntityId::now(),
            receipt,
            SendReceiptOutcome::Failed,
            false,
            None,
        )
        .unwrap();
        assert_review_rejected(&vault, &owner, &evidence);
    }
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
}

#[test]
fn graduation_rejects_ambiguous_persisted_receipt_ids() {
    let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    let receipt = review_receipt(&scope, 1, &DraftReviewOutcome::ApprovedUntouched);
    let evidence = GraduationEvidence {
        scope: scope.clone(),
        outcome: DraftReviewOutcome::ApprovedUntouched,
        receipt_ref: receipt.receipt_id.clone(),
        occurred_at: 1,
    };
    persist_send_receipt(
        &vault,
        EntityId::now(),
        receipt.clone(),
        SendReceiptOutcome::Failed,
        false,
        None,
    )
    .unwrap();
    let mut ambiguous = receipt;
    // Even a conflicting actor/time/outcome cannot hide behind query filters.
    ambiguous.actor = Some(entity(0x72).to_hex());
    ambiguous.occurred_at = 2;
    ambiguous
        .fields
        .insert("review_outcome".to_owned(), "rejected".to_owned());
    persist_send_receipt(
        &vault,
        EntityId::now(),
        ambiguous,
        SendReceiptOutcome::Failed,
        false,
        None,
    )
    .unwrap();
    assert_review_rejected(&vault, &owner, &evidence);
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
}

#[test]
fn graduation_rejects_capped_source_hiding_a_duplicate_review() {
    use crate::receipt::{MAX_RECEIPT_QUERY_SCAN, put_attempt_pack_receipt_for_test};

    let (dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    drop(vault);
    let mut config = embedding_test_config();
    config.map_size = 256 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).unwrap();
    let scope = review_scope(&request);
    let mut receipt = review_receipt(&scope, 1, &DraftReviewOutcome::ApprovedUntouched);
    receipt.receipt_id = format!("attempt:{:032x}", 0);
    let evidence = GraduationEvidence {
        scope: scope.clone(),
        outcome: DraftReviewOutcome::ApprovedUntouched,
        receipt_ref: receipt.receipt_id.clone(),
        occurred_at: 1,
    };
    persist_send_receipt(
        &vault,
        EntityId::now(),
        receipt.clone(),
        SendReceiptOutcome::Failed,
        false,
        None,
    )
    .unwrap();
    // A conflicting, ineligible duplicate lives just beyond the source cap.
    // Off-kind filler leaves only the eligible durable row in the result, so
    // neither result length nor filtering can establish uniqueness.
    receipt.actor = Some(entity(0x72).to_hex());
    receipt.occurred_at = 2;
    receipt
        .fields
        .insert("review_outcome".to_owned(), "rejected".to_owned());
    vault
        .with_write_txn(|wtxn| {
            put_attempt_pack_receipt_for_test(&vault.store, wtxn, &receipt)?;
            let mut filler = ReceiptRecord {
                receipt_id: String::new(),
                receipt_kind: ReceiptKind::Gate,
                occurred_at: 2,
                actor: None,
                on_behalf_of: None,
                outcome: "completed".to_owned(),
                job_ref: None,
                trigger_ref: None,
                policy_trace: Vec::new(),
                fields: BTreeMap::new(),
            };
            for index in 1..=MAX_RECEIPT_QUERY_SCAN {
                filler.receipt_id = format!("attempt:{index:032x}");
                put_attempt_pack_receipt_for_test(&vault.store, wtxn, &filler)?;
            }
            Ok(())
        })
        .unwrap();
    let conflicting = crate::receipt::attempt_pack_receipt(&vault, &evidence.receipt_ref)
        .unwrap()
        .unwrap();
    assert_eq!(conflicting.receipt_id, evidence.receipt_ref);
    assert_eq!(conflicting.actor, Some(entity(0x72).to_hex()));
    assert_eq!(
        conflicting.fields.get("review_outcome").map(String::as_str),
        Some("rejected"),
    );
    let scan = vault
        .scan_receipts(ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN).with_kind(ReceiptKind::Outbound))
        .unwrap();
    assert_eq!(scan.records.len(), 1);
    assert_eq!(scan.records[0].receipt_id, evidence.receipt_ref);
    assert_eq!(
        scan.records[0]
            .fields
            .get("review_outcome")
            .map(String::as_str),
        Some("approved_untouched"),
    );
    assert!(
        !scan.complete,
        "one visible match is not proof of uniqueness",
    );
    let continuation = scan.continuation.unwrap();
    assert_eq!(
        continuation.attempt_pack_before,
        Some(format!("attempt_receipt:v1:attempt:{:032x}", 1).into_bytes()),
    );
    assert!(
        continuation.next_record.is_none(),
        "the source, not the result limit, hid the duplicate",
    );
    assert_review_rejected(&vault, &owner, &evidence);
    assert!(
        vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .is_none()
    );
}

#[test]
fn graduation_accepts_complete_unique_review_for_both_writers() {
    for owner_authenticated in [false, true] {
        let (_dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
        vault
            .apply_channel_identity_autonomy(&request, &owner)
            .unwrap();
        let scope = review_scope(&request);
        let evidence = persist_review(&vault, &scope, 1, DraftReviewOutcome::ApprovedUntouched);
        // Other persisted reviews do not make this receipt id ambiguous.
        persist_review(&vault, &scope, 2, DraftReviewOutcome::Rejected);
        let scan = vault
            .scan_receipts(
                ReceiptQuery::new(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
                    .with_kind(ReceiptKind::Outbound),
            )
            .unwrap();
        assert!(scan.complete);
        assert!(scan.continuation.is_none());
        assert_eq!(scan.records.len(), 2);
        let matches: Vec<_> = scan
            .records
            .iter()
            .filter(|r| r.receipt_id == evidence.receipt_ref)
            .collect();
        assert_eq!(matches.len(), 1);
        assert!(
            matches[0]
                .fields
                .get(crate::receipt::FIELD_TASK_REF)
                .and_then(|value| EntityId::from_hex(value).ok())
                .is_some()
        );
        if owner_authenticated {
            vault
                .record_graduation_evidence_as_owner(evidence.clone(), &owner)
                .unwrap();
        } else {
            vault
                .record_graduation_evidence(
                    evidence.clone(),
                    &WriteActor::new(scope.actor_ref, EdgeActorClass::Agent),
                )
                .unwrap();
        }
        let offer = vault
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .unwrap();
        assert_eq!(offer.evidence_refs, [evidence.receipt_ref]);
        assert_eq!(offer.unchanged_streak, 1);
        assert_eq!(offer.scope, scope);
        assert_eq!(
            vault
                .verify_channel_identity_autonomy(&request, &owner)
                .unwrap()
                .mode
                .rung,
            ChannelIdentityAutonomyRung::DraftOnly
        );
    }
}

#[test]
fn graduation_duplicate_admission_is_atomic_and_survives_reopen() {
    let (dir, vault, owner, request) = fixture(ChannelIdentityAutonomyRung::DraftOnly);
    vault
        .apply_channel_identity_autonomy(&request, &owner)
        .unwrap();
    let scope = review_scope(&request);
    let evidence = persist_review(&vault, &scope, 1, DraftReviewOutcome::ApprovedUntouched);
    let barrier = std::sync::Barrier::new(8);
    let accepted = std::thread::scope(|threads| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let vault = &vault;
                let evidence = &evidence;
                let barrier = &barrier;
                threads.spawn(move || {
                    barrier.wait();
                    vault
                        .record_graduation_evidence(
                            evidence.clone(),
                            &WriteActor::new(evidence.scope.actor_ref, EdgeActorClass::Agent),
                        )
                        .is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(accepted, 1);
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
    assert_review_rejected(&reopened, &owner, &evidence);
    assert_eq!(
        reopened
            .evaluate_graduation_offer(&scope, 1, crate::unix_seconds_now())
            .unwrap()
            .unwrap()
            .evidence_refs,
        [evidence.receipt_ref]
    );
}
