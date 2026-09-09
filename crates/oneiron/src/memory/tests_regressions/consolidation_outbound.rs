//! BRIDGE-03 wiring regressions: Dreamer queue round-trip, seed-claim receipts, outbound schedule and dedupe.

use super::*;

// ═══ BRIDGE-03 (ONE-1456): Dreamer + seed + outbound wiring ═════════════

#[test]
fn consolidation_queue_round_trip_with_facade_writeback() {
    use crate::dreamer_runner::{
        AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
        CompleteDreamerAttemptOutcome, DreamerAdmissionOutcome, DreamerClaimAuthoringAdmission,
        DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
        DreamerConsolidationScope, DreamerRunnerStore,
    };

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x51);
    let subject = put_person(&vault, 0x52);
    let facade = facade_for(&vault, actor);

    // Enqueue through the bridge verb; advisory dedupe coalesces re-enqueues.
    let attempt = facade
        .enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-1"}),
            run_id: Some("run-bridge-1".to_owned()),
            dedupe_key: Some("bridge-dedupe-1".to_owned()),
            now: Some(2000),
        })
        .expect("enqueue");
    assert_eq!(attempt.state, "queued");
    assert!(!attempt.existing);
    let again = facade
        .enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-1"}),
            run_id: Some("run-bridge-1".to_owned()),
            dedupe_key: Some("bridge-dedupe-1".to_owned()),
            now: Some(2001),
        })
        .expect("re-enqueue");
    assert!(again.existing, "advisory dedupe coalesces");
    assert_eq!(again.job_ref, attempt.job_ref);

    // Poll model: queued → (admit engine-side) → leased → completed.
    let status = facade
        .dreamer_attempt_status(&attempt.job_ref)
        .expect("status")
        .expect("attempt exists");
    assert_eq!(status.state, "queued");
    assert_eq!(status.run_id.as_deref(), Some("run-bridge-1"));

    let store = DreamerRunnerStore::new(&vault);
    let admitted = store
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 7,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "bridge-test-worker".to_owned(),
                now: 2002,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 10,
                reserve_units: 1,
                started_milestone: None,
            },
        })
        .expect("admit");
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted_attempt,
    )) = admitted
    else {
        panic!("expected admitted consolidation attempt, got {admitted:?}");
    };
    let leased = facade
        .dreamer_attempt_status(&attempt.job_ref)
        .expect("status")
        .expect("attempt exists");
    assert_eq!(leased.state, "leased");
    assert_eq!(leased.lease_owner.as_deref(), Some("bridge-test-worker"));

    // AC-5 (W3 non-contention): an interactive witness during the running
    // consolidation succeeds without waiting on the attempt.
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x53; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "mid-consolidation note",
            )],
            occurred_at: 2003,
        })
        .expect("source write never queues behind derived work");

    // Writeback rides the SAME facade commit path: generated source lands
    // proposed (requires_explicit_auto_permit; no generated auto-permit
    // policy exists at base) with a per-write receipt.
    let writeback = facade
        .commit(&[{
            let mut input = claim_input(
                "eiri.summary.window",
                &subject,
                "generated",
                serde_json::json!({"summary": "moss gardens dominate the week"}),
            );
            input.occurred_at = Some(2004);
            input.learned_at = Some(2004);
            input
        }])
        .expect("writeback commit");
    assert_eq!(writeback.len(), 1);
    assert_eq!(
        writeback[0].approval, "proposed",
        "generated writeback never lands auto"
    );
    assert!(writeback[0].receipt_ref.starts_with("gate:"));
    let receipts = facade.receipts(50).expect("receipts");
    assert!(
        receipts
            .iter()
            .any(|r| r.receipt_ref == writeback[0].receipt_ref),
        "writeback receipt resolvable via receipts()"
    );
    assert!(
        !facade.pending_writes(50).expect("pending").is_empty(),
        "proposed writeback parks for consent"
    );

    // Writeback is retrievable through the ungated claim reads; the D19
    // admission keeps PROPOSED claims out of recall packs until consent
    // resolves (asserted as non-leakage).
    let listed = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: Some("eiri.summary.window".to_owned()),
            lifecycle: Some("active".to_owned()),
            limit: 10,
        })
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].source.as_deref(), Some("generated"));
    let pack = facade
        .recall(
            "moss gardens",
            Effort::Standard,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    assert!(
        !pack.items.iter().any(|item| item.kind == "CLAIM"),
        "proposed writeback must NOT surface in packs before consent"
    );

    // Complete the lease; the bridge polls the terminal state.
    let completed = store
        .complete(CompleteDreamerAttempt {
            id: admitted_attempt.status.attempt.id,
            lease_owner: "bridge-test-worker".to_owned(),
            attempt_count: admitted_attempt.status.attempt.attempt_count,
            now: 2005,
        })
        .expect("complete");
    assert!(matches!(
        completed,
        CompleteDreamerAttemptOutcome::Completed(_)
    ));
    let done = facade
        .dreamer_attempt_status(&attempt.job_ref)
        .expect("status")
        .expect("attempt exists");
    assert_eq!(done.state, "completed");

    // Unknown scope fails closed.
    let err = facade
        .enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "giga".to_owned(),
            input: serde_json::json!({}),
            run_id: None,
            dedupe_key: None,
            now: Some(2006),
        })
        .expect_err("unknown scope");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
}

/// G1: enqueue_consolidation is a side-effecting verb and runs the same
/// store-resolved actor check as every other write verb.
#[test]
fn enqueue_consolidation_requires_a_verified_actor() {
    let (_dir, vault) = open_vault();
    let enqueue = |facade: &Memory<'_>| {
        facade.enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-g1"}),
            run_id: None,
            dedupe_key: None,
            now: Some(2100),
        })
    };

    // Ghost actor: refused.
    let ghost = EntityId::from_bytes([0x60; 16]).unwrap();
    let err = enqueue(&facade_for(&vault, ghost)).expect_err("ghost enqueue");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);

    // Type-mismatched actor (an EVENT bound as human): refused.
    let owner = put_person(&vault, 0x61);
    let owner_facade = facade_for(&vault, owner);
    let event = owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "g1"}),
            text_fields: None,
            edges: None,
            occurred_at: 2101,
            learned_at: None,
        })
        .expect("event");
    let event_id = EntityId::from_hex(&event.id_hex).unwrap();
    let err = enqueue(&facade_for(&vault, event_id)).expect_err("mismatch enqueue");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);

    // A verified actor enqueues normally.
    enqueue(&owner_facade).expect("verified enqueue");
}

#[test]
fn seed_claims_force_proposed_with_per_element_receipts() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x54);
    let subject = put_person(&vault, 0x55);
    let facade = facade_for(&vault, actor);

    // AC-3: a user_stated seed — auto-eligible through commit — is FORCED
    // proposed on the seed path, parks for consent, and emits a receipt.
    // eiri.* predicates carry the default manifest's critical criticality,
    // so the forced-proposed seed parks as a pending consent (profile.*
    // seeds land proposed with gate outcome allow and do not park).
    let receipts = facade
        .seed_claims(&[
            claim_input(
                "eiri.profile.name",
                &subject,
                "user_stated",
                serde_json::json!("Cold Start"),
            ),
            // Violating element: rejected while the others land (C3).
            claim_input(
                "BadPredicate",
                &subject,
                "user_stated",
                serde_json::json!("x"),
            ),
            claim_input(
                "eiri.onboarding.answer",
                &subject,
                "imported",
                serde_json::json!({"question_id": "q-1", "selected_option_id": "a"}),
            ),
        ])
        .expect("seed");
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].approval, "proposed", "seed forces proposed");
    assert!(receipts[0].receipt_ref.starts_with("gate:"));
    assert_eq!(receipts[1].approval, "rejected");
    assert_eq!(receipts[2].approval, "proposed");

    let pending = facade.pending_writes(50).expect("pending");
    assert_eq!(pending.len(), 2, "both landed seeds park for consent");
    let listed = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: Some("active".to_owned()),
            limit: 10,
        })
        .expect("list");
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|claim| claim.approval == "proposed"));
}

#[test]
fn schedule_outbound_holds_gate_checks_and_dedupes() {
    use crate::attempt_queue::AttemptQueue;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x56);
    let facade = facade_for(&vault, actor);

    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "kenji@example.com".to_owned(),
        on_behalf_of: Some("owner".to_owned()),
        content_ref: Some("content:invite".to_owned()),
        idempotency_key: Some("idem-invite-1".to_owned()),
        dedupe_key: Some("dedupe-invite-1".to_owned()),
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:send-now".to_owned(),
        job_ref: Some("brief:party".to_owned()),
        occurred_at: Some(3000),
    };
    let receipt = facade.schedule_outbound(&draft).expect("schedule");
    assert!(receipt.intent_ref.starts_with("intent:"));
    assert!(!receipt.deduped);
    // Schedule-only surface: the sink is never reached — under the default
    // manifest the external-effect gate pends (no policy grant) and the
    // Hold window keeps delivery with the delivery-window machinery.
    // Receipts, not admission, are the contract (GOV-compatible).
    assert!(
        matches!(receipt.outcome.as_str(), "held" | "suppressed" | "let_go"),
        "schedule-only dispatch must not deliver; got {}",
        receipt.outcome
    );
    let gate_ref = receipt
        .gate_decision_ref
        .clone()
        .expect("gate decision persisted");
    let receipts = facade.receipts(50).expect("receipts");
    assert!(
        receipts.iter().any(|r| r.receipt_ref == gate_ref),
        "intent's gate receipt queryable via receipts()"
    );

    // AC-4 idempotency: a second call with the same idempotency_key does
    // not double-enqueue and produces no second gate decision.
    let decisions_before = facade.receipts(100).expect("receipts").len();
    let replay = facade.schedule_outbound(&draft).expect("replay");
    assert!(replay.deduped);
    assert_eq!(replay.outcome, "already_scheduled");
    assert_eq!(replay.intent_ref, receipt.intent_ref);
    assert_eq!(
        facade.receipts(100).expect("receipts").len(),
        decisions_before,
        "no second gate decision on dedupe"
    );
    let queue = AttemptQueue::new(&vault);
    let scheduled = queue
        .list()
        .expect("list attempts")
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .count();
    assert_eq!(scheduled, 1, "one durable schedule row");

    // Unknown trigger fails closed.
    let mut bad = draft;
    bad.idempotency_key = Some("idem-invite-2".to_owned());
    bad.trigger = "vibes".to_owned();
    let err = facade.schedule_outbound(&bad).expect_err("unknown trigger");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn missing_bound_outbound_actor_maps_to_forbidden() {
    let err = facade_error_from_outbound_dispatch(OutboundDispatchError::InvalidBoundActor);

    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    assert_ne!(err.code, MEMORY_CODE_NOT_FOUND);
}

/// #484a regression: an unsupported channel is rejected BEFORE the durable
/// enqueue, so it leaves no orphan attempt/dedupe entry and a retry (on a
/// supported channel, same idempotency key) is not wedged as an existing
/// dedupe hit.
#[test]
fn schedule_outbound_unsupported_channel_leaves_no_orphan_and_allows_retry() {
    use crate::attempt_queue::{AttemptQueue, AttemptState};

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x60);
    let facade = facade_for(&vault, actor);

    let mut draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "carrier_pigeon".to_owned(),
        target: "roost@example.com".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some("idem-orphan-1".to_owned()),
        dedupe_key: Some("dedupe-orphan-1".to_owned()),
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:pigeon".to_owned(),
        job_ref: None,
        occurred_at: Some(4000),
    };

    let err = facade
        .schedule_outbound(&draft)
        .expect_err("unsupported channel fails closed");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);

    // No live (non-cancelled) schedule row orphaned by the failed dispatch.
    let queue = AttemptQueue::new(&vault);
    let live = queue
        .list()
        .expect("list attempts")
        .into_iter()
        .find(|attempt| {
            attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND && attempt.state != AttemptState::Cancelled
        });
    assert!(
        live.is_none(),
        "unsupported channel must not leave a live outbound attempt"
    );

    // A retry on a supported channel with the SAME idempotency key proceeds
    // (no lingering dedupe entry to coalesce onto).
    draft.channel = "email".to_owned();
    let receipt = facade.schedule_outbound(&draft).expect("retry proceeds");
    assert!(
        !receipt.deduped,
        "retry re-enqueues instead of deduping onto an orphan"
    );
    assert!(receipt.intent_ref.starts_with("intent:"));
}

/// #484b regression: an idempotent retry recovers the ORIGINAL gate decision
/// ref instead of an empty gate result. The first schedule persists its gate
/// surface keyed by attempt id; the dedupe branch reads it back.
#[test]
fn schedule_outbound_dedupe_recovers_original_gate_decision_ref() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let facade = facade_for(&vault, actor);

    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "kenji@example.com".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some("idem-recover-1".to_owned()),
        dedupe_key: Some("dedupe-recover-1".to_owned()),
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:recover".to_owned(),
        job_ref: None,
        occurred_at: Some(5000),
    };

    let first = facade.schedule_outbound(&draft).expect("first schedule");
    assert!(!first.deduped);
    let gate_ref = first
        .gate_decision_ref
        .clone()
        .expect("first schedule persists a gate decision");

    let replay = facade.schedule_outbound(&draft).expect("replay");
    assert!(replay.deduped);
    assert_eq!(replay.outcome, "already_scheduled");
    assert_eq!(
        replay.gate_decision_ref,
        Some(gate_ref),
        "retry recovers the original gate decision ref"
    );
    assert_eq!(replay.gate_outcome, first.gate_outcome);
    assert_eq!(replay.gate_reason_codes, first.gate_reason_codes);
}
