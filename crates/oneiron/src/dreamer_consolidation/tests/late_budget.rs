//! Real wake-driver accounting across late step checkpoint and resume.
use super::*;
use crate::attempt_queue::{AttemptQueue, AttemptState, CleanupAttemptLeases};
use crate::dreamer_wake::{
    DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassStop, WakeTrigger,
};
use std::future::Future;
use std::task::{Context, Poll, Waker};

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("wake pass did not reach a boundary");
}

fn wake_input(node_id: u64, now: u64) -> RunWakePass {
    RunWakePass {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
        local_node_id: node_id,
        lease_owner: "wake-worker".to_owned(),
        budget_total_units: 10_000,
        reserve_units: 500,
        now,
        host_scope: None,
    }
}

#[derive(Clone, Copy)]
enum LateCall {
    ExtractionOnly,
    ExtractionThenMerge,
    ExtractionThenMergeNewBudget,
    Merge,
    InvalidJson,
    NativeInvalidJson,
    FinalInvalidCorrection,
    MergeFinalInvalidCorrection,
    FinalizeInvalidJson,
    FinalizeMergeInvalidJson,
}

fn run_case(case: LateCall) -> Result<()> {
    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    crate::test_util::provision_engine_machines(&vault);
    authorize_test_inference(&vault)?;
    install_shipped_policy(&vault)?;
    let store = DreamerRunnerStore::new(&vault);
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let conversation = seed_session(&vault, 0x7a, 1);
    let turns = [
        seed_turn(&vault, &conversation, "user", "call me Oleksii", 10),
        seed_turn(&vault, &conversation, "user", "or Alex", 11),
    ];
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Micro)?;
    let dirty = scan_dirty_turns(&vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    let queued_rows = enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &dirty,
        &watermark,
        "run-1",
        20,
    )?;
    let [queued] = queued_rows.as_slice() else {
        panic!("one queued partition");
    };
    let attempt_id = match queued {
        crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(row)
        | crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(row) => row.attempt.id,
    };
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let first_response = match case {
        LateCall::ExtractionOnly => extraction_response(&subject, &turns[0]),
        LateCall::ExtractionThenMerge
        | LateCall::ExtractionThenMergeNewBudget
        | LateCall::Merge
        | LateCall::MergeFinalInvalidCorrection
        | LateCall::FinalizeMergeInvalidJson => {
            two_candidate_extraction(&subject, &turns[0], &turns[1])
        }
        LateCall::InvalidJson
        | LateCall::NativeInvalidJson
        | LateCall::FinalInvalidCorrection
        | LateCall::FinalizeInvalidJson => text_response("not json".to_owned()),
    };
    let expire_on_call = match case {
        LateCall::Merge | LateCall::FinalizeMergeInvalidJson => 2,
        LateCall::FinalInvalidCorrection => 3,
        LateCall::MergeFinalInvalidCorrection => 4,
        _ => 1,
    };
    let rest = match case {
        LateCall::FinalInvalidCorrection => vec![Ok(text_response("not json".to_owned())); 2],
        LateCall::MergeFinalInvalidCorrection => {
            vec![Ok(text_response("not json".to_owned())); 3]
        }
        LateCall::FinalizeInvalidJson => vec![Ok(extraction_response(&subject, &turns[0]))],
        LateCall::FinalizeMergeInvalidJson => vec![
            Ok(text_response("not json".to_owned())),
            Ok(text_response(
                "{\"resolution\":\"merge\",\"value\":\"Merged\"}".to_owned(),
            )),
        ],
        _ => vec![Ok(text_response(
            "{\"resolution\":\"merge\",\"value\":\"Merged\"}".to_owned(),
        ))],
    };
    let backend = ExpiringBackend {
        inner: ScriptedBackend::new(std::iter::once(Ok(first_response)).chain(rest).collect()),
        clock: std::sync::Arc::new(AtomicU64::new(0)),
        expire_on_call,
        expiry_elapsed_ms: if matches!(
            case,
            LateCall::FinalizeInvalidJson | LateCall::FinalizeMergeInvalidJson
        ) {
            170_000
        } else {
            180_001
        },
        calls: AtomicUsize::new(0),
        native_json: matches!(case, LateCall::NativeInvalidJson),
    };
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
    };
    let clock = std::sync::Arc::clone(&backend.clock);
    let deadline = WakePassDeadline::with_clock(
        180_000,
        std::sync::Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    store_clock.set(21);
    let first = ready(driver.run_wake_pass(
        wake_input(node_id, 21),
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(first.completed, 0);
    assert_eq!(first.parked, 1);
    assert_eq!(first.stop, WakePassStop::DeadlineHardCut);
    drop(executor);
    assert!(sink.accepted.is_empty());
    assert!(store.parked_attempt(attempt_id)?.is_some());
    let first_spend = match case {
        LateCall::ExtractionOnly => 120,
        LateCall::ExtractionThenMerge
        | LateCall::ExtractionThenMergeNewBudget
        | LateCall::InvalidJson
        | LateCall::NativeInvalidJson
        | LateCall::FinalizeInvalidJson => 50,
        LateCall::Merge | LateCall::FinalizeMergeInvalidJson => 100,
        LateCall::FinalInvalidCorrection => 150,
        LateCall::MergeFinalInvalidCorrection => 200,
    };
    assert_eq!(backend.calls.load(Ordering::SeqCst), expire_on_call);
    assert_eq!(guard.read().used_units, first_spend);
    assert_eq!(
        store.budget("wake")?.expect("wake budget").remaining_units,
        10_000 - first_spend
    );
    assert_eq!(
        store.budget("wake")?.expect("wake budget").reserved_units,
        0
    );
    if matches!(
        case,
        LateCall::InvalidJson
            | LateCall::NativeInvalidJson
            | LateCall::FinalInvalidCorrection
            | LateCall::MergeFinalInvalidCorrection
    ) {
        return Ok(()); // failed response(s) are paid, never memoized
    }

    backend.clock.store(0, Ordering::SeqCst);
    store
        .resume_parked(attempt_id, "wake-worker", 30)?
        .expect("resumable");
    AttemptQueue::new(&vault).cleanup_leases(CleanupAttemptLeases {
        now: 120,
        lease_timeout_secs: 10,
    })?;
    store_clock.set(130);
    let clock = std::sync::Arc::clone(&backend.clock);
    let deadline = WakePassDeadline::with_clock(
        180_000,
        std::sync::Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    let resume_budget = if matches!(case, LateCall::ExtractionThenMergeNewBudget) {
        "wake-next"
    } else {
        "wake"
    };
    let mut driver = DreamerWakeDriver::new(&vault, resume_budget, deadline);
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
    };
    let resumed = ready(driver.run_wake_pass(
        wake_input(node_id, 130),
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(resumed.completed, 1);
    drop(executor);
    assert_eq!(
        store.status(attempt_id)?.expect("attempt").attempt.state,
        AttemptState::Completed
    );
    let expected_total = match case {
        LateCall::ExtractionOnly => 120,
        LateCall::ExtractionThenMerge
        | LateCall::ExtractionThenMergeNewBudget
        | LateCall::Merge => 100,
        LateCall::FinalizeInvalidJson => 170,
        LateCall::FinalizeMergeInvalidJson => 150,
        LateCall::InvalidJson
        | LateCall::NativeInvalidJson
        | LateCall::FinalInvalidCorrection
        | LateCall::MergeFinalInvalidCorrection => unreachable!(),
    };
    let new_calls = usize::from(matches!(
        case,
        LateCall::ExtractionThenMerge
            | LateCall::ExtractionThenMergeNewBudget
            | LateCall::FinalizeInvalidJson
            | LateCall::FinalizeMergeInvalidJson
    ));
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        expire_on_call + new_calls
    );
    assert_eq!(guard.read().used_units, expected_total);
    let wake_debit = if resume_budget == "wake" {
        expected_total
    } else {
        first_spend
    };
    assert_eq!(
        store.budget("wake")?.expect("wake budget").remaining_units,
        10_000 - wake_debit
    );
    if resume_budget != "wake" {
        assert_eq!(
            store
                .budget(resume_budget)?
                .expect("new wake budget")
                .remaining_units,
            10_000 - (expected_total - first_spend)
        );
    }
    assert_eq!(sink.accepted.len(), 1);
    Ok(())
}

#[test]
fn late_terminal_checkpoint_resume_charges_only_unpaid_steps() -> Result<()> {
    for case in [
        LateCall::ExtractionOnly,
        LateCall::ExtractionThenMerge,
        LateCall::ExtractionThenMergeNewBudget,
        LateCall::Merge,
    ] {
        run_case(case)?;
    }
    Ok(())
}

#[test]
fn late_invalid_json_checkpoints_actual_spend_in_shared_budget() -> Result<()> {
    run_case(LateCall::InvalidJson)
}

#[test]
fn late_native_terminal_schema_failure_charges_the_wake_ledger() -> Result<()> {
    run_case(LateCall::NativeInvalidJson)
}

#[test]
fn late_final_correction_failure_charges_all_paid_calls() -> Result<()> {
    run_case(LateCall::FinalInvalidCorrection)?;
    run_case(LateCall::MergeFinalInvalidCorrection)
}

#[test]
fn finalize_window_refusal_charges_extraction_and_only_new_work_on_resume() -> Result<()> {
    run_case(LateCall::FinalizeInvalidJson)?;
    run_case(LateCall::FinalizeMergeInvalidJson)
}

#[test]
fn wake_pins_retry_expansion_before_admission() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let conversation = seed_session(&vault, 0x7b, 1);
    let first = seed_turn(&vault, &conversation, "user", "initial evidence", 10);
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Micro)?;
    let dirty = scan_dirty_turns(&vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &dirty,
        &watermark,
        "pinned-retry",
        20,
    )?;
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 2,
        ..Default::default()
    })?;
    let response = |ids: &[EntityId]| {
        text_response(serde_json::json!({"candidates":[{
        "subject": conversation.to_hex(), "predicate":"profile.name", "value":"supported",
        "evidence_refs": ids.iter().map(|id| serde_json::json!({"source_id":id.to_hex(), "byte_range":[0,1]})).collect::<Vec<_>>()
    }]}).to_string())
    };
    let backend = ScriptedBackend::new(vec![Ok(response(&[first]))]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
    };
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    let report = ready(driver.run_wake_pass(
        wake_input(node_id, 21),
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.deferred, 1);
    drop(executor);
    assert!(sink.accepted.is_empty());
    let retry = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .find(|row| row.retry_of.is_some() && row.state == AttemptState::Scheduled)
        .expect("scheduled selection retry");
    let next_turn = seed_turn(&vault, &conversation, "assistant", "new before wake", 22);
    // A fresh backend for the fresh retry identity gives the model exactly
    // what the second wake's frozen source expansion must include.
    let backend = ScriptedBackend::new(vec![Ok(response(&[first, next_turn]))]);
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
    };
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut driver = DreamerWakeDriver::new(&vault, "wake-next", deadline);
    let report = ready(driver.run_wake_pass(
        wake_input(node_id, 100),
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.completed, 1);
    assert_eq!(
        store.status(retry.id)?.expect("retry").attempt.state,
        AttemptState::Completed
    );
    drop(executor);
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(sink.accepted[0].evidence_turn_refs, vec![first, next_turn]);
    Ok(())
}

#[test]
fn broken_retry_parks_without_poisoning_healthy_wake_work() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let bad_parent = seed_session(&vault, 0x7c, 1);
    let bad_turn = seed_turn(&vault, &bad_parent, "user", "original", 10);
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Micro)?;
    let dirty = scan_dirty_turns(&vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &dirty,
        &watermark,
        "poisoned-retry",
        20,
    )?;
    let admitted = match store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        local_node_id: node,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: "initial".into(),
            now: 21,
            budget_id: "first-wake".into(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })? {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(row)) => {
            row
        }
        other => panic!("{other:?}"),
    };
    store.defer_selection(
        &admitted,
        crate::dreamer_runner::SettleDreamerBudget {
            budget_id: "first-wake".into(),
            child_attempt: admitted.status.attempt.id,
            actual_units: 0,
            now: 21,
        },
        30,
    )?;
    let retry = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .find(|row| row.retry_of == Some(admitted.status.attempt.id))
        .expect("scheduled retry");
    // The original still has a ChildOf edge, but its role is no longer
    // extraction-admissible at the next frozen wake revision.
    vault.put_entity(
        &bad_turn,
        ENTITY_TYPE_TURN,
        occurred(10),
        10,
        &turn_body("tool", "no longer admissible", None),
    )?;
    let good_parent = seed_session(&vault, 0x7d, 1);
    let good_turn = seed_turn(&vault, &good_parent, "user", "healthy", 22);
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Micro)?;
    let dirty = scan_dirty_turns(&vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &dirty,
        &watermark,
        "healthy",
        25,
    )?;
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..Default::default()
    })?;
    let response = text_response(
        serde_json::json!({"candidates":[{
            "subject":good_parent.to_hex(), "predicate":"profile.name", "value":"healthy",
            "evidence_refs":[{"source_id":good_turn.to_hex(), "byte_range":[0,1]}]
        }]})
        .to_string(),
    );
    let backend = ScriptedBackend::new(vec![Ok(response)]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
    };
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    let report = ready(driver.run_wake_pass(
        wake_input(node, 100),
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1);
    assert_eq!(report.completed, 1);
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "the poisoned retry must not call the extraction model"
    );
    assert!(store.parked_attempt(retry.id)?.is_some());
    drop(executor);
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(sink.accepted[0].evidence_turn_refs, vec![good_turn]);
    assert_eq!(
        store.budget("wake")?.expect("wake budget").reserved_units,
        0
    );
    Ok(())
}

#[test]
fn manifest_retry_source_budget_limits_pinned_attempt_and_holder_cannot_widen() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let parent = seed_session(&vault, 0x7e, 1);
    seed_turn(&vault, &parent, "user", "first", 10);
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Micro)?;
    let dirty = scan_dirty_turns(&vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &dirty,
        &watermark,
        "budget-retry",
        20,
    )?;
    let admitted = match store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        local_node_id: node,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: "budget".into(),
            now: 21,
            budget_id: "wake".into(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })? {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(row)) => {
            row
        }
        other => panic!("{other:?}"),
    };
    store.defer_selection(
        &admitted,
        crate::dreamer_runner::SettleDreamerBudget {
            budget_id: "wake".into(),
            child_attempt: admitted.status.attempt.id,
            actual_units: 0,
            now: 21,
        },
        30,
    )?;
    let retry = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .find(|row| row.retry_of == Some(admitted.status.attempt.id))
        .expect("retry");
    seed_turn(&vault, &parent, "assistant", "second", 22);
    let default_id = crate::gate::default_policy_manifest_id()?;
    let manifest = vault.get(&default_id)?.expect("default policy");
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut manifest.as_slice()).expect("manifest")
    else {
        panic!("manifest map")
    };
    let holder = vault.dreamer_actor_for_attempt(retry.id)?.entity_ref();
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("retry_source_policy"))
        .expect("shipped policy")
        .1 = Value::Array(vec![
        Value::Map(vec![
            ("selector".into(), "vault".into()),
            ("max_sources".into(), Value::from(1_u64)),
            ("precedence".into(), "nested_narrowing".into()),
        ]),
        Value::Map(vec![
            ("selector".into(), "holder".into()),
            ("source_id".into(), holder.to_hex().into()),
            ("max_sources".into(), Value::from(100_u64)),
        ]),
    ]);
    let encode = |fields: &[(Value, Value)]| -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(fields.to_vec())).expect("manifest codec");
        out
    };
    crate::test_util::put_policy_manifest_bytes(&vault, default_id, &encode(&fields))?;
    let pinned = PreparedWake::capture(&vault, DreamerConsolidationScope::Micro)?;
    assert!(
        pinned.retry_failure(retry.id).is_some(),
        "vault's one-source row must hold a two-source retry"
    );
    // The holder's larger work preference cannot widen the vault ceiling.
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        crate::gate::resolve_policy_manifest(&vault.store, &txn)?
            .retry_budget_for(holder, None)?
            .max_sources(),
        1
    );
    drop(txn);
    Ok(())
}
