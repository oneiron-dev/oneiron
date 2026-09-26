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
}

fn run_case(case: LateCall) -> Result<()> {
    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    grant_fixture_reads(&vault)?;
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
        | LateCall::MergeFinalInvalidCorrection => {
            two_candidate_extraction(&subject, &turns[0], &turns[1])
        }
        LateCall::InvalidJson | LateCall::NativeInvalidJson | LateCall::FinalInvalidCorrection => {
            text_response("not json".to_owned())
        }
    };
    let expire_on_call = match case {
        LateCall::Merge => 2,
        LateCall::FinalInvalidCorrection => 3,
        LateCall::MergeFinalInvalidCorrection => 4,
        _ => 1,
    };
    let rest = match case {
        LateCall::FinalInvalidCorrection => vec![Ok(text_response("not json".to_owned())); 2],
        LateCall::MergeFinalInvalidCorrection => {
            vec![Ok(text_response("not json".to_owned())); 3]
        }
        _ => vec![Ok(text_response(
            "{\"resolution\":\"merge\",\"value\":\"Merged\"}".to_owned(),
        ))],
    };
    let backend = ExpiringBackend {
        inner: ScriptedBackend::new(std::iter::once(Ok(first_response)).chain(rest).collect()),
        clock: std::sync::Arc::new(AtomicU64::new(0)),
        expire_on_call,
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
        | LateCall::NativeInvalidJson => 50,
        LateCall::Merge => 100,
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
        LateCall::InvalidJson
        | LateCall::NativeInvalidJson
        | LateCall::FinalInvalidCorrection
        | LateCall::MergeFinalInvalidCorrection => unreachable!(),
    };
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        if matches!(
            case,
            LateCall::ExtractionThenMerge | LateCall::ExtractionThenMergeNewBudget
        ) {
            2
        } else {
            expire_on_call
        }
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
