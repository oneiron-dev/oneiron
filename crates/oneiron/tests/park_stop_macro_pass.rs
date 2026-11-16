#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::code_run::blocked::{BlockedCategory, SelfReportBlockedCall};
use oneiron::code_run::{HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher};
use oneiron::dreamer_runner::maintenance::coach::COACH_ISSUES_FACET;
use oneiron::dreamer_runner::{
    COACH_HEAL_ATTEMPT_KIND, DREAMER_SERVER_PARK_OWNER, DreamerAttemptStatus,
    DreamerParkedAttemptRecord, FreeTimeCadence, FreeTimeCycleState, FreeTimeItemOutcome,
    FreeTimeKind, FreeTimePolicyInput, FreeTimeSchedule,
};
use oneiron::memory::DreamerParkCauseView;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::wake_d1_park_release as doors;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerConsolidationScope, DreamerParkCause, DreamerRunnerStore, DreamerWakeDriver,
    EdgeActorClass, EntityId, Result, RunWakePass, Vault, VaultConfig, WakeAttemptContext,
    WakeCancellation, WakePassDeadline, WakeTrigger, WriteActor,
};
use oneiron_store::ports::manual_clock::ManualClock;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The pass yields once at each attempt boundary without waiting on I/O.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("wake-pass future pending on something other than an attempt-boundary yield");
}

fn open_vault_with(config: VaultConfig) -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
}

fn embedded_owner_proof(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

fn attempt_hex(status: &DreamerAttemptStatus) -> String {
    status
        .attempt
        .id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn attempt_count(store: &DreamerRunnerStore<'_>, status: &DreamerAttemptStatus) -> Result<u32> {
    Ok(store
        .status(status.attempt.id)?
        .expect("the try")
        .attempt
        .attempt_count)
}

fn frozen_deadline(elapsed_ms: u64, ceiling_ms: u64) -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(elapsed_ms));
    WakePassDeadline::with_clock(ceiling_ms, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

fn run_input(local_node_id: u64, now: u64) -> RunWakePass {
    RunWakePass {
        trigger: WakeTrigger::Timer,
        scope: DreamerConsolidationScope::Macro,
        local_node_id,
        lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
        budget_total_units: 10_000,
        reserve_units: 100,
        now,
        host_scope: None,
        destination_bound: None,
    }
}

struct ParkingExecutor;

impl DreamerAttemptExecutor for ParkingExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        Ok(DreamerAttemptExecution::Park {
            reason: "wake-pass cancelled".to_owned(),
            cause: DreamerParkCause::Cancelled,
        })
    }

    fn runs_coach_heals(&self) -> bool {
        true
    }
}

struct ParkedFreeTimeCycle {
    agent: EntityId,
    cycle: EntityId,
    tries: Vec<(DreamerAttemptStatus, DreamerParkedAttemptRecord)>,
}

/// Opens one real cycle and parks both items on one server MACRO Timer pass.
fn park_free_time_cycle(vault: &Vault, clock: &ManualClock) -> Result<ParkedFreeTimeCycle> {
    let agent = define_agent(vault)?;
    vault.set_free_time_policy(
        &embedded_owner_proof(vault),
        None,
        agent,
        0,
        FreeTimePolicyInput {
            total_units: 10_000,
            schedule: FreeTimeSchedule {
                cadence: FreeTimeCadence::Nightly,
                hour: 0,
                minute: 0,
                zone: "UTC".to_owned(),
            },
            pinned_split: None,
            cap_shown_at_ms: 1_000,
        },
    )?;
    let due = vault.next_free_time_due_at()?.expect("first boundary");
    let node = doors::load_or_mint_client_id(vault)?;
    let store = DreamerRunnerStore::new(vault);
    let candidate = store.local_home_node_candidate(true, true, true)?;
    clock.set(due);
    assert_eq!(
        store
            .elect_home_node(&[candidate], due)?
            .expect("home")
            .node_id,
        node,
    );
    assert_eq!(vault.enqueue_due_free_time_cycles(due, node)?, 1);
    let cycles = vault.free_time_cycles(agent, None, 2)?;
    assert_eq!(cycles.len(), 1, "one production cycle opened");
    let sheet = &cycles[0];
    assert_eq!(sheet.cycle.state, FreeTimeCycleState::Open);
    assert!(sheet.receipts.is_empty());
    assert_eq!(sheet.cycle.items.len(), 2);
    assert_eq!(sheet.cycle.items[0].kind, FreeTimeKind::ForHuman);
    assert_eq!(sheet.cycle.items[1].kind, FreeTimeKind::OwnTime);

    let mut driver = DreamerWakeDriver::new(vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        run_input(node, due),
        &mut ParkingExecutor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.admitted, 2, "the pass admits both cycle items");
    assert_eq!(report.parked, 2, "the executor parks every admitted try");
    assert_eq!(report.completed, 0);

    let mut tries = Vec::new();
    for item in &sheet.cycle.items {
        let id = AttemptId::from_bytes(&item.attempt.expect("the item has a try"))?;
        let (status, park) = store.status_with_park(id)?.expect("the cycle's try");
        let park = park.expect("the cycle's park");
        assert_eq!(status.attempt.state, AttemptState::Leased);
        assert_eq!(park.cause, DreamerParkCause::Cancelled);
        assert_eq!(park.park_owner, DREAMER_SERVER_PARK_OWNER);
        tries.push((status, park));
    }
    Ok(ParkedFreeTimeCycle {
        agent,
        cycle: sheet.cycle.cycle,
        tries,
    })
}

fn coach_issues_attempts(vault: &Vault) -> Result<Vec<DreamerAttemptStatus>> {
    let store = DreamerRunnerStore::new(vault);
    let mut issues = Vec::new();
    for record in AttemptQueue::new(vault).list()? {
        if record.kind == COACH_HEAL_ATTEMPT_KIND {
            let status = store.status(record.id)?.expect("Coach attempt");
            if status.payload.attempt_type == COACH_ISSUES_FACET {
                issues.push(status);
            }
        }
    }
    Ok(issues)
}

/// Two distinct public blocked reports wake the same Issues run, the second under its lease.
fn park_coach_issues_with_redrive(
    vault: &Vault,
    clock: &ManualClock,
) -> Result<(DreamerAttemptStatus, DreamerParkedAttemptRecord)> {
    let reporter = vault.ensure_embedded_owner_actor().expect("reporter");
    let dispatcher = HostSelfDispatcher::new(
        vault,
        WriteActor::new(reporter, EdgeActorClass::Agent),
        "park-stop-coach-issues",
    )?;
    let file_report = |sequence, now| -> Result<EntityId> {
        clock.set(now);
        let call = SelfCall::ReportBlocked(SelfReportBlockedCall::new(
            BlockedCategory::Tool,
            "fixture operation needs a tool",
        ))
        .with_bridge_stamp(sequence, now * 1_000);
        match dispatcher.dispatch(call)? {
            SelfDispatchOutcome::ReportBlocked { receipt } => Ok(receipt),
            other => panic!("expected a blocked report, got {other:?}"),
        }
    };
    let first_receipt = file_report(0, 10)?;
    let queued = coach_issues_attempts(vault)?;
    assert_eq!(queued.len(), 1);
    let id = queued[0].attempt.id;
    assert_eq!(queued[0].attempt.state, AttemptState::Queued);
    assert_eq!(queued[0].payload.parent_attempt, None);

    let node = doors::load_or_mint_client_id(vault)?;
    clock.set(20);
    let mut driver = DreamerWakeDriver::new(vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        run_input(node, 20),
        &mut ParkingExecutor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.admitted, 1);
    assert_eq!(report.parked, 1);
    assert_eq!(report.completed, 0);
    let store = DreamerRunnerStore::new(vault);
    let (leased, park) = store.status_with_park(id)?.expect("the leased Issues try");
    assert_eq!(leased.attempt.state, AttemptState::Leased);
    assert_eq!(
        leased.attempt.lease_owner.as_deref(),
        Some(DREAMER_SERVER_PARK_OWNER)
    );
    let park = park.expect("the server's park");
    assert_eq!(park.park_owner, DREAMER_SERVER_PARK_OWNER);

    // A repeated receipt would be idempotent and would not write the redrive mark.
    let second_receipt = file_report(1, 25)?;
    assert_ne!(second_receipt, first_receipt);
    assert_eq!(
        coach_issues_attempts(vault)?.len(),
        1,
        "no successor before Stop"
    );
    let (status, after_park) = store.status_with_park(id)?.expect("the marked try");
    assert_eq!(status.attempt.state, AttemptState::Leased);
    assert_eq!(status.attempt.attempt_count, leased.attempt.attempt_count);
    assert_eq!(after_park, Some(park.clone()));
    Ok((status, park))
}

#[test]
fn the_owner_stop_ends_a_free_time_item_cancelled() -> Result<()> {
    let clock = ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let fixture = park_free_time_cycle(&vault, &clock)?;
    let store = DreamerRunnerStore::new(&vault);
    let owner = embedded_owner_proof(&vault);

    for (index, (status, park)) in fixture.tries.iter().enumerate() {
        let binding = vault
            .free_time_item_binding(status.attempt.id)?
            .expect("the cycle item's binding");
        let before = vault
            .free_time_cycle(fixture.agent, fixture.cycle)?
            .expect("the cycle before Stop");
        assert_eq!(before.cycle.state, FreeTimeCycleState::Open);
        assert_eq!(before.receipts.len(), index);
        assert!(
            before
                .receipts
                .iter()
                .all(|receipt| receipt.item != binding.item)
        );
        let stop_now = park.parked_at + 10 + index as u64;
        clock.set(stop_now);
        let state = doors::stop_as_owner(
            &vault,
            &owner,
            &attempt_hex(status),
            DreamerParkCauseView::from(park.cause),
            park.parked_at,
            attempt_count(&store, status)?,
        )?;
        assert_eq!(
            state, "cancelled",
            "FAILBEFORE park-stop settlement: Stop returns cancelled"
        );
        let after = vault
            .free_time_cycle(fixture.agent, fixture.cycle)?
            .expect("FAILBEFORE park-stop settlement: cycle remains readable");
        let receipt = after
            .receipts
            .iter()
            .find(|receipt| receipt.item == binding.item);
        assert_eq!(
            receipt.map(|receipt| receipt.outcome),
            Some(FreeTimeItemOutcome::Cancelled),
            "FAILBEFORE park-stop settlement: Stop gives the item its Cancelled receipt",
        );
        assert_eq!(
            receipt.map(|receipt| receipt.at),
            Some(stop_now),
            "FAILBEFORE park-stop settlement: receipt lands in Stop's write"
        );
        assert_eq!(
            after.receipts.len(),
            index + 1,
            "FAILBEFORE park-stop settlement: one receipt per stopped item"
        );
        assert!(
            store.parked_attempt(status.attempt.id)?.is_none(),
            "FAILBEFORE park-stop settlement: Stop clears the park"
        );
        assert_eq!(
            store
                .status(status.attempt.id)?
                .expect("stopped try")
                .attempt
                .state,
            AttemptState::Cancelled,
            "FAILBEFORE park-stop settlement: the item try is cancelled"
        );
        if index + 1 == fixture.tries.len() {
            assert_eq!(
                after.cycle.state,
                FreeTimeCycleState::Closed,
                "FAILBEFORE park-stop settlement: the last item's Stop closes the cycle"
            );
            assert_eq!(
                after.cycle.closed_at,
                Some(stop_now),
                "FAILBEFORE park-stop settlement: cycle closes in the last Stop's write"
            );
        } else {
            assert_eq!(
                after.cycle.state,
                FreeTimeCycleState::Open,
                "FAILBEFORE park-stop settlement: the other item keeps the cycle open"
            );
            assert_eq!(
                after.cycle.closed_at, None,
                "FAILBEFORE park-stop settlement: the cycle is not closed early"
            );
        }
    }
    Ok(())
}

#[test]
fn the_owner_stop_queues_a_stopped_coach_issues_runs_successor() -> Result<()> {
    let clock = ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let (status, park) = park_coach_issues_with_redrive(&vault, &clock)?;
    let store = DreamerRunnerStore::new(&vault);
    let owner = embedded_owner_proof(&vault);
    let id = status.attempt.id;
    let cause = DreamerParkCauseView::from(park.cause);
    let generation = attempt_count(&store, &status)?;
    assert_eq!(
        coach_issues_attempts(&vault)?.len(),
        1,
        "no successor before Stop"
    );

    clock.set(30);
    let state = doors::stop_as_owner(
        &vault,
        &owner,
        &attempt_hex(&status),
        cause,
        park.parked_at,
        generation,
    )?;
    assert_eq!(
        state, "cancelled",
        "FAILBEFORE park-stop settlement: Stop returns cancelled"
    );
    assert_eq!(
        store.status(id)?.expect("stopped Issues try").attempt.state,
        AttemptState::Cancelled,
        "FAILBEFORE park-stop settlement: the stopped Issues run is cancelled"
    );
    assert!(
        store.parked_attempt(id)?.is_none(),
        "FAILBEFORE park-stop settlement: Stop clears the Issues park"
    );
    let attempts = coach_issues_attempts(&vault)?;
    assert_eq!(
        attempts.len(),
        2,
        "FAILBEFORE park-stop settlement: Stop queues exactly one Issues successor"
    );
    let successor = attempts
        .iter()
        .find(|attempt| attempt.attempt.id != id)
        .expect("FAILBEFORE park-stop settlement: the successor exists");
    assert_eq!(
        successor.attempt.state,
        AttemptState::Queued,
        "FAILBEFORE park-stop settlement: the successor is queued"
    );
    assert_eq!(
        successor.payload.parent_attempt,
        Some(id),
        "FAILBEFORE park-stop settlement: the successor's parent is the stopped run"
    );

    let replay = doors::stop_as_owner(
        &vault,
        &owner,
        &attempt_hex(&status),
        cause,
        park.parked_at,
        generation,
    );
    assert!(
        matches!(replay, Err(oneiron::Error::EntityNotFound)),
        "FAILBEFORE park-stop settlement: a replay finds no park"
    );
    assert_eq!(
        coach_issues_attempts(&vault)?.len(),
        2,
        "FAILBEFORE park-stop settlement: a replay queues no second successor"
    );
    Ok(())
}
