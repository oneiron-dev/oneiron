//! WAKE-D1 (#6877): a Cancelled park resumes on the next pass, and a run
//! its owner cancelled never does; an ExecutorError park raises the owner's
//! notice and resumes only at the owner's release, and after a restart it
//! stays parked with its notice.
//! Moved from `dreamer_wake/tests.rs` (the oneiron lib test target does not
//! compile); the node id and the notice read go through
//! `oneiron::test_doors::wake_d1_park_release`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::dreamer_runner::{
    DREAMER_SERVER_PARK_OWNER, DreamerAttemptStatus, DreamerParkedAttemptRecord,
    EnqueueDreamerConsolidationAttempt, ParkResumer,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::memory::DreamerParkCauseView;
use oneiron::task_verb::run_cancel::RunCancelOutcome;
use oneiron::test_doors::wake_d1_park_release as doors;
use oneiron::{
    AttemptInterventionEffect, AttemptInterventionKind, DreamerAdmittedAttempt,
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerConsolidationScope, DreamerParkCause,
    DreamerRunnerStore, DreamerWakeDriver, EnqueueDreamerAttemptOutcome, InterveneAttempt, Result,
    RunWakePass, Vault, VaultConfig, WakeAttemptContext, WakeCancellation, WakePassDeadline,
    WakeTrigger,
};

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The pass self-wakes and pends once per attempt boundary, so polling
    // again immediately is correct; the bound catches a future pending on
    // anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("wake-pass future pending on something other than an attempt-boundary yield");
}

/// A temporary vault opened with `config` and a process-memory device
/// keystore, as the crate's test opener opens one (it keeps the seeded
/// default policy, which holds the shipped bytes that opener's tests read).
fn open_vault_with(config: VaultConfig) -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The owner exists before any park, so a park's notice has its owner to name.
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
}

fn open_vault() -> Result<(tempfile::TempDir, Vault)> {
    open_vault_with(VaultConfig::device())
}

fn enqueue_micro(
    store: &DreamerRunnerStore<'_>,
    tag: &str,
    now: u64,
) -> Result<DreamerAttemptStatus> {
    match store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: rmpv::Value::from(format!("input:{tag}")),
        parent_attempt: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status),
        // The outcome enum is `#[non_exhaustive]` outside the crate.
        other => panic!("unexpected enqueue outcome {other:?}"),
    }
}

fn frozen_deadline(elapsed_ms: u64, ceiling_ms: u64) -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(elapsed_ms));
    WakePassDeadline::with_clock(ceiling_ms, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

fn run_input(scope: DreamerConsolidationScope, local_node_id: u64, now: u64) -> RunWakePass {
    RunWakePass {
        trigger: WakeTrigger::Compaction,
        scope,
        local_node_id,
        lease_owner: "wake-worker".to_owned(),
        budget_total_units: 10_000,
        reserve_units: 100,
        now,
        host_scope: None,
        destination_bound: None,
    }
}

/// Completes every admitted attempt.
struct CompletingExecutor {
    completed_units: u64,
    executed: u32,
}

impl DreamerAttemptExecutor for CompletingExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        self.executed += 1;
        Ok(DreamerAttemptExecution::Completed {
            completed_units: self.completed_units,
            step_bindings: Vec::new(),
        })
    }
}

/// Parks every admitted attempt as a cancelled pass does after admission.
struct CancelledParkExecutor;

impl DreamerAttemptExecutor for CancelledParkExecutor {
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
}

/// WAKE-D1 (lead, 9 Nov): a Cancelled park resumes on the next pass of the same running process, with no restart
/// and no lease reclaim.
#[test]
fn a_cancelled_park_resumes_on_the_next_pass() -> Result<()> {
    let store_clock = oneiron_store::ports::manual_clock::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "cancelled", 10)?;
    let node_id = doors::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(20);
            20
        }),
        &mut CancelledParkExecutor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1);
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert_eq!(parked.cause, DreamerParkCause::Cancelled);

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut completer = CompletingExecutor {
        completed_units: 25,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(30);
            30
        }),
        &mut completer,
        &WakeCancellation::new(),
    ))?;
    assert!(
        store.parked_attempt(queued.attempt.id)?.is_none(),
        "the next pass resumes the cancelled park"
    );
    assert_eq!(report.completed, 1);
    Ok(())
}

/// Engine 06:50 (D): the owner's cancel is not the drain's or the stop's. A drain or a stop parks an admitted try
/// as Cancelled, and the next pass resumes it (WAKE-D1). The owner's cancel settles the run as Cancelled with no
/// park, so no pass resumes it.
#[test]
fn a_run_cancelled_by_its_owner_never_resumes() -> Result<()> {
    let store_clock = oneiron_store::ports::manual_clock::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let store = DreamerRunnerStore::new(&vault);
    let node_id = doors::load_or_mint_client_id(&vault)?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");

    // The drain's cancel: the pass parks the try it admitted as Cancelled.
    let drained = enqueue_micro(&store, "drained", 10)?;
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(20);
            20
        }),
        &mut CancelledParkExecutor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1);
    let parked = store
        .parked_attempt(drained.attempt.id)?
        .expect("the drain's park");
    assert_eq!(parked.cause, DreamerParkCause::Cancelled);

    // The owner's cancel, through the run tree's cancel door.
    let stopped = enqueue_micro(&store, "owner-cancelled", 20)?;
    store_clock.set(25);
    let outcome = vault
        .memory(owner, EdgeActorClass::Human)
        .cancel_run_branch(InterveneAttempt {
            id: stopped.attempt.id,
            kind: AttemptInterventionKind::Cancel,
            actor: owner.to_hex(),
            note: Some("the owner stops this run".to_owned()),
            now: 25,
        })
        .expect("the owner's cancel");
    assert!(
        matches!(
            &outcome,
            RunCancelOutcome::Applied(applied)
                if matches!(applied.effect, AttemptInterventionEffect::Cancelled)
        ),
        "the owner's cancel applies at once: {outcome:?}"
    );
    assert!(
        store.parked_attempt(stopped.attempt.id)?.is_none(),
        "the owner's cancel parks nothing"
    );

    // Two later passes: the first resumes the drain's park and runs it; neither runs the owner's cancelled run.
    let mut completer = CompletingExecutor {
        completed_units: 25,
        executed: 0,
    };
    for now in [30, 40] {
        let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
        block_on_ready(driver.run_wake_pass(
            run_input(DreamerConsolidationScope::Micro, node_id, {
                store_clock.set(now);
                now
            }),
            &mut completer,
            &WakeCancellation::new(),
        ))?;
    }
    assert_eq!(
        completer.executed, 1,
        "the later passes run the drained try once and the owner's cancelled run never"
    );
    assert!(store.parked_attempt(drained.attempt.id)?.is_none());
    let after = store.status(stopped.attempt.id)?.expect("the owner's run");
    assert_eq!(
        after.attempt.state.as_str(),
        "cancelled",
        "the owner's cancelled run stays cancelled"
    );
    assert!(store.parked_attempt(stopped.attempt.id)?.is_none());
    Ok(())
}

/// Parks every admitted attempt as an executor error does (a lapsed seat login).
struct ExecutorErrorParkExecutor;

impl DreamerAttemptExecutor for ExecutorErrorParkExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        Ok(DreamerAttemptExecution::Park {
            reason: "the seat login lapsed".to_owned(),
            cause: DreamerParkCause::ExecutorError,
        })
    }
}

/// Parks `queued` as an executor error of the server's Dreamer pass, and returns the park.
/// The pass leases the try under the server's lease owner and parks it under that owner,
/// so the parked try keeps its lease, as on a running server.
fn park_executor_error(
    vault: &Vault,
    store: &DreamerRunnerStore<'_>,
    queued: &DreamerAttemptStatus,
    now: u64,
) -> Result<DreamerParkedAttemptRecord> {
    let node_id = doors::load_or_mint_client_id(vault)?;
    let mut input = run_input(DreamerConsolidationScope::Micro, node_id, now);
    input.lease_owner = DREAMER_SERVER_PARK_OWNER.to_owned();
    let mut driver = DreamerWakeDriver::new(vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        input,
        &mut ExecutorErrorParkExecutor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1, "the pass parks the try");
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert_eq!(parked.cause, DreamerParkCause::ExecutorError);
    assert_eq!(parked.park_owner, DREAMER_SERVER_PARK_OWNER);
    Ok(parked)
}

/// The vault's embedded owner, authenticated: what an owner door takes.
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

/// A try's lease generation (`attempt_count`), as the owner's reads show it beside its park.
fn attempt_count(store: &DreamerRunnerStore<'_>, queued: &DreamerAttemptStatus) -> Result<u32> {
    Ok(store
        .status(queued.attempt.id)?
        .expect("the try")
        .attempt
        .attempt_count)
}

/// A try's id as the owner's reads spell it: 32 lowercase hex digits.
fn attempt_hex(status: &DreamerAttemptStatus) -> String {
    status
        .attempt
        .id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// WAKE-D1: an ExecutorError park raises the owner's notice, no later pass resumes it, and the owner's release
/// resumes it as the same try and resolves the notice.
#[test]
fn an_executor_error_park_raises_the_notice_and_resumes_only_at_release() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "owner act", 10)?;
    let parked = park_executor_error(&vault, &store, &queued, 20)?;
    assert_eq!(
        doors::park_notice_seen(&vault, &parked)?,
        Some(false),
        "the owner's notice is raised"
    );

    let node_id = doors::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut completer = CompletingExecutor {
        completed_units: 25,
        executed: 0,
    };
    block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 40),
        &mut completer,
        &WakeCancellation::new(),
    ))?;
    assert!(
        store.parked_attempt(queued.attempt.id)?.is_some(),
        "no pass retries an owner-act park"
    );

    let owner = embedded_owner_proof(&vault);
    let view = doors::release_as_owner(
        &vault,
        &owner,
        &attempt_hex(&queued),
        DreamerParkCauseView::ExecutorError,
        parked.parked_at,
        attempt_count(&store, &queued)?,
    )?;
    assert_eq!(view.cause, "executor_error");
    assert!(store.parked_attempt(queued.attempt.id)?.is_none());
    assert_eq!(
        doors::park_notice_seen(&vault, &parked)?,
        Some(true),
        "the release resolves the notice"
    );
    Ok(())
}

/// WAKE-D1-BOOT (lead, 9 Nov): boot no longer resumes an ExecutorError park of the Dreamer's own pass (C5). After a
/// restart the park stays and its notice stands, until the owner's release. Boot recovery asks the BootRecovery row
/// (oneiron-server ai_host/lifecycle.rs), which this checks on the reopened vault.
#[test]
fn after_a_restart_an_executor_error_park_stays_parked_with_its_notice() -> Result<()> {
    let (dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "owner act", 10)?;
    park_executor_error(&vault, &store, &queued, 20)?;
    let queued_id = queued.attempt.id;
    drop(store);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let store = DreamerRunnerStore::new(&vault);
    let parked = store
        .parked_attempt(queued_id)?
        .expect("the park outlives the restart");
    assert!(!parked.resumable_by(ParkResumer::BootRecovery));
    assert_eq!(
        doors::park_notice_seen(&vault, &parked)?,
        Some(false),
        "the owner's notice stands"
    );
    Ok(())
}

/// Review 6910 P1: each live owner's notice of a park names that owner as its recipient, so no other reader whose
/// lane admits notifications sees the parked try.
#[test]
fn the_park_notice_names_its_owner_as_recipient() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "owner act", 10)?;
    let parked = park_executor_error(&vault, &store, &queued, 20)?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    assert_eq!(
        doors::park_notice_recipient(&vault, &parked)?,
        Some(Some(owner.to_hex())),
        "FAILBEFORE 6910 P1: the owner's notice names its owner"
    );
    Ok(())
}

/// Review 6910 P1: a release of an earlier park of the same try refuses, even when the later park falls in the same
/// second; the later park stands and its notice stays raised. A try parks only under a lease, so the later park is a
/// later lease generation.
#[test]
fn a_stale_release_of_an_earlier_park_refuses() -> Result<()> {
    let store_clock = oneiron_store::ports::manual_clock::ManualClock::new(20);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "owner act", 10)?;
    let owner = embedded_owner_proof(&vault);

    let first = park_executor_error(&vault, &store, &queued, 20)?;
    let first_count = attempt_count(&store, &queued)?;
    doors::release_as_owner(
        &vault,
        &owner,
        &attempt_hex(&queued),
        DreamerParkCauseView::ExecutorError,
        first.parked_at,
        first_count,
    )?;

    // In the same second the next pass claims the try again, and it parks again.
    let second = park_executor_error(&vault, &store, &queued, 20)?;
    assert_eq!(
        second.parked_at, first.parked_at,
        "both parks fall in the same second"
    );
    assert!(attempt_count(&store, &queued)? > first_count);

    let stale = doors::release_as_owner(
        &vault,
        &owner,
        &attempt_hex(&queued),
        DreamerParkCauseView::ExecutorError,
        first.parked_at,
        first_count,
    );
    assert!(
        matches!(stale, Err(oneiron::Error::ConcurrentWrite(_))),
        "FAILBEFORE 6910 P1: a release of the earlier park refuses: {stale:?}"
    );
    assert!(
        store.parked_attempt(queued.attempt.id)?.is_some(),
        "the later park stands"
    );
    assert_eq!(
        doors::park_notice_seen(&vault, &second)?,
        Some(false),
        "the later park's notice stays raised"
    );
    Ok(())
}

/// Parks `queued` as the host's drain cancels the server's Dreamer pass after admission, and returns the park.
/// The parked try keeps the server's lease, as on a running server.
fn park_drained(
    vault: &Vault,
    store: &DreamerRunnerStore<'_>,
    queued: &DreamerAttemptStatus,
    now: u64,
) -> Result<DreamerParkedAttemptRecord> {
    let node_id = doors::load_or_mint_client_id(vault)?;
    let mut input = run_input(DreamerConsolidationScope::Micro, node_id, now);
    input.lease_owner = DREAMER_SERVER_PARK_OWNER.to_owned();
    let mut driver = DreamerWakeDriver::new(vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        input,
        &mut CancelledParkExecutor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1, "the pass parks the try");
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert_eq!(parked.cause, DreamerParkCause::Cancelled);
    assert_eq!(parked.park_owner, DREAMER_SERVER_PARK_OWNER);
    Ok(parked)
}

/// Runs one server Dreamer pass at `now` with a completing executor, and returns how many tries it ran.
fn run_server_pass(vault: &Vault, now: u64) -> Result<u32> {
    let node_id = doors::load_or_mint_client_id(vault)?;
    let mut input = run_input(DreamerConsolidationScope::Micro, node_id, now);
    input.lease_owner = DREAMER_SERVER_PARK_OWNER.to_owned();
    let mut completer = CompletingExecutor {
        completed_units: 25,
        executed: 0,
    };
    let mut driver = DreamerWakeDriver::new(vault, "wake", frozen_deadline(0, 180_000));
    block_on_ready(driver.run_wake_pass(input, &mut completer, &WakeCancellation::new()))?;
    Ok(completer.executed)
}

/// Engine 08:3x: the owner stops a try the host's drain parked. The parked try keeps its lease, so the run tree's
/// cancel refuses it; the owner's stop on the park door ends it, clears its park, and no later pass runs it.
#[test]
fn the_owner_stops_a_drained_park() -> Result<()> {
    let store_clock = oneiron_store::ports::manual_clock::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "drained", 10)?;
    store_clock.set(20);
    let parked = park_drained(&vault, &store, &queued, 20)?;

    store_clock.set(25);
    let state = doors::stop_as_owner(
        &vault,
        &embedded_owner_proof(&vault),
        &attempt_hex(&queued),
        DreamerParkCauseView::Cancelled,
        parked.parked_at,
        attempt_count(&store, &queued)?,
    )
    .expect("FAILBEFORE park-stop: the owner stops a parked try");
    assert_eq!(state, "cancelled");
    assert!(
        store.parked_attempt(queued.attempt.id)?.is_none(),
        "the stop clears the park"
    );

    for now in [30, 40] {
        store_clock.set(now);
        assert_eq!(
            run_server_pass(&vault, now)?,
            0,
            "no later pass runs the stopped try"
        );
    }
    let after = store.status(queued.attempt.id)?.expect("the try");
    assert_eq!(after.attempt.state.as_str(), "cancelled");
    assert!(store.parked_attempt(queued.attempt.id)?.is_none());
    Ok(())
}

/// Engine 08:3x: the owner stops a park that waits on his release instead of resuming it. The try ends, its park
/// clears and its notice is resolved; no later pass runs it.
#[test]
fn the_owner_stops_an_executor_error_park_and_its_notice_resolves() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "owner act", 10)?;
    let parked = park_executor_error(&vault, &store, &queued, 20)?;
    assert_eq!(
        doors::park_notice_seen(&vault, &parked)?,
        Some(false),
        "the park raised its notice"
    );

    let state = doors::stop_as_owner(
        &vault,
        &embedded_owner_proof(&vault),
        &attempt_hex(&queued),
        DreamerParkCauseView::ExecutorError,
        parked.parked_at,
        attempt_count(&store, &queued)?,
    )
    .expect("FAILBEFORE park-stop: the owner stops a parked try");
    assert_eq!(state, "cancelled");
    assert!(store.parked_attempt(queued.attempt.id)?.is_none());
    assert_eq!(
        doors::park_notice_seen(&vault, &parked)?,
        Some(true),
        "the stop resolves the park's notice"
    );
    assert_eq!(
        run_server_pass(&vault, 30)?,
        0,
        "no later pass runs the stopped try"
    );
    Ok(())
}

/// Engine 08:3x: a stop names the exact park the owner read. A stop against a lease generation that is no longer
/// the try's refuses, and the park stands.
#[test]
fn a_stop_of_a_changed_park_refuses() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "drained", 10)?;
    let parked = park_drained(&vault, &store, &queued, 20)?;
    let stale = doors::stop_as_owner(
        &vault,
        &embedded_owner_proof(&vault),
        &attempt_hex(&queued),
        DreamerParkCauseView::Cancelled,
        parked.parked_at,
        attempt_count(&store, &queued)? + 1,
    );
    assert!(
        matches!(stale, Err(oneiron::Error::ConcurrentWrite(_))),
        "FAILBEFORE park-stop: a stop of a changed park refuses: {stale:?}"
    );
    assert!(
        store.parked_attempt(queued.attempt.id)?.is_some(),
        "the park stands"
    );
    Ok(())
}

/// Engine 08:3x: the stop serves the Dreamer server's own parks only. A park under any other owner keeps its own
/// door, and the stop refuses it as a park it does not serve.
#[test]
fn a_stop_refuses_a_park_of_another_owner() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "worker park", 10)?;
    let node_id = doors::load_or_mint_client_id(&vault)?;
    // `run_input` leases under a caller-chosen worker, not the server.
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut CancelledParkExecutor,
        &WakeCancellation::new(),
    ))?;
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert_ne!(parked.park_owner, DREAMER_SERVER_PARK_OWNER);
    let refused = doors::stop_as_owner(
        &vault,
        &embedded_owner_proof(&vault),
        &attempt_hex(&queued),
        DreamerParkCauseView::Cancelled,
        parked.parked_at,
        attempt_count(&store, &queued)?,
    );
    assert!(
        matches!(refused, Err(oneiron::Error::EntityNotFound)),
        "FAILBEFORE park-stop: the stop refuses another owner's park: {refused:?}"
    );
    assert!(store.parked_attempt(queued.attempt.id)?.is_some());
    Ok(())
}

/// Owner Stop abandons the stopped try's own Pending outbound intents.
#[test]
fn the_owner_stop_abandons_the_stopped_trys_pending_sends() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "stop-pending-send", 10)?;
    let parked = park_drained(&vault, &store, &queued, 20)?;
    doors::insert_pending_send(&vault, queued.attempt.id, 20_000)?;
    assert_eq!(
        doors::pending_send_state(&vault, queued.attempt.id)?,
        Some((oneiron::outbound_intent_ledger::IntentState::Pending, None)),
        "the send is Pending immediately before Stop"
    );

    let state = doors::stop_as_owner(
        &vault,
        &embedded_owner_proof(&vault),
        &attempt_hex(&queued),
        DreamerParkCauseView::Cancelled,
        parked.parked_at,
        attempt_count(&store, &queued)?,
    )?;
    assert_eq!(state, "cancelled");
    assert_eq!(
        doors::pending_send_state(&vault, queued.attempt.id)?,
        Some((
            oneiron::outbound_intent_ledger::IntentState::Abandoned,
            Some(
                oneiron::outbound_intent_ledger::RecordedOutboundOutcome::Abandoned(
                    oneiron::outbound_intent_ledger::IntentEscalationReason::OwnerStopped,
                )
            ),
        )),
        "FAILBEFORE park-stop settlement: Stop abandons the try's Pending send as owner_stopped"
    );
    Ok(())
}

struct SettlementStepBackend;
impl llm::LlmBackend for SettlementStepBackend {
    fn generate<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmGenerateFuture<'a> {
        Box::pin(async {
            let mut usage = llm::LlmUsage::zero();
            usage.input.total = 37;
            usage.output.total = 1;
            usage.output.text = 1;
            Ok(llm::LlmResponse {
                message: llm::LlmMessage {
                    role: llm::LlmMessageRole::Assistant,
                    content: vec![llm::ContentPart::Text {
                        text: "paid".into(),
                        signature: None,
                    }],
                },
                usage,
                finish_reason: llm::FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }
    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        Err(llm::LlmError::Fatal(llm::FatalLlmError::InvalidRequest))
    }
}

/// Owner Stop retires a receipt only a real terminal step and settlement can pin.
#[test]
fn the_owner_stop_retires_the_stopped_trys_step_receipts() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "stop-paid-step", 10)?;
    let parked = park_drained(&vault, &store, &queued, 20)?;
    let request = llm::LlmRequest {
        model: llm::ModelId::new("test/model@r1").expect("model id"),
        envelope: llm::CallEnvelope {
            scope: llm::Scope::default(),
            purpose: llm::CallPurpose::Consolidation,
            class: llm::CallClass::BestEffort,
            tier: llm::TierPrecedence::for_purpose(
                &llm::CallPurpose::Consolidation,
                llm::ModelTierRef("default".into()),
            ),
            response_format: llm::ResponseFormat::Text,
            locality: llm::ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: vec![llm::LlmMessage {
            role: llm::LlmMessageRole::User,
            content: vec![llm::ContentPart::Text {
                text: "paid step".into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    };
    let step_hash = block_on_ready(doors::settle_paid_step(
        &vault,
        queued.attempt.id,
        &SettlementStepBackend,
        request,
        21,
    ))?;
    assert!(
        doors::step_charged(&vault, queued.attempt.id, &step_hash)?,
        "the terminal memo reads charged immediately before Stop"
    );
    let state = doors::stop_as_owner(
        &vault,
        &embedded_owner_proof(&vault),
        &attempt_hex(&queued),
        DreamerParkCauseView::Cancelled,
        parked.parked_at,
        attempt_count(&store, &queued)?,
    )?;
    assert_eq!(state, "cancelled");
    assert!(
        !doors::step_charged(&vault, queued.attempt.id, &step_hash)?,
        "FAILBEFORE park-stop settlement: Stop retires the try's paid-step receipt"
    );
    Ok(())
}

/// Owner Stop pays the measured usage a failed settlement retained on this try.
#[test]
fn the_owner_stop_settles_the_stopped_trys_owed_charge() -> Result<()> {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "stop-owed-charge", 10)?;
    let parked = park_drained(&vault, &store, &queued, 20)?;
    let budget_id = "park-stop-owed";
    doors::retain_owed_charge(
        &vault,
        oneiron::dreamer_runner::ReserveDreamerBudget {
            budget_id: budget_id.to_owned(),
            child_attempt: queued.attempt.id,
            budget_total_units: 1_000,
            reserve_units: 100,
            now: 21,
        },
        37,
    )?;
    let retained = store
        .budget_reservation(budget_id, queued.attempt.id)?
        .expect("retained reservation");
    assert_eq!(retained.owed_units, 37, "the measured usage is still owed");
    assert_eq!(
        doors::attempt_budget_reservation_count(&vault, queued.attempt.id)?,
        1
    );
    let before = store.budget(budget_id)?.expect("the budget line");
    assert_eq!(
        (
            before.spent_units(),
            before.remaining_units,
            before.reserved_units
        ),
        (Some(0), 900, 100)
    );

    let state = doors::stop_as_owner(
        &vault,
        &embedded_owner_proof(&vault),
        &attempt_hex(&queued),
        DreamerParkCauseView::Cancelled,
        parked.parked_at,
        attempt_count(&store, &queued)?,
    )?;
    assert_eq!(state, "cancelled");
    let after = store
        .budget(budget_id)?
        .expect("the budget line after Stop");
    assert_eq!(
        (
            doors::attempt_budget_reservation_count(&vault, queued.attempt.id)?,
            after.spent_units(),
            after.remaining_units,
            after.reserved_units,
            after.overdraft_units,
        ),
        (0, Some(37), 963, 0, 0),
        "FAILBEFORE park-stop settlement: Stop retires every reservation and charges its owed units"
    );
    Ok(())
}
