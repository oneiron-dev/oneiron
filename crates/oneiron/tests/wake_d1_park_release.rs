//! WAKE-D1 (#6877): a Cancelled park resumes on the next pass; an
//! ExecutorError park raises the owner's notice and resumes only at the
//! owner's release, and after a restart it stays parked with its notice.
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
    EnqueueDreamerConsolidationAttempt, ParkResumer, ReleaseParkedAttemptRequest,
    release_parked_attempt_as_owner,
};
use oneiron::memory::DreamerParkCauseView;
use oneiron::test_doors::wake_d1_park_release as doors;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerConsolidationScope, DreamerParkCause, DreamerRunnerStore, DreamerWakeDriver,
    EnqueueDreamerAttemptOutcome, Result, RunWakePass, Vault, VaultConfig, WakeAttemptContext,
    WakeCancellation, WakePassDeadline, WakeTrigger,
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
    let view = release_parked_attempt_as_owner(
        &vault,
        &owner,
        &ReleaseParkedAttemptRequest {
            attempt: attempt_hex(&queued),
            cause: DreamerParkCauseView::ExecutorError,
            parked_at: parked.parked_at,
            note: None,
        },
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
