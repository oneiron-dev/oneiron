//! Shared fixtures for the supervisor test suites.
use std::time::Duration;

use super::{config::*, factory::*, pass::*, run::*, shutdown::*};
#[cfg(all(unix, feature = "voice"))]
use crate::tick::PushTick;
use crate::tick::{Tick, TickSource};
use oneiron::attempt_queue::AttemptId;
#[cfg(all(unix, feature = "voice"))]
use oneiron::edge::EdgeActorClass;
use oneiron::{
    BudgetGuard, ConsolidationSink, DreamerAdmittedAttempt, DreamerAttemptExecution,
    DreamerAttemptExecutor, DreamerBudgetReserveOutcome, DreamerConsolidationScope,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    ReserveDreamerBudget, Result, Vault, VaultConfig, WakeAttemptContext,
};
#[cfg(all(unix, feature = "voice"))]
use oneiron::{
    DreamerClaimAuthoringStrategy, LlmBackend, ModelId, WakeCancellation, WakePassDeadline,
    WriteActor,
};
#[cfg(all(unix, feature = "voice"))]
use oneiron_server::managed::ManagedShutdown;
#[cfg(all(unix, feature = "voice"))]
use oneiron_server::voice_host::{VoiceHost, VoiceHostConfig, VoiceServeConnection};
#[cfg(all(unix, feature = "voice"))]
use std::sync::{Arc, Mutex};
#[cfg(all(unix, feature = "voice"))]
use tokio::sync::watch;

#[cfg(all(unix, feature = "voice"))]
mod voice;

/// Seeds a durable budget row at `budget_id` (init-if-absent via reserve).
pub(super) fn seed_budget_row(vault: &Vault, budget_id: &str) {
    let store = DreamerRunnerStore::new(vault);
    match store
        .reserve_budget(ReserveDreamerBudget {
            budget_id: budget_id.to_owned(),
            child_attempt: AttemptId::now(),
            budget_total_units: 1,
            reserve_units: 1,
            now: 1,
        })
        .expect("seed reserve")
    {
        // Only Reserved persists a new counter row; Exhausted on a
        // missing id is in-memory only and must not be treated as seed.
        DreamerBudgetReserveOutcome::Reserved(_) => {}
        other => panic!("expected Reserved seed outcome, got {other:?}"),
    }
    assert!(
        store.budget(budget_id).expect("budget read").is_some(),
        "seeded budget row must exist at {budget_id}"
    );
}

pub(super) fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    (dir, vault)
}

pub(super) fn enqueue_micro(vault: &Vault, tag: &str, now: u64) -> AttemptId {
    match DreamerRunnerStore::new(vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: rmpv::Value::from(tag),
            parent_attempt: None,
            dedupe_key: Some(tag.to_owned()),
            run_id: None,
            now,
        })
        .expect("enqueue")
    {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    }
}

pub(super) fn test_config() -> WakeSupervisorConfig {
    let mut config = WakeSupervisorConfig::new("driver-budget", "driver-worker", 1, 10_000);
    config.reserve_units = 100;
    config
}

pub(super) struct ScriptedTicks {
    pub(super) ticks: Vec<Tick>,
}

impl TickSource for ScriptedTicks {
    async fn next_tick(&mut self) -> Option<Tick> {
        if self.ticks.is_empty() {
            None
        } else {
            Some(self.ticks.remove(0))
        }
    }
}

pub(super) struct TestExec {
    pub(super) panic_now: bool,
    pub(super) completed_units: u64,
}

impl DreamerAttemptExecutor for TestExec {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        assert!(!self.panic_now, "scripted executor panic");
        Ok(DreamerAttemptExecution::Completed {
            completed_units: self.completed_units,
        })
    }
}

pub(super) struct TestExecFactory {
    pub(super) panics_left: u32,
    pub(super) factory_panics_left: u32,
    /// Pre-admission `Err` count (not panic): surfaces as
    /// [`PassOutcome::PreAdmissionFailed`] so the supervisor re-drives.
    pub(super) factory_errors_left: u32,
    pub(super) completed_units: u64,
}

impl PassExecutorFactory for TestExecFactory {
    type Exec<'p> = TestExec;

    fn executor<'p>(&'p mut self, _guard: &'p BudgetGuard) -> Result<TestExec> {
        if self.factory_panics_left > 0 {
            self.factory_panics_left -= 1;
            panic!("scripted factory panic");
        }
        if self.factory_errors_left > 0 {
            self.factory_errors_left -= 1;
            return Err(oneiron::Error::InvalidConfig(
                "scripted pre-admission factory error".into(),
            ));
        }
        let panic_now = self.panics_left > 0;
        if panic_now {
            self.panics_left -= 1;
        }
        Ok(TestExec {
            panic_now,
            completed_units: self.completed_units,
        })
    }
}

/// Factory that sleeps past the finalize threshold for a
/// `pass_ceiling_ms = WRAP + 1` config, so Instant-elapsed hard-cuts
/// before any admission (defense path for runtime-induced empty cuts).
/// `delays_left` counts how many factory calls still sleep (then the
/// redrive path can complete work without a second push).
pub(super) struct DelayedHardCutFactory {
    pub(super) completed_units: u64,
    pub(super) delay: Duration,
    pub(super) delays_left: u32,
}

impl PassExecutorFactory for DelayedHardCutFactory {
    type Exec<'p> = TestExec;

    fn executor<'p>(&'p mut self, _guard: &'p BudgetGuard) -> Result<TestExec> {
        // Advances the real Instant behind WakePassDeadline::new so the
        // pass is already in the finalize window when run_wake_pass starts.
        if self.delays_left > 0 {
            self.delays_left -= 1;
            std::thread::sleep(self.delay);
        }
        Ok(TestExec {
            panic_now: false,
            completed_units: self.completed_units,
        })
    }
}

pub(super) struct UnusedSink;

impl ConsolidationSink for UnusedSink {
    fn accept(
        &mut self,
        _candidates: Vec<oneiron::dreamer_consolidation::PromotionCandidate>,
    ) -> Result<()> {
        panic!("the commitment wake path promotes no consolidation candidates")
    }
}

pub(super) fn seed_actor(vault: &Vault, seed: u8, entity_type: u8) -> oneiron::EntityId {
    let id = oneiron::EntityId::from_bytes([seed; 16]).expect("fixture id");
    vault
        .put_entity(
            &id,
            entity_type,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"cmt3 supervisor actor",
        )
        .expect("seed actor");
    id
}

pub(super) fn enqueue_input(vault: &Vault, input: rmpv::Value, tag: &str, now: u64) -> AttemptId {
    match DreamerRunnerStore::new(vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input,
            parent_attempt: None,
            dedupe_key: Some(tag.to_owned()),
            run_id: Some(tag.to_owned()),
            now,
        })
        .expect("enqueue")
    {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    }
}

pub(super) fn admit(vault: &Vault, now: u64) -> DreamerAdmittedAttempt {
    let store = DreamerRunnerStore::new(vault);
    let node_id = store
        .local_home_node_candidate(false, false, false)
        .expect("client id")
        .node_id;
    let outcome = store
        .admit_next_consolidation(oneiron::dreamer_runner::AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: node_id,
            claim_authoring_tier: oneiron::dreamer_runner::DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: oneiron::dreamer_runner::DreamerClaimAuthoringAdmission::single_pass(),
            admission: oneiron::dreamer_runner::AdmitDreamerAttempt {
                lease_owner: "cmt3-supervisor-test".to_owned(),
                now,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })
        .expect("admit");
    let oneiron::dreamer_runner::DreamerConsolidationAdmissionOutcome::Admission(
        oneiron::dreamer_runner::DreamerAdmissionOutcome::Admitted(admitted),
    ) = outcome
    else {
        panic!("expected an admitted micro attempt, got {outcome:?}");
    };
    *admitted
}
