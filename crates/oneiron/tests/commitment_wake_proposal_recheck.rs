//! FIX COMMITMENT-WAKE-PROPOSAL-WRITE-RECHECK: the commitment wake executor
//! asks whether the instance may still wake in its own read (step 3), then
//! runs the planner, then writes the proposal in a separate write
//! transaction. An instance the owner fulfilled or withdrew between that read
//! and that write still got a proposal: an inbox card for a promise that is
//! no longer open. The write now asks the same wake verdict again inside its
//! own transaction and completes without a proposal when the instance may no
//! longer wake.
//!
//! The planner is the window: it runs after step 3 and before the write, so a
//! planner that closes the instance lands the close exactly there.
//!
//! The fixture is the one `oneiron-server/tests/connector_send_no_transport.rs`
//! runs the same executor on: the engine's machines provisioned and the
//! embedded owner bound through the `label_writers` door, so the file builds
//! only under `--cfg oneiron_test_support`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test commitment_wake_proposal_recheck`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::attempt_queue::AttemptId;
use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
};
use oneiron::commitment_schedule::{CommitmentSchedulePayload, Schedule};
use oneiron::commitment_wake::{
    CommitmentWakeDue, CommitmentWakeEvent, CommitmentWakeExecutor, CommitmentWakeFireOutcome,
    CommitmentWakeProposalDraft, CommitmentWakeProposalPlanner, commitment_wake_proposal_claim_id,
    fire_due_commitment_wake,
};
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::dreamer_wake::{
    DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext, WakePassDeadline,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
    WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

const LEAD_SECONDS: u64 = 100;
const BUDGET_ID: &str = "commitment-wake-recheck";

/// What the planner does to the instance before it proposes.
#[derive(Debug, Clone, Copy)]
enum InstanceAct {
    /// Nothing: the instance is still open at the write.
    None,
    /// The owner marks the promise fulfilled (a status close).
    Fulfil,
    /// The owner withdraws the instance (a generic retraction).
    Retract,
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let _issuer = oneiron::test_support::provision_engine_machines(&vault);
        let (owner, _proof) = oneiron::test_doors::label_writers::embedded_owner(&vault)
            .expect("the vault's bound embedded owner");
        Self {
            vault,
            owner,
            _dir: dir,
        }
    }

    fn owner_envelope(&self) -> WriteEnvelope {
        WriteEnvelope::new(
            WriteActor::new(self.owner, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("commitment wake recheck fixture"))
                .expect("provenance"),
            ClaimApprovalStatus::Auto,
        )
    }

    /// Indexes the owner's `Once` series due a lead after `now` and lets the
    /// projection mint its one instance; returns the instance.
    fn project_once_instance(&self, now: u64) -> EntityId {
        let beneficiary = EntityId::now();
        self.vault
            .put_entity(
                &beneficiary,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"wake recheck beneficiary",
            )
            .expect("the beneficiary is a live PERSON");
        let due_at = now + LEAD_SECONDS;
        let record = CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Owner, self.owner),
            beneficiary,
            CommitmentContent::new("send the signed lease", None).expect("content"),
            CommitmentSchedulePayload::series(Schedule::Once { due: due_at }, Some(LEAD_SECONDS))
                .encode()
                .expect("series payload"),
            CommitmentStrength::Commitment,
            CommitmentStatus::Open,
            CommitmentBirthProvenance::new(
                CommitmentBirthKind::RunTreeNode,
                "run:commitment-wake-recheck",
            )
            .expect("birth provenance"),
        )
        .expect("commitment record");
        self.vault
            .put_commitment_series(
                &EntityId::now(),
                &record,
                &self.owner_envelope(),
                TimeRange {
                    start: now,
                    end: due_at + 10_000,
                },
                now,
            )
            .expect("series indexes");
        let report = self
            .vault
            .reconcile_commitment_schedule(now)
            .expect("the projection mints the occurrence at its lead");
        assert_eq!(
            report.minted_instances.len(),
            1,
            "one occurrence per series"
        );
        report.minted_instances[0]
    }

    /// Fires the instance's Lead through the fire door and admits the Micro
    /// attempt it enqueued.
    fn fire_and_admit_lead(&self, instance: EntityId, now: u64) -> DreamerAdmittedAttempt {
        let entry = self
            .vault
            .next_actionable_wake_phase()
            .expect("wake read")
            .expect("the projection made a Lead phase");
        let due = CommitmentWakeDue::from_due_entry(&entry)
            .expect("typed wake due")
            .expect("the next actionable phase is a Lead or a Due");
        assert_eq!(due.instance_id, instance, "the Lead is this instance's");
        let attempt_id = match fire_due_commitment_wake(&self.vault, due, now).expect("fire door") {
            CommitmentWakeFireOutcome::Enqueued { attempt_id } => attempt_id,
            other => panic!("an open owner commitment enqueues its Lead: {other:?}"),
        };
        let admitted = match DreamerRunnerStore::new(&self.vault)
            .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
                scope: DreamerConsolidationScope::Micro,
                local_node_id: 1,
                claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
                admission: AdmitDreamerAttempt {
                    lease_owner: BUDGET_ID.into(),
                    now,
                    budget_id: BUDGET_ID.into(),
                    budget_total_units: 100,
                    reserve_units: 1,
                    started_milestone: None,
                },
            })
            .expect("admit")
        {
            DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
                attempt,
            )) => *attempt,
            other => panic!("the fired Lead is admitted as Micro work: {other:?}"),
        };
        assert_eq!(
            admitted.status.attempt.id, attempt_id,
            "the fired Lead's attempt"
        );
        admitted
    }
}

/// Proposes a call, after doing `act` to the instance through the vault it is
/// handed: the act lands after the executor's step-3 read and before its
/// proposal write.
struct ActingPlanner {
    act: InstanceAct,
    envelope: WriteEnvelope,
    close_at: u64,
    plans: u32,
}

impl CommitmentWakeProposalPlanner for ActingPlanner {
    fn plan(
        &mut self,
        _event: &CommitmentWakeEvent,
        _commitment: &CommitmentRecord,
    ) -> oneiron::Result<CommitmentWakeProposalDraft> {
        self.plans += 1;
        Ok(CommitmentWakeProposalDraft {
            verb: "call".into(),
            channel: "voice".into(),
            target: "+15551234567".into(),
            on_behalf_of: None,
            content_ref: None,
            dedupe_key: None,
        })
    }

    fn plan_in_vault(
        &mut self,
        vault: &Vault,
        event: &CommitmentWakeEvent,
        commitment: &CommitmentRecord,
    ) -> oneiron::Result<Option<CommitmentWakeProposalDraft>> {
        match self.act {
            InstanceAct::None => {}
            InstanceAct::Fulfil => {
                vault.fulfill_commitment(&event.instance_id, &self.envelope, self.close_at)?;
            }
            InstanceAct::Retract => vault.retract_claim(&event.instance_id, self.close_at)?,
        }
        self.plan(event, commitment).map(Some)
    }
}

struct NoOrdinaryWork;

impl DreamerAttemptExecutor for NoOrdinaryWork {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        panic!("a tagged commitment wake runs in the wake wrapper, not as ordinary work")
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the host clock is after the Unix epoch")
        .as_secs()
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the commitment wake executor never pends on real work");
}

/// One fired and admitted Lead, executed by the wake wrapper with the System
/// Dreamer as its author and a planner that does `act` first. Returns the
/// execution (errors as text), whether the attempt's proposal claim exists,
/// and how many times the planner ran.
fn execute_lead_with(act: InstanceAct) -> (Result<DreamerAttemptExecution, String>, bool, u32) {
    let fixture = Fixture::new();
    let now = now_seconds();
    let instance = fixture.project_once_instance(now);
    let admitted = fixture.fire_and_admit_lead(instance, now);
    let dreamer = fixture
        .vault
        .dreamer_authority()
        .expect("the provisioned System Dreamer");
    let mut planner = ActingPlanner {
        act,
        envelope: fixture.owner_envelope(),
        close_at: now,
        plans: 0,
    };
    let execution = {
        let mut executor = CommitmentWakeExecutor::new(NoOrdinaryWork, Some(&mut planner), dreamer)
            .expect("the System Dreamer may author a wake proposal");
        let deadline = WakePassDeadline::new(180_000);
        let mut ctx = WakeAttemptContext {
            vault: &fixture.vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: BUDGET_ID,
            now_ms: now * 1_000,
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        };
        block_on_ready(executor.execute(&admitted, &mut ctx)).map_err(|error| format!("{error:?}"))
    };
    let attempt: AttemptId = admitted.status.attempt.id;
    let proposed = fixture
        .vault
        .get_claim(&commitment_wake_proposal_claim_id(attempt))
        .expect("claim read")
        .is_some();
    (execution, proposed, planner.plans)
}

fn completed() -> Result<DreamerAttemptExecution, String> {
    Ok(DreamerAttemptExecution::Completed {
        completed_units: 0,
        step_bindings: Vec::new(),
    })
}

/// The harness proves its own path: an instance that stays open gets its
/// proposal, so a missing proposal below is the recheck, not a broken fixture.
#[test]
fn a_wake_for_an_open_instance_writes_its_proposal() {
    assert_eq!(
        execute_lead_with(InstanceAct::None),
        (completed(), true, 1),
        "an open instance's wake completes with its proposal written"
    );
}

#[test]
fn a_wake_whose_instance_is_fulfilled_while_it_plans_writes_no_proposal() {
    assert_eq!(
        execute_lead_with(InstanceAct::Fulfil),
        (completed(), false, 1),
        "the instance was fulfilled before the proposal write: the wake completes without a \
         proposal"
    );
}

#[test]
fn a_wake_whose_instance_is_withdrawn_while_it_plans_writes_no_proposal() {
    assert_eq!(
        execute_lead_with(InstanceAct::Retract),
        (completed(), false, 1),
        "the instance was withdrawn before the proposal write: the wake completes without a \
         proposal"
    );
}
