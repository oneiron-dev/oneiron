//! Tick tests: shared helpers (scripted deadlines, frozen and movable clocks, vault seed helpers).

use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND;
use oneiron::attempt_queue::AttemptQueue;
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
};
use oneiron::commitment_schedule::{
    CommitmentSchedulePayload, CommitmentSeriesWriteOutcome, Schedule, commitment_projection_actor,
};
use oneiron::edge::EdgeActorClass;
use oneiron::entity_id::EntityId;
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use oneiron::{
    DreamerConsolidationScope, DreamerHomeNodeCandidate, DreamerRunnerStore,
    EnqueueDreamerConsolidationAttempt, Vault, VaultConfig,
};

use super::*;

mod tests_commitment;
mod tests_push;

const COALESCE_FLOOR_MS: u64 =
    crate::session::DEFAULT_SESSION_IDLE_FLOOR_SECS.saturating_mul(1_000);

struct ScriptedDeadlines {
    deadlines: Vec<Option<CommitmentDeadline>>,
}

impl ScriptedDeadlines {
    fn new(mut deadlines: Vec<Option<CommitmentDeadline>>) -> Self {
        deadlines.reverse();
        Self { deadlines }
    }
}

impl DeadlineSource for ScriptedDeadlines {
    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
        Ok(self.deadlines.pop().flatten())
    }
}

fn frozen_clock(now: u64) -> NowMillis {
    Arc::new(move || now)
}

// -----------------------------------------------------------------------
// CMT-2 (ONE-1539): the commitment due lane
// -----------------------------------------------------------------------

/// The frozen-clock model [`TimerTick::with_clock`] uses, with a handle the
/// test moves by hand. One [`NowMillis`] is shared by every consumer, so
/// "now" is a fact of the test rather than of the host.
fn movable_clock(now_ms: u64) -> (Arc<AtomicU64>, NowMillis) {
    let cell = Arc::new(AtomicU64::new(now_ms));
    let reader = Arc::clone(&cell);
    (cell, Arc::new(move || reader.load(Ordering::SeqCst)))
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    (dir, vault)
}

fn enqueue(vault: &Vault, scope: DreamerConsolidationScope, tag: &str, now: u64) {
    DreamerRunnerStore::new(vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope,
            input: rmpv::Value::from(tag),
            parent_attempt: None,
            dedupe_key: Some(tag.to_owned()),
            run_id: None,
            now,
        })
        .expect("enqueue");
}

fn elect_home(vault: &Vault, node_id: u64, now: u64) {
    DreamerRunnerStore::new(vault)
        .elect_home_node(
            &[DreamerHomeNodeCandidate {
                node_id,
                cloud: true,
                attached: true,
                always_on_local: false,
                primary_device: false,
            }],
            now,
        )
        .expect("elect home node");
}

/// Vault stable client identity — the same id macro admission compares
/// via `load_or_mint_client_id` / `local_home_node_candidate`.
fn vault_client_node_id(vault: &Vault) -> u64 {
    DreamerRunnerStore::new(vault)
        .local_home_node_candidate(false, false, false)
        .expect("vault client identity")
        .node_id
}

fn commitment_party(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

/// Seeds the parties a commitment write needs — including the projector's
/// PINNED System actor, which the claim door resolves against a stored
/// MACHINE entity before it will mint anything.
fn seed_commitment_world(vault: &Vault) -> WriteEnvelope {
    let at = TimeRange { start: 1, end: 1 };
    for seed in [0x71_u8, 0x72] {
        vault
            .put_entity(
                &commitment_party(seed),
                ENTITY_TYPE_PERSON,
                at,
                1,
                b"person",
            )
            .expect("seed commitment party");
    }
    vault
        .put_entity(
            &commitment_projection_actor().entity_ref(),
            ENTITY_TYPE_MACHINE,
            at,
            1,
            b"commitment projector",
        )
        .expect("seed projection actor");
    WriteEnvelope::new(
        WriteActor::new(commitment_party(0x71), EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("driver commitment fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    )
}

/// Indexes a `Once` series whose Project row lands exactly at `project_at`
/// SECONDS, and whose occurrence is owed 100 s later.
fn seed_project_row_at(vault: &Vault, project_at: u64) {
    let envelope = seed_commitment_world(vault);
    let due = project_at + 100;
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, commitment_party(0x71)),
        commitment_party(0x72),
        CommitmentContent::new("file the driver report", None).expect("content"),
        CommitmentSchedulePayload::series(Schedule::Once { due }, Some(100))
            .encode()
            .expect("series payload encodes"),
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:driver")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    let outcome = vault
        .put_commitment_series(
            &commitment_party(0x83),
            &record,
            &envelope,
            TimeRange {
                start: 1,
                end: due + 1_000,
            },
            1,
        )
        .expect("series indexes");
    assert_eq!(
        outcome,
        CommitmentSeriesWriteOutcome::Indexed {
            project_at,
            next_due: due,
        }
    );
}

/// One merge read over a fresh vault: a commitment Project row at 3 s
/// against a single queued attempt due at `attempt_secs`.
fn merged_deadline(
    attempt_secs: u64,
    scope: DreamerConsolidationScope,
) -> Option<CommitmentDeadline> {
    let (_dir, vault) = open_vault();
    seed_project_row_at(&vault, 3);
    let local = vault_client_node_id(&vault);
    enqueue(&vault, scope, "merge-attempt", attempt_secs);
    let (_clock, now) = movable_clock(0);
    AttemptQueueDeadlines::with_commitment_clock(&vault, local, now)
        .next_deadline()
        .expect("merged deadline read")
}

/// Every MICRO consolidation row currently queued.
fn micro_attempts(vault: &Vault) -> Vec<oneiron::attempt_queue::AttemptRecord> {
    AttemptQueue::new(vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|row| row.kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND)
        .collect()
}
