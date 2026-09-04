//! CMT-3 (ONE-1540) acceptance tests: due phase → one durable Dreamer attempt
//! → inbox proposal → OF-327 delivery, and every refusal on the way.

use std::cell::RefCell;
use std::future::Future;
use std::pin::pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind,
};
use crate::commitment_schedule::{
    CommitmentSchedulePayload, CommitmentSeriesWriteOutcome, Schedule, commitment_projection_actor,
};
use crate::config::VaultConfig;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, EnqueueDreamerConsolidationAttempt,
};
use crate::dreamer_wake::WakePassDeadline;
use crate::inbox::InboxBulkVerb;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::test_util::{entity_record, put_policy_manifest_bytes};

use super::*;

// ─── fixture vocabulary ────────────────────────────────────────────────────

const OBLIGOR: u8 = 0x71;
const BENEFICIARY: u8 = 0x72;
const SERIES: u8 = 0x83;
/// Deliberately NOT in `0xA1..=0xA6`: those bytes are the seeded system-agent
/// roster ids production pins.
const DREAMER_AGENT: u8 = 0x5A;
const OTHER_AGENT: u8 = 0x5B;

const LEAD_SECS: u64 = 100;
const DUE_AT: u64 = 1_000;
/// The projector schedules the Project row a lead ahead of the due instant, so
/// this is both "when the series materializes" and "when Lead fires".
const PROJECT_AT: u64 = DUE_AT - LEAD_SECS;

const CALL_VERB: &str = "call";
const VOICE_CHANNEL: &str = "voice";
const CALL_TARGET: &str = "+15551234567";

fn party(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

fn at(instant: u64) -> TimeRange {
    TimeRange {
        start: instant,
        end: instant,
    }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    (dir, vault)
}

fn reopen(dir: &tempfile::TempDir) -> Vault {
    Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault")
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        // Every path this module owns is synchronous by construction (blueprint
        // §4: no model call, no `call_as_step`), so a pend is the failure.
        Poll::Pending => panic!("the commitment wake executor must never pend"),
    }
}

/// Seeds the parties a commitment write needs, plus the two agent actors the
/// proposal and its replay use. Returns the series-write envelope.
fn seed_world(vault: &Vault) -> WriteEnvelope {
    for seed in [OBLIGOR, BENEFICIARY, DREAMER_AGENT, OTHER_AGENT] {
        vault
            .put_entity(&party(seed), ENTITY_TYPE_PERSON, at(1), 1, b"cmt3 person")
            .expect("seed person");
    }
    vault
        .put_entity(
            &commitment_projection_actor().entity_ref(),
            ENTITY_TYPE_MACHINE,
            at(1),
            1,
            b"commitment projector",
        )
        .expect("seed projection actor");
    WriteEnvelope::new(
        WriteActor::new(party(OBLIGOR), EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("cmt3 fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    )
}

fn dreamer_actor() -> WriteActor {
    WriteActor::new(party(DREAMER_AGENT), EdgeActorClass::Agent)
}

/// Indexes a `Once` series at `strength` and materializes its one occurrence,
/// returning the minted instance. The Lead row lands at [`PROJECT_AT`] and the
/// Due row at [`DUE_AT`].
fn project_instance(vault: &Vault, strength: CommitmentStrength) -> EntityId {
    let envelope = seed_world(vault);
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, party(OBLIGOR)),
        party(BENEFICIARY),
        CommitmentContent::new("ring the beneficiary back", None).expect("content"),
        CommitmentSchedulePayload::series(Schedule::Once { due: DUE_AT }, Some(LEAD_SECS))
            .encode()
            .expect("series payload"),
        strength,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:cmt3")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    let outcome = vault
        .put_commitment_series(
            &party(SERIES),
            &record,
            &envelope,
            TimeRange {
                start: 1,
                end: DUE_AT + 10_000,
            },
            1,
        )
        .expect("series indexes");
    assert_eq!(
        outcome,
        CommitmentSeriesWriteOutcome::Indexed {
            project_at: PROJECT_AT,
            next_due: DUE_AT,
        }
    );
    vault
        .reconcile_commitment_schedule(PROJECT_AT)
        .expect("projection mints the occurrence");
    vault
        .next_actionable_wake_phase()
        .expect("wake read")
        .expect("a minted occurrence has a Lead row")
        .instance_ref
        .expect("an instance phase names its instance")
}

fn next_due(vault: &Vault) -> Option<CommitmentWakeDue> {
    let entry = vault.next_actionable_wake_phase().expect("wake read")?;
    CommitmentWakeDue::from_due_entry(&entry).expect("typed wake due")
}

fn fire_next(vault: &Vault, now: u64) -> CommitmentWakeFireOutcome {
    let due = next_due(vault).expect("an actionable phase is due");
    fire_due_commitment_wake(vault, due, now).expect("fire door")
}

/// Every durable MICRO consolidation row, oldest first — the "how many
/// attempts exist" question every fire-once assertion asks.
fn wake_attempts(vault: &Vault) -> Vec<AttemptRecord> {
    let mut rows: Vec<AttemptRecord> = AttemptQueue::new(vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|row| row.kind == DreamerConsolidationScope::Micro.attempt_kind())
        .collect();
    // Sorted by the TIME-SORTABLE attempt id, not by `created_at`: a late
    // start fires both phases at the same injected instant, and enqueue order
    // is what "Lead then Due" means there.
    rows.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    rows
}

fn run_ids(vault: &Vault) -> Vec<String> {
    wake_attempts(vault)
        .into_iter()
        .filter_map(|row| row.run_id)
        .collect()
}

fn phase_key(instance: EntityId, phase: CommitmentWakePhase) -> String {
    format!("cmt:{}:{}", instance.to_hex(), phase.as_str())
}

// ─── executor harness ──────────────────────────────────────────────────────

/// Records every delegated attempt and answers with a fixed unit count, so a
/// delegated result can be compared byte-for-byte with what the inner returned.
#[derive(Clone, Default)]
struct RecordingInner {
    calls: Rc<RefCell<Vec<Option<String>>>>,
    completed_units: u64,
}

impl DreamerAttemptExecutor for RecordingInner {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        self.calls
            .borrow_mut()
            .push(attempt.status.attempt.run_id.clone());
        Ok(DreamerAttemptExecution::Completed {
            completed_units: self.completed_units,
        })
    }
}

/// Deterministic v1 planner: no model call, no `call_as_step`, no spend. The
/// draft is a pure function of the event, which is exactly what makes the
/// read-first replay rule sound.
#[derive(Default)]
struct FakePlanner {
    plans: usize,
}

impl CommitmentWakeProposalPlanner for FakePlanner {
    fn plan(
        &mut self,
        event: &CommitmentWakeEvent,
        commitment: &CommitmentRecord,
    ) -> Result<CommitmentWakeProposalDraft> {
        assert_eq!(commitment.strength, CommitmentStrength::Commitment);
        assert_eq!(commitment.status, CommitmentStatus::Open);
        self.plans += 1;
        Ok(CommitmentWakeProposalDraft {
            verb: CALL_VERB.to_owned(),
            channel: VOICE_CHANNEL.to_owned(),
            target: CALL_TARGET.to_owned(),
            on_behalf_of: None,
            content_ref: Some(format!("content:{}", event.phase.as_str())),
            dedupe_key: None,
        })
    }
}

fn admit_micro(vault: &Vault, now: u64) -> DreamerAdmittedAttempt {
    let store = DreamerRunnerStore::new(vault);
    let node_id = crate::identity::load_or_mint_client_id(vault).expect("client id");
    let outcome = store
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: node_id,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "cmt3-test".to_owned(),
                now,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })
        .expect("admit");
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = outcome
    else {
        panic!("expected an admitted micro attempt, got {outcome:?}");
    };
    *admitted
}

fn execute_wrapped(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    planner: Option<&mut dyn CommitmentWakeProposalPlanner>,
    inner: RecordingInner,
    actor: WriteActor,
) -> Result<DreamerAttemptExecution> {
    let deadline = WakePassDeadline::new(180_000);
    let mut ctx = WakeAttemptContext {
        vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: DUE_AT.saturating_mul(1_000),
    };
    let mut executor = CommitmentWakeExecutor::new(inner, planner, actor)?;
    block_on_ready(executor.execute(attempt, &mut ctx))
}

/// Fires the Lead phase, admits the attempt it created, and runs it through a
/// planner-configured wrapper — the whole producer side in one call.
fn propose_lead_wake(vault: &Vault) -> (EntityId, DreamerAdmittedAttempt, EntityId) {
    let instance = project_instance(vault, CommitmentStrength::Commitment);
    assert!(matches!(
        fire_next(vault, PROJECT_AT),
        CommitmentWakeFireOutcome::Enqueued { .. }
    ));
    let attempt = admit_micro(vault, PROJECT_AT);
    let mut planner = FakePlanner::default();
    let execution = execute_wrapped(
        vault,
        &attempt,
        Some(&mut planner),
        RecordingInner::default(),
        dreamer_actor(),
    )
    .expect("proposal write");
    assert_eq!(
        execution,
        DreamerAttemptExecution::Completed { completed_units: 0 }
    );
    assert_eq!(planner.plans, 1, "v1 plans exactly once per attempt");
    let proposal = commitment_wake_proposal_claim_id(attempt.status.attempt.id);
    (instance, attempt, proposal)
}

fn accept_group(vault: &Vault, key: &str, now: u64) {
    vault
        .resolve_inbox_group_at(key, InboxBulkVerb::AcceptAll, None, now)
        .expect("the decider accepts the wake proposal group");
}

// ─── 1-2: the fire-once door ───────────────────────────────────────────────

/// Both phases fire, each exactly once, and the count survives a reopen: the
/// enqueue and the phase settle share one transaction, so no crash point can
/// leave a duplicate attempt or a lost phase.
#[test]
fn lead_and_due_enqueue_once_across_reopen() {
    let (dir, vault) = open_vault();
    let instance = project_instance(&vault, CommitmentStrength::Commitment);
    let lead_key = phase_key(instance, CommitmentWakePhase::Lead);
    let due_key = phase_key(instance, CommitmentWakePhase::Due);

    let stale_lead = next_due(&vault).expect("a Lead phase is due");
    assert!(matches!(
        fire_due_commitment_wake(&vault, stale_lead, PROJECT_AT).expect("fire"),
        CommitmentWakeFireOutcome::Enqueued { .. }
    ));

    drop(vault);
    let vault = reopen(&dir);
    assert_eq!(run_ids(&vault), vec![lead_key.clone()]);

    // The settled phase cannot be re-consumed: the equality re-read misses, so
    // the stale caller settles nothing and enqueues nothing.
    assert_eq!(
        fire_due_commitment_wake(&vault, stale_lead, PROJECT_AT).expect("fire"),
        CommitmentWakeFireOutcome::Skipped(CommitmentWakeSkip::Raced)
    );
    assert_eq!(run_ids(&vault), vec![lead_key.clone()]);

    assert!(matches!(
        fire_next(&vault, DUE_AT),
        CommitmentWakeFireOutcome::Enqueued { .. }
    ));
    drop(vault);
    let vault = reopen(&dir);
    let mut keys = run_ids(&vault);
    keys.sort();
    assert_eq!(keys, vec![due_key, lead_key]);
    assert!(
        next_due(&vault).is_none(),
        "both acknowledgeable phases are settled"
    );
}

/// A late start is two immediate, distinct, fire-once transactions — Lead then
/// Due — and synthesizes no escalation event of its own.
#[test]
fn late_start_consumes_lead_then_due_once() {
    let (_dir, vault) = open_vault();
    let instance = project_instance(&vault, CommitmentStrength::Commitment);
    let late = DUE_AT + 5_000;

    assert!(matches!(
        fire_next(&vault, late),
        CommitmentWakeFireOutcome::Enqueued { .. }
    ));
    assert!(matches!(
        fire_next(&vault, late),
        CommitmentWakeFireOutcome::Enqueued { .. }
    ));
    assert!(next_due(&vault).is_none());

    assert_eq!(
        run_ids(&vault),
        vec![
            phase_key(instance, CommitmentWakePhase::Lead),
            phase_key(instance, CommitmentWakePhase::Due),
        ],
        "exactly two attempts, in phase order, and nothing else"
    );
}

/// Only `Commitment` wakes. `Decision` is query/check-in material and
/// `StatedIntention` is retrieval-only: both settle their phase without
/// enqueueing, so the deadline source converges instead of busy-looping.
#[test]
fn only_commitment_strength_emits_event_attempt() {
    for (strength, expected) in [
        (
            CommitmentStrength::StatedIntention,
            Some(CommitmentWakeSkip::StatedIntention),
        ),
        (
            CommitmentStrength::Decision,
            Some(CommitmentWakeSkip::Decision),
        ),
        (CommitmentStrength::Commitment, None),
    ] {
        let (_dir, vault) = open_vault();
        project_instance(&vault, strength);
        let outcome = fire_next(&vault, PROJECT_AT);
        match expected {
            Some(skip) => {
                assert_eq!(outcome, CommitmentWakeFireOutcome::Skipped(skip));
                assert!(run_ids(&vault).is_empty(), "{strength:?} must not wake");
            }
            None => {
                assert!(matches!(
                    outcome,
                    CommitmentWakeFireOutcome::Enqueued { .. }
                ));
                assert_eq!(run_ids(&vault).len(), 1);
            }
        }
        assert_eq!(
            next_due(&vault).map(|due| due.phase),
            Some(CommitmentWakePhase::Due),
            "{strength:?}: the Lead phase is settled either way"
        );
    }
}

/// A closed instance is a stale row, not a wake. The status write and the
/// schedule's close hook are separate calls, so the rows a crash between them
/// leaves behind are exactly what this settles.
#[test]
fn closed_or_missing_instance_settles_stale_due_row() {
    let (_dir, vault) = open_vault();
    let instance = project_instance(&vault, CommitmentStrength::Commitment);
    let envelope = seed_world(&vault);
    vault
        .fulfill_commitment(&instance, &envelope, DUE_AT)
        .expect("close the instance without running the schedule hook");

    assert_eq!(
        fire_next(&vault, PROJECT_AT),
        CommitmentWakeFireOutcome::Skipped(CommitmentWakeSkip::ClosedInstance)
    );
    assert_eq!(
        fire_next(&vault, DUE_AT),
        CommitmentWakeFireOutcome::Skipped(CommitmentWakeSkip::ClosedInstance)
    );
    assert!(
        next_due(&vault).is_none(),
        "both stale phases are settled, so the source converges"
    );
    assert!(
        run_ids(&vault).is_empty(),
        "a closed instance never enqueues"
    );
}

// ─── 4: the wrapper executor ───────────────────────────────────────────────

/// An ordinary partition attempt is delegated with its payload, context, and
/// result untouched.
#[test]
fn ordinary_partition_attempt_delegates_unchanged() {
    let (_dir, vault) = open_vault();
    DreamerRunnerStore::new(&vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: Value::from("ordinary-partition-payload"),
            parent_attempt: None,
            dedupe_key: Some("ordinary".to_owned()),
            run_id: Some("run-ordinary".to_owned()),
            now: 10,
        })
        .expect("enqueue an ordinary attempt");
    let attempt = admit_micro(&vault, 11);

    let inner = RecordingInner {
        calls: Rc::default(),
        completed_units: 7,
    };
    let calls = Rc::clone(&inner.calls);
    let execution = execute_wrapped(&vault, &attempt, None, inner, dreamer_actor())
        .expect("delegation never fails on the wrapper's account");

    assert_eq!(
        execution,
        DreamerAttemptExecution::Completed { completed_units: 7 },
        "the delegated result is the inner executor's, verbatim"
    );
    assert_eq!(
        calls.borrow().as_slice(),
        &[Some("run-ordinary".to_owned())]
    );
}

/// A tagged event with no planner is a typed COMPLETION with zero units. It
/// never reaches the partition decoder and never parks the driver — which is
/// why the production factory installs the wrapper unconditionally.
#[test]
fn missing_planner_completes_tagged_attempt_without_parking() {
    let (_dir, vault) = open_vault();
    project_instance(&vault, CommitmentStrength::Commitment);
    fire_next(&vault, PROJECT_AT);
    let attempt = admit_micro(&vault, PROJECT_AT);

    let inner = RecordingInner::default();
    let calls = Rc::clone(&inner.calls);
    // A System-class actor: legal precisely because a planner-less wrapper
    // never uses it.
    let system = WriteActor::new(party(BENEFICIARY), EdgeActorClass::System);
    let execution =
        execute_wrapped(&vault, &attempt, None, inner, system).expect("no-planner skip completes");

    assert_eq!(
        execution,
        DreamerAttemptExecution::Completed { completed_units: 0 }
    );
    assert!(
        calls.borrow().is_empty(),
        "a tagged event must never reach the partition decoder"
    );
}

/// The proposal exists as a PENDING consent row whose inbox group key is the
/// phase key itself, through the existing literal-run fallback — no new
/// grouping mechanism and no `inbox.rs` edit.
#[test]
fn wake_proposal_records_pending_consent() {
    let (_dir, vault) = open_vault();
    let (instance, attempt, proposal) = propose_lead_wake(&vault);
    let key = phase_key(instance, CommitmentWakePhase::Lead);
    assert_eq!(attempt.status.attempt.run_id.as_deref(), Some(key.as_str()));

    let body = vault
        .get_claim(&proposal)
        .expect("claim read")
        .expect("the proposal landed");
    assert_eq!(body.predicate, PREDICATE_COMMITMENT_WAKE_PROPOSAL);
    assert_eq!(body.subject, ClaimSubject::Entity(instance));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.source, Some(ClaimSource::Generated));

    // The pending consent row is what makes the proposal answerable at all.
    let group = vault
        .inbox_groups(crate::inbox::InboxQuery::at(DUE_AT, 16))
        .expect("inbox projection")
        .into_iter()
        .find(|group| group.run_id == key)
        .expect("the proposal is reviewable in its phase-key group");
    assert_eq!(group.group_key, key, "the group key IS the phase key");

    accept_group(&vault, &key, DUE_AT);
    assert_eq!(
        vault
            .get_claim(&proposal)
            .expect("claim read")
            .expect("proposal")
            .approval,
        ClaimApprovalStatus::Approved
    );

    // Producer-side only: nothing was scheduled before approval.
    assert!(
        vault
            .connector_send_tasks()
            .expect("connector tasks")
            .is_empty(),
        "the timer side schedules zero connector TASKs"
    );
}

/// The proposal id is a pure function of the attempt under its own domain
/// separator, and the sentinel perturb is the documented `raw[0]^1,raw[15]^1`
/// rule — it rewrites NO RFC-4122 version or variant bit.
#[test]
fn proposal_claim_id_is_domain_separated_and_sentinel_safe() {
    let attempt = crate::attempt_queue::AttemptId::now();
    let other = crate::attempt_queue::AttemptId::now();
    assert_eq!(
        commitment_wake_proposal_claim_id(attempt),
        commitment_wake_proposal_claim_id(attempt),
        "re-executing one attempt derives one id"
    );
    assert_ne!(
        commitment_wake_proposal_claim_id(attempt),
        commitment_wake_proposal_claim_id(other)
    );

    // Domain separation: the same 16 bytes under the consolidation domain are a
    // different id, so a wake proposal can never collide with a distilled claim.
    let mut bare = blake3::Hasher::new();
    bare.update(attempt.as_bytes());
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&bare.finalize().as_bytes()[..16]);
    assert_ne!(
        commitment_wake_proposal_claim_id(attempt).as_bytes(),
        &raw,
        "the domain separator is load-bearing"
    );

    // The perturb branch, reachable only through a fixture: a real BLAKE3
    // prefix landing on a reserved sentinel is a ~2^-120 event.
    for (sentinel, expected) in [
        ([0x00_u8; 16], {
            let mut want = [0x00_u8; 16];
            want[0] = 0x01;
            want[15] = 0x01;
            want
        }),
        ([0xFF_u8; 16], {
            let mut want = [0xFF_u8; 16];
            want[0] = 0xFE;
            want[15] = 0xFE;
            want
        }),
    ] {
        let perturbed = entity_id_from_digest_prefix(sentinel);
        assert_eq!(perturbed.as_bytes(), &expected);
        assert_eq!(
            perturbed.as_bytes()[6],
            sentinel[6],
            "the RFC-4122 version nibble is untouched"
        );
        assert_eq!(
            perturbed.as_bytes()[8],
            sentinel[8],
            "the RFC-4122 variant bits are untouched"
        );
    }
}

/// Replay after approval is success with NO write. Identical immutables at the
/// deterministic id are the at-least-once contract being honored; rewriting the
/// row would downgrade an answered consent back to `Proposed`.
#[test]
fn replay_after_approval_preserves_approved_status() {
    let (_dir, vault) = open_vault();
    let (instance, attempt, proposal) = propose_lead_wake(&vault);
    let key = phase_key(instance, CommitmentWakePhase::Lead);
    accept_group(&vault, &key, DUE_AT);

    let approved = vault
        .get_claim(&proposal)
        .expect("claim read")
        .expect("proposal");
    assert_eq!(approved.approval, ClaimApprovalStatus::Approved);

    let mut planner = FakePlanner::default();
    let replay = execute_wrapped(
        &vault,
        &attempt,
        Some(&mut planner),
        RecordingInner::default(),
        dreamer_actor(),
    )
    .expect("replay is success, not corruption");
    assert_eq!(
        replay,
        DreamerAttemptExecution::Completed { completed_units: 0 }
    );

    let after = vault
        .get_claim(&proposal)
        .expect("claim read")
        .expect("proposal");
    assert_eq!(
        after.approval,
        ClaimApprovalStatus::Approved,
        "replay never downgrades an approved proposal"
    );
    assert_eq!(after, approved, "replay wrote nothing at all");
}

// ─── 5: the approved token and the outbound adapter ────────────────────────

/// The token binds the PROPOSAL'S AUTHOR, read from the envelope evidence the
/// write path already stamped. Inbox acceptance records no separate approver,
/// so author binding is what stops a cross-actor replay double-send.
#[test]
fn approved_proposal_binds_facade_actor() {
    let (_dir, vault) = open_vault();
    let (instance, _attempt, proposal) = propose_lead_wake(&vault);
    let key = phase_key(instance, CommitmentWakePhase::Lead);

    // Before acceptance the token cannot be minted at all.
    assert!(
        approved_commitment_wake(&vault, &proposal).is_err(),
        "a Proposed row is not an approved wake"
    );
    accept_group(&vault, &key, DUE_AT);

    let token = approved_commitment_wake(&vault, &proposal).expect("approved token");
    assert_eq!(token.bound_actor(), party(DREAMER_AGENT));
    assert_eq!(token.instance_id(), instance);
    assert_eq!(token.phase(), CommitmentWakePhase::Lead);
    assert_eq!(token.idempotency_key(), key);
    assert_eq!(
        token.trigger_ref(),
        format!("commitment:{}", instance.to_hex())
    );

    // A different actor is refused BEFORE any outbound work.
    let stranger = vault.memory(party(OTHER_AGENT), EdgeActorClass::Agent);
    let error = schedule_approved_commitment_wake(&stranger, token)
        .expect_err("cross-actor replay is refused");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_FORBIDDEN);
    assert!(
        vault
            .connector_send_tasks()
            .expect("connector tasks")
            .is_empty(),
        "the refusal lands before any connector, gate, task, or receipt work"
    );
}

/// Schedule-time reconstruction is guard 0: a previously valid token whose
/// commitment has since closed is refused before the actor check and before
/// any outbound call.
#[test]
fn stale_token_rejected_after_commitment_close() {
    let (_dir, vault) = open_vault();
    let (instance, _attempt, proposal) = propose_lead_wake(&vault);
    accept_group(
        &vault,
        &phase_key(instance, CommitmentWakePhase::Lead),
        DUE_AT,
    );
    let token = approved_commitment_wake(&vault, &proposal).expect("approved token");

    let envelope = seed_world(&vault);
    vault
        .fulfill_commitment(&instance, &envelope, DUE_AT)
        .expect("close the commitment");

    let facade = vault.memory(party(DREAMER_AGENT), EdgeActorClass::Agent);
    let error =
        schedule_approved_commitment_wake(&facade, token).expect_err("a stale token is refused");
    assert!(
        error.message.contains("stale"),
        "guard 0 names the staleness: {}",
        error.message
    );
    assert!(
        vault
            .connector_send_tasks()
            .expect("connector tasks")
            .is_empty()
    );
}

/// The approved token supplies every delivery field and the adapter delegates
/// exactly once. `job_ref` stays `None`: `cmt:...` is not a 32-hex attempt id
/// and must never alias the attempt run index.
#[test]
fn approved_proposal_schedules_commitment_outbound_without_job_ref() {
    let (_dir, vault) = open_vault();
    let (instance, _attempt, proposal) = propose_lead_wake(&vault);
    let key = phase_key(instance, CommitmentWakePhase::Lead);
    accept_group(&vault, &key, DUE_AT);
    let token = approved_commitment_wake(&vault, &proposal).expect("approved token");

    let facade = vault.memory(party(DREAMER_AGENT), EdgeActorClass::Agent);
    let receipt =
        schedule_approved_commitment_wake(&facade, token.clone()).expect("the wake schedules");
    assert!(receipt.intent_ref.starts_with("intent:"));

    let task = vault
        .connector_send_tasks()
        .expect("connector tasks")
        .into_iter()
        .find(|task| task.intent.idempotency_key.as_deref() == Some(key.as_str()))
        .expect("the phase key is the outbound idempotency key");
    assert_eq!(task.intent.intent_source, "commitment");
    assert_eq!(
        task.intent.trigger_ref,
        format!("commitment:{}", instance.to_hex())
    );
    assert_eq!(task.intent.job_ref, None);
    assert_eq!(task.intent.verb, CALL_VERB);
    assert_eq!(task.intent.channel, VOICE_CHANNEL);
    assert_eq!(
        task.occurred_at, PROJECT_AT,
        "occurred_at is the fire instant"
    );

    // Same-actor replay coalesces through the existing idempotency path rather
    // than double-sending.
    schedule_approved_commitment_wake(&facade, token).expect("same-actor replay");
    assert_eq!(
        vault
            .connector_send_tasks()
            .expect("connector tasks")
            .into_iter()
            .filter(|task| task.intent.idempotency_key.as_deref() == Some(key.as_str()))
            .count(),
        1,
        "replay coalesces onto the one scheduled TASK"
    );
}

// ─── the suppression window: held, never dropped ───────────────────────────

#[derive(Default)]
struct RecordingSink {
    calls: Vec<String>,
}

impl OutboundExecutionSink for RecordingSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls.push(request.intent_ref.to_owned());
        OutboundExecutionOutcome::delivered_to_channel("provider:cmt3")
    }
}

/// The quiet-hours claim the evaluator reads at the door. Interrupt-class only,
/// 22:00-08:00 local.
fn quiet_hours_claim(subject: EntityId) -> ClaimBody {
    let mut claim = ClaimBody::new(
        crate::delivery_window::PREDICATE_DELIVERY_WINDOW_QUIET,
        ClaimSubject::Entity(subject),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(crate::delivery_window::DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(crate::delivery_window::DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from("window"),
                Value::Map(vec![
                    (Value::from("start_minute"), Value::from(22 * 60)),
                    (Value::from("end_minute"), Value::from(8 * 60)),
                ]),
            ),
            (Value::from("tz"), Value::from("user-local")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    claim
}

fn put_raw_claim(vault: &Vault, id: EntityId, body: &ClaimBody) {
    let data = crate::claim::encode_claim_body(body).expect("encode claim");
    let payload = entity_record(crate::registry::ENTITY_TYPE_CLAIM, at(1), 1, &data);
    vault
        .with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let key = crate::store::Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, &id);
            vault.store.type_index.put(wtxn, &key, &[])?;
            Ok(())
        })
        .expect("seed delivery-window claim");
    if let ClaimSubject::Entity(subject) = body.subject {
        vault
            .put_edge(&id, crate::edge::EdgeKind::ClaimOf, &subject, 1.0)
            .expect("claim-of edge");
    }
}

fn voice_send_manifest(actor_ref: &str) -> Vec<u8> {
    let entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("cmt3-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("agent")),
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (
            Value::from("scoped_grants"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (
                    Value::from("effector"),
                    Value::from(format!("external:{CALL_VERB}")),
                ),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("channel"), Value::from(VOICE_CHANNEL))]),
                ),
            ])]),
        ),
    ];
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

/// A suppression window is a durable HOLD, never a `LetGo`. The clock is
/// injected as the door's local minute-of-day, so the LIVE evaluator — not a
/// re-derived copy of it — decides both dispatches.
///
/// Deliberately asserts no exact `retry_at`: `most_restrictive_delivery_window_decision`
/// currently lets a seeded `Hold { retry_at: None }` outrank the evaluator's
/// `Some(window_end)`, and that defect belongs to SPINE-COMM.
#[test]
fn quiet_window_holds_then_eventually_delivers_after_window() {
    let (_dir, vault) = open_vault();
    let (instance, _attempt, proposal) = propose_lead_wake(&vault);
    let key = phase_key(instance, CommitmentWakePhase::Lead);
    accept_group(&vault, &key, DUE_AT);
    let token = approved_commitment_wake(&vault, &proposal).expect("approved token");

    let agent = party(DREAMER_AGENT);
    let actor = OutboundDispatchActor::agent(agent);
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().expect("default manifest id"),
        &voice_send_manifest(actor.actor_ref.as_deref().expect("actor ref")),
    )
    .expect("seed policy manifest");
    put_raw_claim(&vault, party(0x6C), &quiet_hours_claim(agent));

    let facade = vault.memory(agent, EdgeActorClass::Agent);
    schedule_approved_commitment_wake(&facade, token).expect("the approved wake schedules");
    let scheduled = || {
        vault
            .connector_send_tasks()
            .expect("connector tasks")
            .into_iter()
            .filter(|task| task.intent.idempotency_key.as_deref() == Some(key.as_str()))
            .count()
    };
    assert_eq!(scheduled(), 1);

    let dispatch = |minute: u16, sink: &mut RecordingSink| {
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(agent.to_hex(), CALL_VERB, VOICE_CHANNEL, CALL_TARGET)
                .idempotency_key(key.clone()),
            OutboundIntentTrigger::commitment_timer_wake(format!(
                "commitment:{}",
                instance.to_hex()
            )),
        );
        let request = OutboundDispatchRequest::new(
            format!("outbound:intent:{key}"),
            format!("intent:{key}"),
            intent,
            actor.clone(),
            OutboundDispatchGate::allow_when_policy_grants(),
            u64::from(minute).saturating_mul(60),
            OutboundDeliveryWindowDecision::DeliverNow,
        )
        .delivery_window_local_minute_of_day(minute);
        vault
            .dispatch_outbound_intent(request, sink)
            .expect("dispatch")
    };

    // 23:00 local — inside the quiet window.
    let mut sink = RecordingSink::default();
    let held = dispatch(23 * 60, &mut sink);
    assert_eq!(held.outcome, OutboundDispatchOutcome::Held);
    assert_ne!(
        held.receipt.outcome, "let_go",
        "a suppression window defers; it never drops"
    );
    assert!(sink.calls.is_empty(), "nothing reached the connector");
    assert_eq!(scheduled(), 1, "the durable attempt row remains");

    // 09:00 local — past `window_end`. The same intent now delivers.
    let delivered = dispatch(9 * 60, &mut sink);
    assert_eq!(
        delivered.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(sink.calls.len(), 1, "the deferred send eventually happens");
}
