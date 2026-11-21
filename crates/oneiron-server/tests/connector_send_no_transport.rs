//! FIX COMMITMENT-NO-TRANSPORT-NOT-STARTED-NO-TEST.
//! Canon: cross/hosting/cross-arch-0022-node-supervisor-vault-lifecycle.md:317:
//! "A send still needs a served channel: one with no transport fails the attempt as not started".
//!
//! `approved_commitment_reminder_without_transport_fails_not_started` proves that a
//! real Lead wake, admitted Micro attempt, generated proposal, owner approval and
//! approved-wake schedule reach the served drain's no-transport branch.
//! `owner_send_without_transport_fails_not_started` proves the same terminal
//! no-wire settlement for an ordinary owner-authorized `gap_queue` send.
//! Both inspect the source bridge attempt, connector-send TASK, durable Outbound
//! receipt and logical intent ledger after exactly one pass of the server's own
//! connector-send drain (`test_doors::connector_sends`). Neither
//! supplies a stub transport failure, starts a worker, or makes a provider call.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util --test connector_send_no_transport`

#![cfg(oneiron_test_support)]
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
};
use oneiron::commitment_schedule::{CommitmentSchedulePayload, Schedule};
use oneiron::commitment_wake::{
    CommitmentWakeDue, CommitmentWakeEvent, CommitmentWakeExecutor, CommitmentWakeFireOutcome,
    CommitmentWakePhase, CommitmentWakeProposalDraft, CommitmentWakeProposalPlanner,
    commitment_wake_proposal_claim_id, fire_due_commitment_wake,
    schedule_approved_commitment_wakes_with_wordings,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::dreamer_wake::{
    DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext, WakePassDeadline,
};
use oneiron::memory::{
    BRIDGE_OUTBOUND_ATTEMPT_KIND, ClaimProposalReviewRequest, ClaimSettleDecision,
    ClaimSettleRequest, OutboundDraftInput, OutboundIntentReceipt,
};
use oneiron::outbound::ConnectorSendTaskOutcome;
use oneiron::outbound_intent_ledger::{RecordedOutboundOutcome, intent_ledger_records};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyGrantMapEntry, PolicyGrantValue, PolicyManifestPut,
    PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::connector_sends::connector_send_pass;
use rmpv::Value;

const LEAD_SECONDS: u64 = 100;
const CHANNEL: &str = "voice";
const VERB: &str = "call";
const TARGET: &str = "+15551234567";
const BUDGET_ID: &str = "commitment-send-no-transport";

struct Fixture {
    // Drop the server and the owned vault (with its writer lease) before the
    // vault's directory.
    server: SyncServer,
    vault: Arc<Vault>,
    owner: EntityId,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("an isolated vault directory is available");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device())
            .expect("the fixture holds the process-owned vault writer lease");
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let _issuer = oneiron::test_support::provision_engine_machines(&vault);
        let (owner, proof) = oneiron::test_doors::label_writers::embedded_owner(&vault)
            .expect("the fixture has its real embedded owner and live owner proof");
        let vault = Arc::new(vault);
        // A server over this vault, built only: no listener binds and no
        // worker starts (no async runtime runs here), so the drain pass a
        // test runs is the only one. It holds no transport for voice.
        let server = SyncServer::new(Arc::clone(&vault), SyncServerConfig::default())
            .expect("a plain server builds over the fixture vault");
        Self {
            server,
            vault,
            owner,
            proof,
            _dir: dir,
        }
    }

    fn grant_voice_call(&self, actor: WriteActor) {
        let view = policy_manifests_as_owner(
            &self.vault,
            &self.proof,
            &PolicyManifestRead { manifest_ref: None },
        )
        .expect("the owner can read the shipped policy before granting this send");
        let default = view
            .manifests
            .iter()
            .find(|entry| entry.manifest_ref == view.default_manifest_ref)
            .expect("the shipped default manifest is present");
        let mut manifest = default.manifest.clone();
        manifest.actor_ceilings.push(ActorCeiling {
            actor_class: match actor.actor_class() {
                EdgeActorClass::Human => "human",
                EdgeActorClass::System => "system",
                _ => panic!("the fixture grants only its owner or its System Dreamer"),
            }
            .into(),
            actor_ref: Some(actor.entity_ref().to_hex()),
            ceiling: PolicyCeiling::Auto,
        });
        let mut grants = manifest.scoped_grants.clone().unwrap_or_default();
        grants.push(PolicyScopedGrantRow {
            actor_class: None,
            actor_ref: Some(actor.entity_ref().to_hex()),
            effector: "external:call".into(),
            scope: oneiron::test_support::effect_preset(),
            selectors: Some(PolicyGrantValue::Map(vec![PolicyGrantMapEntry {
                key: PolicyGrantValue::String("channel".into()),
                value: PolicyGrantValue::String(CHANNEL.into()),
            }])),
            budget: None,
            receipt_required: false,
        });
        manifest.scoped_grants = Some(grants);
        put_policy_manifest_as_owner(
            &self.vault,
            &self.proof,
            PolicyManifestPut {
                manifest_ref: Some(default.manifest_ref.clone()),
                expected_body_hash: Some(default.body_hash.clone()),
                manifest,
            },
        )
        .expect("the owner grants this actor a voice call without installing a transport");
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the host clock is after the Unix epoch")
        .as_secs()
}

fn project_once_instance(fixture: &Fixture, now: u64) -> EntityId {
    let beneficiary = EntityId::now();
    fixture
        .vault
        .put_entity(
            &beneficiary,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"reminder beneficiary",
        )
        .expect("the commitment beneficiary is a live PERSON");
    let envelope = WriteEnvelope::new(
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("owner commitment no-transport fixture"))
            .expect("the owner's series has explicit provenance"),
        ClaimApprovalStatus::Auto,
    );
    let due_at = now + LEAD_SECONDS;
    let payload =
        CommitmentSchedulePayload::series(Schedule::Once { due: due_at }, Some(LEAD_SECONDS))
            .encode()
            .expect("the Once series uses the typed schedule codec");
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, fixture.owner),
        beneficiary,
        CommitmentContent::new("send the signed lease", None)
            .expect("the commitment has nonempty content"),
        payload,
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(
            CommitmentBirthKind::RunTreeNode,
            "run:commitment-send-no-transport-fixture",
        )
        .expect("the series records its birth provenance"),
    )
    .expect("the owner owes a typed open commitment");
    fixture
        .vault
        .put_commitment_series(
            &EntityId::now(),
            &record,
            &envelope,
            TimeRange {
                start: now,
                end: due_at + 10_000,
            },
            now,
        )
        .expect("the owner series and its projection index commit together");
    let report = fixture
        .vault
        .reconcile_commitment_schedule(now)
        .expect("the due projector materializes the Once occurrence at its Lead");
    assert_eq!(
        report.minted_instances.len(),
        1,
        "the Once series mints one real instance"
    );
    report.minted_instances[0]
}

struct VoicePlanner;

impl CommitmentWakeProposalPlanner for VoicePlanner {
    fn plan(
        &mut self,
        _event: &CommitmentWakeEvent,
        _commitment: &CommitmentRecord,
    ) -> oneiron::Result<CommitmentWakeProposalDraft> {
        Ok(CommitmentWakeProposalDraft {
            verb: VERB.into(),
            channel: CHANNEL.into(),
            target: TARGET.into(),
            on_behalf_of: None,
            content_ref: None,
            dedupe_key: None,
        })
    }
}

struct NoOrdinaryWork;

impl DreamerAttemptExecutor for NoOrdinaryWork {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        panic!("a tagged commitment wake must use the real proposal wrapper, not ordinary work")
    }
}

// The vault is isolated: identify the bridge row by its TASK, never by the
// separate Dreamer lease. Keep this source id across the drain pass.
fn admitted_send(vault: &Vault, receipt: &OutboundIntentReceipt) -> (AttemptId, EntityId) {
    assert_eq!(
        receipt.outcome, "held",
        "schedule-only admission holds the real send for the drain"
    );
    assert_eq!(
        receipt.gate_outcome.as_deref(),
        Some("allow"),
        "owner policy must allow the send, not park it for consent before transport"
    );
    let tasks = vault
        .connector_send_tasks()
        .expect("read the admitted connector-send TASK");
    assert_eq!(
        tasks.len(),
        1,
        "the isolated fixture schedules exactly one connector-send TASK"
    );
    let task = &tasks[0];
    assert_eq!(
        task.intent.channel, CHANNEL,
        "the send uses the admitted unsupported channel"
    );
    assert_eq!(
        task.intent.verb, VERB,
        "the send uses the registered call verb"
    );
    assert_eq!(
        task.intent.target, TARGET,
        "the planner's target survives scheduling"
    );
    let task_hex = task.task_ref.to_hex();
    let rows = AttemptQueue::new(vault)
        .list()
        .expect("read queue admission");
    let sources: Vec<_> = rows
        .iter()
        .filter(|row| {
            row.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND
                && row.task_ref.as_deref() == Some(task_hex.as_str())
        })
        .collect();
    assert_eq!(
        sources.len(),
        1,
        "the admitted TASK has one source bridge attempt"
    );
    let source = sources[0];
    assert_eq!(
        source.state,
        AttemptState::Queued,
        "the fresh send is ready, not leased or parked"
    );
    let ready_at = source.scheduled_at.or(source.backoff_until).unwrap_or(0);
    assert!(
        ready_at <= now_seconds(),
        "the source send is ready at the server's real clock"
    );
    assert!(
        ready_at <= vault.now_recorded_at(),
        "the source send is ready at the vault's live clock"
    );
    (source.id, task.task_ref)
}

fn assert_failed_not_started(vault: &Vault, source_id: AttemptId, task_ref: EntityId) {
    let queue = AttemptQueue::new(vault);
    let source = queue
        .get(source_id)
        .expect("read the source bridge attempt")
        .expect("the source attempt remains readable after settlement");
    let task_hex = task_ref.to_hex();
    assert_eq!(
        source.kind, BRIDGE_OUTBOUND_ATTEMPT_KIND,
        "the failed source is the outbound bridge attempt, not the Dreamer attempt"
    );
    assert_eq!(
        source.task_ref.as_deref(),
        Some(task_hex.as_str()),
        "the failed source belongs to the scheduled connector-send TASK"
    );
    assert_eq!(
        source.state,
        AttemptState::Failed,
        "a channel with no transport fails the attempt as not started"
    );
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the settled connector-send TASK")
        .expect("the connector-send TASK survives its failed attempt");
    assert_eq!(
        task.outcome,
        Some(ConnectorSendTaskOutcome::Failed),
        "a terminal no-transport voice attempt projects Failed onto its TASK"
    );

    let receipts = vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Outbound))
        .expect("read the durable Outbound receipt family");
    let matching: Vec<_> = receipts
        .iter()
        .filter(|receipt| {
            receipt.fields.get("task_ref").map(String::as_str) == Some(task_hex.as_str())
                && receipt.fields.get("retry_state").map(String::as_str)
                    == Some("no_served_transport_for_channel")
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "one real served pass records one no-transport receipt for this TASK"
    );
    let receipt = matching[0];
    assert_eq!(
        receipt.receipt_kind,
        ReceiptKind::Outbound,
        "the no-wire evidence is an Outbound receipt"
    );
    assert_eq!(
        receipt.outcome, "failed",
        "the durable receipt records failure, not delivery"
    );
    assert_eq!(
        receipt.fields.get("task_ref").map(String::as_str),
        Some(task_hex.as_str()),
        "the durable no-transport receipt names this TASK"
    );
    assert_eq!(
        receipt.fields.get("retry_state").map(String::as_str),
        Some("no_served_transport_for_channel"),
        "the real served sink, not a gate refusal or supplied stub, reports missing transport"
    );
    assert_eq!(
        receipt
            .fields
            .get("delivery_may_have_occurred")
            .map(String::as_str),
        Some("false"),
        "a send whose transport never started cannot have delivered"
    );
    assert_eq!(
        receipt
            .fields
            .get("transport_dispatched")
            .map(String::as_str),
        Some("false"),
        "a channel with no transport fails before transport dispatch"
    );

    // The ledger uses a logical-send attempt identity, not source_id. With
    // one send and no other effects in this fresh vault, its sole voice/call
    // record is this TASK's logical send; do not compare those two ids.
    let ledger = intent_ledger_records(vault).expect("read the logical intent ledger");
    assert!(
        ledger.corrupt.is_empty(),
        "no corrupt ledger row may hide the no-wire result"
    );
    assert_eq!(
        ledger.records.len(),
        1,
        "the isolated vault has one logical send ledger row"
    );
    let record = &ledger.records[0];
    assert_eq!(
        record.server, CHANNEL,
        "the logical send ledger belongs to voice"
    );
    assert_eq!(record.tool, VERB, "the logical send ledger belongs to call");
    assert_eq!(
        record.recorded_outcome,
        Some(RecordedOutboundOutcome::DefiniteNonDelivery),
        "a transport that never started records definite non-delivery"
    );
    assert!(
        !record.delivery_uncertain,
        "no earlier possible delivery exists in this fresh send"
    );
    assert!(
        !record.idempotency_supported,
        "voice/call's emulated idempotency is not provider replay safety"
    );
    let rows = queue
        .list()
        .expect("read the queue after the single served pass");
    assert!(
        !rows
            .iter()
            .any(|row| { row.state == AttemptState::Scheduled && row.retry_of == Some(source_id) }),
        "a no-transport voice attempt does not mint an automatic Scheduled retry"
    );
}

#[test]
fn approved_commitment_reminder_without_transport_fails_not_started() {
    let fixture = Fixture::new();
    let vault: &Vault = &fixture.vault;
    let now = now_seconds();
    let instance = project_once_instance(&fixture, now);
    let entry = vault
        .next_actionable_wake_phase()
        .expect("read the instance's Lead")
        .expect("projection creates an actionable Lead phase");
    assert!(
        entry.at <= now,
        "the Lead is due at the current-time-relative fixture instant"
    );
    let due = CommitmentWakeDue::from_due_entry(&entry)
        .expect("decode the typed due phase")
        .expect("the next actionable row is a Lead or Due");
    assert_eq!(
        due.phase,
        CommitmentWakePhase::Lead,
        "fire only the instance's Lead, not its Due"
    );
    assert_eq!(
        due.instance_id, instance,
        "the Lead belongs to the projected real instance"
    );
    let phase_key = due.idempotency_key();
    let wake_id = match fire_due_commitment_wake(vault, due, now)
        .expect("fire one Lead through the real atomic enqueue door")
    {
        CommitmentWakeFireOutcome::Enqueued { attempt_id } => attempt_id,
        other => panic!("a fresh live owner commitment must enqueue its Lead: {other:?}"),
    };
    let admitted = match DreamerRunnerStore::new(vault)
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
        .expect("admit the genuine tagged Micro attempt")
    {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            attempt,
        )) => *attempt,
        other => panic!("the fired Lead must be admitted as Micro work: {other:?}"),
    };
    assert_eq!(
        admitted.status.attempt.id, wake_id,
        "execute exactly the fired Lead's attempt"
    );
    assert_eq!(
        admitted.status.attempt.run_id.as_deref(),
        Some(phase_key.as_str()),
        "the real wake's run id is its deterministic phase key"
    );
    let dreamer = vault
        .dreamer_authority()
        .expect("resolve the provisioned System Dreamer");
    let mut planner = VoicePlanner;
    let mut executor = CommitmentWakeExecutor::new(NoOrdinaryWork, Some(&mut planner), dreamer)
        .expect("the real System Dreamer can author the wake proposal");
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the async executor has a Tokio runtime");
        let deadline = WakePassDeadline::new(180_000);
        let mut ctx = WakeAttemptContext {
            vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: BUDGET_ID,
            now_ms: now * 1_000,
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        };
        runtime
            .block_on(executor.execute(&admitted, &mut ctx))
            .expect("the public executor writes a genuine generated reminder proposal");
    }
    let proposal_id = commitment_wake_proposal_claim_id(wake_id);
    let proposed = vault
        .get_claim(&proposal_id)
        .expect("read the real reminder proposal")
        .expect("the tagged executor wrote its deterministic proposal claim");
    assert_eq!(
        proposed.approval,
        ClaimApprovalStatus::Proposed,
        "the reminder requires owner approval"
    );
    assert_eq!(
        proposed.lifecycle,
        ClaimLifecycleStatus::Active,
        "the reminder proposal is active"
    );
    assert_eq!(
        proposed.source,
        Some(ClaimSource::Generated),
        "approval must not erase generated origin"
    );

    let owner_memory = vault.memory(fixture.owner, EdgeActorClass::Human);
    let review = owner_memory
        .claim_review_as_owner(
            &fixture.proof,
            &ClaimProposalReviewRequest {
                claim_ref: proposal_id.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the exact generated reminder claim");
    owner_memory
        .claim_settle_as_owner(
            &fixture.proof,
            &ClaimSettleRequest {
                claim_ref: proposal_id.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            },
        )
        .expect("the owner's reviewed approval settles the reminder proposal");
    let approved = vault
        .get_claim(&proposal_id)
        .expect("read the approved reminder")
        .expect("the approved reminder remains stored");
    assert_eq!(
        approved.approval,
        ClaimApprovalStatus::Approved,
        "the owner actually approved the reminder"
    );
    assert_eq!(
        approved.source,
        Some(ClaimSource::Generated),
        "settlement preserves the reminder's origin"
    );
    fixture.grant_voice_call(dreamer);

    let mut scheduled =
        schedule_approved_commitment_wakes_with_wordings(vault, &[proposal_id], &BTreeMap::new());
    assert_eq!(
        scheduled.len(),
        1,
        "approval schedules one checked commitment reminder, not an empty result"
    );
    let (scheduled_claim, result) = scheduled.pop().expect("the one scheduling result exists");
    assert_eq!(
        scheduled_claim, proposal_id,
        "the scheduler processes the approved proposal"
    );
    let receipt = result.expect("the approved commitment reminder is successfully scheduled");
    let (source_id, task_ref) = admitted_send(vault, &receipt);
    assert_ne!(
        source_id, wake_id,
        "the outbound source is distinct from the Dreamer attempt"
    );
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the approved reminder's TASK")
        .expect("the scheduler committed its connector-send TASK");
    assert_eq!(
        task.actor_ref,
        dreamer.entity_ref(),
        "the scheduler preserves the proposal's Dreamer author"
    );
    assert_eq!(
        task.intent.intent_source, "commitment",
        "the TASK is a real commitment reminder"
    );
    assert_eq!(
        task.intent.trigger_ref,
        format!("commitment:{}", instance.to_hex()),
        "the TASK points to the real projected instance"
    );
    assert_eq!(
        task.intent.idempotency_key.as_deref(),
        Some(phase_key.as_str()),
        "the TASK carries the approved Lead's phase key"
    );
    assert_eq!(task.intent.job_ref, None, "a phase key is not a job id");

    // Plain #[test], after the scoped runtime was dropped: the pass builds
    // and drops its blocking reqwest clients outside any async runtime.
    connector_send_pass(&fixture.server)
        .expect("one real served drain pass reaches the unsupported voice transport");
    assert_failed_not_started(vault, source_id, task_ref);
}

#[test]
fn owner_send_without_transport_fails_not_started() {
    let fixture = Fixture::new();
    let vault: &Vault = &fixture.vault;
    fixture.grant_voice_call(WriteActor::new(fixture.owner, EdgeActorClass::Human));
    let receipt = vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .schedule_outbound(&OutboundDraftInput {
            verb: VERB.into(),
            channel: CHANNEL.into(),
            target: TARGET.into(),
            on_behalf_of: None,
            content_ref: None,
            idempotency_key: Some("ordinary-no-transport-proof".into()),
            dedupe_key: None,
            trigger: "gap_queue".into(),
            trigger_ref: "ordinary-no-transport-proof".into(),
            job_ref: None,
            occurred_at: Some(now_seconds()),
            mention: None,
        })
        .expect("the owner's ordinary voice call passes schedule admission");
    let (source_id, task_ref) = admitted_send(vault, &receipt);
    connector_send_pass(&fixture.server)
        .expect("one real served drain pass reaches the owner's unsupported voice transport");
    assert_failed_not_started(vault, source_id, task_ref);
}
