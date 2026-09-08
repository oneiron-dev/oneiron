//! cfg(test) fixture and helpers plus native-route and follow-up cursor tests.

use super::*;

use crate::attempt_queue::AttemptQueue;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
};
use crate::comm::{
    CommClaimValue, record_comm_inbound_stop, resolve_or_create_comm_party, run_comm_projector,
};
use crate::config::VaultConfig;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome, ParkDreamerAttempt,
};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::llm::{DurableStepContext, TrapRef, open_trap, trap_for_durable_wait, trap_park_owner};
use crate::registry::ENTITY_TYPE_TURN;
use crate::task_verb::{TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

pub(super) const NOW: u64 = 1_772_600_000;

const HUMAN_ADDRESS: &str = "alice@example.test";

const OWN_ADDRESS: &str = "assistant@example.test";

pub(super) const STEP_HASH: [u8; 32] = [0x71; 32];

pub(super) struct HumanFixture {
    pub(super) _dir: tempfile::TempDir,
    pub(super) vault: Vault,
    /// The first-party connector actor — the one identity the default
    /// policy manifest grants an Auto ceiling, so the create effects.
    /// Pinned (`0xE1`), so it is constructed explicitly rather than through
    /// the band-asserting generic helper.
    pub(super) owner: EntityId,
    pub(super) person: EntityId,
}

impl HumanFixture {
    pub(super) fn open() -> Self {
        Self::open_with_grant(true)
    }

    fn open_with_grant(granted: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let (owner, person) = seed_human_vault(&vault, granted);
        Self {
            _dir: dir,
            vault,
            owner,
            person,
        }
    }

    pub(super) fn create_human_task(&self) -> EntityId {
        self.vault
            .memory(self.owner, EdgeActorClass::Agent)
            .tasks_create(
                &TaskCreateSpec::new(Value::from("ask the person"), None, None, Some(NOW))
                    .with_assignee(TaskAssignee::Human {
                        actor_ref: self.person,
                    }),
            )
            .expect("human create effects")
            .task_ref
            .expect("an effected create mints one TASK")
    }

    fn cursor(&self, task_ref: EntityId) -> HumanTaskFollowupRecord {
        human_followup_record(&self.vault, task_ref)
            .expect("read cursor")
            .expect("a human task always has a cursor")
    }

    fn rewind_to(&self, record: &HumanTaskFollowupRecord, stage: HumanFollowupStage, due: u64) {
        let rewound = HumanTaskFollowupRecord {
            stage,
            next_due_at: Some(due),
            ..record.clone()
        };
        self.vault
            .with_write_txn(|wtxn| put_followup_record_in_txn(&self.vault, wtxn, &rewound))
            .expect("rewind cursor");
    }

    /// Scheduled connector sends carrying one exact idempotency key. This is
    /// the OUTBOUND effect count — what a duplicate wake must not double.
    fn scheduled_sends(&self, key: &str) -> usize {
        self.vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities")
            .into_iter()
            .filter(|task_ref| {
                self.vault
                    .connector_send_task(task_ref)
                    .ok()
                    .flatten()
                    .is_some_and(|send| send.intent.idempotency_key.as_deref() == Some(key))
            })
            .count()
    }
}

/// Seeds one vault with the first-party owner and a person the vault
/// ALREADY knows: a comm party (so the PERSON row carries its address),
/// standing-reachable on a connected channel we hold an active sending
/// identity and a live counterparty contact on.
pub(super) fn seed_human_vault(vault: &Vault, granted: bool) -> (EntityId, EntityId) {
    let owner = EntityId::from_bytes([0xE1; 16]).expect("first-party connector actor id");
    put_person(vault, owner);
    if granted {
        vault
            .mint_standing_outbound_grant(
                &crate::test_util::entity(0x7B),
                &GrantMintIntent {
                    principal_ref: owner.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "human.followup".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: HUMAN_FOLLOWUP_VERB.to_owned(),
                    },
                },
                NOW,
            )
            .expect("mint outbound grant");
    }
    let person = resolve_or_create_comm_party(vault, HUMAN_ADDRESS).expect("comm party");
    let identity_ref = active_email_identity(vault);
    vault
        .create_counterparty_contact(
            &crate::test_util::entity(0x7D),
            &CounterpartyContactRecord::user_introduction(identity_ref, HUMAN_ADDRESS, NOW)
                .expect("contact record"),
        )
        .expect("create counterparty contact");
    (owner, person)
}

pub(super) fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("put actor");
}

fn active_email_identity(vault: &Vault) -> EntityId {
    let identity_ref = crate::test_util::entity(0x7C);
    vault
        .create_channel_identity(
            &identity_ref,
            &ChannelIdentity::requested(
                "email",
                OWN_ADDRESS,
                SelfHeldShape::DedicatedAddress,
                ChannelIdentityBinding::vault(1),
                NOW,
            ),
        )
        .expect("create channel identity");
    vault
        .transition_channel_identity(
            &identity_ref,
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Api),
            NOW,
            None,
        )
        .expect("enter fulfillment");
    vault
        .transition_channel_identity(&identity_ref, ChannelIdentityState::Active, None, NOW, None)
        .expect("activate the identity");
    identity_ref
}

/// Parks one step on a human answer and returns everything the resume path
/// needs. The trap kind comes from the REAL mapping, so a regression in
/// `trap_for_durable_wait` shows up here rather than silently parking a
/// human wait as a consent trap.
pub(super) fn park_on_human(
    fixture: &HumanFixture,
    task_ref: EntityId,
    step_hash: [u8; 32],
) -> (
    crate::attempt_queue::AttemptId,
    TrapRef,
    HumanTaskWaitBinding,
) {
    let runner = DreamerRunnerStore::new(&fixture.vault);
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = runner
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: "human-workflow-step".to_owned(),
            input: Value::from("step"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("human-run".to_owned()),
            now: NOW,
        })
        .expect("enqueue the workflow step");
    let attempt_id = status.attempt.id;
    let ctx = DurableStepContext {
        vault: &fixture.vault,
        attempt_id,
        run_id: Some("human-run".to_owned()),
        envelope_actor: WriteActor::new(fixture.owner, EdgeActorClass::Agent),
        subject: fixture.person,
        pinned_config: None,
        deadline: None,
        now_ms: NOW,
    };
    let kind = trap_for_durable_wait(&human_input_wait(task_ref), step_hash);
    let trap = open_trap(&fixture.vault, &ctx, kind, step_hash, "human response")
        .expect("open the human trap");
    runner
        .park_attempt(ParkDreamerAttempt {
            attempt_id,
            reason: "human response".to_owned(),
            park_owner: trap_park_owner(&trap.trap_claim_id),
            now: NOW,
        })
        .expect("park the suspended step");
    // Binding first, THEN the trap's own wait registration: a crash between
    // the two leaves a locatable binding on a `created` trap, which the
    // signal path still accepts.
    let binding = bind_human_wait(&fixture.vault, task_ref, fixture.person, &trap)
        .expect("bind the human wait");
    crate::llm::register_wait(&fixture.vault, &trap, NOW).expect("register the wait");
    (attempt_id, trap, binding)
}

/// The durable wait a workflow step raises when it asks a PERSON. Built
/// exactly as the C9 dispatcher builds it, so the mapping under test is the
/// production one.
fn human_input_wait(task_ref: EntityId) -> crate::code_run::SelfDurableWait {
    crate::code_run::SelfDurableWait {
        wait_id: task_ref,
        effect: crate::code_run::SelfEffect::AskHuman,
        reason: crate::code_run::SelfDurableWaitReason::HumanInput,
        prompt: None,
    }
}

pub(super) fn response(
    fixture: &HumanFixture,
    task_ref: EntityId,
    seed: u8,
) -> HumanResponseSignal {
    HumanResponseSignal {
        task_ref,
        responder_ref: fixture.person,
        surface_event_ref: crate::test_util::entity(seed),
        occurred_at: NOW + 10,
    }
}

pub(super) fn open_test_trap(
    fixture: &HumanFixture,
    kind: DreamerTrapKind,
    step_hash: [u8; 32],
) -> TrapRef {
    let runner = DreamerRunnerStore::new(&fixture.vault);
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = runner
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: "human-workflow-step".to_owned(),
            input: Value::from("step"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("human-run".to_owned()),
            now: NOW,
        })
        .expect("enqueue the workflow step");
    let ctx = DurableStepContext {
        vault: &fixture.vault,
        attempt_id: status.attempt.id,
        run_id: Some("human-run".to_owned()),
        envelope_actor: WriteActor::new(fixture.owner, EdgeActorClass::Agent),
        subject: fixture.person,
        pinned_config: None,
        deadline: None,
        now_ms: NOW,
    };
    open_trap(&fixture.vault, &ctx, kind, step_hash, "human response").expect("open test trap")
}

// ── native-human resolution ─────────────────────────────────────────────

/// A PERSON with an effective `comm.reachable_via` fact, one of our active
/// channel identities on that channel, and a live contact IS a native
/// route — no pack, no marketplace, no synthesized machine assignee.
#[test]
fn native_route_resolves_a_vault_known_person() {
    let fixture = HumanFixture::open();
    let route = resolve_native_human_route(&fixture.vault, fixture.person)
        .expect("a connected person is natively reachable");

    assert_eq!(route.person_ref, fixture.person);
    assert_eq!(route.channel, "email");
    assert_eq!(route.target, HUMAN_ADDRESS);
    assert_eq!(
        route.channel_identity_ref,
        crate::test_util::entity(0x7C),
        "the route names OUR sending identity, not the recipient"
    );
}

/// Every rejection keeps its own name: a non-person is not "unreachable",
/// and a known-but-unreachable person is not "missing".
#[test]
fn unreachable_and_non_person_assignees_get_distinct_typed_errors() {
    let fixture = HumanFixture::open();
    let stranger = crate::test_util::entity(0x7E);
    put_person(&fixture.vault, stranger);
    let turn_ref = crate::test_util::entity(0x7F);
    fixture
        .vault
        .put_entity(
            &turn_ref,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"turn",
        )
        .expect("put turn");

    assert!(matches!(
        resolve_native_human_route(&fixture.vault, stranger),
        Err(HumanTaskError::NotNativelyReachable)
    ));
    assert!(matches!(
        resolve_native_human_route(&fixture.vault, turn_ref),
        Err(HumanTaskError::NotAPerson)
    ));
}

/// Standing `comm.*` state VETOES a route it can never invent. Both vetoes
/// are exercised on the same connected person: the production STOP path
/// (inbound event -> projector -> `comm.opt_out`), and the explicit
/// `comm.reachable_via: false` fact, which is validated but has no
/// projector rule yet and so is written directly.
///
/// Writing comm standing state trips the gate's criticality floor under a
/// live policy manifest, so these run on the legacy-manifest test vault —
/// the resolver is the subject here, not the create ceiling.
#[test]
fn standing_comm_state_vetoes_an_otherwise_live_route() {
    for veto in ["opt_out", "not_reachable"] {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
        let person = resolve_or_create_comm_party(&vault, HUMAN_ADDRESS).expect("comm party");
        let identity_ref = active_email_identity(&vault);
        vault
            .create_counterparty_contact(
                &crate::test_util::entity(0x7D),
                &CounterpartyContactRecord::user_introduction(identity_ref, HUMAN_ADDRESS, NOW)
                    .expect("contact record"),
            )
            .expect("create counterparty contact");
        assert!(
            resolve_native_human_route(&vault, person).is_ok(),
            "{veto}: the route is live before the veto"
        );

        if veto == "opt_out" {
            record_comm_inbound_stop(&vault, HUMAN_ADDRESS, "email", NOW).expect("record the STOP");
            run_comm_projector(&vault).expect("project the STOP into standing state");
        } else {
            vault
                .put_claim(
                    &EntityId::now(),
                    &CommClaimValue::ReachableVia {
                        party_ref: person,
                        channel_class: "email".to_owned(),
                        reachable: false,
                    }
                    .claim_body(),
                    TimeRange { start: 1, end: 1 },
                    1,
                )
                .expect("record unreachability");
        }

        assert!(
            matches!(
                resolve_native_human_route(&vault, person),
                Err(HumanTaskError::NotNativelyReachable)
            ),
            "{veto}: the veto takes the channel away"
        );
    }
}

// ── follow-up cursor ────────────────────────────────────────────────────

/// A revoked contact is not a route: the relationship that made the person
/// natively reachable is the thing that ended.
#[test]
fn a_revoked_contact_removes_the_route() {
    let fixture = HumanFixture::open();
    assert!(resolve_native_human_route(&fixture.vault, fixture.person).is_ok());

    fixture
        .vault
        .revoke_counterparty_contact(&crate::test_util::entity(0x7D), NOW + 1)
        .expect("revoke the contact");

    assert!(matches!(
        resolve_native_human_route(&fixture.vault, fixture.person),
        Err(HumanTaskError::NotNativelyReachable)
    ));
}

/// The create opens the cursor and nothing else: the person is tracked, and
/// no queue row anywhere carries this task's backlink.
#[test]
fn human_create_opens_a_tracking_cursor_and_no_attempt() {
    let fixture = HumanFixture::open();
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Agent)
        .tasks_create(
            &TaskCreateSpec::new(Value::from("ask the person"), None, None, Some(NOW))
                .with_assignee(TaskAssignee::Human {
                    actor_ref: fixture.person,
                }),
        )
        .expect("human create effects");
    let task_ref = receipt.task_ref.expect("an effected create mints one TASK");
    let cursor = fixture.cursor(task_ref);

    assert!(receipt.effected);
    assert_eq!(
        receipt.route,
        Some(crate::task_verb::TaskRouteOutcome::HumanFollowup {
            actor_ref: fixture.person
        })
    );
    assert_eq!(
        receipt
            .route
            .and_then(crate::task_verb::TaskRouteOutcome::local_attempt),
        None,
        "a person is not a worker"
    );
    assert_eq!(cursor.stage, HumanFollowupStage::Tracking);
    assert_eq!(cursor.assignee_ref, fixture.person);
    assert_eq!(cursor.reminders_sent, 0);
    assert_eq!(
        cursor.next_due_at,
        Some(NOW + REMINDER_AFTER_SECONDS),
        "tracking rests until the first nudge is due"
    );
    assert_eq!(
        AttemptQueue::new(&fixture.vault)
            .list()
            .expect("list")
            .len(),
        0
    );
}

/// A cursor that is not yet due is not work. The driver must not nudge a
/// person the moment their task is created.
#[test]
fn a_cursor_before_its_due_time_dispatches_nothing() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();

    let dispatched = HumanTaskFollowupDriver::new(&fixture.vault)
        .run_due(NOW + 1, 8)
        .expect("run due");

    assert!(dispatched.is_empty());
    assert_eq!(fixture.cursor(task_ref).stage, HumanFollowupStage::Tracking);
}

/// The ladder walks track → remind → digest → escalate, and only the
/// repeatable stage advances its generation.
#[test]
fn followup_walks_the_ladder_and_only_escalation_regenerates() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let driver = HumanTaskFollowupDriver::new(&fixture.vault);
    let mut seen = Vec::new();

    for _ in 0..4 {
        let due = fixture
            .cursor(task_ref)
            .next_due_at
            .expect("an open loop is always due later");
        let dispatched = driver.run_due(due, 8).expect("run due");
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].task_ref, task_ref);
        assert_eq!(dispatched[0].stage, fixture.cursor(task_ref).stage);
        seen.push(dispatched[0].stage_token.clone());
    }

    assert_eq!(
        seen,
        vec![
            "human_reminder:0".to_owned(),
            "human_digest:0".to_owned(),
            "human_escalation:0".to_owned(),
            "human_escalation:1".to_owned(),
        ],
        "the generation rides inside the stage token, and only where \
             repetition is intentional"
    );
    let cursor = fixture.cursor(task_ref);
    assert_eq!(cursor.stage, HumanFollowupStage::EscalationDue);
    assert_eq!(cursor.reminders_sent, 4);
    assert!(cursor.last_receipt_ref.is_some());
}

/// The crash window between "outbound scheduled" and "cursor advanced":
/// the next pass re-drives the SAME `(task_ref, stage)` key, and the shared
/// follow-up namespace collapses it onto one outbound effect.
#[test]
fn a_replayed_stage_collapses_onto_one_outbound_effect() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let driver = HumanTaskFollowupDriver::new(&fixture.vault);
    let due = NOW + REMINDER_AFTER_SECONDS;
    let key = task_follow_up_dedupe_key(task_ref, "human_reminder:0");

    let first = driver.run_due(due, 8).expect("first pass");
    // Exactly the state a crash after the schedule would leave behind.
    fixture.rewind_to(&fixture.cursor(task_ref), HumanFollowupStage::Tracking, due);
    let replay = driver.run_due(due, 8).expect("replayed pass");

    assert_eq!(first.len(), 1);
    assert_eq!(replay.len(), 1);
    assert_eq!(first[0].stage_token, replay[0].stage_token);
    assert_eq!(first[0].intent_ref, replay[0].intent_ref);
    assert_eq!(
        fixture.scheduled_sends(&key),
        1,
        "a replayed stage re-notifies nobody"
    );
}

/// The ONE-1699 expiry stage and the ONE-1708 human stages share one
/// namespace, so two follow-up families can never collide on one task.
#[test]
fn human_stages_share_the_one_follow_up_namespace() {
    let task_ref = crate::test_util::entity(0x6A);
    let reminder = task_follow_up_dedupe_key(task_ref, "human_reminder:0");

    assert!(reminder.starts_with("tasks.followup.v1:"));
    assert_ne!(
        reminder,
        task_follow_up_dedupe_key(
            task_ref,
            crate::task_verb::TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED
        )
    );
    assert_ne!(
        reminder,
        task_follow_up_dedupe_key(task_ref, "human_reminder:1")
    );
}

/// A delivery the pipeline declines to push is an outbound RECEIPT outcome.
/// The cursor has no failure state to move into and must not invent one:
/// it advances exactly as it would on a clean send.
#[test]
fn a_declined_delivery_stays_a_receipt_outcome_and_never_fails_the_cursor() {
    // No standing outbound grant: the gate declines, which is precisely the
    // "held / degraded / suppressed" family ARCH-0046 O3 receipts.
    let fixture = HumanFixture::open_with_grant(false);
    let task_ref = fixture.create_human_task();

    let dispatched = HumanTaskFollowupDriver::new(&fixture.vault)
        .run_due(NOW + REMINDER_AFTER_SECONDS, 8)
        .expect("run due");
    let cursor = fixture.cursor(task_ref);

    assert_eq!(dispatched.len(), 1);
    assert_ne!(
        dispatched[0].outcome, "delivered_to_channel",
        "the pipeline declined this one"
    );
    assert_eq!(cursor.stage, HumanFollowupStage::ReminderDue);
    assert_eq!(cursor.completed_at, None);
    assert_eq!(
        cursor.last_receipt_ref.as_deref(),
        Some(dispatched[0].intent_ref.as_str())
    );
}

/// The authoritative synced fact closes the loop: once the TASK settles,
/// the cursor completes and the nudging stops for good.
#[test]
fn a_settled_task_completes_its_cursor_and_stops_nudging() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let result_ref = crate::test_util::entity(0x6B);
    fixture
        .vault
        .put_entity(
            &result_ref,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"answer",
        )
        .expect("put result");
    fixture
        .vault
        .memory(fixture.person, EdgeActorClass::Agent)
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: NOW + 5,
            },
        )
        .expect("the person's answer settles the task");

    let driver = HumanTaskFollowupDriver::new(&fixture.vault);
    let at = NOW + REMINDER_AFTER_SECONDS;
    let dispatched = driver.run_due(at, 8).expect("run due");
    let cursor = fixture.cursor(task_ref);

    assert!(dispatched.is_empty());
    assert_eq!(cursor.stage, HumanFollowupStage::Completed);
    assert_eq!(cursor.completed_at, Some(at));
    assert_eq!(cursor.next_due_at, None);
    assert!(
        driver
            .run_due(at + ESCALATION_AFTER_SECONDS, 8)
            .expect("later pass")
            .is_empty()
    );
}

/// The cursor is derived scheduler state: losing it costs a re-walk of the
/// synced TASK facts, never a second truth or a registry byte.
#[test]
fn a_lost_cursor_rebuilds_from_the_synced_task_fact() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    fixture
        .vault
        .with_write_txn(|wtxn| {
            fixture
                .vault
                .store
                .vault_meta
                .delete(wtxn, followup_key(task_ref).as_slice())?;
            Ok(())
        })
        .expect("drop the cursor");
    assert!(
        human_followup_record(&fixture.vault, task_ref)
            .expect("read cursor")
            .is_none()
    );

    let rebuilt = HumanTaskFollowupDriver::new(&fixture.vault)
        .rebuild_cursors(NOW + 1)
        .expect("rebuild");

    assert_eq!(rebuilt, 1);
    assert_eq!(fixture.cursor(task_ref).assignee_ref, fixture.person);
    assert_eq!(
        HumanTaskFollowupDriver::new(&fixture.vault)
            .rebuild_cursors(NOW + 2)
            .expect("second rebuild"),
        0,
        "a rebuild never rewinds live nudging state"
    );
}

/// Only human-assigned tasks get a cursor. A dreamer task is realized by a
/// job and has nothing to follow up on — and a rebuild walking every TASK
/// row must not invent one for it.
#[test]
fn non_human_lanes_get_no_cursor() {
    let fixture = HumanFixture::open();
    let human_task = fixture.create_human_task();
    let dreamer_task = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            Value::from("ordinary"),
            None,
            None,
            Some(NOW),
        ))
        .expect("dreamer create")
        .task_ref
        .expect("task ref");

    assert!(
        human_followup_record(&fixture.vault, dreamer_task)
            .expect("read cursor")
            .is_none()
    );
    assert_eq!(
        human_followup_records(&fixture.vault)
            .expect("all cursors")
            .into_iter()
            .map(|record| record.task_ref)
            .collect::<Vec<_>>(),
        vec![human_task]
    );
    assert_eq!(
        HumanTaskFollowupDriver::new(&fixture.vault)
            .rebuild_cursors(NOW + 1)
            .expect("rebuild"),
        0,
        "a rebuild invents no cursor for a realized lane"
    );
}
