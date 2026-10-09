//! cfg(test) fixture and helpers plus native-route and follow-up cursor tests.

use super::*;

use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use crate::comm::{
    CommClaimValue, record_comm_inbound_stop, resolve_or_create_comm_party, run_comm_projector,
};
use crate::config::VaultConfig;
use crate::connector_key::ConnectorKeyRecord;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome, ParkDreamerAttempt,
};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::llm::{DurableStepContext, TrapRef, open_trap, trap_for_durable_wait, trap_park_owner};
use crate::registry::ENTITY_TYPE_TURN;
use crate::task_verb::{TaskAssignee, TaskCreateSpec};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

pub(super) const NOW: u64 = 1_772_600_000;

const HUMAN_ADDRESS: &str = "alice@example.test";

const OWN_ADDRESS: &str = "assistant@example.test";
const ACTOR_ADDRESS: &str = "owner@example.test";
const ACTOR_IDENTITY: u8 = 0x7A;

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

fn add_owner_route(fixture: &HumanFixture) {
    let vault = &fixture.vault;
    let owner = fixture.owner;
    // A contact on an unrelated vault face sorts before the ACTOR's sender.
    // Preflight and the outbound scheduler must both choose the latter.
    vault
        .register_connector_key(
            &crate::test_util::entity(0x78),
            ConnectorKeyRecord::active("email", Some(owner), Vec::new(), NOW),
        )
        .expect("owner connector key");
    let actor_identity = crate::test_util::entity(ACTOR_IDENTITY);
    let identity = ChannelIdentity::requested(
        "email",
        ACTOR_ADDRESS,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::actor(owner),
        NOW,
    )
    .step(
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        NOW,
    )
    .and_then(|pending| pending.step(ChannelIdentityStep::Fulfill, NOW))
    .expect("owner sending face is active");
    vault
        .create_channel_identity(&actor_identity, &identity)
        .expect("owner sending face");
    vault
        .create_counterparty_contact(
            &crate::test_util::entity(0x79),
            &CounterpartyContactRecord::user_introduction(actor_identity, HUMAN_ADDRESS, NOW)
                .expect("owner contact"),
        )
        .expect("owner contact route");
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
        .step_channel_identity(
            &identity_ref,
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            NOW,
        )
        .expect("enter fulfillment");
    vault
        .step_channel_identity(&identity_ref, ChannelIdentityStep::Fulfill, NOW)
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
        effect: crate::code_run::SelfEffect::Ask,
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
        deadline: None,
        now_ms: NOW,
    };
    open_trap(&fixture.vault, &ctx, kind, step_hash, "human response").expect("open test trap")
}

// ── native-human resolution ─────────────────────────────────────────────

fn routed_ask_spec(fixture: &HumanFixture) -> crate::task_verb::TaskAskSpec {
    use crate::task_verb::{
        ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
    };
    let question = crate::test_util::entity(0x7F);
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))
        .expect("encode question");
    fixture
        .vault
        .put_entity(
            &question,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            &body,
        )
        .expect("question turn");
    TaskAskSpec::shorthand(
        Some(TaskAskTarget::People([fixture.person].into())),
        TaskAskQuestion::new(ConsultPayloadRef::Turn(question)),
        Some(u64::MAX),
        TaskAskDefault::Hold,
    )
}

#[test]
fn can_ask_reports_live_face_channel_and_word_without_creating_a_task() {
    let fixture = HumanFixture::open();
    add_owner_route(&fixture);
    let spec = routed_ask_spec(&fixture);
    let before = fixture
        .vault
        .entities_by_type(crate::registry::ENTITY_TYPE_TASK)
        .expect("tasks before");
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Agent);
    let preflight = memory.tasks_can_ask(&spec).expect("preflight");
    let sdk_preflight =
        crate::task_verb::sdk::invoke(&memory, "can", serde_json::json!({"ask": spec}))
            .expect("SDK can(ask)");
    assert_eq!(
        sdk_preflight,
        serde_json::to_value(&preflight).expect("encode preflight")
    );
    let mut deprecated = serde_json::to_value(&spec).expect("ask schema");
    deprecated
        .as_object_mut()
        .expect("spec object")
        .insert("escalation".into(), serde_json::json!(["email"]));
    assert!(crate::task_verb::sdk::invoke(&memory, "tasks.ask", deprecated).is_err());
    assert!(crate::task_verb::sdk::AgentVerb::from_name("ask_human").is_none());
    assert_eq!(preflight.recipients.len(), 1);
    let recipient = &preflight.recipients[0];
    assert_eq!(recipient.who, fixture.person);
    assert_eq!(recipient.face.as_deref(), Some(ACTOR_ADDRESS));
    assert_eq!(recipient.channel.as_deref(), Some("email"));
    assert!(recipient.word_required);
    assert_eq!(
        fixture
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TASK)
            .expect("tasks after"),
        before
    );
    assert!(
        human_followup_records(&fixture.vault)
            .expect("notices")
            .is_empty()
    );
}

#[test]
fn preflight_face_is_the_sender_on_the_scheduled_ask_notice() {
    let fixture = HumanFixture::open();
    add_owner_route(&fixture);
    let mut spec = routed_ask_spec(&fixture);
    spec.remind = Some(vec![1]);
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Agent);
    let route = memory.tasks_can_ask(&spec).expect("preflight");
    let face = route.recipients[0].face.as_deref().expect("sender face");
    assert_eq!(face, ACTOR_ADDRESS);
    let receipt = memory.tasks_ask(&spec).expect("admit ask");
    let task = receipt.task_refs[0];
    let due = fixture.cursor(task).next_due_at.expect("notice deadline");
    let notice = HumanTaskFollowupDriver::new(&fixture.vault)
        .run_due(due, 16)
        .expect("schedule");
    assert_eq!(notice.len(), 1);
    let sender_ref = notice[0].sender_ref.expect("sender on scheduled effect");
    assert_eq!(sender_ref, crate::test_util::entity(ACTOR_IDENTITY));
    let sender = fixture
        .vault
        .get_channel_identity(&sender_ref)
        .expect("sender read")
        .expect("sender identity");
    assert_eq!(sender.address_or_handle(), face);
    assert_ne!(sender_ref, crate::test_util::entity(0x7C));
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
                    .claim_body()
                    .unwrap(),
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

#[test]
fn token_answer_completes_its_member_and_suppresses_due_reminder_while_group_waits() {
    use crate::task_verb::{
        TaskAskOptionId, TaskAskStatus, TaskAskTarget, task_human_assignee, task_is_terminal,
    };
    let fixture = HumanFixture::open();
    add_owner_route(&fixture);
    let other = crate::test_util::entity(0xD6);
    put_person(&fixture.vault, other);
    let mut spec = routed_ask_spec(&fixture);
    spec.intent_key = "linked-member-followup".into();
    spec.who = Some(TaskAskTarget::People([fixture.person, other].into()));
    spec.decide = None;
    spec.what
        .options
        .insert(TaskAskOptionId::new("yes").expect("id"), "Yes".into());
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Agent);
    let receipt = memory.tasks_ask(&spec).expect("two-person ask");
    let task = receipt
        .task_refs
        .into_iter()
        .find(|task_ref| {
            task_human_assignee(&fixture.vault, *task_ref).expect("assignee")
                == Some(fixture.person)
        })
        .expect("routed member");
    let due = fixture.cursor(task).next_due_at.expect("reminder due");
    let link = memory
        .tasks_ask_option_link(receipt.handle, fixture.person)
        .expect("link");
    fixture
        .vault
        .answer_ask_option_link(&link.token, &TaskAskOptionId::new("yes").expect("id"))
        .expect("bearer answer");
    assert!(task_is_terminal(&fixture.vault, task).expect("terminal member"));
    assert!(matches!(
        memory.tasks_ask_status(receipt.handle).expect("aggregate"),
        TaskAskStatus::Pending { .. }
    ));
    let dispatched = HumanTaskFollowupDriver::new(&fixture.vault)
        .run_due(due, 8)
        .expect("due pass");
    assert!(dispatched.iter().all(|entry| entry.task_ref != task));
    assert!(fixture.cursor(task).completed_at.is_some());
    assert_eq!(
        fixture.scheduled_sends(&task_follow_up_dedupe_key(task, "human_reminder:0")),
        0
    );
}
