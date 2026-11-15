//! PACK-SETTINGS-ALL = B: the human-task follow-up ladder's three intervals are pack Setting keys.
//! - With no row, a person assigned a TASK is first nudged 24 h after the TASK is made, the
//!   digest follows 3 days after the nudge, and each escalation 7 days after the stage before it:
//!   today's ladder.
//! - Once the owner sets `human_task.followup.reminder_after_secs`, `digest_after_secs` and
//!   `escalation_after_secs`, each due time moves to the owner's value.
//!
//! `cargo test --locked -p oneiron --all-features --test pack_keys_human_task`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use oneiron::comm::resolve_or_create_comm_party;
use oneiron::config::VaultConfig;
use oneiron::consent::AuthenticatedOwner;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::human_task::{HumanFollowupStage, HumanTaskFollowupDriver, human_followup_record};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use serde_json::json;

/// The fixture's clock origin for its channel identity and contact.
const T0: u64 = 1_772_400_000;
/// When the TASK is made.
const MADE_AT: u64 = T0 + 60;
/// The seeded first-party actor: the one id the default policy manifest grants an Auto ceiling,
/// so its creates take direct effect.
const CREATOR_BYTES: [u8; 16] = [0xE1; 16];
const PERSON_ADDRESS: &str = "owen@example.com";
const DAY: u64 = 24 * 60 * 60;

/// A vault with no plugin pack, whose first-party actor may send, and a person it reaches
/// through a channel identity it holds and a live contact (as cb_oracle_tasks' human fixture).
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    creator: EntityId,
    person: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open fixture vault");
        let creator = EntityId::from_bytes(CREATOR_BYTES).expect("creator id");
        vault
            .put_entity(
                &creator,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"creator",
            )
            .expect("store the creator");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
        let owner_proof = vault
            .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof");
        // A standing outbound grant is the vault owner's act (FIX 11874).
        vault
            .mint_standing_outbound_grant(
                &owner_proof,
                EntityId::from_bytes([0x7B; 16]).expect("grant id"),
                &GrantMintIntent {
                    principal_ref: creator.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "human.followup".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: "send".to_owned(),
                    },
                },
            )
            .expect("mint outbound grant");

        let person = resolve_or_create_comm_party(&vault, PERSON_ADDRESS).expect("comm party");
        let identity_ref = EntityId::from_bytes([0x7C; 16]).expect("identity id");
        vault
            .create_channel_identity(
                &identity_ref,
                &ChannelIdentity::requested(
                    "email",
                    "assistant@example.com",
                    SelfHeldShape::DedicatedAddress,
                    ChannelIdentityBinding::vault(1),
                    T0,
                ),
            )
            .expect("create channel identity");
        vault
            .step_channel_identity(
                &identity_ref,
                ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
                T0,
            )
            .expect("enter fulfillment");
        vault
            .step_channel_identity(&identity_ref, ChannelIdentityStep::Fulfill, T0)
            .expect("activate the identity");
        vault
            .create_counterparty_contact(
                &EntityId::from_bytes([0x7D; 16]).expect("contact id"),
                &CounterpartyContactRecord::user_introduction(identity_ref, PERSON_ADDRESS, T0)
                    .expect("contact record"),
            )
            .expect("create counterparty contact");

        Self {
            _dir: dir,
            vault,
            creator,
            person,
            owner_proof,
        }
    }

    /// The owner sets one key's vault value.
    fn set(&self, key: &str, secs: u64) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(key, json!(secs)),
            )
            .expect("the owner sets the key");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "{key}: {outcome:?}"
        );
    }

    /// A TASK assigned to the person, made at [`MADE_AT`], naming no notice and no deadline.
    fn human_task(&self) -> EntityId {
        self.vault
            .memory(self.creator, EdgeActorClass::Agent)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from("review the draft"),
                    Some("review the draft".to_owned()),
                    None,
                    Some(MADE_AT),
                )
                .with_assignee(TaskAssignee::Human {
                    actor_ref: self.person,
                }),
            )
            .expect("human create effects")
            .task_ref
            .expect("an effected create mints one TASK")
    }

    /// When the TASK's follow-up cursor is next due.
    fn due_at(&self, task: EntityId) -> u64 {
        human_followup_record(&self.vault, task)
            .expect("read the cursor")
            .expect("the human TASK has a cursor")
            .next_due_at
            .expect("an open cursor is due")
    }

    /// Runs the follow-ups due at `at`, and the stage this TASK's run reached.
    fn run(&self, task: EntityId, at: u64) -> HumanFollowupStage {
        let sent = HumanTaskFollowupDriver::new(&self.vault)
            .run_due(at, 16)
            .expect("run the due follow-ups");
        let stages: Vec<_> = sent
            .iter()
            .filter(|dispatch| dispatch.task_ref == task)
            .map(|dispatch| dispatch.stage)
            .collect();
        assert_eq!(stages.len(), 1, "one stage ran at {at}: {sent:?}");
        stages[0]
    }

    /// The ladder from the TASK's write: the first due time, then for each later run the stage it
    /// reached and the next due time.
    fn walk(&self, task: EntityId) -> (u64, Vec<(HumanFollowupStage, u64)>) {
        let first = self.due_at(task);
        let mut at = first;
        let mut runs = Vec::new();
        for _ in 0..3 {
            let stage = self.run(task, at);
            let next = self.due_at(task);
            runs.push((stage, next));
            at = next;
        }
        (first, runs)
    }
}

#[test]
fn with_no_row_the_ladder_is_24_hours_then_3_days_then_every_7_days() {
    let fixture = Fixture::open();
    let task = fixture.human_task();
    let (first, runs) = fixture.walk(task);
    assert_eq!(first, MADE_AT + DAY);
    let reminder = first;
    let digest = reminder + 3 * DAY;
    let escalation = digest + 7 * DAY;
    assert_eq!(
        runs,
        vec![
            (HumanFollowupStage::ReminderDue, digest),
            (HumanFollowupStage::DigestDue, escalation),
            (HumanFollowupStage::EscalationDue, escalation + 7 * DAY),
        ]
    );
}

#[test]
fn the_owners_values_move_each_follow_up_due_time() {
    let fixture = Fixture::open();
    fixture.set("human_task.followup.reminder_after_secs", 3_600);
    fixture.set("human_task.followup.digest_after_secs", 7_200);
    fixture.set("human_task.followup.escalation_after_secs", 10_800);
    let task = fixture.human_task();
    let (first, runs) = fixture.walk(task);
    assert_eq!(first, MADE_AT + 3_600);
    let digest = first + 7_200;
    let escalation = digest + 10_800;
    assert_eq!(
        runs,
        vec![
            (HumanFollowupStage::ReminderDue, digest),
            (HumanFollowupStage::DigestDue, escalation),
            (HumanFollowupStage::EscalationDue, escalation + 10_800),
        ]
    );
}

#[test]
fn a_zero_interval_is_refused() {
    let fixture = Fixture::open();
    let refused = fixture.vault.set_setting(
        SettingCaller::Owner(&fixture.owner_proof),
        SetSetting::vault_value("human_task.followup.escalation_after_secs", json!(0)),
    );
    assert!(refused.is_err(), "{refused:?}");
}
