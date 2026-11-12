//! DEC-0006 #undo-send (owner ruling REV-8 = B, 2026-10-09): "undo send is a
//! great idea, yeah. like email has it right. i think it can be off by
//! default and we surface that they can set delay", and "maybe you can also
//! set for all channels at once in the ui or something, only per channel for
//! power users/detailed settings". Engine RULING 02:57 (13 Nov): every send
//! is held, whoever sends it; the owner, or the person who made the send,
//! takes it back; no limit on the length.
//!
//! The owner sets one length for every outbound channel through
//! `vault.consent.undo_send.set`, and a length of its own for a single
//! channel. Off by default, a send goes at once. With a length set, a send
//! waits Scheduled until its window closes, and the owner takes it back
//! through `vault.outbound.undo_send` while the window is open: the attempt
//! is cancelled and its TASK settles `undo_send`. Once the window has closed
//! the undo is refused and the send goes. A person's own send is held too,
//! and that person takes it back; another person neither lists it nor takes
//! it back. The first agent send through a channel carries the one-line
//! hint. The setting and a held send survive a reopen. Only the owner sets
//! the window, and an agent never lists or undoes.
//!
//! Every new door is reached by its verb name, and every other read goes
//! through a public door main already has, so this file builds on a tree
//! without the window and fails there at the first verb call.
//!
//! The sends go out on `discord` and `email_resend`, two channels with a
//! `send` verb that no built-in pack names: a seeded vault refuses a
//! channel a built-in pack names (email, telegram) until that pack is
//! installed and its connection checked (OF-519), which no test can ready.
//! The owner gives the agent the full-access ceiling and each sender a
//! standing `send` grant, so the Gate admits each send to the queue as it
//! admits a granted send in production.
//!
//! `cargo test --locked -p oneiron --all-features --test outbound_undo_send`.

use std::path::Path;
use std::sync::Arc;

use oneiron::agent_def::AgentCeiling;
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, MemoryResult,
};
use oneiron::outbound::BRIDGE_OUTBOUND_ATTEMPT_KIND;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, OutboundDraftInput, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const READ: &str = "vault.consent.undo_send";
const SET: &str = "vault.consent.undo_send.set";
const HELD: &str = "vault.outbound.undo_send.held";
const UNDO: &str = "vault.outbound.undo_send";
/// The owner act's setting name (`PolicySetting::as_str`).
const SETTING: &str = "settings.undo_send";
const NOW: u64 = 1_800_000_000;
const TARGET: &str = "owen@example.com";
/// A channel with a `send` verb that no built-in pack names.
const CHANNEL: &str = "discord";
/// A second such channel, which keeps the all-channel length.
const OTHER_CHANNEL: &str = "email_resend";

/// A device vault this process owns (the writer lease), on `clock`, as an
/// embedded host opens it at each start: the owner's handle carries the
/// owner's proof, and the outbound doors find this install's keys.
fn open_owned(path: &Path, clock: &Arc<ManualClock>) -> (Vault, EntityId) {
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(path, config).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    (vault, owner)
}

/// A PERSON row that acts as `seed`'s actor.
fn put_actor(vault: &Vault, seed: u8) -> EntityId {
    let actor = EntityId::from_bytes([seed; 16]).expect("actor id");
    if vault.get_entity_type(&actor).expect("read actor").is_none() {
        vault
            .put_entity(
                &actor,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                b"undo-send actor",
            )
            .expect("put actor");
    }
    actor
}

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    agent: EntityId,
    // Dropped after the vault.
    dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(NOW);
    let (vault, owner) = open_owned(dir.path(), &clock);
    let agent = put_actor(&vault, 0xC4);
    let fx = Fixture {
        vault,
        clock,
        owner,
        agent,
        dir,
    };
    fx.vault
        .grant_agent_principal(&fx.owner_proof(), &agent.to_hex(), AgentCeiling::Auto)
        .expect("the owner gives the agent the full-access ceiling");
    fx.permit_send(agent, 0xD4);
    fx
}

impl Fixture {
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// The owner's standing grant for `actor`'s sends, under id `seed`.
    fn permit_send(&self, actor: EntityId, seed: u8) {
        self.vault
            .mint_standing_outbound_grant(
                &self.owner_proof(),
                EntityId::from_bytes([seed; 16]).expect("grant id"),
                &GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "create".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: "send".to_owned(),
                    },
                },
            )
            .expect("the owner grants the sends");
    }

    fn call(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        verb: &str,
        input: Value,
    ) -> MemoryResult<Value> {
        invoke(&self.vault.memory(actor, class), verb, input)
    }

    fn owner_call(&self, verb: &str, input: Value) -> MemoryResult<Value> {
        self.call(self.owner, EdgeActorClass::Human, verb, input)
    }

    fn set(&self, setting: Value) -> Value {
        self.owner_call(SET, setting)
            .expect("the owner sets the window")
    }

    fn held(&self) -> Vec<Value> {
        let held = self
            .owner_call(HELD, json!({}))
            .expect("the owner lists held sends");
        held["sends"].as_array().expect("a list of sends").clone()
    }

    /// One send by `actor` as `class` on `channel`; its attempt.
    fn send(&self, actor: EntityId, class: EdgeActorClass, channel: &str, key: &str) -> AttemptId {
        let receipt = self
            .vault
            .memory(actor, class)
            .schedule_outbound(&OutboundDraftInput {
                verb: "send".to_owned(),
                channel: channel.to_owned(),
                target: TARGET.to_owned(),
                on_behalf_of: None,
                content_ref: None,
                idempotency_key: Some(key.to_owned()),
                dedupe_key: None,
                trigger: "agent_immediate".to_owned(),
                trigger_ref: "session:undo-send".to_owned(),
                job_ref: None,
                occurred_at: None,
                mention: None,
            })
            .expect("the send schedules");
        assert_eq!(
            receipt.outcome, "held",
            "the schedule queues the send: {receipt:?}"
        );
        attempt_id(&receipt.intent_ref)
    }

    fn agent_send(&self, channel: &str, key: &str) -> AttemptId {
        self.send(self.agent, EdgeActorClass::Agent, channel, key)
    }

    fn attempt(&self, id: AttemptId) -> AttemptRecord {
        AttemptQueue::new(&self.vault)
            .get(id)
            .expect("read the attempt")
            .expect("the attempt stands")
    }

    /// The outbound attempt a connector worker claims at `now`, if any.
    fn claim(&self, now: u64) -> Option<AttemptId> {
        self.clock.set(now);
        match AttemptQueue::new(&self.vault)
            .claim_kind(
                BRIDGE_OUTBOUND_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "undo-send-test".to_owned(),
                    now,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(record) => Some(record.id),
            _ => None,
        }
    }

    fn setting_acts(&self) -> usize {
        self.vault
            .policy_setting_acts()
            .expect("the owner's setting acts")
            .iter()
            .filter(|receipt| receipt.setting.as_str() == SETTING)
            .count()
    }
}

/// The attempt an `intent:<32 hex>` ref names.
fn attempt_id(intent_ref: &str) -> AttemptId {
    let hex = intent_ref
        .strip_prefix("intent:")
        .expect("an attempt intent ref");
    assert_eq!(hex.len(), 32, "a 32-hex attempt id: {intent_ref}");
    let bytes: Vec<u8> = (0..16)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect();
    AttemptId::from_bytes(&bytes).expect("an attempt id")
}

fn task_ref(value: &Value) -> EntityId {
    EntityId::from_hex(value.as_str().expect("a hex TASK ref")).expect("a TASK ref")
}

/// Off by default: the read answers no length, an agent's send is
/// claimable at once, and its channel records the first agent send.
#[test]
fn undo_send_is_off_by_default_and_an_agent_send_goes_at_once() {
    let fx = fixture();
    let read = fx
        .owner_call(READ, json!({}))
        .expect("the owner reads the window");
    assert_eq!(
        read,
        json!({"all_channels_secs": 0, "channels": [], "first_agent_sends": []}),
        "the window is off by default"
    );

    let send = fx.agent_send(CHANNEL, "off:1");
    let attempt = fx.attempt(send);
    assert_eq!(
        attempt.state,
        AttemptState::Queued,
        "the send waits for nothing"
    );
    assert_eq!(attempt.scheduled_at, None);
    assert!(fx.held().is_empty(), "no send is held");
    assert_eq!(
        fx.claim(NOW),
        Some(send),
        "the worker takes the send at once"
    );

    let read = fx
        .owner_call(READ, json!({}))
        .expect("the owner reads again");
    let first = read["first_agent_sends"].as_array().expect("first sends");
    assert_eq!(first.len(), 1, "the first agent send is recorded: {read}");
    assert_eq!(first[0]["channel"], CHANNEL);
    assert_eq!(first[0]["at"], NOW);
    assert_eq!(
        task_ref(&first[0]["task_ref"]).to_hex(),
        attempt.task_ref.expect("the attempt names its TASK"),
        "the hint names this send"
    );
}

/// With a length set, an agent's send waits out its window; the owner takes
/// it back inside the window, and it never goes.
#[test]
fn a_set_length_holds_an_agent_send_and_undo_cancels_it() {
    let fx = fixture();
    let set = fx.set(json!({"all_channels_secs": 60}));
    assert_eq!(set, json!({"all_channels_secs": 60, "channels": []}));
    assert_eq!(fx.setting_acts(), 1, "the change records the owner's act");
    assert_eq!(
        fx.set(json!({"all_channels_secs": 60, "channels": []})),
        set,
        "the same setting again"
    );
    assert_eq!(
        fx.setting_acts(),
        1,
        "a set that changes nothing records nothing"
    );

    let send = fx.agent_send(CHANNEL, "held:1");
    let attempt = fx.attempt(send);
    assert_eq!(
        attempt.state,
        AttemptState::Scheduled,
        "the send waits in its window"
    );
    assert_eq!(attempt.scheduled_at, Some(NOW + 60));
    assert_eq!(fx.claim(NOW), None, "no worker takes it inside the window");

    let held = fx.held();
    assert_eq!(held.len(), 1, "the owner sees the held send: {held:?}");
    assert_eq!(held[0]["release_at"], NOW + 60);
    assert_eq!(held[0]["channel"], CHANNEL);
    assert_eq!(held[0]["target"], TARGET);
    assert_eq!(held[0]["actor_ref"], fx.agent.to_hex());
    assert_eq!(
        held[0]["first_send_hint"], true,
        "the first agent send carries the hint"
    );
    let task = task_ref(&held[0]["task_ref"]);
    assert_eq!(Some(task.to_hex()), attempt.task_ref);

    fx.clock.set(NOW + 30);
    let undone = fx
        .owner_call(UNDO, json!({"task_ref": task.to_hex()}))
        .expect("the owner takes the send back");
    assert_eq!(
        undone,
        json!({"task_ref": task.to_hex(), "release_at": NOW + 60, "undone_at": NOW + 30})
    );
    assert_eq!(
        fx.attempt(send).state,
        AttemptState::Cancelled,
        "the attempt is cancelled"
    );
    let settled = fx
        .vault
        .connector_send_task(&task)
        .expect("read the TASK")
        .expect("the TASK stands");
    assert_eq!(
        settled.suppression.as_deref(),
        Some("undo_send"),
        "the TASK settles undo_send"
    );
    assert!(fx.held().is_empty(), "nothing is held any more");
    assert_eq!(
        fx.claim(NOW + 61),
        None,
        "no worker takes it after the window either"
    );

    let again = fx
        .owner_call(UNDO, json!({"task_ref": task.to_hex()}))
        .expect_err("a second undo finds nothing held");
    assert_eq!(again.code, MEMORY_CODE_NOT_FOUND);

    let second = fx.agent_send(CHANNEL, "held:2");
    assert_eq!(fx.attempt(second).state, AttemptState::Scheduled);
    let held = fx.held();
    assert_eq!(held.len(), 1);
    assert_eq!(
        held[0]["first_send_hint"], false,
        "only the first send carries the hint"
    );
}

/// Once the window has closed the undo is refused, nothing is written, and
/// the worker takes the send.
#[test]
fn undo_after_the_window_closes_is_refused_and_the_send_goes() {
    let fx = fixture();
    fx.set(json!({"all_channels_secs": 60}));
    let send = fx.agent_send(CHANNEL, "closed:1");
    let task = task_ref(&fx.held()[0]["task_ref"]);

    fx.clock.set(NOW + 61);
    assert!(fx.held().is_empty(), "a closed window is not listed");
    let refused = fx
        .owner_call(UNDO, json!({"task_ref": task.to_hex()}))
        .expect_err("the window has closed");
    assert_eq!(refused.code, MEMORY_CODE_INVALID_STATE, "{refused:?}");
    assert_eq!(
        fx.attempt(send).state,
        AttemptState::Scheduled,
        "the refusal wrote nothing"
    );
    let task_row = fx
        .vault
        .connector_send_task(&task)
        .expect("read the TASK")
        .expect("the TASK stands");
    assert_eq!(task_row.suppression, None, "the TASK still sends");
    assert_eq!(fx.claim(NOW + 61), Some(send), "the worker takes the send");
}

/// A length of one channel's own replaces the all-channel length there.
#[test]
fn a_channel_length_replaces_the_all_channel_length() {
    let fx = fixture();
    let set = fx.set(json!({
        "all_channels_secs": 60,
        "channels": [{"channel": "Discord", "secs": 0}],
    }));
    assert_eq!(
        set,
        json!({"all_channels_secs": 60, "channels": [{"channel": CHANNEL, "secs": 0}]}),
        "the channel is stored in its manifest spelling"
    );
    let own = fx.agent_send(CHANNEL, "channel:own");
    let other = fx.agent_send(OTHER_CHANNEL, "channel:other");
    assert_eq!(
        fx.attempt(own).state,
        AttemptState::Queued,
        "the channel's own length is 0"
    );
    let held = fx.attempt(other);
    assert_eq!(
        held.state,
        AttemptState::Scheduled,
        "another channel takes every channel's length"
    );
    assert_eq!(held.scheduled_at, Some(NOW + 60));
}

/// A person's own send waits out the window too, and that person takes it
/// back; another person neither lists it nor takes it back.
#[test]
fn a_persons_own_send_is_held_and_they_can_undo_it() {
    let fx = fixture();
    fx.set(json!({"all_channels_secs": 60}));
    let human = EdgeActorClass::Human;
    let person = put_actor(&fx.vault, 0xC5);
    let other = put_actor(&fx.vault, 0xC6);
    fx.permit_send(person, 0xD5);
    let send = fx.send(person, human, CHANNEL, "person:1");
    let attempt = fx.attempt(send);
    assert_eq!(
        attempt.state,
        AttemptState::Scheduled,
        "a person's send waits in its window"
    );
    assert_eq!(attempt.scheduled_at, Some(NOW + 60));
    let read = fx.owner_call(READ, json!({})).expect("the owner reads");
    assert_eq!(
        read["first_agent_sends"],
        json!([]),
        "a person's send carries no agent hint"
    );

    let held = fx.held();
    assert_eq!(held.len(), 1, "the owner sees every held send");
    assert_eq!(held[0]["actor_ref"], person.to_hex());
    assert_eq!(held[0]["first_send_hint"], false);
    let task = task_ref(&held[0]["task_ref"]);
    let own = fx
        .call(person, human, HELD, json!({}))
        .expect("the person lists their own sends");
    assert_eq!(own["sends"].as_array().map(Vec::len), Some(1), "{own}");
    let others = fx
        .call(other, human, HELD, json!({}))
        .expect("another person lists their own sends");
    assert_eq!(
        others["sends"],
        json!([]),
        "another person's send is not listed"
    );
    let refused = fx
        .call(other, human, UNDO, json!({"task_ref": task.to_hex()}))
        .expect_err("another person cannot take it back");
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
    assert_eq!(
        fx.attempt(send).state,
        AttemptState::Scheduled,
        "the refusal wrote nothing"
    );

    fx.clock.set(NOW + 5);
    let undone = fx
        .call(person, human, UNDO, json!({"task_ref": task.to_hex()}))
        .expect("the person takes their own send back");
    assert_eq!(undone["undone_at"], NOW + 5);
    assert_eq!(
        fx.attempt(send).state,
        AttemptState::Cancelled,
        "the attempt is cancelled"
    );
    assert_eq!(fx.claim(NOW + 61), None, "it never goes");
}

/// The setting and a held send survive a reopen, and the undo still works.
#[test]
fn the_hold_and_the_setting_survive_a_reopen() {
    let fx = fixture();
    fx.set(json!({"all_channels_secs": 120}));
    let send = fx.agent_send(CHANNEL, "reopen:1");
    let Fixture {
        vault,
        clock,
        owner: _,
        agent,
        dir,
    } = fx;
    drop(vault);

    let (vault, owner) = open_owned(dir.path(), &clock);
    let fx = Fixture {
        vault,
        clock,
        owner,
        agent,
        dir,
    };
    let read = fx
        .owner_call(READ, json!({}))
        .expect("the owner reads after a reopen");
    assert_eq!(
        read["all_channels_secs"], 120,
        "the setting survives a reopen"
    );
    let attempt = fx.attempt(send);
    assert_eq!(
        attempt.state,
        AttemptState::Scheduled,
        "the hold survives a reopen"
    );
    assert_eq!(attempt.scheduled_at, Some(NOW + 120));
    let held = fx.held();
    assert_eq!(held.len(), 1, "the held send is still listed");
    let task = task_ref(&held[0]["task_ref"]);
    fx.clock.set(NOW + 10);
    fx.owner_call(UNDO, json!({"task_ref": task.to_hex()}))
        .expect("the owner takes it back after a reopen");
    assert_eq!(fx.attempt(send).state, AttemptState::Cancelled);
}

/// Only the owner sets or reads the window, and an agent never lists or
/// undoes; a setting that names no channel rightly is refused and writes
/// nothing, and no length is too long.
#[test]
fn only_the_owner_sets_the_window_and_an_agent_never_undoes() {
    let fx = fixture();
    let agent = EdgeActorClass::Agent;
    for (verb, input) in [
        (SET, json!({"all_channels_secs": 60})),
        (READ, json!({})),
        (HELD, json!({})),
        (UNDO, json!({"task_ref": fx.agent.to_hex()})),
    ] {
        let refused = fx
            .call(fx.agent, agent, verb, input)
            .expect_err("an agent is refused");
        assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{verb}: {refused:?}");
    }

    for setting in [
        json!({"all_channels_secs": 0, "channels": [{"channel": "carrier_pigeon", "secs": 5}]}),
        json!({"all_channels_secs": 0, "channels": [{"channel": "esign", "secs": 5}]}),
        json!({"all_channels_secs": 0, "channels": [
            {"channel": "email", "secs": 5}, {"channel": "EMAIL", "secs": 6}
        ]}),
    ] {
        let refused = fx
            .owner_call(SET, setting.clone())
            .expect_err("the setting is out of bounds");
        assert_eq!(
            refused.code, MEMORY_CODE_BAD_REQUEST,
            "{setting}: {refused:?}"
        );
    }
    assert_eq!(fx.setting_acts(), 0, "no refused set records an act");
    let read = fx.owner_call(READ, json!({})).expect("the owner reads");
    assert_eq!(
        read["all_channels_secs"], 0,
        "no refused set changed the window"
    );

    // No length is refused: thirty days stands as the owner set it.
    let long =
        json!({"all_channels_secs": 2_592_000, "channels": [{"channel": "slack", "secs": 86_400}]});
    assert_eq!(fx.set(long.clone()), long, "the owner's length stands");
    assert_eq!(fx.setting_acts(), 1);
}
