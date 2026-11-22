//! DESIGN 15-setting-primitive, stage 5c: a held send's release becomes a row of the schedule's
//! jobs, so a host that stopped its vault is woken for it.
//! - The write that holds a send for its undo-send window arms one row of
//!   `outbound.undo_send_release` about its connector-send TASK, at the release instant, and the
//!   row wakes its host then (`Vault::housekeeping_wake_at`).
//! - Taking the send back disarms the row in the undo's own write.
//! - The attempt queue still releases the send: the pass at the release runs the row, which only
//!   ends, and the connector worker claims the send. The held row stays, so an undo after the
//!   window closed is still refused as closed.
//! - A later hold drops a closed window's held row with its release row.
//!
//! The fixture is `tests/outbound_undo_send.rs`'s: an owned device vault on a manual clock, an
//! agent with the full-access ceiling and a standing `send` grant, sends on `discord`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test undo_send_release_due_jobs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::agent_def::AgentCeiling;
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryResult};
use oneiron::outbound::BRIDGE_OUTBOUND_ATTEMPT_KIND;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::schedule::due_at;
use oneiron::{EdgeActorClass, EntityId, OutboundDraftInput, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const SET: &str = "vault.consent.undo_send.set";
const HELD: &str = "vault.outbound.undo_send.held";
const UNDO: &str = "vault.outbound.undo_send";
/// The job a held send's release arms.
const RELEASE_JOB: &str = "outbound.undo_send_release";
const NOW: u64 = 1_800_000_000;
/// The window every test sets for every channel.
const WINDOW: u64 = 60;
const TARGET: &str = "owen@example.com";
/// A channel with a `send` verb that no built-in pack names.
const CHANNEL: &str = "discord";

/// A device vault this process owns (the writer lease), on `clock`, as an embedded host opens it
/// at each start: the owner's handle carries the owner's proof, and the outbound doors find this
/// install's keys.
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
    _dir: tempfile::TempDir,
}

/// The fixture with every channel's window set to [`WINDOW`] after its first housekeeping pass,
/// and when its vault wakes its host before any send is held.
fn fixture() -> (Fixture, Option<u64>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(NOW);
    let (vault, owner) = open_owned(dir.path(), &clock);
    let agent = put_actor(&vault, 0xC4);
    let fx = Fixture {
        vault,
        clock,
        owner,
        agent,
        _dir: dir,
    };
    fx.vault
        .grant_agent_principal(&fx.owner_proof(), &agent.to_hex(), AgentCeiling::Auto)
        .expect("the owner gives the agent the full-access ceiling");
    fx.permit_send(agent, 0xD4);
    fx.owner_call(SET, json!({"all_channels_secs": WINDOW}))
        .expect("the owner sets the window");
    // The first pass arms the engine's sweeps and does whatever the new vault owes now.
    fx.pass_at(NOW);
    let before = fx.wake_at();
    assert!(
        before.is_none_or(|at| at > NOW + 2 * WINDOW),
        "nothing else wakes the host before the releases these tests hold: {before:?}"
    );
    (fx, before)
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

    fn owner_call(&self, verb: &str, input: Value) -> MemoryResult<Value> {
        invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            verb,
            input,
        )
    }

    /// The TASK refs of the sends the owner may take back, soonest release first.
    fn held(&self) -> Vec<EntityId> {
        let held = self
            .owner_call(HELD, json!({}))
            .expect("the owner lists held sends");
        held["sends"]
            .as_array()
            .expect("a list of sends")
            .iter()
            .map(|send| {
                EntityId::from_hex(send["task_ref"].as_str().expect("a hex TASK ref"))
                    .expect("a TASK ref")
            })
            .collect()
    }

    /// One send by the agent on [`CHANNEL`], held for its window: its attempt and its TASK.
    fn agent_send(&self, key: &str) -> (AttemptId, EntityId) {
        let before = self.held();
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .schedule_outbound(&OutboundDraftInput {
                verb: "send".to_owned(),
                channel: CHANNEL.to_owned(),
                target: TARGET.to_owned(),
                on_behalf_of: None,
                content_ref: None,
                idempotency_key: Some(key.to_owned()),
                dedupe_key: None,
                trigger: "agent_immediate".to_owned(),
                trigger_ref: "session:undo-send-release".to_owned(),
                job_ref: None,
                occurred_at: None,
                mention: None,
            })
            .expect("the send schedules");
        assert_eq!(
            receipt.outcome, "held",
            "the schedule queues the send: {receipt:?}"
        );
        let attempt = attempt_id(&receipt.intent_ref);
        assert_eq!(
            self.attempt(attempt).state,
            AttemptState::Scheduled,
            "the window holds the send"
        );
        let task = self
            .held()
            .into_iter()
            .find(|task| !before.contains(task))
            .expect("the send is listed as held");
        (attempt, task)
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
                    lease_owner: "undo-send-release-test".to_owned(),
                    now,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(record) => Some(record.id),
            _ => None,
        }
    }

    /// When the release row about `task` is next due, or `None` when it is not armed.
    fn release_due(&self, task: EntityId) -> Option<u64> {
        due_at(&self.vault, RELEASE_JOB, Some(task)).expect("schedule")
    }

    fn wake_at(&self) -> Option<u64> {
        self.vault.housekeeping_wake_at().expect("wake")
    }

    /// One housekeeping pass at `now`, as the host's tick runs it.
    fn pass_at(&self, now: u64) {
        self.clock.set(now);
        self.vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("housekeeping");
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

/// The hold arms one release row about the send's TASK at the release instant, and the vault
/// wakes its host then.
#[test]
fn a_held_send_arms_its_release_and_wakes_its_host_then() {
    let (fx, _) = fixture();
    let (_, task) = fx.agent_send("arm:1");

    assert_eq!(
        fx.release_due(task),
        Some(NOW + WINDOW),
        "the hold arms the release row at the release instant"
    );
    assert_eq!(
        fx.wake_at(),
        Some(NOW + WINDOW),
        "a stopped vault wakes its host for the release"
    );
}

/// The undo's own write disarms the release row: nothing wakes the host for a send taken back.
#[test]
fn taking_a_send_back_disarms_its_release() {
    let (fx, before) = fixture();
    let (attempt, task) = fx.agent_send("undo:1");
    assert_eq!(fx.release_due(task), Some(NOW + WINDOW), "the hold arms it");

    fx.clock.set(NOW + 10);
    fx.owner_call(UNDO, json!({"task_ref": task.to_hex()}))
        .expect("the owner takes the send back");

    assert_eq!(
        fx.attempt(attempt).state,
        AttemptState::Cancelled,
        "the undo cancels the attempt"
    );
    assert_eq!(fx.release_due(task), None, "the undo disarms the release");
    assert_eq!(fx.wake_at(), before, "nothing wakes the host for it");
}

/// The pass at the release runs the row and the row goes; the attempt queue still releases the
/// send, and the window's held row stays, so an undo after it is refused as closed.
#[test]
fn the_pass_at_the_release_runs_its_row_and_the_send_still_goes() {
    let (fx, _) = fixture();
    let (attempt, task) = fx.agent_send("release:1");

    fx.pass_at(NOW + WINDOW - 1);
    assert_eq!(
        fx.release_due(task),
        Some(NOW + WINDOW),
        "a pass before the release leaves its row due then"
    );

    fx.pass_at(NOW + WINDOW);
    assert_eq!(
        fx.release_due(task),
        None,
        "the pass at the release runs its row"
    );
    assert_eq!(
        fx.attempt(attempt).state,
        AttemptState::Scheduled,
        "the run sends nothing itself"
    );
    let refused = fx
        .owner_call(UNDO, json!({"task_ref": task.to_hex()}))
        .expect_err("the window has closed");
    assert_eq!(
        refused.code, MEMORY_CODE_INVALID_STATE,
        "an undo after the release is refused as closed, not as unknown: {refused:?}"
    );
    assert_eq!(
        fx.claim(NOW + WINDOW),
        Some(attempt),
        "the worker takes the send"
    );
}

/// A hold after an earlier window closed drops that window's held row with its release row, in
/// its own write, and arms its own.
#[test]
fn a_later_hold_drops_a_closed_window_with_its_release_row() {
    let (fx, _) = fixture();
    let (_, first) = fx.agent_send("closed:1");
    assert_eq!(
        fx.release_due(first),
        Some(NOW + WINDOW),
        "the first hold arms its row"
    );

    fx.clock.set(NOW + WINDOW + 1);
    let (_, second) = fx.agent_send("closed:2");

    assert_eq!(
        fx.release_due(first),
        None,
        "the later hold drops the closed window's release row"
    );
    assert_eq!(
        fx.release_due(second),
        Some(NOW + 2 * WINDOW + 1),
        "the later hold arms its own release row"
    );
}
