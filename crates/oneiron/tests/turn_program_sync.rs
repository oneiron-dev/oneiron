//! Turn programs between a vault's machines (FIX 5266; untangle 6.9a, the
//! #6229 rebuild).
//!
//! Two machines of one vault, each with its own live window manager, as a
//! host runs them. Machine B records the wake a TURN owes a program armed
//! there under a capability slip; machine A is the elected home. The arming
//! and the riding wake reach A through the shared base window, and A's
//! housekeeping admits the wake: no Dreamer pass runs. B never decides it,
//! and learns A's decision through the same window.
//!
//! Whether the program then runs (its SKILL, its turn's conversation) is the
//! admission's own judgment and out of scope here: a queued and a refused
//! admission both decide the wake.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_sync`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::{ExportMode, LoroDoc};
use oneiron::authority::holder_proof_challenge;
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::housekeeping_schedule::HousekeepingBudget;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::turn_programs as doors;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};

/// The base window every row here lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;

fn config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// One machine: its vault and its live window manager.
struct Machine {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    _dir: tempfile::TempDir,
}

impl Machine {
    fn open(user: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), config()).unwrap());
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            user,
        ));
        Self {
            vault,
            manager,
            _dir: dir,
        }
    }

    fn doc(&self) -> LoroDoc {
        self.manager
            .open_window(&WindowKey::new(WINDOW))
            .unwrap()
            .doc
            .clone()
    }

    fn housekeeping(&self) {
        self.vault
            .housekeeping(HousekeepingBudget::unbounded())
            .unwrap();
    }
}

/// Both machines elect `home` as the MACRO home.
fn elect(machines: &[&Machine], home: u64) {
    for machine in machines {
        DreamerRunnerStore::new(&machine.vault)
            .elect_home_node(&[DreamerHomeNodeCandidate::always_on_local(home)], T0)
            .unwrap();
    }
}

/// Exchanges the window both ways until the two docs hold the same ops.
fn exchange(a: &LoroDoc, b: &LoroDoc) {
    for _ in 0..5 {
        if a.oplog_vv() == b.oplog_vv() {
            return;
        }
        let to_b = a.export(ExportMode::updates(&b.oplog_vv())).unwrap();
        let to_a = b.export(ExportMode::updates(&a.oplog_vv())).unwrap();
        b.import(&to_b).unwrap();
        a.import(&to_a).unwrap();
    }
    assert_eq!(a.oplog_vv(), b.oplog_vv(), "the window did not converge");
}

/// On `machine`: an agent principal, a read/write capability slip bound to
/// its own holder key, and the slip's instrument, verified as a host binds
/// a request's.
fn agent_slip(
    machine: &Machine,
) -> (
    EntityId,
    oneiron::authority::VerifiedSlip,
    oneiron::authority::InvocationSlipBinding,
) {
    let vault = &machine.vault;
    let issuer = test_host_issuer();
    let agent = vault.ensure_agent_principal("turn-program-agent").unwrap();
    let holder = SigningKey::from_bytes(&[7; 32]);
    let mut claims = vault.ensure_host_root_slip(&issuer).unwrap().claims;
    claims.slip_id = [0x5a; 32];
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.binding_key = holder.verifying_key().to_bytes();
    claims.actor_class = Some("agent".into());
    claims.scope.verbs = ScopeAxis::Some(["read".into(), "write".into()].into());
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let challenge = holder_proof_challenge(vault.now_recorded_at(), "turn-program-sync");
    let signature = holder
        .sign(&slip.binding_transcript(&challenge).unwrap())
        .to_bytes();
    let binding = vault
        .bind_invocation_slip(&slip, &challenge, &signature)
        .unwrap();
    let verified = vault.verify_invocation_slip(&binding).unwrap();
    (agent, verified, binding)
}

/// A TURN learned at [`T0`], so it lands in [`WINDOW`].
fn put_turn(machine: &Machine) -> EntityId {
    let turn = EntityId::from_bytes([0x61; 16]).unwrap();
    let body =
        rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")])).unwrap();
    machine
        .vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: T0, end: T0 },
            T0,
            &body,
        )
        .unwrap();
    turn
}

/// A row at `id`, learned at [`T0`]: the record an arming pins arriving on
/// `machine`.
fn put_row(machine: &Machine, id: EntityId) {
    let body =
        rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")])).unwrap();
    machine
        .vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: T0, end: T0 },
            T0,
            &body,
        )
        .unwrap();
}

#[test]
fn the_home_admits_a_wake_another_machine_recorded_with_no_dreamer_pass() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    let home = doors::node_id(&a.vault).unwrap();
    doors::node_id(&b.vault).unwrap();
    elect(&[&a, &b], home);

    // B: a TURN lands and owes the program B's agent armed under its slip.
    let (agent, slip, instrument) = agent_slip(&b);
    let turn = put_turn(&b);
    let conversation = EntityId::from_bytes([0x62; 16]).unwrap();
    let registration = doors::plant_slip_wake(
        &b.vault,
        agent,
        &slip,
        &instrument,
        conversation,
        turn,
        T0 - 60,
        T0,
    )
    .unwrap();
    assert!(doors::wake_owed_here(&b.vault, turn, registration).unwrap());

    // The window opens on both machines and carries the rows across.
    let doc_b = b.doc();
    let doc_a = a.doc();
    exchange(&doc_a, &doc_b);

    // B is not the home: its own pass leaves the riding wake to the home.
    b.housekeeping();
    assert_eq!(
        doors::wake_decisions_here(&b.vault, turn, registration).unwrap(),
        0,
        "a machine that is not the home decided a riding wake"
    );

    // A, the home, holds the carried wake while the SKILL its arming pins
    // has not arrived: a record not here yet is no moved pin, and the wake
    // waits in the window rather than being refused for good.
    a.housekeeping();
    assert_eq!(
        doors::wake_decisions_here(&a.vault, turn, registration).unwrap(),
        0,
        "the home decided a wake before the SKILL its arming pins arrived"
    );

    // The pinned SKILL's row arrives. It is no callable SKILL, so the
    // admission refuses the wake, which decides it all the same.
    put_row(&a, registration);

    // A, the home, decides the carried wake on its own housekeeping pass.
    a.housekeeping();
    assert_eq!(
        doors::wake_decisions_here(&a.vault, turn, registration).unwrap(),
        1,
        "the home did not decide the wake another machine carried to it"
    );
    assert!(!doors::wake_owed_here(&a.vault, turn, registration).unwrap());

    // A's decision rides back: B no longer owes the wake and never decides it.
    exchange(&doc_a, &doc_b);
    b.housekeeping();
    assert!(
        !doors::wake_owed_here(&b.vault, turn, registration).unwrap(),
        "the machine that recorded the wake still owes it after the home decided it"
    );
    assert_eq!(
        doors::wake_decisions_here(&b.vault, turn, registration).unwrap(),
        0
    );

    // A second pass on the home decides nothing new: one decision.
    a.housekeeping();
    assert_eq!(
        doors::wake_decisions_here(&a.vault, turn, registration).unwrap(),
        1
    );
}

#[test]
fn a_held_wake_rides_to_the_home_elected_after_it_was_held() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    let home_a = doors::node_id(&a.vault).unwrap();
    let home_b = doors::node_id(&b.vault).unwrap();
    elect(&[&a, &b], home_a);

    // A, the home, records its own turn's wake, and holds it on its lapsed
    // slip, as its own admission holds one: owed until its rebind or its
    // expiry, a week after the turn landed. As the home, A carries no `Owed`
    // row for it.
    let (agent, slip, instrument) = agent_slip(&a);
    let turn = put_turn(&a);
    let conversation = EntityId::from_bytes([0x62; 16]).unwrap();
    let now = a.vault.now_recorded_at();
    let registration = doors::plant_slip_wake(
        &a.vault,
        agent,
        &slip,
        &instrument,
        conversation,
        turn,
        now - 60,
        now,
    )
    .unwrap();
    assert!(doors::hold_wake_on_lapsed_slip(&a.vault, turn, registration, now).unwrap());
    put_row(&a, registration);

    // B is elected home, and the window opens on both machines.
    elect(&[&a, &b], home_b);
    put_row(&b, registration);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    b.housekeeping();

    // The held wake rode to B with its hold: B owes it, and decides nothing
    // before its rebind or its expiry.
    assert!(
        doors::wake_owed_here(&b.vault, turn, registration).unwrap(),
        "the wake A held never reached the home elected after it"
    );
    assert_eq!(
        doors::wake_decisions_here(&b.vault, turn, registration).unwrap(),
        0
    );
}

#[test]
fn a_wake_whose_turn_stays_on_its_machine_is_admitted_there() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    let home = doors::node_id(&a.vault).unwrap();
    doors::node_id(&b.vault).unwrap();
    elect(&[&a, &b], home);
    let (actor, slip, instrument) = agent_slip(&b);
    let turn = put_turn(&b);
    assert!(doors::withhold_turn(&b.vault, turn).unwrap());
    let conversation = EntityId::from_bytes([0x62; 16]).unwrap();
    let registration = doors::plant_slip_wake(
        &b.vault,
        actor,
        &slip,
        &instrument,
        conversation,
        turn,
        T0 - 60,
        T0,
    )
    .unwrap();
    put_row(&b, registration);
    let doc_b = b.doc();
    let doc_a = a.doc();
    assert!(doc_b.get_map("entities").get(&turn.to_hex()).is_none());
    exchange(&doc_a, &doc_b);
    b.housekeeping();
    a.housekeeping();
    assert_eq!(
        doors::wake_decisions_here(&b.vault, turn, registration).unwrap(),
        1
    );
    assert!(!doors::wake_owed_here(&b.vault, turn, registration).unwrap());
    assert_eq!(
        doors::wake_decisions_here(&a.vault, turn, registration).unwrap(),
        0
    );
    assert!(!doors::wake_owed_here(&a.vault, turn, registration).unwrap());
    let wake_key = format!("{}{}", turn.to_hex(), registration.to_hex());
    for doc in [&doc_a, &doc_b] {
        assert!(doc.get_map("turn_program_wakes").get(&wake_key).is_none());
    }
}

/// A synthetic pin shared byte-for-byte by separate armings.
fn definition(skill: EntityId) -> oneiron::dreamer_runner::ProgramRecipePin {
    oneiron::dreamer_runner::ProgramRecipePin {
        skill,
        version: "1".into(),
        content_hash: "0".repeat(64),
        entry: "main".into(),
        contract_digest: [0; 32],
        executor: "test".into(),
        args: "{}".into(),
    }
}

#[test]
fn a_disarm_stands_against_an_arming_stamped_later() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    let (actor, _, _) = agent_slip(&a);
    let conversation = EntityId::from_bytes([0x62; 16]).unwrap();
    let skill = a.vault.new_entity_id().unwrap();
    let armed_at = a.vault.now_recorded_at() + 120;
    let registration =
        doors::plant_arming(&a.vault, actor, conversation, &definition(skill), armed_at).unwrap();
    let window = WindowKey::from_timestamp(armed_at);
    let doc_a = a.manager.open_window(&window).unwrap().doc.clone();
    let doc_b = b.manager.open_window(&window).unwrap().doc.clone();
    exchange(&doc_a, &doc_b);
    assert!(doors::program_armed_here(&b.vault, actor, registration).unwrap());

    let disarmed_at = doors::disarm_program(&b.vault, actor, registration)
        .unwrap()
        .unwrap();
    assert!(disarmed_at < armed_at, "the fixture lost its clock skew");
    exchange(&doc_a, &doc_b);
    // Near a month boundary the disarm and arming can have different windows.
    let disarm_window = WindowKey::from_timestamp(disarmed_at);
    let disarm_a = a.manager.open_window(&disarm_window).unwrap().doc.clone();
    let disarm_b = b.manager.open_window(&disarm_window).unwrap().doc.clone();
    exchange(&disarm_a, &disarm_b);
    a.housekeeping();
    b.housekeeping();

    // Unload persists the doc; the cold open merges its carried intents again.
    drop(doc_b);
    drop(disarm_b);
    assert!(b.manager.unload_window(&window).unwrap());
    b.manager.open_window(&window).unwrap();
    assert!(!doors::program_armed_here(&a.vault, actor, registration).unwrap());
    assert!(!doors::program_armed_here(&b.vault, actor, registration).unwrap());
}

#[test]
fn one_definition_armed_on_two_machines_wakes_once_for_a_turn() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    let home = doors::node_id(&a.vault).unwrap();
    doors::node_id(&b.vault).unwrap();
    elect(&[&a, &b], home);
    let (actor, slip, instrument) = agent_slip(&a);
    let conversation = EntityId::from_bytes([0x62; 16]).unwrap();
    let skill = a.vault.new_entity_id().unwrap();
    let pin = definition(skill);
    let registration_a = doors::plant_arming(&a.vault, actor, conversation, &pin, T0 - 60).unwrap();
    let registration_b = doors::plant_arming(&b.vault, actor, conversation, &pin, T0 - 60).unwrap();
    assert_ne!(registration_a, registration_b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    for machine in [&a, &b] {
        for registration in [registration_a, registration_b] {
            assert!(doors::program_armed_here(&machine.vault, actor, registration).unwrap());
        }
    }

    let turn = put_turn(&a);
    let landed = oneiron::dreamer_runner::LandedTurnRef {
        turn,
        conversation,
        landed_at: T0,
    };
    doors::record_slip_turn_wakes(&a.vault, actor, &slip, &instrument, landed).unwrap();
    let registrations = [registration_a, registration_b];
    let count = registrations
        .iter()
        .filter(|&&registration| {
            doors::wake_owed_here(&a.vault, turn, registration).unwrap()
                || doors::wake_decisions_here(&a.vault, turn, registration).unwrap() > 0
        })
        .count();
    assert_eq!(count, 1);
    let chosen = registration_a.min(registration_b);
    assert!(doors::wake_owed_here(&a.vault, turn, chosen).unwrap());
    // An append finds the group's existing wake, whichever registration owns it.
    assert_eq!(
        doors::record_slip_turn_wakes(&a.vault, actor, &slip, &instrument, landed).unwrap(),
        0
    );
    a.housekeeping();
    let decisions: usize = registrations
        .iter()
        .map(|&registration| doors::wake_decisions_here(&a.vault, turn, registration).unwrap())
        .sum();
    assert_eq!(decisions, 1);
    assert_eq!(
        doors::record_slip_turn_wakes(&a.vault, actor, &slip, &instrument, landed).unwrap(),
        0
    );
}

#[test]
fn a_wake_rides_with_an_arming_of_an_older_month() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    let home = doors::node_id(&a.vault).unwrap();
    doors::node_id(&b.vault).unwrap();
    elect(&[&a, &b], home);

    // B: a TURN lands and owes the program B's agent armed under its slip.
    let (agent, slip, instrument) = agent_slip(&b);
    let turn = put_turn(&b);
    let conversation = EntityId::from_bytes([0x62; 16]).unwrap();
    let registration = doors::plant_slip_wake(
        &b.vault,
        agent,
        &slip,
        &instrument,
        conversation,
        turn,
        T0 - 100 * 86_400,
        T0,
    )
    .unwrap();
    assert!(doors::wake_owed_here(&b.vault, turn, registration).unwrap());
    assert_ne!(
        WindowKey::from_timestamp(T0 - 100 * 86_400),
        WindowKey::new(WINDOW)
    );

    // The window opens on both machines and carries the rows across.
    let doc_b = b.doc();
    let doc_a = a.doc();
    exchange(&doc_a, &doc_b);

    // B is not the home: its own pass leaves the riding wake to the home.
    b.housekeeping();
    assert_eq!(
        doors::wake_decisions_here(&b.vault, turn, registration).unwrap(),
        0,
        "a machine that is not the home decided a riding wake"
    );

    // The pinned row is present before A's first pass: only the arming
    // could keep the carried wake waiting. It is no callable SKILL, so a
    // refusal decides the wake all the same.
    put_row(&a, registration);
    a.housekeeping();
    assert!(doors::program_armed_here(&a.vault, agent, registration).unwrap());
    assert_eq!(
        doors::wake_decisions_here(&a.vault, turn, registration).unwrap(),
        1,
        "the home did not decide the wake another machine carried to it"
    );
    assert!(!doors::wake_owed_here(&a.vault, turn, registration).unwrap());

    // A's decision rides back: B no longer owes the wake and never decides it.
    exchange(&doc_a, &doc_b);
    b.housekeeping();
    assert!(
        !doors::wake_owed_here(&b.vault, turn, registration).unwrap(),
        "the machine that recorded the wake still owes it after the home decided it"
    );
    assert_eq!(
        doors::wake_decisions_here(&b.vault, turn, registration).unwrap(),
        0
    );

    // A second pass on the home decides nothing new: one decision.
    a.housekeeping();
    assert_eq!(
        doors::wake_decisions_here(&a.vault, turn, registration).unwrap(),
        1
    );
}

#[test]
fn a_timer_arming_stays_on_the_machine_that_armed_it() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    doors::node_id(&a.vault).unwrap();
    let home = doors::node_id(&b.vault).unwrap();
    elect(&[&a, &b], home);
    let (actor, slip, instrument) = agent_slip(&a);
    let registration =
        doors::plant_timer_arming(&a.vault, actor, &slip, &instrument, T0 - 60, T0).unwrap();

    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.housekeeping();
    b.housekeeping();
    assert!(doors::program_armed_here(&a.vault, actor, registration).unwrap());
    assert!(!doors::program_armed_here(&b.vault, actor, registration).unwrap());

    // A due time is released on the elected home alone, here B, and B holds
    // no arming: this timer fires nowhere, as on main. Which machine should
    // release it is an open design question, so no occurrence is asserted.
    doors::disarm_program(&a.vault, actor, registration).unwrap();
    exchange(&doc_a, &doc_b);
    // The disarm's recording clock can put it in a different month.
    let disarm_window = WindowKey::from_timestamp(a.vault.now_recorded_at());
    let disarm_a = a.manager.open_window(&disarm_window).unwrap().doc.clone();
    let disarm_b = b.manager.open_window(&disarm_window).unwrap().doc.clone();
    exchange(&disarm_a, &disarm_b);
    a.housekeeping();
    b.housekeeping();
    assert!(!doors::disarm_kept_here(&a.vault, actor, registration).unwrap());
    assert!(!doors::disarm_kept_here(&b.vault, actor, registration).unwrap());
}

#[test]
fn a_carried_arming_that_no_turn_wakes_is_refused() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    doors::node_id(&a.vault).unwrap();
    let home = doors::node_id(&b.vault).unwrap();
    elect(&[&a, &b], home);
    let (actor, slip, instrument) = agent_slip(&a);
    let registration =
        doors::plant_timer_arming(&a.vault, actor, &slip, &instrument, T0 - 60, T0).unwrap();
    let bytes = doors::arming_row_bytes(&a.vault, actor, registration).unwrap();
    let doc_a = a.doc();
    let doc_b = b.doc();
    // B reads an injected row, not one selected by A's outbound filter.
    doc_a
        .get_map("turn_program_arms")
        .insert(
            &registration.to_hex(),
            loro::LoroValue::Binary(bytes.into()),
        )
        .unwrap();
    doc_a.commit();
    exchange(&doc_a, &doc_b);
    b.housekeeping();
    assert!(!doors::program_armed_here(&b.vault, actor, registration).unwrap());
}
