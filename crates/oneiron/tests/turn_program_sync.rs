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
