//! A carried terminal wake row names no trigger: an `Admitted` row holds ids
//! alone, so admission cannot judge whether its wake is a turn's. The merge
//! refuses one that names an occurrence's wake, which is admitted where it
//! was recorded, and no decision of an occurrence rides a window.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turnprogram_carried_terminal_row_names_no_trigger`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::{ExportMode, LoroDoc};
use oneiron::authority::holder_proof_challenge;
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::federation::ScopeAxis;
use oneiron::store::housekeeping_schedule::HousekeepingBudget;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
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

#[test]
fn a_carried_decision_never_consumes_an_occurrence_wake() {
    let a = Machine::open("machine-a");
    let b = Machine::open("machine-b");
    doors::node_id(&a.vault).unwrap();
    let home = doors::node_id(&b.vault).unwrap();

    // B arms a one-shot timer and releases its due time: the occurrence's
    // wake is owed here, sealed with the slip authority it armed with.
    let (actor, slip, instrument) = agent_slip(&b);
    let registration =
        doors::plant_timer_arming(&b.vault, actor, &slip, &instrument, T0 - 60, T0).unwrap();
    assert_eq!(b.vault.release_timer_program_wakes(T0).unwrap(), 1);
    let (occurrence, map_key, row) =
        doors::admitted_row_bytes(&b.vault, actor, registration).unwrap();
    assert!(doors::wake_owed_here(&b.vault, occurrence, registration).unwrap());

    // B is elected home, and a linked machine carries a decision for the
    // occurrence's key: ids alone, as a home's decision mirror writes them.
    elect(&[&a, &b], home);
    let doc_a = a.doc();
    let doc_b = b.doc();
    doc_a
        .get_map("turn_program_wakes")
        .insert(&map_key, loro::LoroValue::Binary(row.into()))
        .unwrap();
    doc_a.commit();
    exchange(&doc_a, &doc_b);
    b.housekeeping();

    // The carried decision names an occurrence's wake: it is refused, keeps
    // no decision, and the occurrence is admitted where it was recorded.
    assert!(
        !doors::decision_kept_here(&b.vault, occurrence, registration).unwrap(),
        "a carried decision was kept for an occurrence's wake"
    );
    assert_eq!(
        doors::wake_decisions_here(&b.vault, occurrence, registration).unwrap(),
        1,
        "the occurrence was never admitted where it was recorded"
    );
    assert!(!doors::wake_owed_here(&b.vault, occurrence, registration).unwrap());
}

#[test]
fn an_occurrence_decision_rides_no_window() {
    let machine = Machine::open("machine");
    let (actor, slip, instrument) = agent_slip(&machine);
    let registration = doors::plant_timer_arming(
        &machine.vault,
        actor,
        &slip,
        &instrument,
        T0 - 60,
        T0,
    )
    .unwrap();
    assert_eq!(machine.vault.release_timer_program_wakes(T0).unwrap(), 1);
    let (occurrence, _, _) =
        doors::admitted_row_bytes(&machine.vault, actor, registration).unwrap();

    // The occurrence is admitted where it was recorded, under its sealed
    // slip authority, which verifies on any machine.
    let drained = machine.vault.wake_turn_programs(T0).unwrap();
    assert_eq!(
        drained.admitted + drained.refused,
        1,
        "the occurrence was never admitted where it was recorded"
    );
    assert_eq!(
        doors::decided_rows_for_turn(&machine.vault, occurrence).unwrap(),
        0,
        "an occurrence's decision rides the window"
    );
}
