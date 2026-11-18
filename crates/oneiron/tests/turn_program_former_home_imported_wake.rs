//! A riding turn-program wake the elected home took from the window, once
//! that machine is the home no more (FIX
//! TURNPROGRAM-HOME-CHANGE-CARRIED-COPY-DOUBLE-DECIDE).
//!
//! Machines of one vault, each with its own live window manager. The recorder
//! lands a TURN that owes a program armed there; another machine is the
//! elected home and takes the riding wake from the shared base window, without
//! deciding it yet. Then the home changes: no home is elected, the recorder
//! is, or a third machine is. The former home must not decide the copy it
//! took: the wake is the recorder's, and the machine the election names now
//! decides it. The former home drops the copy on its next pass.
//!
//! A wake the former home recorded itself stays its own, and a machine
//! elected the home again takes the recorder's wake again.
//!
//! The tests count decisions: admission rows, queued or refused. Whether the
//! program then runs is the admission's own judgment and out of scope here,
//! as in `turn_program_sync`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_former_home_imported_wake`.
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
use oneiron::sync::window::forward_rematerialize;
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

    fn owes(&self, turn: EntityId, registration: EntityId) -> bool {
        doors::wake_owed_here(&self.vault, turn, registration).unwrap()
    }

    fn decisions(&self, turn: EntityId, registration: EntityId) -> usize {
        doors::wake_decisions_here(&self.vault, turn, registration).unwrap()
    }
}

/// Each machine elects `home` as the MACRO home.
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
    let challenge = holder_proof_challenge(vault.now_recorded_at(), "turn-program-former-home");
    let signature = holder
        .sign(&slip.binding_transcript(&challenge).unwrap())
        .to_bytes();
    let binding = vault
        .bind_invocation_slip(&slip, &challenge, &signature)
        .unwrap();
    let verified = vault.verify_invocation_slip(&binding).unwrap();
    (agent, verified, binding)
}

/// A row at `id`, learned at [`T0`], so it lands in [`WINDOW`]: a TURN, or
/// the record an arming pins arriving on `machine`.
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

/// Each machine's election finds no candidate: no home is elected.
fn elect_no_home(machines: &[&Machine]) {
    for machine in machines {
        let home = DreamerRunnerStore::new(&machine.vault)
            .elect_home_node(&[], T0)
            .unwrap();
        assert!(
            home.is_none(),
            "fixture: an election over no candidate named a home"
        );
    }
}

const TURN: [u8; 16] = [0x61; 16];
const CONVERSATION: [u8; 16] = [0x62; 16];

/// On `recorder`: a TURN that owes a program its agent armed under its slip.
/// The row the arming pins stands on every machine of `machines`. It is no
/// callable SKILL, so an admission refuses the wake, which decides it all
/// the same. Answers the TURN and the registration.
fn record_wake(recorder: &Machine, machines: &[&Machine]) -> (EntityId, EntityId) {
    let (agent, slip, instrument) = agent_slip(recorder);
    let turn = EntityId::from_bytes(TURN).unwrap();
    put_row(recorder, turn);
    let registration = doors::plant_slip_wake(
        &recorder.vault,
        agent,
        &slip,
        &instrument,
        EntityId::from_bytes(CONVERSATION).unwrap(),
        turn,
        T0 - 60,
        T0,
    )
    .unwrap();
    for machine in machines {
        put_row(machine, registration);
    }
    (turn, registration)
}

/// A wake the recorder carried and the home took, undecided: what the
/// role-change tests start from.
struct Taken {
    turn: EntityId,
    registration: EntityId,
    doc_home: LoroDoc,
    doc_recorder: LoroDoc,
}

/// Every machine of `machines` elects `home`. The recorder lands the TURN,
/// the window opens on the recorder and the home and carries the wake, the
/// recorder's own pass leaves the riding wake to the home, and the home takes
/// it from the window without deciding it: no drain ran there.
fn home_takes_the_carried_wake(machines: &[&Machine], home: &Machine, recorder: &Machine) -> Taken {
    for machine in machines {
        doors::node_id(&machine.vault).unwrap();
    }
    elect(machines, doors::node_id(&home.vault).unwrap());
    let (turn, registration) = record_wake(recorder, machines);
    let doc_recorder = recorder.doc();
    let doc_home = home.doc();
    exchange(&doc_home, &doc_recorder);
    recorder.housekeeping();
    assert!(
        recorder.owes(turn, registration),
        "fixture: the recorder no longer owes the riding wake"
    );
    assert_eq!(
        recorder.decisions(turn, registration),
        0,
        "fixture: a machine that is not the home decided a riding wake"
    );
    forward_rematerialize(
        &home.vault,
        &doc_home,
        &Materializer::new(),
        &WindowKey::new(WINDOW),
    )
    .unwrap();
    assert!(
        home.owes(turn, registration),
        "fixture: the home did not take the carried wake"
    );
    assert_eq!(
        home.decisions(turn, registration),
        0,
        "fixture: the home decided the carried wake before the election changed"
    );
    Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    }
}

/// Case 4: the election names no home any more. The former home drops the
/// copy it took and decides nothing; the recorder decides its wake where it
/// was recorded. One decision, on the recorder.
#[test]
fn a_former_home_decides_no_copy_once_no_home_is_elected() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);

    elect_no_home(&[&home, &recorder]);
    home.housekeeping();
    recorder.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        0,
        "a former home decided the copy of a wake it took from the window, once no home was elected"
    );
    assert!(
        !home.owes(turn, registration),
        "a former home kept the copy of a wake it took from the window, once no home was elected"
    );
    assert_eq!(
        recorder.decisions(turn, registration),
        1,
        "the recorder did not decide its wake once no home was elected"
    );
    assert!(!recorder.owes(turn, registration));

    // The recorder's decision reaches the former home, which keeps it and
    // decides nothing on a later pass.
    exchange(&doc_home, &doc_recorder);
    home.housekeeping();
    assert!(doors::decision_kept_here(&home.vault, turn, registration).unwrap());
    assert_eq!(home.decisions(turn, registration), 0);
    assert!(!home.owes(turn, registration));
}

/// Case 5: the recorder is elected the home. The former home's copy stops
/// riding from it (its TURN is withheld there), which is when it would decide
/// the copy by itself. It decides nothing and drops the copy; the recorder,
/// now the home, decides its own wake. One decision, on the recorder.
#[test]
fn a_former_home_decides_no_copy_once_the_recorder_is_the_home() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);

    elect(
        &[&home, &recorder],
        doors::node_id(&recorder.vault).unwrap(),
    );
    assert!(
        doors::withhold_turn(&home.vault, turn).unwrap(),
        "fixture: the former home did not withhold the TURN"
    );
    home.housekeeping();
    recorder.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        0,
        "a former home decided the copy of a wake it took from the window, after the recorder became the home"
    );
    assert!(
        !home.owes(turn, registration),
        "a former home kept the copy of a wake it took from the window, after the recorder became the home"
    );
    assert_eq!(
        recorder.decisions(turn, registration),
        1,
        "the recorder, elected the home, did not decide its own wake"
    );
    assert!(!recorder.owes(turn, registration));

    exchange(&doc_home, &doc_recorder);
    home.housekeeping();
    assert!(doors::decision_kept_here(&home.vault, turn, registration).unwrap());
    assert_eq!(home.decisions(turn, registration), 0);
}

/// Case 6: a third machine is elected the home and takes the recorder's wake
/// from the window. The former home's copy stops riding from it. It decides
/// nothing and drops the copy; the new home decides the wake, and its
/// decision consumes the recorder's. One decision, on the new home.
#[test]
fn a_former_home_decides_no_copy_once_a_third_machine_is_the_home() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let next = Machine::open("machine-next-home");
    let machines = [&home, &recorder, &next];
    let Taken {
        turn,
        registration,
        doc_home: _,
        doc_recorder,
    } = home_takes_the_carried_wake(&machines, &home, &recorder);

    elect(&machines, doors::node_id(&next.vault).unwrap());
    // The window reaches the new home from the recorder, with the recorder's
    // `Owed` row; the new home takes the wake and decides it.
    let doc_next = next.doc();
    exchange(&doc_next, &doc_recorder);
    next.housekeeping();
    assert_eq!(
        next.decisions(turn, registration),
        1,
        "fixture: the new home did not decide the wake the recorder carried to it"
    );

    assert!(
        doors::withhold_turn(&home.vault, turn).unwrap(),
        "fixture: the former home did not withhold the TURN"
    );
    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        0,
        "a former home decided the copy of a wake it took from the window, after a third machine became the home"
    );
    assert!(
        !home.owes(turn, registration),
        "a former home kept the copy of a wake it took from the window, after a third machine became the home"
    );

    // The new home's decision consumes the recorder's wake.
    exchange(&doc_next, &doc_recorder);
    recorder.housekeeping();
    assert_eq!(recorder.decisions(turn, registration), 0);
    assert!(!recorder.owes(turn, registration));
    assert_eq!(next.decisions(turn, registration), 1);
}

/// A wake the home recorded itself is no copy: once another machine is
/// elected the home, the former home still owes it, carries it to the new
/// home, and the new home's decision consumes it.
#[test]
fn a_former_home_keeps_a_wake_it_recorded_itself() {
    let first = Machine::open("machine-first-home");
    let second = Machine::open("machine-second-home");
    let machines = [&first, &second];
    for machine in machines {
        doors::node_id(&machine.vault).unwrap();
    }
    elect(&machines, doors::node_id(&first.vault).unwrap());
    let (turn, registration) = record_wake(&first, &machines);

    // The window opens after the election: the former home carries its own
    // wake as owed. Its pass keeps the wake and leaves it to the new home.
    elect(&machines, doors::node_id(&second.vault).unwrap());
    let doc_first = first.doc();
    let doc_second = second.doc();
    exchange(&doc_first, &doc_second);
    first.housekeeping();
    assert!(
        first.owes(turn, registration),
        "a former home dropped a wake it recorded itself"
    );
    assert_eq!(first.decisions(turn, registration), 0);

    // The new home takes the wake and decides it.
    second.housekeeping();
    assert_eq!(
        second.decisions(turn, registration),
        1,
        "the new home did not decide the wake the former home recorded"
    );
    exchange(&doc_first, &doc_second);
    first.housekeeping();
    assert_eq!(first.decisions(turn, registration), 0);
    assert!(!first.owes(turn, registration));
}

/// A machine that lost the home role and is elected the home again, before
/// any other machine decided the wake, takes the recorder's wake from the
/// window again and decides it. One decision, on that machine.
#[test]
fn a_machine_elected_the_home_again_takes_the_recorders_wake_again() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let machines = [&home, &recorder];
    let Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&machines, &home, &recorder);

    // The recorder is elected the home and runs no pass; the former home
    // runs one.
    elect(&machines, doors::node_id(&recorder.vault).unwrap());
    home.housekeeping();
    assert_eq!(home.decisions(turn, registration), 0);

    // The first home is elected again, and decides the recorder's wake.
    elect(&machines, doors::node_id(&home.vault).unwrap());
    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "a machine elected the home again did not decide the wake its recorder still carries"
    );
    assert!(!home.owes(turn, registration));

    // Its decision consumes the recorder's wake.
    exchange(&doc_home, &doc_recorder);
    recorder.housekeeping();
    assert_eq!(recorder.decisions(turn, registration), 0);
    assert!(!recorder.owes(turn, registration));
}
