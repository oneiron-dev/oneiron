//! A carried turn-program decision row names its wake's actor (FIX
//! TURNPROGRAM-ERASE-KEEPS-DECIDED, the first of two changes; ruled by the
//! lead, 21 Nov 2026).
//!
//! The `Admitted` row a machine writes for a wake it decided, or for a
//! decision it imported, held ids alone: the turn, the registration and the
//! admission. It named no actor, so an erase of that actor could find neither
//! the row nor the marker a machine keeps of it. The row now names the actor
//! where its writer knows it, and each machine keeps the actor beside the
//! decision, so a machine that only imported a decision writes it again with
//! the actor. Nothing reads the actor yet: the erase, the import's refusal
//! and the scrub come with the second change.
//!
//! The kept actor goes with its actor's erase, so no row names an erased
//! actor; the decision itself stays until the second change.
//!
//! A machine names on a decision row only the actor its own rows hold for
//! that decision: its admission's, or the one it kept beside a decision it
//! imported. The actor a carried `Retracted` row asserts is no proof of it,
//! and an actor erased on the machine is named by no row it writes.
//!
//! A row written before the row named its actor names none, and is taken as
//! it was then: it merges, it is kept, and a machine that holds no wake of it
//! writes it again without an actor. A machine that still owes the wake such
//! a row decides learns the actor from the wake itself, whose admission is a
//! digest over that actor.
//!
//! Machines of one vault, each with its own live window manager, as in
//! `turn_program_former_home_imported_wake`. The tests read the rows a window
//! carries; whether the program then runs is out of scope here.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_decision_row_names_actor`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::authority::holder_proof_challenge;
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::housekeeping_schedule::HousekeepingBudget;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{forward_rematerialize, reverse_rematerialize};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::turn_programs as doors;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};

/// The base window every row here lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;
/// The window root map that carries the wake rows.
const WAKES: &str = "turn_program_wakes";

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
    let challenge =
        holder_proof_challenge(vault.now_recorded_at(), "turn-program-decision-row-actor");
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

const TURN: [u8; 16] = [0x61; 16];
const CONVERSATION: [u8; 16] = [0x62; 16];

/// On `recorder`: a TURN that owes a program its agent armed under its slip.
/// The row the arming pins stands on every machine of `machines`, so a home
/// can take the wake. The TURN has no conversation here, so an admission
/// refuses the wake, which decides it all the same. Answers the wake's actor,
/// the TURN and the registration.
fn record_wake(recorder: &Machine, machines: &[&Machine]) -> (EntityId, EntityId, EntityId) {
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
    (agent, turn, registration)
}

/// A wake the recorder carried and the home took, undecided: what every
/// test here starts from.
struct Taken {
    agent: EntityId,
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
    let (agent, turn, registration) = record_wake(recorder, machines);
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
        agent,
        turn,
        registration,
        doc_home,
        doc_recorder,
    }
}

/// The map key a wake row rides under: its turn, then its registration.
fn wake_key(turn: EntityId, registration: EntityId) -> String {
    format!("{}{}", turn.to_hex(), registration.to_hex())
}

/// The wake row `doc` carries for the wake, read as JSON.
fn wake_row(doc: &LoroDoc, turn: EntityId, registration: EntityId) -> Option<serde_json::Value> {
    match doc.get_map(WAKES).get(&wake_key(turn, registration)) {
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
            Some(serde_json::from_slice(&bytes.to_vec()).unwrap())
        }
        _ => None,
    }
}

/// The row `machine` writes for the wake into its window `doc` once the
/// window holds none: the row leaves the map, and the machine's own state is
/// mirrored into the window again, as each open of the window does.
fn row_written_again(
    machine: &Machine,
    doc: &LoroDoc,
    turn: EntityId,
    registration: EntityId,
) -> Option<serde_json::Value> {
    doc.get_map(WAKES)
        .delete(&wake_key(turn, registration))
        .unwrap();
    doc.commit();
    assert!(
        wake_row(doc, turn, registration).is_none(),
        "fixture: the row did not leave the window"
    );
    reverse_rematerialize(&machine.vault, doc, &WindowKey::new(WINDOW)).unwrap();
    doc.commit();
    wake_row(doc, turn, registration)
}

/// The actor as a row names it.
fn named(actor: EntityId) -> serde_json::Value {
    serde_json::to_value(actor).unwrap()
}

/// The agent's PERSON row on `machine`, where the agent never acted: an
/// erase marks an actor hard-deleted only where its row is stored. The id is
/// derived from the name, so it is the agent `agent_slip` made.
fn store_agent_row(machine: &Machine, agent: EntityId) {
    assert_eq!(
        machine
            .vault
            .ensure_agent_principal("turn-program-agent")
            .unwrap(),
        agent,
        "fixture: the agent's row took another id on this machine"
    );
}

/// The bytes of the row `doc` carries for the wake.
fn wake_row_bytes(doc: &LoroDoc, turn: EntityId, registration: EntityId) -> Option<Vec<u8>> {
    match doc.get_map(WAKES).get(&wake_key(turn, registration)) {
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// A `Retracted` row for the wake the decision row `decision` decides, with
/// that decision's turn, registration and admission, naming `actor`.
fn retracted_row(decision: &serde_json::Value, actor: EntityId) -> Vec<u8> {
    let admitted = &decision["admitted"];
    format!(
        r#"{{"retracted":{{"turn":{},"registration":{},"actor":{},"admission":{}}}}}"#,
        admitted["turn"],
        admitted["registration"],
        named(actor),
        admitted["admission"]
    )
    .into_bytes()
}

/// Puts the carried row `row` over the row `machine`'s window `doc` holds for
/// the wake, as a peer's write of an earlier row that won the key does, and
/// runs one pass of the machine: the pass answers each carried row with the
/// latest row the machine knows for its key. Answers the row the window then
/// carries.
fn answer_to_carried_row(
    machine: &Machine,
    doc: &LoroDoc,
    turn: EntityId,
    registration: EntityId,
    row: &[u8],
) -> Option<serde_json::Value> {
    doc.get_map(WAKES)
        .insert(
            &wake_key(turn, registration),
            LoroValue::Binary(row.to_vec().into()),
        )
        .unwrap();
    doc.commit();
    machine.housekeeping();
    wake_row(doc, turn, registration)
}

/// The decision row for the wake `recorder` owes, as a build wrote it before
/// the row named its actor: the turn, the registration and the admission, in
/// that order, and no more. Answers its map key and its bytes.
fn decision_row_without_actor(
    recorder: &Machine,
    agent: EntityId,
    registration: EntityId,
) -> (String, Vec<u8>) {
    let (_, map_key, bytes) =
        doors::admitted_row_bytes(&recorder.vault, agent, registration).unwrap();
    let row: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let admitted = &row["admitted"];
    let old = format!(
        r#"{{"admitted":{{"turn":{},"registration":{},"admission":{}}}}}"#,
        admitted["turn"], admitted["registration"], admitted["admission"]
    );
    (map_key, old.into_bytes())
}

/// Puts `row` into `machine`'s window `doc` under `map_key` and merges the
/// window's rows into the machine, as an open of the window does.
fn merge_carried_row(machine: &Machine, doc: &LoroDoc, map_key: &str, row: &[u8]) {
    doc.get_map(WAKES)
        .insert(map_key, LoroValue::Binary(row.to_vec().into()))
        .unwrap();
    doc.commit();
    forward_rematerialize(
        &machine.vault,
        doc,
        &Materializer::new(),
        &WindowKey::new(WINDOW),
    )
    .unwrap();
}

/// The machine that decides a wake writes the wake's actor on its decision
/// row.
#[test]
fn the_deciding_machine_names_the_actor_on_its_decision_row() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);

    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the home did not decide the wake it took"
    );
    let row = wake_row(&doc_home, turn, registration)
        .expect("fixture: the home's window carries no row for the wake it decided");
    assert!(
        row.get("admitted").is_some(),
        "fixture: the home's window does not carry its decision: {row}"
    );
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "the deciding machine's decision row does not name the wake's actor: {row}"
    );
}

/// A third machine imports the home's decision and never held the wake. It
/// keeps the decision with its actor, and writes the row again with that
/// actor into a window that lost it.
#[test]
fn a_machine_that_imported_a_decision_writes_it_again_with_its_actor() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let third = Machine::open("machine-third");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder, &third], &home, &recorder);

    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the home did not decide the wake it took"
    );
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    third.housekeeping();
    assert!(
        doors::decision_kept_here(&third.vault, turn, registration).unwrap(),
        "fixture: the third machine did not keep the decision the window carried"
    );
    assert!(!third.owes(turn, registration));
    assert_eq!(third.decisions(turn, registration), 0);

    let row = row_written_again(&third, &doc_third, turn, registration)
        .expect("a machine that keeps an imported decision wrote no row for it into the window");
    assert!(
        row.get("admitted").is_some(),
        "the row written again is no decision: {row}"
    );
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "a machine that only imported a decision wrote it again without its actor: {row}"
    );
    assert_eq!(third.decisions(turn, registration), 0);
}

/// A decision row written before the row named its actor reaches a machine
/// that holds no wake of it. The machine takes it as before: it keeps the
/// decision, and writes the same row again, with no actor.
#[test]
fn a_decision_row_that_names_no_actor_is_kept_and_written_again_as_it_was() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let third = Machine::open("machine-third");
    let Taken {
        agent,
        turn,
        registration,
        doc_recorder,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder, &third], &home, &recorder);
    let (map_key, old) = decision_row_without_actor(&recorder, agent, registration);
    assert_eq!(map_key, wake_key(turn, registration));

    // The window reaches the third machine with the TURN and the recorder's
    // `Owed` row, which only the home takes.
    let doc_third = third.doc();
    exchange(&doc_third, &doc_recorder);
    assert!(!third.owes(turn, registration));
    merge_carried_row(&third, &doc_third, &map_key, &old);
    assert!(
        doors::decision_kept_here(&third.vault, turn, registration).unwrap(),
        "a decision row that names no actor was not kept"
    );
    assert_eq!(third.decisions(turn, registration), 0);

    let row = row_written_again(&third, &doc_third, turn, registration)
        .expect("a machine that keeps a decision wrote no row for it into the window");
    let old: serde_json::Value = serde_json::from_slice(&old).unwrap();
    assert_eq!(
        row, old,
        "a decision kept from a row that names no actor was written again as another row"
    );
    assert!(
        row["admitted"].get("actor").is_none(),
        "a decision whose actor no row named and no wake proved was written with one: {row}"
    );
}

/// A decision row written before the row named its actor reaches the machine
/// that still owes the wake it decides. The row consumes the wake as before,
/// and the machine keeps the wake's own actor with the decision: the
/// admission the row names is a digest over that actor.
#[test]
fn a_decision_row_that_names_no_actor_takes_the_actor_of_the_wake_it_consumes() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        agent,
        turn,
        registration,
        doc_recorder,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);
    let (map_key, old) = decision_row_without_actor(&recorder, agent, registration);

    merge_carried_row(&recorder, &doc_recorder, &map_key, &old);
    assert!(
        !recorder.owes(turn, registration),
        "a decision row that names no actor did not consume the wake it decides"
    );
    assert!(doors::decision_kept_here(&recorder.vault, turn, registration).unwrap());
    assert_eq!(recorder.decisions(turn, registration), 0);

    let row = row_written_again(&recorder, &doc_recorder, turn, registration)
        .expect("a machine that keeps a decision wrote no row for it into the window");
    assert!(
        row.get("admitted").is_some(),
        "the row written again is no decision: {row}"
    );
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "a decision that consumed the wake owed here was written again without that wake's actor: {row}"
    );
}

/// An erase of the actor's turn programs on a machine that only imported the
/// decision drops the actor it kept beside the decision: the machine writes
/// the decision again with no actor, as a decision whose actor it never
/// learned. The decision itself stays here.
#[test]
fn an_erase_of_the_actor_drops_the_actor_kept_beside_a_decision() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let third = Machine::open("machine-third");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder, &third], &home, &recorder);

    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the home did not decide the wake it took"
    );
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    third.housekeeping();
    assert!(
        doors::decision_kept_here(&third.vault, turn, registration).unwrap(),
        "fixture: the third machine did not keep the decision the window carried"
    );

    doors::erase_actor_programs(&third.vault, agent).unwrap();
    let row = row_written_again(&third, &doc_third, turn, registration)
        .expect("a machine that keeps a decision wrote no row for it into the window");
    assert!(
        row.get("admitted").is_some(),
        "the row written again is no decision: {row}"
    );
    assert!(
        row["admitted"].get("actor").is_none(),
        "a machine wrote a decision with the actor it kept, after that actor's erase: {row}"
    );
}

/// A carried `Retracted` row of a decided wake names another actor than the
/// wake's. The machine that decided the wake answers with its decision under
/// the actor of its own admission, and a machine that imported the decision
/// under the actor it kept: neither writes the actor the carried row asserts.
#[test]
fn a_wake_answer_names_the_decisions_own_actor_not_the_carried_rows() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let third = Machine::open("machine-third");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder, &third], &home, &recorder);

    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the home did not decide the wake it took"
    );
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    third.housekeeping();
    assert!(
        doors::decision_kept_here(&third.vault, turn, registration).unwrap(),
        "fixture: the third machine did not keep the decision the window carried"
    );
    let decision = wake_row(&doc_home, turn, registration)
        .expect("fixture: the home's window carries no row for the wake it decided");
    assert!(
        decision.get("admitted").is_some(),
        "fixture: the home's window does not carry its decision: {decision}"
    );
    let other = EntityId::from_bytes([0x63; 16]).unwrap();
    assert_ne!(other, agent);
    let carried = retracted_row(&decision, other);

    let row = answer_to_carried_row(&home, &doc_home, turn, registration, &carried)
        .expect("the deciding machine's window carries no row for the wake after its pass");
    assert!(
        row.get("admitted").is_some(),
        "the deciding machine did not answer a carried retraction with its decision: {row}"
    );
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "the deciding machine's answer names another actor than its own admission's: {row}"
    );

    let row = answer_to_carried_row(&third, &doc_third, turn, registration, &carried)
        .expect("the importing machine's window carries no row for the wake after its pass");
    assert!(
        row.get("admitted").is_some(),
        "the importing machine did not answer a carried retraction with the decision it kept: {row}"
    );
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "the importing machine's answer names another actor than the one it kept: {row}"
    );
}

/// The actor is hard-deleted on a machine that imported a decision of its
/// wake, and a carried `Retracted` row of that wake still names the actor.
/// The machine answers with the decision it kept, and the answer names no
/// actor: the carried row's word puts an erased actor on no row written here.
#[test]
fn a_wake_answer_names_no_actor_erased_here() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let third = Machine::open("machine-third");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder, &third], &home, &recorder);

    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the home did not decide the wake it took"
    );
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    third.housekeeping();
    assert!(
        doors::decision_kept_here(&third.vault, turn, registration).unwrap(),
        "fixture: the third machine did not keep the decision the window carried"
    );
    let decision = wake_row(&doc_third, turn, registration)
        .expect("fixture: the third machine's window carries no row for the wake");
    assert_eq!(
        decision["admitted"]["actor"],
        named(agent),
        "fixture: the decision the third machine imported does not name the actor: {decision}"
    );
    let carried = retracted_row(&decision, agent);

    store_agent_row(&third, agent);
    assert!(
        doors::erase_hard_deleted_actor_programs(&third.vault, agent).unwrap(),
        "fixture: the actor does not read as erased on the third machine"
    );
    assert!(
        doors::decision_kept_here(&third.vault, turn, registration).unwrap(),
        "fixture: the erase took the decision itself, which stays until the second change"
    );

    let row = answer_to_carried_row(&third, &doc_third, turn, registration, &carried)
        .expect("the window carries no row for the wake after the machine's pass");
    assert!(
        row.get("admitted").is_some(),
        "the machine did not answer a carried retraction with the decision it kept: {row}"
    );
    assert!(
        row["admitted"].get("actor").is_none(),
        "a wake answer names an actor erased on the machine that wrote it: {row}"
    );
}

/// The actor is hard-deleted on the machine that decided its wake, which
/// keeps the admission. A stale `Owed` row of that wake comes back into the
/// window. The machine writes its decision over it, and that row names no
/// actor: the carried wake's actor is erased here.
#[test]
fn the_deciding_machine_names_no_erased_actor_on_the_decision_over_a_stale_owed_row() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);
    let owed = wake_row_bytes(&doc_home, turn, registration)
        .expect("fixture: the home's window carries no row for the wake it took");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&owed)
            .unwrap()
            .get("owed")
            .is_some(),
        "fixture: the row the home took is no owed wake"
    );

    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the home did not decide the wake it took"
    );
    store_agent_row(&home, agent);
    assert!(
        doors::erase_hard_deleted_actor_programs(&home.vault, agent).unwrap(),
        "fixture: the actor does not read as erased on the home"
    );
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the erase took the admission, which an erase keeps"
    );

    doc_home
        .get_map(WAKES)
        .insert(
            &wake_key(turn, registration),
            LoroValue::Binary(owed.into()),
        )
        .unwrap();
    doc_home.commit();
    reverse_rematerialize(&home.vault, &doc_home, &WindowKey::new(WINDOW)).unwrap();
    doc_home.commit();
    let row = wake_row(&doc_home, turn, registration)
        .expect("the window carries no row for the wake after the machine mirrored its state");
    assert!(
        row.get("admitted").is_some(),
        "the deciding machine did not write its decision over a stale owed row: {row}"
    );
    assert!(
        row["admitted"].get("actor").is_none(),
        "the deciding machine's decision row names an actor erased there: {row}"
    );
}
