//! An erase of a turn program's actor deletes the decisions this machine
//! keeps of that actor's wakes, and no carried row brings one back (FIX
//! TURNPROGRAM-ERASE-KEEPS-DECIDED, the second of two changes; ruled by the
//! lead, 21 Nov 2026).
//!
//! A machine keeps a marker of each wake another machine decided, so it never
//! decides that wake again. The marker named no actor, so an erase of the
//! actor left it, and a marker deleted by hand came back with the next merge
//! of the decision row a window still carried. Since the first change the
//! decision row names its wake's actor and each machine keeps that actor
//! beside its marker (`turn_program_decision_row_names_actor`). Here:
//!
//! - the erase deletes each marker kept under the erased actor;
//! - a machine refuses a decision row of an actor erased there, before it
//!   writes anything: the actor of the wake the row would consume there, else
//!   the actor the row names;
//! - a machine writes no decision row for an actor erased there, from its
//!   own admission or as an answer to a carried row;
//! - a window stored or sent by such a machine carries no decision row that
//!   names the actor;
//! - a decision row that names its actor goes with that actor when a
//!   checkpoint or a discarded window is taken apart.
//!
//! What stays as it was: a decision row that names no actor (one written
//! before the row named it) is refused for no erase and leaves no window; a
//! decision row consumes the wake owed on a machine whatever actor it names,
//! under the actor that wake proves; another actor's erase touches nothing.
//!
//! Deleting the marker opens no second decision on the machine: the same
//! erase deletes the actor's armings and owed wakes, and the machine refuses
//! every carried row of that actor afterwards.
//!
//! Machines of one vault, each with its own live window manager, as in
//! `turn_program_former_home_imported_wake`. An actor reads as erased on a
//! machine once its row there took the hard-delete marker; the door
//! `erase_hard_deleted_actor_programs` writes that marker and runs the
//! turn-program erase in one writer, as a hard delete of the row does.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_erase_deletes_decided_rows`.
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
use oneiron::test_doors::sync_parted_row_binding::discard_projection;
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
        holder_proof_challenge(vault.now_recorded_at(), "turn-program-erase-decided-rows");
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
/// test over machines here starts from.
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

/// Merges the rows `doc` carries into `machine`, as an open of the window
/// does.
fn take_window_rows(machine: &Machine, doc: &LoroDoc) {
    forward_rematerialize(
        &machine.vault,
        doc,
        &Materializer::new(),
        &WindowKey::new(WINDOW),
    )
    .unwrap();
}

/// The home's pass decides the wake it took: one admission there.
fn home_decides(home: &Machine, turn: EntityId, registration: EntityId) {
    home.housekeeping();
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "fixture: the home did not decide the wake it took"
    );
}

/// Marks `actor` hard-deleted on `machine` and erases its turn programs
/// there, as a hard delete of its row does.
fn erase_actor(machine: &Machine, actor: EntityId) {
    assert!(
        doors::erase_hard_deleted_actor_programs(&machine.vault, actor).unwrap(),
        "fixture: the actor does not read as erased on the machine"
    );
}

/// Whether `machine` keeps a decision another machine made of the wake.
fn keeps_decision(machine: &Machine, turn: EntityId, registration: EntityId) -> bool {
    doors::decision_kept_here(&machine.vault, turn, registration).unwrap()
}

/// Whether `row` is a decision row.
fn is_decision(row: &serde_json::Value) -> bool {
    row.get("admitted").is_some()
}

/// The decision row `decision`, naming `actor` in place of the actor it
/// names.
fn decision_row_naming(decision: &[u8], actor: EntityId) -> Vec<u8> {
    let mut row: serde_json::Value = serde_json::from_slice(decision).unwrap();
    row["admitted"]["actor"] = named(actor);
    serde_json::to_vec(&row).unwrap()
}

/// The snapshot of a window that carries one decision row for the wake TURN
/// `turn` owes `registration`, naming `actor` or no actor.
fn decision_window(turn: EntityId, registration: EntityId, actor: Option<EntityId>) -> Vec<u8> {
    let admission = [0_u8; 32];
    let mut decision = serde_json::json!({
        "turn": named(turn),
        "registration": named(registration),
        "admission": admission,
    });
    if let Some(actor) = actor {
        decision["actor"] = named(actor);
    }
    let row = serde_json::to_vec(&serde_json::json!({ "admitted": decision })).unwrap();
    let doc = LoroDoc::new();
    doc.get_map(WAKES)
        .insert(&wake_key(turn, registration), LoroValue::Binary(row.into()))
        .unwrap();
    doc.commit();
    doc.export(ExportMode::Snapshot).unwrap()
}

/// The home's decision consumed the wake on the machine that recorded it,
/// which keeps the decision. The actor is then erased on that machine. The
/// decision goes with the erase, and the decision row the window still
/// carries brings it back on no merge and no pass.
#[test]
fn an_erase_on_the_recording_machine_deletes_the_decision_that_consumed_its_wake() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);
    home_decides(&home, turn, registration);
    exchange(&doc_home, &doc_recorder);
    take_window_rows(&recorder, &doc_recorder);
    assert!(
        !recorder.owes(turn, registration),
        "fixture: the home's decision did not consume the wake on the recording machine"
    );
    assert!(
        keeps_decision(&recorder, turn, registration),
        "fixture: the recording machine did not keep the home's decision"
    );

    erase_actor(&recorder, agent);
    assert!(
        !keeps_decision(&recorder, turn, registration),
        "the erase of the actor left the decision of its wake on the recording machine"
    );

    // The window still carries the home's decision row, which names the actor.
    let row = wake_row(&doc_recorder, turn, registration)
        .expect("fixture: the recording machine's window carries no row for the wake");
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "fixture: the window does not carry the home's decision with its actor: {row}"
    );
    exchange(&doc_home, &doc_recorder);
    take_window_rows(&recorder, &doc_recorder);
    recorder.housekeeping();
    assert!(
        !keeps_decision(&recorder, turn, registration),
        "a decision row of the erased actor was kept again after the erase"
    );
    assert!(!recorder.owes(turn, registration));
    assert_eq!(
        recorder.decisions(turn, registration),
        0,
        "the recording machine decided a wake the home had decided"
    );
    assert_eq!(home.decisions(turn, registration), 1);
}

/// A third machine imported the home's decision and never held the wake. The
/// actor is then erased there. The decision goes with the erase, no merge of
/// the window brings it back, and the machine writes no decision row for the
/// wake into a window that lost it.
#[test]
fn an_erase_deletes_the_decision_a_machine_only_imported() {
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
    home_decides(&home, turn, registration);
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    take_window_rows(&third, &doc_third);
    assert!(
        keeps_decision(&third, turn, registration),
        "fixture: the third machine did not keep the decision the window carried"
    );

    store_agent_row(&third, agent);
    erase_actor(&third, agent);
    assert!(
        !keeps_decision(&third, turn, registration),
        "the erase of the actor left the decision a machine imported of its wake"
    );

    exchange(&doc_third, &doc_home);
    take_window_rows(&third, &doc_third);
    third.housekeeping();
    assert!(
        !keeps_decision(&third, turn, registration),
        "a decision row of the erased actor was kept again after the erase"
    );
    assert!(!third.owes(turn, registration));
    assert_eq!(third.decisions(turn, registration), 0);
    assert_eq!(home.decisions(turn, registration), 1);

    let row = row_written_again(&third, &doc_third, turn, registration);
    assert!(
        row.is_none(),
        "a machine wrote a row for the wake of an actor erased there: {row:?}"
    );
}

/// The actor is erased on a machine before any decision of its wake arrives
/// there. The window then brings the home's decision row, which names the
/// actor. The machine refuses it: it keeps no decision.
#[test]
fn a_decision_row_of_an_actor_erased_here_is_not_kept() {
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
    home_decides(&home, turn, registration);
    let row = wake_row(&doc_home, turn, registration)
        .expect("fixture: the home's window carries no row for the wake it decided");
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "fixture: the home's decision row does not name the actor: {row}"
    );

    store_agent_row(&third, agent);
    erase_actor(&third, agent);
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    take_window_rows(&third, &doc_third);
    third.housekeeping();
    assert!(
        !keeps_decision(&third, turn, registration),
        "a machine kept the decision of a wake whose actor is erased there"
    );
    assert!(!third.owes(turn, registration));
    assert_eq!(third.decisions(turn, registration), 0);
}

/// The actor is erased on the machine that decided its wake, whose window
/// carries the decision row with the actor. The window is stored and opened
/// again: it carries no row for the wake, and the machine, which keeps its
/// admission, writes none.
#[test]
fn a_stored_window_carries_no_decision_row_of_an_actor_erased_here() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);
    home_decides(&home, turn, registration);
    let row = wake_row(&doc_home, turn, registration)
        .expect("fixture: the home's window carries no row for the wake it decided");
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "fixture: the home's decision row does not name the actor: {row}"
    );

    store_agent_row(&home, agent);
    erase_actor(&home, agent);
    drop(doc_home);
    assert!(
        home.manager.unload_window(&WindowKey::new(WINDOW)).unwrap(),
        "fixture: the home's window was not loaded"
    );
    let doc_home = home.doc();
    let row = wake_row(&doc_home, turn, registration);
    assert!(
        row.is_none(),
        "a window stored by a machine carries a row for the wake of an actor erased there: {row:?}"
    );
    assert_eq!(
        home.decisions(turn, registration),
        1,
        "the erase took the admission, which an erase keeps"
    );
}

/// A decision row written before the row named its actor reaches a machine
/// where that actor is erased. Nothing ties the row to the actor, so it is
/// taken as before: the machine keeps the decision and writes the same row
/// again.
#[test]
fn a_decision_row_that_names_no_actor_is_kept_where_its_actor_is_erased() {
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

    store_agent_row(&third, agent);
    erase_actor(&third, agent);
    let doc_third = third.doc();
    exchange(&doc_third, &doc_recorder);
    merge_carried_row(&third, &doc_third, &map_key, &old);
    assert!(
        keeps_decision(&third, turn, registration),
        "a decision row that names no actor was refused for an erase"
    );
    assert_eq!(third.decisions(turn, registration), 0);

    let row = row_written_again(&third, &doc_third, turn, registration)
        .expect("a machine that keeps a decision wrote no row for it into the window");
    let old: serde_json::Value = serde_json::from_slice(&old).unwrap();
    assert_eq!(
        row, old,
        "a decision kept from a row that names no actor was written again as another row"
    );
}

/// A decision row reaches the machine that still owes the wake it decides,
/// and names another actor, one erased on that machine. The wake's own actor
/// is live there and the admission the row names is a digest over it. The row
/// is not refused: it consumes the wake, and the decision is kept under the
/// wake's actor. A refusal would leave the wake owed there, for a second
/// decision.
#[test]
fn a_decision_row_consumes_the_wake_owed_here_whatever_actor_it_names() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        agent,
        turn,
        registration,
        doc_recorder,
        ..
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);
    let other = recorder
        .vault
        .ensure_agent_principal("turn-program-other-agent")
        .unwrap();
    assert_ne!(other, agent);
    erase_actor(&recorder, other);
    let (_, map_key, decision) =
        doors::admitted_row_bytes(&recorder.vault, agent, registration).unwrap();
    let row = decision_row_naming(&decision, other);

    merge_carried_row(&recorder, &doc_recorder, &map_key, &row);
    assert!(
        !recorder.owes(turn, registration),
        "a decision row that names another actor than the wake's left the wake owed here"
    );
    assert!(
        keeps_decision(&recorder, turn, registration),
        "a decision row that consumed the wake owed here was not kept"
    );
    assert_eq!(recorder.decisions(turn, registration), 0);

    let row = row_written_again(&recorder, &doc_recorder, turn, registration)
        .expect("a machine that keeps a decision wrote no row for it into the window");
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "the decision was not kept under the actor of the wake it consumed: {row}"
    );
}

/// An erase of another actor on a machine that imported a decision leaves the
/// decision, and the actor kept beside it.
#[test]
fn an_erase_of_another_actor_leaves_the_decision_and_its_actor() {
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
    home_decides(&home, turn, registration);
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    take_window_rows(&third, &doc_third);
    assert!(
        keeps_decision(&third, turn, registration),
        "fixture: the third machine did not keep the decision the window carried"
    );

    let other = third
        .vault
        .ensure_agent_principal("turn-program-other-agent")
        .unwrap();
    assert_ne!(other, agent);
    erase_actor(&third, other);
    assert!(
        keeps_decision(&third, turn, registration),
        "an erase of another actor deleted a decision"
    );
    let row = row_written_again(&third, &doc_third, turn, registration)
        .expect("a machine that keeps a decision wrote no row for it into the window");
    assert_eq!(
        row["admitted"]["actor"],
        named(agent),
        "an erase of another actor dropped the actor kept beside a decision: {row}"
    );
}

/// The actor is erased on a machine that imported a decision of its wake, and
/// a carried `Retracted` row of that wake still names the actor. The machine
/// keeps no decision of the wake now, and answers the row with none.
#[test]
fn a_carried_row_of_an_actor_erased_here_is_answered_by_no_decision() {
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
    home_decides(&home, turn, registration);
    let doc_third = third.doc();
    exchange(&doc_third, &doc_home);
    take_window_rows(&third, &doc_third);
    assert!(
        keeps_decision(&third, turn, registration),
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
    erase_actor(&third, agent);
    let row = answer_to_carried_row(&third, &doc_third, turn, registration, &carried);
    assert!(
        !row.as_ref().is_some_and(is_decision),
        "a machine answered a carried row of an actor erased there with a decision: {row:?}"
    );
    assert!(!keeps_decision(&third, turn, registration));
}

/// The actor is erased on the machine that decided its wake, which keeps the
/// admission. A stale `Owed` row of that wake comes back into the window. The
/// machine writes no decision over it: a decision of an actor erased here
/// goes into no window.
#[test]
fn the_deciding_machine_writes_no_decision_row_for_an_actor_erased_there() {
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
    home_decides(&home, turn, registration);
    store_agent_row(&home, agent);
    erase_actor(&home, agent);
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
    let row = wake_row(&doc_home, turn, registration);
    assert!(
        !row.as_ref().is_some_and(is_decision),
        "the deciding machine wrote a decision row for an actor erased there: {row:?}"
    );
    assert_eq!(home.decisions(turn, registration), 1);
}

/// The worst case for a machine that lost its decision to the erase: the
/// actor is erased on the machine that recorded the wake, after the home's
/// decision consumed it there; a stale `Owed` row of the wake comes back into
/// its window; and the machine is then elected home. It takes no wake and
/// decides none: it refuses every carried row of an actor erased there.
#[test]
fn a_machine_elected_home_after_the_erase_decides_no_wake_of_the_erased_actor() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        agent,
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);
    let owed = wake_row_bytes(&doc_recorder, turn, registration)
        .expect("fixture: the recording machine's window carries no row for the wake");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&owed)
            .unwrap()
            .get("owed")
            .is_some(),
        "fixture: the row the recording machine carried is no owed wake"
    );
    home_decides(&home, turn, registration);
    exchange(&doc_home, &doc_recorder);
    take_window_rows(&recorder, &doc_recorder);
    assert!(
        !recorder.owes(turn, registration),
        "fixture: the home's decision did not consume the wake on the recording machine"
    );

    erase_actor(&recorder, agent);
    elect(&[&recorder], doors::node_id(&recorder.vault).unwrap());
    doc_recorder
        .get_map(WAKES)
        .insert(
            &wake_key(turn, registration),
            LoroValue::Binary(owed.into()),
        )
        .unwrap();
    doc_recorder.commit();
    take_window_rows(&recorder, &doc_recorder);
    recorder.housekeeping();
    assert!(
        !recorder.owes(turn, registration),
        "a machine took a carried wake of an actor erased there"
    );
    assert_eq!(
        recorder.decisions(turn, registration),
        0,
        "a machine elected home after the erase decided a wake the old home had decided"
    );
    assert_eq!(home.decisions(turn, registration), 1);
}

/// A decision row that names its actor is that actor's when a window is taken
/// apart: a discard of the actor erases it, and so does a discard of its
/// turn. A decision row that names no actor goes with its turn alone, as
/// before.
#[test]
fn a_decision_row_goes_with_the_actor_it_names_when_a_window_is_taken_apart() {
    let turn = EntityId::from_bytes(TURN).unwrap();
    let registration = EntityId::from_bytes(CONVERSATION).unwrap();
    let actor = EntityId::from_bytes([0x63; 16]).unwrap();
    let other = EntityId::from_bytes([0x64; 16]).unwrap();
    let erases = |window: &[u8], discarded: EntityId| {
        let outcome = discard_projection(window, &[discarded]).unwrap();
        assert!(
            outcome == "unchanged" || outcome.starts_with("erased "),
            "fixture: the projection did not run over the window: {outcome}"
        );
        outcome != "unchanged"
    };

    let named_row = decision_window(turn, registration, Some(actor));
    assert!(
        erases(&named_row, actor),
        "a discard of the actor a decision row names left the row"
    );
    assert!(
        erases(&named_row, turn),
        "a discard of its turn left a decision row that names its actor"
    );
    assert!(
        !erases(&named_row, other),
        "a discard of another row erased a decision row"
    );

    let unnamed_row = decision_window(turn, registration, None);
    assert!(
        erases(&unnamed_row, turn),
        "a discard of its turn left a decision row that names no actor"
    );
    assert!(
        !erases(&unnamed_row, actor),
        "a discard of an actor erased a decision row that names none"
    );
}
