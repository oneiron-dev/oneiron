//! A retraction's rows and a window that is not loaded (FIX
//! TURNPROGRAM-RETRACTION-ROW-WAITS-FOR-WINDOW-OPEN).
//!
//! Two machines of one vault, each with its own live window manager. The
//! recorder lands a TURN that owes a program armed there; the other machine
//! is the elected home and takes the riding wake from the shared base window,
//! without deciding it yet. Then the recorder withholds the TURN, so it
//! retracts the wake, and the home releases it.
//!
//! Each of those two rows is owed to the window that carried the wake. A
//! housekeeping pass writes its rows into the windows that are loaded. When
//! the window is not loaded on the machine that owes the row, that machine's
//! pass must open it, so the row is written, stored and routed; otherwise the
//! row waits until something else opens that month, and the recorder waits
//! for an answer that does not come.
//!
//! The tests ask the manager for the window without opening it
//! (`WindowManager::window`): a window the test opened itself would take the
//! row at that open and show nothing.
//!
//! The pass forgets that it owes a window a row only once that window is
//! stored with the row and made ready, so every connection asks its peer to
//! exchange it: a row that only a live channel took is not lost with a
//! machine that stops. And a window the pass opened is unloaded again once
//! more than four such windows are loaded; an unload a held handle refused
//! is tried again on each later pass.
//!
//! The tests count decisions: admission rows, queued or refused. Whether the
//! program then runs is the admission's own judgment and out of scope here,
//! as in `turn_program_sync`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_retraction_row_cold_window`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
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
use oneiron::sync::manager::{ReadyProgress, WindowManager};
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

    /// Whether window `key` is loaded here, read without a handle to it.
    fn loaded(&self, key: &WindowKey) -> bool {
        self.manager.loaded_keys().contains(key)
    }

    /// Window `key`'s ready generation as a new connection reads it: 0 while
    /// no connection is asked to exchange the window.
    fn ready_generation(&self, key: &WindowKey) -> u64 {
        ReadyProgress::default()
            .due(&self.manager, usize::MAX, |_| true)
            .unwrap()
            .into_iter()
            .find(|(ready, _)| ready == key)
            .map_or(0, |(_, generation)| generation)
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
    let challenge = holder_proof_challenge(vault.now_recorded_at(), "turn-program-cold-window");
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
    put_row_at(machine, id, T0);
}

/// A row at `id`, learned at `at`, so it lands in that month's base window.
fn put_row_at(machine: &Machine, id: EntityId, at: u64) {
    let body =
        rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")])).unwrap();
    machine
        .vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .unwrap();
}

const TURN: [u8; 16] = [0x61; 16];
const CONVERSATION: [u8; 16] = [0x62; 16];

/// On `recorder`: a TURN that owes a program its agent armed under its slip.
/// The row the arming pins stands on every machine of `machines`, so a home
/// can take the wake. The TURN has no conversation here, so an admission
/// refuses the wake, which decides it all the same. Answers the TURN and the
/// registration.
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

/// A wake the recorder carried and the home took, undecided: what every test
/// here starts from.
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
        "fixture: the home decided the carried wake before any retraction"
    );
    Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    }
}

/// The recorder's window is not loaded when its pass retracts the wake. The
/// pass opens it: the window carries the retraction, the home drops its copy
/// and releases the wake, and the recorder decides it once.
#[test]
fn a_retraction_is_written_into_a_window_that_was_not_loaded() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);

    // The recorder's window closes, and then its TURN is withheld: the wake
    // no longer rides from it.
    drop(doc_recorder);
    assert!(
        recorder
            .manager
            .unload_window(&WindowKey::new(WINDOW))
            .unwrap(),
        "fixture: the recorder's window was not loaded"
    );
    assert!(doors::withhold_turn(&recorder.vault, turn).unwrap());

    // The recorder's pass retracts the wake and writes the retraction into
    // the window, though nothing else opens it.
    recorder.housekeeping();
    assert_eq!(recorder.decisions(turn, registration), 0);
    let doc_recorder = recorder
        .manager
        .window(&WindowKey::new(WINDOW))
        .expect("the recorder's pass left the window that owes the retraction closed")
        .doc
        .clone();

    // The retraction reaches the home, which drops its copy, undecided.
    exchange(&doc_home, &doc_recorder);
    home.housekeeping();
    assert!(
        !home.owes(turn, registration),
        "the retraction the recorder's pass wrote did not reach the home"
    );
    assert_eq!(home.decisions(turn, registration), 0);

    // The release reaches the recorder, which decides the wake once.
    exchange(&doc_home, &doc_recorder);
    recorder.housekeeping();
    assert_eq!(
        recorder.decisions(turn, registration),
        1,
        "the recorder did not decide the wake the home released"
    );
    assert!(!recorder.owes(turn, registration));
    assert_eq!(home.decisions(turn, registration), 0);
}

/// The home's window is not loaded when its pass owes the release: it took
/// the retraction as an import does, and the window closed before any pass.
/// The pass opens the window: it carries the release, and the recorder
/// decides the wake once.
#[test]
fn a_release_is_written_into_a_window_that_was_not_loaded() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);

    // The recorder withholds the TURN and retracts the wake; the retraction
    // reaches the home's window.
    assert!(doors::withhold_turn(&recorder.vault, turn).unwrap());
    recorder.housekeeping();
    exchange(&doc_home, &doc_recorder);

    // The home takes the retraction as an import does: it drops its copy and
    // keeps the release. Its window closes before any pass of its own.
    forward_rematerialize(
        &home.vault,
        &doc_home,
        &Materializer::new(),
        &WindowKey::new(WINDOW),
    )
    .unwrap();
    assert!(
        !home.owes(turn, registration),
        "fixture: the home did not take the retraction"
    );
    drop(doc_home);
    assert!(
        home.manager.unload_window(&WindowKey::new(WINDOW)).unwrap(),
        "fixture: the home's window was not loaded"
    );

    // The home's pass writes the release into the window, though nothing
    // else opens it.
    home.housekeeping();
    assert_eq!(home.decisions(turn, registration), 0);
    let doc_home = home
        .manager
        .window(&WindowKey::new(WINDOW))
        .expect("the home's pass left the window that owes the release closed")
        .doc
        .clone();

    // The release reaches the recorder, which decides the wake once.
    exchange(&doc_home, &doc_recorder);
    recorder.housekeeping();
    assert_eq!(
        recorder.decisions(turn, registration),
        1,
        "the release the home's pass wrote did not reach the recorder"
    );
    assert!(!recorder.owes(turn, registration));
    assert_eq!(home.decisions(turn, registration), 0);
}

/// A pass that owes a window no row opens no window: a riding wake's `Owed`
/// row is in the window already, and the recorder waits for the home.
#[test]
fn a_pass_that_owes_no_row_opens_no_window() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        turn,
        registration,
        doc_home: _doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);

    drop(doc_recorder);
    assert!(
        recorder
            .manager
            .unload_window(&WindowKey::new(WINDOW))
            .unwrap(),
        "fixture: the recorder's window was not loaded"
    );
    recorder.housekeeping();
    assert!(
        recorder.manager.window(&WindowKey::new(WINDOW)).is_none(),
        "a pass that owed the window no row opened it"
    );
    assert!(recorder.owes(turn, registration));
    assert_eq!(recorder.decisions(turn, registration), 0);
}

/// The home's window is loaded when its pass owes the release. The pass
/// writes the release, stores the window and makes it ready: a connection
/// made after it, on a machine that stopped before a live channel sent the
/// row, asks its peer to exchange the window all the same.
#[test]
fn a_window_stored_with_an_owed_row_is_ready_for_every_connection() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    let Taken {
        turn,
        registration,
        doc_home,
        doc_recorder,
    } = home_takes_the_carried_wake(&[&home, &recorder], &home, &recorder);
    let window = WindowKey::new(WINDOW);

    // The recorder withholds the TURN and retracts the wake; the home takes
    // the retraction as an import does and keeps the release. Its window
    // stays loaded.
    assert!(doors::withhold_turn(&recorder.vault, turn).unwrap());
    recorder.housekeeping();
    exchange(&doc_home, &doc_recorder);
    forward_rematerialize(&home.vault, &doc_home, &Materializer::new(), &window).unwrap();
    assert!(
        !home.owes(turn, registration),
        "fixture: the home did not take the retraction"
    );
    assert!(
        home.loaded(&window),
        "fixture: the home's window is not loaded"
    );
    let before = home.ready_generation(&window);

    home.housekeeping();
    assert!(
        home.ready_generation(&window) > before,
        "the home's pass did not make the window it owed the release ready"
    );

    // The release is in the window: the recorder decides the wake once.
    exchange(&doc_home, &doc_recorder);
    recorder.housekeeping();
    assert_eq!(
        recorder.decisions(turn, registration),
        1,
        "the release the home's pass wrote did not reach the recorder"
    );
    assert_eq!(home.decisions(turn, registration), 0);
}

const DAY: u64 = 86_400;
/// The 15th of March, April, May, June and July 2026, 00:00 UTC: one time in
/// each of five base windows.
const MONTHS: [u64; 5] = [
    T0,
    T0 + 31 * DAY,
    T0 + 61 * DAY,
    T0 + 92 * DAY,
    T0 + 122 * DAY,
];

/// The pass keeps four of the windows it opened loaded and unloads the one
/// opened longest ago. A handle another caller holds refuses that unload;
/// once the handle is gone a later pass unloads the window, though it owes
/// no window a row by then.
#[test]
fn an_unload_a_held_handle_refused_is_tried_again_on_a_later_pass() {
    let home = Machine::open("machine-home");
    let recorder = Machine::open("machine-recorder");
    for machine in [&home, &recorder] {
        doors::node_id(&machine.vault).unwrap();
    }
    elect(&[&home, &recorder], doors::node_id(&home.vault).unwrap());

    // On the recorder: five TURNs, one a month, each owing a program armed
    // in its own conversation. Each month's window opens, carries its wake,
    // and closes.
    let (agent, slip, instrument) = agent_slip(&recorder);
    let mut wakes = Vec::new();
    for (n, at) in (0u8..).zip(MONTHS) {
        let turn = EntityId::from_bytes([0x71 + n; 16]).unwrap();
        put_row_at(&recorder, turn, at);
        let registration = doors::plant_slip_wake(
            &recorder.vault,
            agent,
            &slip,
            &instrument,
            EntityId::from_bytes([0x81 + n; 16]).unwrap(),
            turn,
            at - 60,
            at,
        )
        .unwrap();
        put_row_at(&recorder, registration, at);
        let window = WindowKey::from_timestamp(at);
        drop(recorder.manager.open_window(&window).unwrap());
        wakes.push((turn, registration, window));
    }
    recorder.housekeeping();
    for (turn, registration, window) in &wakes {
        assert!(
            recorder.owes(*turn, *registration),
            "fixture: the recorder no longer owes a riding wake"
        );
        assert!(
            recorder.manager.unload_window(window).unwrap(),
            "fixture: a month's window was not loaded"
        );
    }

    // The first four TURNs are withheld: the pass opens their four windows
    // for the retractions and keeps them loaded.
    for (turn, _, _) in &wakes[..4] {
        assert!(doors::withhold_turn(&recorder.vault, *turn).unwrap());
    }
    recorder.housekeeping();
    for (_, _, window) in &wakes[..4] {
        assert!(
            recorder.loaded(window),
            "fixture: the pass left a window that owes a retraction closed"
        );
    }

    // Another caller holds the window opened first while the fifth TURN is
    // withheld: the pass opens the fifth window, and the unload of the first
    // is refused.
    let (first, fifth) = (&wakes[0].2, &wakes[4].2);
    let held = recorder
        .manager
        .window(first)
        .expect("fixture: the first window is not loaded");
    assert!(doors::withhold_turn(&recorder.vault, wakes[4].0).unwrap());
    recorder.housekeeping();
    assert!(
        recorder.loaded(fifth),
        "fixture: the pass left the fifth window closed"
    );
    assert!(
        recorder.loaded(first),
        "fixture: a held window was unloaded"
    );

    // The handle goes. No window is owed a row now; a later pass unloads the
    // first window all the same. Three passes are allowed: a handle the
    // mirror thread holds for a moment refuses one unload as a caller's does.
    drop(held);
    for _ in 0..3 {
        recorder.housekeeping();
        if !recorder.loaded(first) {
            break;
        }
    }
    assert!(
        !recorder.loaded(first),
        "a window whose unload was refused once stayed loaded after its handle was gone"
    );
    for (_, _, window) in &wakes[1..] {
        assert!(
            recorder.loaded(window),
            "one of the four windows opened last was unloaded"
        );
    }
}
