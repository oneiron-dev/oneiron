//! Handover budget custody (FIX 4889; L8-28): a handed-over agent run
//! carries its spend, and the taker reserves only the remainder (PR 1); the
//! custody machine keeps one counter for the run (PR 2).
//!
//! Two machines of one vault, each with its own live window manager, as a
//! host runs them. Machine A dispatches one agent run under a root spend
//! scope with a hard budget, spends part of it, and releases its run lease
//! as a closing process does, which stamps A's share on the run TASK. The
//! TASK rides the shared base window to machine B, the elected MACRO home,
//! which takes the run at expiry: B pins only the launch's reservation less
//! A's share, and waits when nothing is left. A share counts what the run's
//! open children hold, and a machine that takes the run back under a new
//! scope still counts what it spent under its first one (REVIEW-7879). A,
//! whose tree funded the launch, keeps the run's scope open while B runs
//! it: the root goes on holding the whole carve, the other machine's share
//! folds into the scope when the run ends or comes back, and the root is
//! charged once. A hold is no spend (REVIEW-7890): a child that outlives the
//! run on B keeps A's scope open until it settles, and the root is charged
//! what the child spent, not its carve; a take that keeps a queued try
//! counts the scope it folded into at once. A machine that lost the run
//! with a child still holding units keeps A's scope open as well, and stamps
//! its share again once the child settles; a hold still named a day after
//! the run's last lease folds as spent; a take back on A folds what a child
//! on B holds, so A's own spend stays out of its room; and a take back
//! under B's retry keeps A's one scope (REVIEW-7890 round 2).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test handover_budget_custody`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use loro::{ExportMode, LoroDoc};
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpawnSpend, SpendScopeId, SpendState,
};
use oneiron::attempt_queue::{AttemptQueue, RetryAttempt, RetryOutcome};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    CompleteDreamerAttempt, DreamerHomeNodeCandidate, DreamerRunnerStore,
};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::{IdGen, ManualClock};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::test_doors::agent_run_handover::agent_run_task_writer;
use oneiron::test_doors::spend::{agent_run_committed_units, reserve_child_scope};
use oneiron::test_doors::turn_programs as doors;
use oneiron::{AttemptId, ErrorKind, HnswConfig, Vault, VaultConfig};

/// The base window every row here lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;
/// The root scope's cap: what the launch's tree holds.
const ROOT_CAP: u64 = 100;
/// The run's hard budget: the carve its launch reserves under the root, or
/// the cap it pins outside any tree.
const RUN_BUDGET: u64 = 60;
/// The run id every run here dispatches under.
const RUN_ID: &str = "handover-budget-custody";
/// The root scope's launch id.
const ROOT: &str = "handover-budget-custody-root";
/// How many ids machine B's clock hands out before its vault opens, far
/// more than machine A mints in a test, so no id of A's recurs on B.
const B_ID_OFFSET: u64 = 1 << 20;

fn config(clock: &Arc<ManualClock>) -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg.store_clock = clock.bundle();
    cfg
}

/// The host secret both machines root under: one host, one genesis (A's).
/// B joins by importing A's history, so B's host root reuses A's genesis
/// instead of minting its own.
const HOST_SECRET: &[u8] = b"handover budget custody test host";

/// The fixture host issuer, as `agent_run_handover_writer_proof.rs` builds it.
fn host_issuer() -> HostSlipIssuer {
    HostSlipIssuer::from_secret(HOST_SECRET).expect("FIXTURE: the fixture host issuer")
}

/// The vault's owner proof, as `agent_run_handover_writer_proof.rs` builds it.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner actor");
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the authenticated owner")
}

/// The vault's genesis-bound id.
fn vault_genesis(vault: &Vault) -> [u8; 32] {
    vault
        .authority_fold()
        .expect("FIXTURE: the authority fold reads")
        .vault_id
        .expect("FIXTURE: the vault has a genesis-bound id")
}

/// One machine: its vault, its clock, and its live window manager.
struct Machine {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
}

impl Machine {
    /// Opens the primary machine (A) whose clock has handed out
    /// `ids_before_open` ids first, on the passing shape of
    /// `agent_run_handover_writer_proof.rs` `fixture()`: an owned vault whose
    /// install is profiled as the owner's own machine, with a loaded signer,
    /// so its run TASKs carry proofs that count. A manual clock mints ids
    /// from a counter that starts at 1, so two machines need distinct
    /// offsets: the client id, the machine id and every row id each mints
    /// then differ, as two real machines' random ids do. The `B_ID_OFFSET`
    /// stays for that reason.
    fn open(user: &str, ids_before_open: u64) -> Self {
        let clock = ManualClock::new(T0);
        for _ in 0..ids_before_open {
            clock.ulid();
        }
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open_owned(dir.path(), config(&clock)).unwrap());
        vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the embedded owner actor");
        let issuer = host_issuer();
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: the host root slip");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
            .expect("FIXTURE: this install's serving profile");
        vault
            .prepare_install_signing()
            .expect("FIXTURE: this install's signing keys load");
        // The host root cosigns the owner's machine answers here, so a peer
        // enrolled as the owner's own machine stands instead of being held
        // (as `carried_pin_awaits_owner.rs` `host()` does).
        vault.hold_checkpoint_root_signer(Arc::new(issuer));
        let local = vault
            .local_machine()
            .expect("FIXTURE: this install's machine reads")
            .expect("FIXTURE: this install has a machine once it is profiled");
        assert!(local.mine, "FIXTURE: the primary machine is mine");
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            user,
        ));
        Self {
            vault,
            manager,
            clock,
            _dir: dir,
        }
    }

    /// Opens a machine joined to `primary`'s vault: it enrols here as the
    /// owner's own machine on the primary, then takes the primary's signed
    /// authority history whole, so both share the one genesis (the
    /// primary's) and count each other's run TASK writer proofs. A fresh
    /// vault has no genesis, so the history imports whole; the host root
    /// slip and serving profile after the import reuse that genesis instead
    /// of minting a new one. The shape is
    /// `file_custody_merge_after_rewrap.rs` `enroll_second_machine` plus
    /// `take_history`, on the `agent_run_handover_writer_proof.rs` owned
    /// vault.
    fn open_joined(user: &str, ids_before_open: u64, primary: &Machine) -> Self {
        let clock = ManualClock::new(T0);
        for _ in 0..ids_before_open {
            clock.ulid();
        }
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open_owned(dir.path(), config(&clock)).unwrap());
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let genesis = vault_genesis(&primary.vault);
        let key = vault
            .machine_encryption_key(genesis)
            .expect("FIXTURE: the joined install's encryption key");
        let request = vault
            .machine_enrolment_request(genesis, key)
            .expect("FIXTURE: the joined install's enrolment request");
        let owner = owner_proof(&primary.vault);
        let landing = primary
            .vault
            .enroll_machine(
                &owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("FIXTURE: the primary enrols the joined machine as mine");
        assert!(
            landing.held().is_none(),
            "FIXTURE: the joined machine's enrolment stands"
        );
        vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the embedded owner actor on the joined vault");
        let history = primary
            .vault
            .export_signed_authority_history()
            .expect("FIXTURE: the primary's history exports");
        vault
            .import_signed_authority_history(&history)
            .expect("FIXTURE: the joined vault takes the history");
        let issuer = host_issuer();
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: the joined vault's host root slip reuses the genesis");
        assert_eq!(
            vault_genesis(&vault),
            genesis,
            "FIXTURE: the joined vault shares the one genesis"
        );
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
            .expect("FIXTURE: the joined install's serving profile stands");
        vault
            .prepare_install_signing()
            .expect("FIXTURE: the joined install's signing keys load");
        let local = vault
            .local_machine()
            .expect("FIXTURE: the joined install's machine reads")
            .expect("FIXTURE: the joined install has a machine once it is profiled");
        assert_eq!(
            local.id, request.machine,
            "FIXTURE: the joined install is the enrolled machine"
        );
        assert!(
            local.mine,
            "FIXTURE: the joined machine is mine on its own vault"
        );
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            user,
        ));
        Self {
            vault,
            manager,
            clock,
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

/// Unloads `machine`'s window and opens it cold, so its doc holds every row
/// the machine wrote since the window loaded before the next exchange. Such
/// a write reaches a loaded doc only later, through the live mirror's thread;
/// a cold open mirrors what the write's pending-mirror markers owe at once.
/// The test holds only `LoroDoc` clones, so no handle keeps the window open;
/// the mirror's thread holds it for the length of a pass, so a busy unload is
/// retried until that pass ends.
fn reload_window(machine: &Machine) {
    let key = WindowKey::new(WINDOW);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match machine.manager.unload_window(&key) {
            Ok(_) => break,
            Err(err) if err.kind() == ErrorKind::WindowBusy && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("the window does not unload: {err:?}"),
        }
    }
    machine.manager.open_window(&key).unwrap();
}

/// Opens the two machines sharing the one genesis (B joined to A) with
/// distinct node ids and elects B the MACRO home on both, so B takes an
/// expired run at expiry with no grace.
fn machines() -> (Machine, Machine) {
    let a = Machine::open("machine-a", 0);
    let b = Machine::open_joined("machine-b", B_ID_OFFSET, &a);
    let node_a = doors::node_id(&a.vault).unwrap();
    let node_b = doors::node_id(&b.vault).unwrap();
    assert_ne!(node_a, node_b, "the two machines mint distinct node ids");
    elect(&[&a, &b], node_b);
    (a, b)
}

/// How A funds the run's launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Funding {
    /// A hard carve of [`RUN_BUDGET`] under root scope R, cap [`ROOT_CAP`].
    Carve,
    /// A hard budget of [`RUN_BUDGET`] pinned outside any tree.
    Pinned,
}

/// On A: dispatches one agent run X with a hard budget of 60, funded as
/// `funding` (under root scope R with cap 100 opened first, or pinned), and
/// spends `spent_on_a` of it. Answers X.
fn dispatch_run(a: &Machine, funding: Funding, spent_on_a: u64) -> AttemptId {
    let dispatcher = AgentDispatcher::new(&a.vault);
    let root = SpendScopeId::launch(ROOT).unwrap();
    let spawn = AgentSpawnContext::default()
        .with_budget(RUN_BUDGET)
        .with_depth_remaining(1);
    let (spawn, parent) = match funding {
        Funding::Carve => {
            let opened_root = dispatcher
                .open_root_spend_scope(
                    root.clone(),
                    DeclaredMaximum {
                        units: ROOT_CAP,
                        unit: LeaseUnit::tokens(),
                    },
                    Some(MaximumShown {
                        at_ms: T0.saturating_mul(1000),
                    }),
                    T0,
                )
                .unwrap();
            assert!(opened_root.hard, "the root is a hard cap");
            (
                spawn.with_spend(SpawnSpend {
                    scope: root.clone(),
                }),
                Some(root),
            )
        }
        Funding::Pinned => (spawn, None),
    };
    let (agent, _) = a
        .vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .unwrap()
        .unwrap();
    let AgentDispatchOutcome::Dispatched(status) = dispatcher
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(RUN_ID.to_owned()),
                now: T0,
            },
            spawn,
        )
        .unwrap()
    else {
        panic!("the metered root run dispatches");
    };
    let x = status.attempt.id;
    let launch = status.input.launch.as_ref().unwrap();
    assert_eq!(launch.parent_scope, parent);
    assert_eq!(launch.reserved_units, RUN_BUDGET);
    assert_eq!(launch.cap_units, Some(RUN_BUDGET));
    let scope_id = SpendScopeId::for_attempt(&x);
    let opened = dispatcher.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(opened.parent, parent);
    assert_eq!(opened.state, SpendState::Open);
    assert_eq!(opened.cap_units, RUN_BUDGET);
    assert!(opened.hard, "the run's scope is hard");
    assert_eq!(opened.spent_units, 0);
    if spent_on_a > 0 {
        dispatcher.charge(&scope_id, spent_on_a).unwrap();
    }
    x
}

/// A releases its run lease as a closing process does, which stamps A's
/// share on the run TASK. The TASK then rides the shared window to B, whose
/// clock moves past the released lease. `x` is the run A dispatched: B must
/// count the TASK A wrote, or the take re-creates nothing.
fn release_to_b(a: &Machine, b: &Machine, x: AttemptId) {
    // A closing process releases the one lease it holds; 0 would mean no run
    // TASK was minted for the dispatch.
    assert_eq!(a.vault.release_agent_run_leases().unwrap(), 1);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    b.clock.set(T0 + 2);
    let machine_a = a
        .vault
        .local_machine()
        .expect("FIXTURE: A's machine reads")
        .expect("FIXTURE: A has a machine")
        .id;
    assert_eq!(
        agent_run_task_writer(&a.vault, x).expect("FIXTURE: A's TASK writer reads"),
        Some(machine_a),
        "FIXTURE: A's TASK carries A's proof"
    );
    assert_eq!(
        agent_run_task_writer(&b.vault, x).expect("FIXTURE: B's TASK writer reads"),
        Some(machine_a),
        "FIXTURE: B counts a TASK A wrote"
    );
}

/// On A: dispatches one agent run X as a hard carve of 60 under root scope R
/// (cap 100), spends `spent_on_a` of it, and releases it to B. Answers X.
fn dispatched_run(a: &Machine, b: &Machine, spent_on_a: u64) -> AttemptId {
    let x = dispatch_run(a, Funding::Carve, spent_on_a);
    release_to_b(a, b, x);
    x
}

#[test]
fn taker_reserves_only_the_remainder() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    let scope = AgentDispatcher::new(&b.vault)
        .read_spend_scope(&SpendScopeId::for_attempt(&x))
        .unwrap()
        .unwrap();
    assert_eq!(scope.parent, None);
    assert!(scope.hard, "the taker's scope is pinned hard");
    // On main this is 60 (launch.rs:219-222 pins the whole reservation again).
    assert_eq!(scope.cap_units, 40);
    assert_eq!(scope.spent_units, 0);
}

#[test]
fn taker_waits_when_the_reservation_is_spent() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 60);
    // On main B takes and pins 60; with the carry it waits and holds nothing.
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 0);
    assert_eq!(reap.waiting, 1);
    assert!(
        AgentDispatcher::new(&b.vault)
            .read_spend_scope(&SpendScopeId::for_attempt(&x))
            .unwrap()
            .is_none(),
        "B holds no scope for a run whose reservation is spent"
    );
}

#[test]
fn taker_leaves_out_what_open_children_hold() {
    let (a, b) = machines();
    let x = dispatch_run(&a, Funding::Carve, 20);
    // X spawned a child that is still open: a hard carve of 25 under X, of
    // which the child spent 15. X's own row still reads spent 20; the child's
    // spend reaches it only when the child settles.
    let x_scope = SpendScopeId::for_attempt(&x);
    let child = AttemptId::from_bytes(&[0xc5; 16]).unwrap();
    reserve_child_scope(&a.vault, &x_scope, &child, 25, T0).unwrap();
    let dispatcher = AgentDispatcher::new(&a.vault);
    dispatcher
        .charge(&SpendScopeId::for_attempt(&child), 15)
        .unwrap();
    let x_row = dispatcher.read_spend_scope(&x_scope).unwrap().unwrap();
    assert_eq!(x_row.spent_units, 20);
    assert_eq!(x_row.held_units, 25);
    release_to_b(&a, &b, x);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    let scope = AgentDispatcher::new(&b.vault)
        .read_spend_scope(&x_scope)
        .unwrap()
        .unwrap();
    assert_eq!(scope.parent, None);
    assert!(scope.hard, "the taker's scope is pinned hard");
    // A committed 45 of the 60: its own 20 and the child's whole carve of 25,
    // which the child keeps and may still spend. On aaf6deff B pins 40: A's
    // share counted X's spent 20 alone.
    assert_eq!(scope.cap_units, 15);
}

/// On A: dispatches X pinned at 60, spends 20 of it and releases it to B;
/// B takes it under a fresh scope, spends `spent_on_b` and releases it back.
/// A's own try never ran, so it is still queued on A. Answers X.
fn pinned_run_back_from_b(a: &Machine, b: &Machine, spent_on_b: u64) -> AttemptId {
    let x = dispatch_run(a, Funding::Pinned, 20);
    release_to_b(a, b, x);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(x, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims the run it took"
    );
    AgentDispatcher::new(&b.vault)
        .charge(&SpendScopeId::for_attempt(&x), spent_on_b)
        .unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's take, claim and release reach B's doc before the exchange carries
    // them to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // B is the elected home, so A takes after the non-home grace.
    a.vault.resume_executor_leases();
    a.clock.set(T0 + 400);
    x
}

#[test]
fn kept_queued_try_takes_only_the_remainder() {
    let (a, b) = machines();
    let x = pinned_run_back_from_b(&a, &b, 30);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "A takes the run back with its queued try");
    let x_scope = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&SpendScopeId::for_attempt(&x))
        .unwrap()
        .unwrap();
    assert_eq!(x_scope.state, SpendState::Open);
    let room = x_scope.cap_units - x_scope.spent_units - x_scope.held_units;
    // A spent 20 and B 30 of the 60, so 10 is left: A is the custody
    // machine, so B's 30 folds into its kept scope (spent 50 of 60); PR 1
    // alone caps the scope at 30. On 3b746e51 it keeps its cap of 60 at spent
    // 20: A may spend 40 more, 90 of the 60.
    assert_eq!(room, 10);
}

#[test]
fn kept_queued_try_waits_when_the_launch_is_spent() {
    let (a, b) = machines();
    // B spends the whole 40 its take pinned, so the 60 is spent.
    let x = pinned_run_back_from_b(&a, &b, 40);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    // On 3b746e51 A takes the run back and keeps its cap of 60: 40 more, 100
    // of the 60.
    assert_eq!(reap.taken, 0, "A waits: nothing of the launch is left");
    let x_scope = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&SpendScopeId::for_attempt(&x))
        .unwrap()
        .unwrap();
    assert_eq!(
        x_scope.cap_units, RUN_BUDGET,
        "the waiting take writes nothing"
    );
}

#[test]
fn take_back_counts_the_takers_earlier_spend() {
    let (a, b) = machines();
    let x = dispatch_run(&a, Funding::Pinned, 20);
    release_to_b(&a, &b, x);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    let x_scope = SpendScopeId::for_attempt(&x);
    let on_b = AgentDispatcher::new(&b.vault)
        .read_spend_scope(&x_scope)
        .unwrap()
        .unwrap();
    assert_eq!(on_b.cap_units, 40);
    // B's take reaches B's doc before the exchange carries it to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(x, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims the run it took"
    );
    AgentDispatcher::new(&b.vault).charge(&x_scope, 20).unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's release reaches B's doc before the exchange carries it to A.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // B is the elected home, so A takes after the non-home grace: held_until
    // T0+2 plus 300 seconds.
    a.clock.set(T0 + 400);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "A takes the run back");
    let successor = AttemptQueue::new(&a.vault)
        .list_run(RUN_ID)
        .unwrap()
        .into_iter()
        .find(|record| record.retry_of == Some(x))
        .expect("A's take queues a successor of its stood-down try");
    let dispatcher = AgentDispatcher::new(&a.vault);
    let scope_id = dispatcher
        .spend_scope_for_attempt(successor.id)
        .unwrap()
        .expect("A's successor spends metered");
    let scope = dispatcher.read_spend_scope(&scope_id).unwrap().unwrap();
    let room = scope.cap_units - scope.spent_units - scope.held_units;
    // A spent 20 and B 20 of the 60, so 20 is left. On aaf6deff A's take
    // pins 60 less B's 20, and its stamp puts its fresh scope's 0 in place of
    // its own 20: A may spend 40 more, 80 of the 60.
    assert_eq!(room, 20);
}

#[test]
fn handed_over_run_keeps_one_counter() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    // B's take rides the window to A; A resumes from its close so its pump
    // judges the run instead of passing over it.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    let claimed = AgentDispatcher::new(&b.vault)
        .claim_agent_run(x, "pump-b", T0 + 2)
        .unwrap()
        .expect("B claims the run it took");
    let scope_id = SpendScopeId::for_attempt(&x);
    AgentDispatcher::new(&b.vault)
        .charge(&scope_id, 30)
        .unwrap();
    let leased = claimed.status.attempt;
    // B finishes the run through the agent launch's own completion door, which
    // settles B's share in the commit and leaves the write for sync to carry.
    DreamerRunnerStore::new(&b.vault)
        .complete(CompleteDreamerAttempt {
            id: x,
            lease_owner: "pump-b".to_owned(),
            attempt_count: leased.attempt_count,
            now: leased.updated_at,
        })
        .unwrap();
    // B's settlement reaches B's doc before the exchange carries it to A.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // PR 1's head has no `reconcile_handed_over_spend`; there A's stand-down
    // settled X at 20, so R spent 20 and free 80.
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 1);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 0);
    let root = SpendScopeId::launch(ROOT).unwrap();
    let r = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&root)
        .unwrap()
        .unwrap();
    // PR 1 head: spent 20 (X settled at 20 on stand-down).
    assert_eq!(r.spent_units, 50);
    let free = r.cap_units - r.spent_units - r.held_units;
    // PR 1 head: free 80.
    assert_eq!(free, 50);
    let x_scope = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&scope_id)
        .unwrap()
        .unwrap();
    // PR 1 head: spent 20 (settled at stand-down, before B's 30).
    assert_eq!(x_scope.spent_units, 50);
    assert_eq!(x_scope.state, SpendState::Closed);
}

#[test]
fn old_machine_standdown_keeps_the_remainder_held() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    // B's take reaches B's doc before the exchange carries it to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    let scope_id = SpendScopeId::for_attempt(&x);
    let x_scope = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&scope_id)
        .unwrap()
        .unwrap();
    // PR 1 head: Closed (stand-down settled it; R free 80).
    assert_eq!(x_scope.state, SpendState::Open);
    assert_eq!(x_scope.spent_units, 20);
    assert_eq!(x_scope.cap_units, RUN_BUDGET);
    let (agent, _) = a
        .vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .unwrap()
        .unwrap();
    let root = SpendScopeId::launch(ROOT).unwrap();
    let second = AgentDispatcher::new(&a.vault).dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("handover-budget-custody-second".to_owned()),
            now: T0,
        },
        AgentSpawnContext::default()
            .with_spend(SpawnSpend {
                scope: root.clone(),
            })
            .with_budget(50)
            .with_depth_remaining(1),
    );
    // PR 1 head: Ok (R free 80, so the 50 carve fits).
    assert!(
        second.is_err(),
        "a 50 carve does not fit in R free 40 while X holds its carve"
    );
    // The refusal is R's room, not the second launch itself: a 30 carve fits.
    let third = AgentDispatcher::new(&a.vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("handover-budget-custody-third".to_owned()),
                now: T0,
            },
            AgentSpawnContext::default()
                .with_spend(SpawnSpend { scope: root })
                .with_budget(30)
                .with_depth_remaining(1),
        )
        .unwrap();
    assert!(
        matches!(third, AgentDispatchOutcome::Dispatched(_)),
        "a 30 carve fits in R free 40"
    );
}

#[test]
fn run_back_home_reopens_the_same_scope() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    // B's take reaches B's doc before the exchange carries it to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(x, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims the run it took"
    );
    AgentDispatcher::new(&b.vault)
        .charge(&SpendScopeId::for_attempt(&x), 30)
        .unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's release reaches B's doc before the exchange carries it to A.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // B is the elected home, so A takes after the non-home grace: held_until
    // T0+2 plus 300 seconds.
    a.clock.set(T0 + 400);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "A takes the run back");
    let scope_id = SpendScopeId::for_attempt(&x);
    let x_scope = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&scope_id)
        .unwrap()
        .unwrap();
    assert_eq!(x_scope.scope, scope_id);
    // PR 1 head: Closed (stand-down settled it, so the take keeps no open scope).
    assert_eq!(x_scope.state, SpendState::Open);
    // PR 1 head: spent 20 (settled at stand-down, B's 30 never folded).
    assert_eq!(x_scope.spent_units, 50);
    assert_eq!(x_scope.cap_units, RUN_BUDGET);
    let root = SpendScopeId::launch(ROOT).unwrap();
    assert_eq!(x_scope.parent, Some(root));
}

#[test]
fn queued_take_back_folds_the_other_share() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(x, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims the run it took"
    );
    let scope_id = SpendScopeId::for_attempt(&x);
    AgentDispatcher::new(&b.vault)
        .charge(&scope_id, 30)
        .unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's take, claim and release reach B's doc before the exchange carries
    // them to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // A's try never ran, so it is still queued here and A's take keeps it.
    // B is the elected home, so A takes after the non-home grace.
    a.vault.resume_executor_leases();
    a.clock.set(T0 + 400);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "A takes the run back with its queued try");
    let x_scope = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&scope_id)
        .unwrap()
        .unwrap();
    assert_eq!(x_scope.state, SpendState::Open);
    assert_eq!(x_scope.cap_units, RUN_BUDGET);
    // B's 30 folds into X, so 10 of the 60 is left. On a5195622 the take of a
    // queued try judged nothing: X stays at spent 20 with 40 left, 90 of 60.
    assert_eq!(x_scope.spent_units, 50);
}

#[test]
fn child_that_outlives_the_run_is_charged_what_it_spent() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    // B's take reaches B's doc before the exchange carries it to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    let claimed = AgentDispatcher::new(&b.vault)
        .claim_agent_run(x, "pump-b", T0 + 2)
        .unwrap()
        .expect("B claims the run it took");
    let scope_id = SpendScopeId::for_attempt(&x);
    let on_b = AgentDispatcher::new(&b.vault);
    on_b.charge(&scope_id, 10).unwrap();
    // B's run spawns a child that outlives it: a hard carve of 30 under B's
    // scope, still open when the run completes.
    let child = AttemptId::from_bytes(&[0xc7; 16]).unwrap();
    reserve_child_scope(&b.vault, &scope_id, &child, 30, T0 + 2).unwrap();
    let leased = claimed.status.attempt;
    DreamerRunnerStore::new(&b.vault)
        .complete(CompleteDreamerAttempt {
            id: x,
            lease_owner: "pump-b".to_owned(),
            attempt_count: leased.attempt_count,
            now: leased.updated_at,
        })
        .unwrap();
    // B's settlement reaches B's doc before the exchange carries it to A.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // B's share is 40, of which the child holds 30: A's scope waits. On
    // 1cc56903 A settles X at 60 (its 20, B's 10 and the child's whole 30)
    // and R is charged 60.
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 0);
    let root = SpendScopeId::launch(ROOT).unwrap();
    let on_a = AgentDispatcher::new(&a.vault);
    let x_scope = on_a.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(x_scope.state, SpendState::Open);
    assert_eq!(x_scope.spent_units, 20);
    let r = on_a.read_spend_scope(&root).unwrap().unwrap();
    assert_eq!(r.held_units, RUN_BUDGET, "R goes on holding X's carve");
    // The child spends 5 of its carve and settles on B; B, the run's last
    // executor, stamps its share again (spent 15, nothing held), once.
    on_b.charge(&SpendScopeId::for_attempt(&child), 5).unwrap();
    on_b.settle_child(&child, T0 + 3).unwrap();
    assert_eq!(b.vault.reconcile_handed_over_spend().unwrap(), 1);
    assert_eq!(b.vault.reconcile_handed_over_spend().unwrap(), 0);
    // B's stamp reaches B's doc before the exchange carries it to A.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 1);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 0);
    let x_scope = on_a.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(x_scope.state, SpendState::Closed);
    assert_eq!(x_scope.spent_units, 35);
    let r = on_a.read_spend_scope(&root).unwrap().unwrap();
    // A's 20, B's 10 and the child's 5; the child's unspent 25 is free again.
    assert_eq!(r.spent_units, 35);
    assert_eq!(r.cap_units - r.spent_units - r.held_units, 65);
}

#[test]
fn queued_take_back_stamps_the_kept_scope() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    let claimed = AgentDispatcher::new(&b.vault)
        .claim_agent_run(x, "pump-b", T0 + 2)
        .unwrap()
        .expect("B claims the run it took");
    let leased = claimed.status.attempt;
    // B's try retries as a new try, which B claims: the TASK's live try is
    // one A's queue never holds.
    let RetryOutcome::Retried(retry) = AttemptQueue::new(&b.vault)
        .retry(RetryAttempt {
            id: x,
            lease_owner: "pump-b".to_owned(),
            attempt_count: leased.attempt_count,
            backoff_until: T0 + 2,
            last_error: Some("again".to_owned()),
            now: T0 + 2,
        })
        .unwrap()
    else {
        panic!("the retry schedules a new try");
    };
    assert_ne!(retry.id, x);
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(retry.id, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims its retry"
    );
    // The retry spends under the scope of the try it retries.
    AgentDispatcher::new(&b.vault)
        .charge(&SpendScopeId::for_attempt(&x), 30)
        .unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's take, claims and release reach B's doc before the exchange carries
    // them to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // A's try never ran, so it is still queued here and A's take keeps it.
    // B is the elected home, so A takes after the non-home grace.
    a.vault.resume_executor_leases();
    a.clock.set(T0 + 400);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "A takes the run back with its queued try");
    let x_scope = AgentDispatcher::new(&a.vault)
        .read_spend_scope(&SpendScopeId::for_attempt(&x))
        .unwrap()
        .unwrap();
    assert_eq!(x_scope.spent_units, 50, "B's 30 folds into X");
    // A spent 20 and B 30, so 50 of the 60 is committed and a fresh take
    // reserves 10. On 1cc56903 the take stamps no share for X, as the live
    // try is B's retry: A's share stays at 20 while the fold of 30 counts
    // against the shares, so 20 reads committed and a fresh take reserves 40.
    assert_eq!(agent_run_committed_units(&a.vault, x).unwrap(), Some(50));
}

#[test]
fn take_back_after_a_retry_keeps_the_custody_scope() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    // B's take reaches B's doc before the exchange carries it to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    let claimed = AgentDispatcher::new(&b.vault)
        .claim_agent_run(x, "pump-b", T0 + 2)
        .unwrap()
        .expect("B claims the run it took");
    let leased = claimed.status.attempt;
    // B's try retries as a new try, which B claims: the TASK's live try is
    // one A's queue never holds, and A has no try of the run pending.
    let RetryOutcome::Retried(retry) = AttemptQueue::new(&b.vault)
        .retry(RetryAttempt {
            id: x,
            lease_owner: "pump-b".to_owned(),
            attempt_count: leased.attempt_count,
            backoff_until: T0 + 2,
            last_error: Some("again".to_owned()),
            now: T0 + 2,
        })
        .unwrap()
    else {
        panic!("the retry schedules a new try");
    };
    assert_ne!(retry.id, x);
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(retry.id, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims its retry"
    );
    AgentDispatcher::new(&b.vault)
        .charge(&SpendScopeId::for_attempt(&x), 30)
        .unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's claims, retry and release reach B's doc before the exchange
    // carries them to A.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // B is the elected home, so A takes after the non-home grace.
    a.clock.set(T0 + 400);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "A takes the run back under B's retry");
    // The try A queues links the run's original try, so its retry chain
    // reaches X: the take keeps X and folds B's 30 into it, and no second
    // carve stands under R.
    let on_a = AgentDispatcher::new(&a.vault);
    let x_scope = on_a
        .read_spend_scope(&SpendScopeId::for_attempt(&x))
        .unwrap()
        .unwrap();
    assert_eq!(x_scope.state, SpendState::Open);
    assert_eq!(x_scope.spent_units, 50, "B's 30 folds into X");
    assert!(
        on_a.read_spend_scope(&SpendScopeId::for_attempt(&retry.id))
            .unwrap()
            .is_none(),
        "A opens no scope under B's retry"
    );
    let root = SpendScopeId::launch(ROOT).unwrap();
    let r = on_a.read_spend_scope(&root).unwrap().unwrap();
    assert_eq!(r.held_units, RUN_BUDGET, "R holds X's one carve");
}

#[test]
fn take_back_keeps_a_foreign_child_hold_out_of_the_room() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(x, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims the run it took"
    );
    let scope_id = SpendScopeId::for_attempt(&x);
    AgentDispatcher::new(&b.vault)
        .charge(&scope_id, 10)
        .unwrap();
    // B's run spawns a child that goes on after B lets the run go: a hard
    // carve of 20 under B's scope.
    let child = AttemptId::from_bytes(&[0xc8; 16]).unwrap();
    reserve_child_scope(&b.vault, &scope_id, &child, 20, T0 + 2).unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's take, claim, carve and release reach B's doc before the exchange
    // carries them to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    // A's try never ran, so it is still queued here and A's take keeps it.
    // B is the elected home, so A takes after the non-home grace.
    a.vault.resume_executor_leases();
    a.clock.set(T0 + 400);
    let reap = a
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "A takes the run back with its queued try");
    let on_a = AgentDispatcher::new(&a.vault);
    let x_scope = on_a.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(x_scope.state, SpendState::Open);
    // B's 10 and the child's hold of 20 fold as spent, so 10 of the 60 is
    // left. On e95e4153 only B's 10 folds (spent 30), and A may spend 30
    // while the child may still spend its 20: 80 of 60.
    assert_eq!(x_scope.spent_units, 50);
    assert!(
        on_a.charge(&scope_id, 15).is_err(),
        "A's spend stays out of the child's room"
    );
    on_a.charge(&scope_id, 10).unwrap();
}

#[test]
fn child_on_a_machine_that_lost_the_run_is_charged_what_it_spent() {
    let (a, b) = machines();
    let c = Machine::open_joined("machine-c", 2 * B_ID_OFFSET, &a);
    let node_b = doors::node_id(&b.vault).unwrap();
    assert_ne!(doors::node_id(&c.vault).unwrap(), node_b);
    elect(&[&c], node_b);
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    // B's take reaches B's doc before the exchange carries it to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    assert!(
        AgentDispatcher::new(&b.vault)
            .claim_agent_run(x, "pump-b", T0 + 2)
            .unwrap()
            .is_some(),
        "B claims the run it took"
    );
    let scope_id = SpendScopeId::for_attempt(&x);
    let on_b = AgentDispatcher::new(&b.vault);
    on_b.charge(&scope_id, 10).unwrap();
    // B's run spawns a child that goes on after B lets the run go: a hard
    // carve of 10 under B's scope.
    let child = AttemptId::from_bytes(&[0xc9; 16]).unwrap();
    reserve_child_scope(&b.vault, &scope_id, &child, 10, T0 + 2).unwrap();
    assert_eq!(b.vault.release_agent_run_leases().unwrap(), 1);
    // B's claim, carve and release reach B's doc before the exchange
    // carries them to C.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_b = b.doc();
    let doc_c = c.doc();
    exchange(&doc_b, &doc_c);
    // B is the elected home, so C takes after the non-home grace. C pins
    // the launch's 60 less A's 20 and B's 20 (10 spent, 10 held).
    c.clock.set(T0 + 400);
    let reap = c
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "C takes the run B released");
    let claimed = AgentDispatcher::new(&c.vault)
        .claim_agent_run(x, "pump-c", T0 + 400)
        .unwrap()
        .expect("C claims the run it took");
    AgentDispatcher::new(&c.vault).charge(&scope_id, 5).unwrap();
    let leased = claimed.status.attempt;
    DreamerRunnerStore::new(&c.vault)
        .complete(CompleteDreamerAttempt {
            id: x,
            lease_owner: "pump-c".to_owned(),
            attempt_count: leased.attempt_count,
            now: leased.updated_at,
        })
        .unwrap();
    // C's settlement reaches C's doc before the exchanges carry it to B and
    // on to A.
    drop(doc_b);
    drop(doc_c);
    reload_window(&c);
    let doc_a = a.doc();
    let doc_b = b.doc();
    let doc_c = c.doc();
    exchange(&doc_b, &doc_c);
    exchange(&doc_a, &doc_b);
    // B's share still holds 10 for its child: A's scope waits. On e95e4153
    // the wait asks only C, the last executor, and A settles X at 35 (A's
    // 20, B's 10 and C's 5) at once; the child's later spend never lands.
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 0);
    let root = SpendScopeId::launch(ROOT).unwrap();
    let on_a = AgentDispatcher::new(&a.vault);
    let x_scope = on_a.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(x_scope.state, SpendState::Open);
    assert_eq!(x_scope.spent_units, 20);
    let r = on_a.read_spend_scope(&root).unwrap().unwrap();
    assert_eq!(r.held_units, RUN_BUDGET, "R goes on holding X's carve");
    // The child spends 5 of its carve and settles on B. B, which lost the
    // run, stamps its share again on the settled TASK (spent 15, nothing
    // held), once. B's clock is past C's settlement, as a later write's.
    b.clock.set(T0 + 500);
    on_b.charge(&SpendScopeId::for_attempt(&child), 5).unwrap();
    on_b.settle_child(&child, T0 + 500).unwrap();
    assert_eq!(b.vault.reconcile_handed_over_spend().unwrap(), 1);
    assert_eq!(b.vault.reconcile_handed_over_spend().unwrap(), 0);
    // B's stamp reaches B's doc before the exchange carries it to A.
    drop(doc_a);
    drop(doc_b);
    drop(doc_c);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 1);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 0);
    let x_scope = on_a.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(x_scope.state, SpendState::Closed);
    assert_eq!(x_scope.spent_units, 40);
    let r = on_a.read_spend_scope(&root).unwrap().unwrap();
    // A's 20, B's 10, the child's 5 and C's 5.
    assert_eq!(r.spent_units, 40);
    assert_eq!(r.cap_units - r.spent_units - r.held_units, 60);
}

#[test]
fn hold_still_named_after_the_wait_folds_as_spent() {
    let (a, b) = machines();
    let x = dispatched_run(&a, &b, 20);
    let reap = b
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)
        .unwrap();
    assert_eq!(reap.taken, 1, "B takes the run A released");
    // B's take reaches B's doc before the exchange carries it to A.
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    a.vault.resume_executor_leases();
    let claimed = AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "pump-a", T0)
        .unwrap();
    assert!(claimed.is_none(), "A stands down: B holds the run");
    let claimed = AgentDispatcher::new(&b.vault)
        .claim_agent_run(x, "pump-b", T0 + 2)
        .unwrap()
        .expect("B claims the run it took");
    let scope_id = SpendScopeId::for_attempt(&x);
    AgentDispatcher::new(&b.vault)
        .charge(&scope_id, 10)
        .unwrap();
    // B's run spawns a child that outlives it and never settles, as on a
    // machine that left: a hard carve of 30 under B's scope.
    let child = AttemptId::from_bytes(&[0xca; 16]).unwrap();
    reserve_child_scope(&b.vault, &scope_id, &child, 30, T0 + 2).unwrap();
    let leased = claimed.status.attempt;
    DreamerRunnerStore::new(&b.vault)
        .complete(CompleteDreamerAttempt {
            id: x,
            lease_owner: "pump-b".to_owned(),
            attempt_count: leased.attempt_count,
            now: leased.updated_at,
        })
        .unwrap();
    // B's settlement reaches B's doc before the exchange carries it to A.
    drop(doc_a);
    drop(doc_b);
    reload_window(&b);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 0);
    // Two days on, the child's hold is still named: A folds it as spent and
    // settles X. On e95e4153 A waits on it for good, and R holds X's carve
    // for good.
    a.clock.set(T0 + 2 * 24 * 60 * 60);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 1);
    assert_eq!(a.vault.reconcile_handed_over_spend().unwrap(), 0);
    let on_a = AgentDispatcher::new(&a.vault);
    let x_scope = on_a.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(x_scope.state, SpendState::Closed);
    // A's 20, B's 10 and the child's whole carve of 30.
    assert_eq!(x_scope.spent_units, 60);
    let root = SpendScopeId::launch(ROOT).unwrap();
    let r = on_a.read_spend_scope(&root).unwrap().unwrap();
    assert_eq!(r.spent_units, 60);
    assert_eq!(r.held_units, 0, "R holds X's carve no longer");
}
