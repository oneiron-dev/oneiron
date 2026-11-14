//! Handover budget custody, PR 1 (FIX 4889; L8-28): a handed-over agent run
//! carries its spend, and the taker reserves only the remainder.
//!
//! Two machines of one vault, each with its own live window manager, as a
//! host runs them. Machine A dispatches one agent run under a root spend
//! scope with a hard budget, spends part of it, and releases its run lease
//! as a closing process does, which stamps A's share on the run TASK. The
//! TASK rides the shared base window to machine B, the elected MACRO home,
//! which takes the run at expiry: B pins only the launch's reservation less
//! A's share, and waits when nothing is left.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test handover_budget_custody`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpawnSpend, SpendScopeId, SpendState,
};
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::store::ports::{IdGen, ManualClock};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::test_doors::turn_programs as doors;
use oneiron::{AttemptId, HnswConfig, Vault, VaultConfig};

/// The base window every row here lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;
/// The root scope's cap: what the launch's tree holds.
const ROOT_CAP: u64 = 100;
/// The run's hard budget: the carve its launch reserves under the root.
const RUN_BUDGET: u64 = 60;
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

/// One machine: its vault, its clock, and its live window manager.
struct Machine {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
}

impl Machine {
    /// Opens a machine whose clock has handed out `ids_before_open` ids
    /// first. A manual clock mints ids from a counter that starts at 1, so
    /// two machines need distinct offsets: the client id and every row id
    /// each mints then differ, as two real machines' random ids do.
    fn open(user: &str, ids_before_open: u64) -> Self {
        let clock = ManualClock::new(T0);
        for _ in 0..ids_before_open {
            clock.ulid();
        }
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), config(&clock)).unwrap());
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

/// Opens the two machines with distinct node ids and elects B the MACRO home
/// on both, so B takes an expired run at expiry with no grace.
fn machines() -> (Machine, Machine) {
    let a = Machine::open("machine-a", 0);
    let b = Machine::open("machine-b", B_ID_OFFSET);
    let node_a = doors::node_id(&a.vault).unwrap();
    let node_b = doors::node_id(&b.vault).unwrap();
    assert_ne!(node_a, node_b, "the two machines mint distinct node ids");
    elect(&[&a, &b], node_b);
    (a, b)
}

/// On A: opens root scope R with cap 100, dispatches one agent run X under R
/// with a hard budget of 60, spends `spent_on_a` of it, and releases A's run
/// lease as a closing process does, which stamps A's share on the run TASK.
/// The TASK then rides the shared window to B, whose clock moves past the
/// released lease. Answers X.
fn dispatched_run(a: &Machine, b: &Machine, spent_on_a: u64) -> AttemptId {
    let dispatcher = AgentDispatcher::new(&a.vault);
    let root = SpendScopeId::launch("handover-budget-custody-root").unwrap();
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
                run_id: Some("handover-budget-custody".to_owned()),
                now: T0,
            },
            AgentSpawnContext::default()
                .with_spend(SpawnSpend {
                    scope: root.clone(),
                })
                .with_budget(RUN_BUDGET)
                .with_depth_remaining(1),
        )
        .unwrap()
    else {
        panic!("the metered root run dispatches");
    };
    let x = status.attempt.id;
    let launch = status.input.launch.as_ref().unwrap();
    assert_eq!(launch.parent_scope, Some(root.clone()));
    assert!(launch.hard, "the budget carves a hard scope");
    assert_eq!(launch.reserved_units, RUN_BUDGET);
    assert_eq!(launch.cap_units, Some(RUN_BUDGET));
    let scope_id = SpendScopeId::for_attempt(&x);
    let opened = dispatcher.read_spend_scope(&scope_id).unwrap().unwrap();
    assert_eq!(opened.parent, Some(root));
    assert_eq!(opened.state, SpendState::Open);
    assert_eq!(opened.cap_units, RUN_BUDGET);
    assert!(opened.hard, "the run's scope is a hard carve");
    assert_eq!(opened.spent_units, 0);
    if spent_on_a > 0 {
        dispatcher.charge(&scope_id, spent_on_a).unwrap();
    }
    // A closing process releases the one lease it holds; 0 would mean no run
    // TASK was minted for the dispatch.
    assert_eq!(a.vault.release_agent_run_leases().unwrap(), 1);
    let doc_a = a.doc();
    let doc_b = b.doc();
    exchange(&doc_a, &doc_b);
    b.clock.set(T0 + 2);
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
