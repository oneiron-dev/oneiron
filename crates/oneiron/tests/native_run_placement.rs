//! Native-run placement (pass 34 row P4, DESIGN 4.8; canon CROSS-ARCH-0019
//! "Where work runs", items 02, 03 and 05): a root agent run's first claim
//! places it among the machines whose `machines.work_roles` names `agents`
//! and the home, by the rule `role_warm_waste_headroom@1` read for a run;
//! the placed machine takes it at once, and the home takes it after
//! `policy.slots.place_grace_ms` when the placed machine does not. With no
//! machine tagged, nothing is placed and the run runs where it was
//! dispatched. Review round 1 of #10505: a run a claim already took is never
//! placed; a pick of the dispatching machine orders no taker; a placed
//! machine that takes no new work at its turn leaves the run; every other
//! machine waits past the home's turn; the grace runs from the placement's
//! write, after the decider's ask.
//!
//! Three machines of one vault, each with its own live window manager, as
//! `handover_budget_custody.rs` runs two: A dispatches, B is tagged with
//! more room, H is the elected home. Each declares its home candidacy, and
//! the authority histories are exchanged, so A reads every machine's node
//! id; capacity records are written on A as sync brings them.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test native_run_placement`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::{Duration, Instant};

use loro::{ExportMode, LoroDoc};
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AGENTS_ROLE, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerRunnerStore};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::machine_capacity::{MachineCapacity, MachinePower};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::{IdGen, ManualClock};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::test_doors::run_placement::{placement, record_capacity_of};
use oneiron::test_doors::turn_programs as doors;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::work_order::PLACE_RULE;
use oneiron::work_order::decider::{
    DECIDER_VERB, DeciderReceipt, DeciderReply, SlotAsk, SlotSubject,
};
use oneiron::work_order::record::DecidedBy;
use oneiron::{AttemptId, EntityId, ErrorKind, HnswConfig, Vault, VaultConfig};
use serde_json::json;

/// The base window every row here lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;
/// The run id every run here dispatches under.
const RUN_ID: &str = "native-run-placement";
/// How many ids machine B's and machine H's clocks hand out before their
/// vaults open, far apart, so no machine's ids recur on another.
const B_ID_OFFSET: u64 = 1 << 20;
const H_ID_OFFSET: u64 = 1 << 21;
/// `policy.slots.place_grace_ms`'s default, in the lease's seconds.
const PLACE_GRACE_SECS: u64 = 120;
/// The handover grace other machines wait (`run_handover`), in seconds.
const HANDOVER_GRACE_SECS: u64 = 300;

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

/// The host secret every machine roots under: one host, one genesis (A's).
/// B and H join by importing A's history, so their host roots reuse A's
/// genesis instead of minting their own.
const HOST_SECRET: &[u8] = b"native run placement test host";

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

/// Every machine elects `home` as the MACRO home.
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
    // testkit-lint: allow(wall-clock) the mirror thread's pass runs in real time, which no fake clock reaches
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match machine.manager.unload_window(&key) {
            Ok(_) => break,
            // testkit-lint: allow(wall-clock) the same real-time bound on the busy unload
            Err(err) if err.kind() == ErrorKind::WindowBusy && Instant::now() < deadline => {
                // testkit-lint: allow(sleep) waits out the mirror thread's pass, as handover_budget_custody.rs does
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("the window does not unload: {err:?}"),
        }
    }
    machine.manager.open_window(&key).unwrap();
}

/// Every authority row `from` holds, landed on `to` (as
/// `restored_machine_join_guards.rs` lands them).
fn sync_authority(from: &Vault, to: &Vault) {
    let history = from
        .export_signed_authority_history()
        .expect("FIXTURE: export authority history");
    to.import_signed_authority_history(&history)
        .expect("FIXTURE: import authority history");
}

/// The MACHINE of `machine`'s install.
fn machine_id(machine: &Machine) -> EntityId {
    machine
        .vault
        .local_machine()
        .expect("FIXTURE: the install's machine reads")
        .expect("FIXTURE: the install has a machine")
        .id
}

/// The three machines: A dispatches; B and H are joined to A. Each declares
/// its home candidacy, every machine holds every authority history, and H
/// is the elected home on all three.
struct Rack {
    a: Machine,
    b: Machine,
    h: Machine,
}

fn rack() -> Rack {
    let a = Machine::open("machine-a", 0);
    let b = Machine::open_joined("machine-b", B_ID_OFFSET, &a);
    let h = Machine::open_joined("machine-h", H_ID_OFFSET, &a);
    for machine in [&a, &b, &h] {
        machine
            .vault
            .declare_home_candidacy(true, false, true)
            .expect("FIXTURE: the machine declares its home candidacy");
    }
    for from in [&b, &h] {
        sync_authority(&from.vault, &a.vault);
    }
    for to in [&b, &h] {
        sync_authority(&a.vault, &to.vault);
    }
    let node_h = doors::node_id(&h.vault).unwrap();
    elect(&[&a, &b, &h], node_h);
    Rack { a, b, h }
}

/// The owner sets `key` for `machine` to `value` on `vault`.
fn set_machine_policy(vault: &Vault, machine: EntityId, key: &str, value: serde_json::Value) {
    let change = SetSetting {
        item: Some(machine.to_hex()),
        ..SetSetting::vault_value(key, value)
    };
    let outcome = vault
        .set_setting(SettingCaller::Owner(&owner_proof(vault)), change)
        .expect("FIXTURE: the owner's machine policy");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's {key} applies: {outcome:?}"
    );
}

/// A capacity record that can run `agents` agents, with no GPU, on mains.
fn capacity(agents: u64) -> MachineCapacity {
    MachineCapacity {
        cores: 16,
        memory_total_bytes: 32 << 30,
        memory_reserve_bytes: 4 << 30,
        memory_available_bytes: 16 << 30,
        gpu_memory_mib: Vec::new(),
        gpus: Vec::new(),
        disk_total_bytes: 1 << 40,
        disk_free_bytes: 1 << 39,
        power: MachinePower::Mains,
        agent_memory_budget_bytes: 1 << 29,
        agents,
        measured_at: T0,
    }
}

/// On A: B and H tagged `agents`, B able to run 8 agents and H 2, as the
/// owner's panel and the machines' probes leave them on A.
fn tag_b_and_h(r: &Rack) {
    for (machine, agents) in [(machine_id(&r.b), 8), (machine_id(&r.h), 2)] {
        set_machine_policy(
            &r.a.vault,
            machine,
            "machines.work_roles",
            json!([AGENTS_ROLE]),
        );
        record_capacity_of(&r.a.vault, machine, &capacity(agents))
            .expect("FIXTURE: the machine's capacity record");
    }
}

/// On A: dispatches one root agent run with a pinned hard budget. Answers
/// its try.
fn dispatch_on(a: &Machine) -> AttemptId {
    let (agent, _) = a
        .vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .unwrap()
        .unwrap();
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&a.vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(RUN_ID.to_owned()),
                now: T0,
            },
            AgentSpawnContext::default()
                .with_budget(60)
                .with_depth_remaining(1),
        )
        .unwrap()
    else {
        panic!("the root run dispatches");
    };
    status.attempt.id
}

/// A's pump claims the try `x` at `now`: whether it runs it here.
fn a_claims(a: &Machine, x: AttemptId, now: u64) -> bool {
    a.clock.set(now);
    AgentDispatcher::new(&a.vault)
        .claim_agent_run(x, "native-run-placement-pump", now)
        .expect("A's claim")
        .is_some()
}

/// `machine`'s reaper pass at `now`, with the host's own check `runs`:
/// (taken, waiting).
fn reap(machine: &Machine, now: u64, runs: bool) -> (usize, usize) {
    machine.clock.set(now);
    let reap = machine
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| runs)
        .expect("the reaper pass");
    (reap.taken, reap.waiting)
}

/// Brings A's rows to B and to H.
fn sync_from_a(r: &Rack) {
    reload_window(&r.a);
    let doc_a = r.a.doc();
    exchange(&doc_a, &r.b.doc());
    exchange(&doc_a, &r.h.doc());
}

#[test]
fn a_native_run_goes_to_the_placed_machine_and_falls_back_to_the_home() {
    let r = rack();
    tag_b_and_h(&r);
    let x = dispatch_on(&r.a);

    assert!(
        !a_claims(&r.a, x, T0),
        "A leaves the run for the machine it placed it on"
    );
    let (placed, decision) = placement(&r.a.vault, x)
        .expect("the placement reads")
        .expect("the first claim placed the run");
    assert_eq!(
        placed,
        machine_id(&r.b),
        "the rule places the run on B, with more room"
    );
    assert_eq!(decision.pick, machine_id(&r.b).to_hex());
    assert_eq!(
        decision.options,
        vec![machine_id(&r.b).to_hex(), machine_id(&r.h).to_hex()],
        "the candidates are the tagged machines and the home, in the rule's order"
    );
    assert_eq!(
        decision.by,
        DecidedBy::Rule {
            name: PLACE_RULE.to_owned()
        }
    );
    assert_eq!(decision.why, "most room");

    sync_from_a(&r);
    assert_eq!(
        reap(&r.h, T0 + 1, true),
        (0, 1),
        "the home leaves a placed run for the grace"
    );
    assert_eq!(
        reap(&r.b, T0 + 1, true),
        (1, 0),
        "the placed machine takes the run at once"
    );

    // B closes: its release hands the run back by the reaper's own order,
    // and the home takes it at expiry (canon item 03).
    assert_eq!(r.b.vault.release_agent_run_leases().unwrap(), 1);
    reload_window(&r.b);
    exchange(&r.b.doc(), &r.h.doc());
    assert_eq!(
        reap(&r.h, T0 + 2, true),
        (1, 0),
        "the home takes a run its machine closed on"
    );
}

#[test]
fn a_placed_run_the_machine_does_not_take_goes_to_the_home_after_the_grace() {
    let r = rack();
    tag_b_and_h(&r);
    let x = dispatch_on(&r.a);
    assert!(!a_claims(&r.a, x, T0));
    sync_from_a(&r);

    assert_eq!(
        reap(&r.b, T0 + 1, false),
        (0, 1),
        "B's own check declines the run"
    );
    assert_eq!(
        reap(&r.h, T0 + PLACE_GRACE_SECS - 1, true),
        (0, 1),
        "not before the grace"
    );
    assert!(
        !a_claims(&r.a, x, T0 + HANDOVER_GRACE_SECS - 1),
        "the dispatching machine, neither placed nor home, waits past the home's turn"
    );
    assert_eq!(
        reap(&r.h, T0 + PLACE_GRACE_SECS, true),
        (1, 0),
        "the home takes it after the grace"
    );
}

#[test]
fn a_vault_with_no_machine_tagged_for_agents_places_nothing() {
    let r = rack();
    for (machine, agents) in [(machine_id(&r.b), 8), (machine_id(&r.h), 2)] {
        record_capacity_of(&r.a.vault, machine, &capacity(agents)).unwrap();
    }
    let x = dispatch_on(&r.a);
    assert!(
        a_claims(&r.a, x, T0),
        "the run runs where it was dispatched"
    );
    assert_eq!(
        placement(&r.a.vault, x).unwrap(),
        None,
        "nothing is placed or written"
    );
}

#[test]
fn a_machine_the_owner_paused_is_not_placed_on() {
    let r = rack();
    tag_b_and_h(&r);
    set_machine_policy(
        &r.a.vault,
        machine_id(&r.b),
        "machines.execution",
        json!({ "state": "paused" }),
    );
    let x = dispatch_on(&r.a);
    assert!(!a_claims(&r.a, x, T0));
    let (placed, decision) = placement(&r.a.vault, x).unwrap().expect("placed");
    assert_eq!(
        placed,
        machine_id(&r.h),
        "B is paused, so the run goes to the home"
    );
    assert_eq!(decision.options, vec![machine_id(&r.h).to_hex()]);
    assert_eq!(decision.why, "the only machine that fits");

    sync_from_a(&r);
    assert_eq!(
        reap(&r.b, T0 + 1, true),
        (0, 1),
        "B was not placed: it waits the handover grace"
    );
    assert_eq!(
        reap(&r.h, T0 + 1, true),
        (1, 0),
        "the home it was placed on takes it at once"
    );
}

/// The owner of `vault` mints a Grant for a new decider agent, naming `read`
/// and the decision read, and names it to decide PLACE at the vault. Its id.
fn name_place_decider(vault: &Vault) -> EntityId {
    let proof = owner_proof(vault);
    let agent = vault
        .ensure_agent_principal("place-decider")
        .expect("FIXTURE: the decider agent");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(
        ["read", DECIDER_VERB]
            .map(str::to_owned)
            .into_iter()
            .collect(),
    );
    let minted = mint_agent_grant_as(
        vault,
        &proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: Default::default(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("FIXTURE: the decider's Grant")
    .grant;
    assert!(minted.confers, "FIXTURE: the decider's Grant confers");
    let change = SetSetting {
        item: Some("place".to_owned()),
        ..SetSetting::vault_value("policy.slots.decider", json!(minted.grant_ref.to_hex()))
    };
    let outcome = vault
        .set_setting(SettingCaller::Owner(&proof), change)
        .expect("FIXTURE: the owner names the decider");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the decider's naming applies: {outcome:?}"
    );
    minted.grant_ref
}

#[test]
fn a_named_place_decider_picks_among_the_rule_s_candidates_and_the_pick_is_kept() {
    let r = rack();
    tag_b_and_h(&r);
    let grant = name_place_decider(&r.a.vault);
    let x = dispatch_on(&r.a);
    let (b, h) = (machine_id(&r.b).to_hex(), machine_id(&r.h).to_hex());
    let asked = RefCell::new(Vec::new());
    let decide = |ask: &SlotAsk| {
        asked.borrow_mut().push((ask.subject, ask.options.clone()));
        DeciderReply::Answered {
            label: h.clone(),
            receipt: DeciderReceipt::of_read(
                "0".repeat(32),
                vec!["big:fixture-model@1".to_owned()],
                Some("big".to_owned()),
                Some(0.9),
                Some(0.002),
            ),
        }
    };
    r.a.clock.set(T0);
    let claimed = AgentDispatcher::new(&r.a.vault)
        .claim_agent_run_placed(x, "native-run-placement-pump", T0, &decide)
        .expect("A's claim");
    assert!(
        claimed.is_none(),
        "A leaves the run for the machine the decider picked"
    );
    assert_eq!(
        asked.borrow().as_slice(),
        &[(SlotSubject::NativeRun, vec![b, h.clone()])],
        "one native-run ask over the rule's candidates, in the rule's order"
    );
    let (placed, decision) = placement(&r.a.vault, x).unwrap().expect("placed");
    assert_eq!(
        placed,
        machine_id(&r.h),
        "the decider's pick, not the rule's, is the placement"
    );
    assert_eq!(decision.pick, h);
    assert!(
        matches!(&decision.by, DecidedBy::Grant { grant: by, .. } if *by == grant),
        "the decision names the decider: {:?}",
        decision.by
    );
}

/// The owner of `vault` sets how long the home leaves a placed run,
/// `policy.slots.place_grace_ms` for the PLACE slot, to `grace_ms`.
fn set_place_grace(vault: &Vault, grace_ms: u64) {
    let change = SetSetting {
        item: Some("place".to_owned()),
        ..SetSetting::vault_value("policy.slots.place_grace_ms", json!(grace_ms))
    };
    let outcome = vault
        .set_setting(SettingCaller::Owner(&owner_proof(vault)), change)
        .expect("FIXTURE: the owner's place grace");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the place grace applies: {outcome:?}"
    );
}

#[test]
fn a_run_claimed_before_any_machine_is_tagged_is_not_placed_at_a_later_claim() {
    let r = rack();
    let x = dispatch_on(&r.a);
    assert!(
        a_claims(&r.a, x, T0),
        "with no machine tagged, the run runs where it was dispatched"
    );
    tag_b_and_h(&r);
    assert!(
        !a_claims(&r.a, x, T0 + 1),
        "the try is leased here: no second claim takes it"
    );
    assert_eq!(
        placement(&r.a.vault, x).unwrap(),
        None,
        "a run a claim already took is never placed, so it is not moved mid-run"
    );
}

#[test]
fn a_run_placed_on_its_own_machine_hands_over_in_the_reaper_s_order() {
    let r = rack();
    set_machine_policy(
        &r.a.vault,
        machine_id(&r.a),
        "machines.work_roles",
        json!([AGENTS_ROLE]),
    );
    record_capacity_of(&r.a.vault, machine_id(&r.a), &capacity(8))
        .expect("FIXTURE: A's capacity record");
    let x = dispatch_on(&r.a);
    assert!(
        a_claims(&r.a, x, T0),
        "the rule picks A, the dispatching machine, which runs it"
    );
    let (placed, _) = placement(&r.a.vault, x).unwrap().expect("the pick is kept");
    assert_eq!(placed, machine_id(&r.a));

    // A closes: nothing was released to another machine, so the home takes
    // the run at expiry, by the reaper's own order.
    assert_eq!(r.a.vault.release_agent_run_leases().unwrap(), 1);
    reload_window(&r.a);
    exchange(&r.a.doc(), &r.h.doc());
    assert_eq!(
        reap(&r.h, T0 + 2, true),
        (1, 0),
        "a pick of the dispatching machine orders no taker"
    );
}

#[test]
fn a_placed_machine_the_owner_pauses_before_its_take_leaves_the_run_to_the_home() {
    let r = rack();
    tag_b_and_h(&r);
    let x = dispatch_on(&r.a);
    assert!(!a_claims(&r.a, x, T0));
    let (placed, _) = placement(&r.a.vault, x).unwrap().expect("placed");
    assert_eq!(placed, machine_id(&r.b), "the rule places the run on B");
    set_machine_policy(
        &r.a.vault,
        machine_id(&r.b),
        "machines.execution",
        json!({ "state": "paused" }),
    );
    sync_authority(&r.a.vault, &r.b.vault);
    sync_from_a(&r);

    assert_eq!(
        reap(&r.b, T0 + 1, true),
        (0, 1),
        "B, paused after the placement, takes no new work and leaves the run"
    );
    assert_eq!(
        reap(&r.h, T0 + PLACE_GRACE_SECS, true),
        (1, 0),
        "the home takes it after the grace"
    );
}

#[test]
fn other_machines_take_a_placed_run_only_after_the_home_s_turn() {
    const GRACE_SECS: u64 = 600;
    let r = rack();
    tag_b_and_h(&r);
    set_place_grace(&r.a.vault, GRACE_SECS * 1_000);
    sync_authority(&r.a.vault, &r.h.vault);
    let x = dispatch_on(&r.a);
    assert!(!a_claims(&r.a, x, T0), "A places the run on B");
    sync_from_a(&r);

    assert!(
        !a_claims(&r.a, x, T0 + HANDOVER_GRACE_SECS),
        "the dispatching machine does not take it back before the home's longer grace"
    );
    assert_eq!(
        reap(&r.h, T0 + GRACE_SECS - 1, true),
        (0, 1),
        "the home waits its grace"
    );
    assert_eq!(
        reap(&r.h, T0 + GRACE_SECS, true),
        (1, 0),
        "the home takes it at the end of its grace, before any other machine"
    );
}

#[test]
fn the_time_a_decider_takes_is_not_taken_from_the_home_s_grace() {
    const DECIDER_SECS: u64 = 50;
    let r = rack();
    tag_b_and_h(&r);
    name_place_decider(&r.a.vault);
    let x = dispatch_on(&r.a);
    let b = machine_id(&r.b).to_hex();
    let asked = Cell::new(false);
    let decide = |_: &SlotAsk| {
        asked.set(true);
        r.a.clock.set(T0 + DECIDER_SECS);
        DeciderReply::Answered {
            label: b.clone(),
            receipt: DeciderReceipt::of_read(
                "0".repeat(32),
                vec!["big:fixture-model@1".to_owned()],
                Some("big".to_owned()),
                Some(0.9),
                Some(0.002),
            ),
        }
    };
    r.a.clock.set(T0);
    let claimed = AgentDispatcher::new(&r.a.vault)
        .claim_agent_run_placed(x, "native-run-placement-pump", T0, &decide)
        .expect("A's claim");
    assert!(claimed.is_none(), "A leaves the run for B");
    assert!(asked.get(), "FIXTURE: the decider was asked");
    let (placed, _) = placement(&r.a.vault, x).unwrap().expect("placed");
    assert_eq!(placed, machine_id(&r.b));
    sync_from_a(&r);

    assert_eq!(
        reap(&r.h, T0 + PLACE_GRACE_SECS, true),
        (0, 1),
        "the grace runs from the placement's write, after the ask"
    );
    assert_eq!(
        reap(&r.h, T0 + DECIDER_SECS + PLACE_GRACE_SECS, true),
        (1, 0),
        "the home takes it a full grace after the placement"
    );
}
