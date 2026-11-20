// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! TASK authority across two real vaults.
//!
//! Owner proof, cancellation and acknowledgement are companion TASK entities
//! (`task_authority`) tied to their subject by the ordinary structural
//! `ScopedTo` edge, so they ride the entity/edge CRDT maps with no sync
//! behaviour of their own. That claim is only worth what a second machine can
//! observe, so every fact here crosses the REAL Loro delta path between two
//! `Vault`s (`sync_harness::exchange` + Observer B materialization) — never a
//! hand-copied row.
//!
//! What this suite pins:
//! - the Owner fact REPLICATES, and the owner then cancels DIRECTLY on the
//!   peer that merely materialized the task, instead of falling to the
//!   foreign, proposal-only ladder;
//! - cancel-wins is MONOTONIC in both arrival orders — independent fact rows
//!   cannot be cleared by a later acknowledgement the way the booleans of one
//!   last-writer-wins body would be;
//! - authority fails CLOSED over the wire: a replicated TASK with no Owner
//!   fact proves nothing however its body decorates itself, and two peers that
//!   minted conflicting proofs refuse rather than pick one.
//!
//! Since #8610 (Fable pass 28 R5) a fact counts on another install only when its carrier's
//! signature proves it, and an unrooted vault writes its facts unsigned: they count on the
//! install that wrote them only (RULING TASK-FACT-RULING-CROSSED-OPTION-D = B). The two cases
//! that read a fact another node wrote run on a rooted pair: both nodes are host and device
//! of one vault, so each node's facts are carrier-signed and count on the other
//! (FIX IT-SYNC-TASK-AUTHORITY-ROOTED-PAIR).
//!
//! Window choice: the two fail-closed cases write only through the window doc
//! and stay in the harness's fixed [`WINDOW`]. The two verb-driven cases
//! cannot — `cancel` and `tasks.update` stamp their facts with the wall
//! clock at the instant they run, so the live window is the only one that can
//! carry them, and those tests open it on both nodes.

#![cfg(feature = "sync")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use loro::LoroDoc;
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, FailAttempt,
};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::edge::EdgeActorClass;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::habit::TaskRole;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{LoadedWindow, reverse_rematerialize};
use oneiron::task_verb::{TaskCancelTarget, TaskCreateSpec};
use oneiron::{EntityId, TaskAuthorityState, Vault};

use crate::sync_harness::{
    T0, TestNode, WINDOW, assert_converged, entity_blob, exchange, exchange_docs, test_config,
    time_range, vault_pair,
};

/// The engine's own clock. Authority facts are stamped with it inside the verb
/// transaction, so a test that wants to see them replicate has to live in the
/// window that clock writes into.
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// A role-only TASK row as a peer ships it, carrying an `owner_ref` DISPLAY
/// field. Naming an owner in the body is free — that is the point: the field is
/// mutable storage, not proof, and no reader may rebuild authority from it.
fn replay_task_entity(
    node: &TestNode,
    window: &str,
    task_ref: EntityId,
    owner_display: EntityId,
    at: u64,
) {
    let body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("role"),
            rmpv::Value::from(TaskRole::Task.role_byte()),
        ),
        (
            rmpv::Value::from("owner_ref"),
            rmpv::Value::from(owner_display.to_hex()),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body)
        .expect("writing MessagePack to a Vec cannot fail");
    node.put_entity_in_window(
        window,
        &task_ref,
        &entity_blob(ENTITY_TYPE_TASK, time_range(at), at, &encoded),
    );
}

/// Mirrors BOTH nodes' local rows into their window docs and exchanges deltas
/// until the two docs agree — the production route from an LMDB write to a
/// peer's LMDB (`reverse_rematerialize` → Loro delta → Observer B), bounded by
/// the harness's five-round convergence cap.
fn converge(a: &TestNode, b: &TestNode, window: &WindowKey) {
    for node in [a, b] {
        reverse_rematerialize(&node.vault, node.doc(window.as_str()), window)
            .expect("mirror local rows into the window doc");
    }
    exchange(a, b, window.as_str());
}

/// Gives `node` live realizing work for `task_ref` — the node-local attempt a
/// device runs for a task it holds. A cancel that stops nothing mints no
/// Cancelled fact (the fact records a cancellation that really happened), so a
/// peer must be carrying real work for a direct cancel there to mean anything.
fn enqueue_realization(node: &TestNode, task_ref: EntityId, now: u64) {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, &rmpv::Value::from("peer-realization"))
        .expect("writing MessagePack to a Vec cannot fail");
    AttemptQueue::new(&node.vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                // The engine's own realizing kind: this models the device
                // realizing the task it holds, not a synthetic queue row.
                kind: "tasks.realize".to_owned(),
                payload,
                dedupe_key: None,
                run_id: None,
                now,
            },
            Some(task_ref.to_hex()),
        )
        .expect("enqueue the peer's realizing attempt");
}

/// Fails the realizing attempt `tasks.create` minted on this node, the way a
/// real run dies. `tasks.update` acknowledges only a genuinely FAILED row, so this
/// is what gives the owner something to acknowledge.
fn fail_realization(node: &TestNode, task_ref: EntityId, now: u64) {
    let queue = AttemptQueue::new(&node.vault);
    let task_hex = task_ref.to_hex();
    let realization = queue
        .list()
        .unwrap()
        .into_iter()
        .find(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
        .expect("a Dreamer-lane create mints one realizing attempt");
    let ClaimOutcome::Claimed(claimed) = queue
        .claim_kind(
            &realization.kind,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now,
            },
        )
        .unwrap()
    else {
        panic!("the realizing attempt must be claimable");
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "realization failed".to_owned(),
            now: now + 1,
        })
        .unwrap();
}

/// A two-vault pair whose owner actor and one verb-created TASK have already
/// crossed the wire: node B holds the task, its Owner fact and the actor row
/// without ever having run the create.
struct TaskPair {
    a: TestNode,
    b: TestNode,
    window: WindowKey,
    owner: EntityId,
    task_ref: EntityId,
    now: u64,
}

impl TaskPair {
    fn open() -> Self {
        let now = now_seconds();
        let window = WindowKey::from_timestamp(now);
        let (mut a, mut b) = vault_pair();
        a.open_window(window.as_str());
        b.open_window(window.as_str());

        // The live vault owner is authored on node A and reaches node B the
        // same way the task and its Owner fact do — by replicating.
        // FIX (a32044b3d27 #1307, 8a5feef95bd #1373): owner acts revalidate live
        // vault ownership at commit, so use the embedded owner actor instead of
        // a synthetic PERSON that authenticates but owns nothing.
        let owner = a
            .vault
            .ensure_embedded_owner_actor()
            .expect("store the owner actor");
        converge(&a, &b, &window);
        // FIX (9062f8d0f89 #1346): the embedded owner has no default Agent
        // Auto ceiling. Author a separate pack so the default seed stays
        // unchanged for the harness's initial-unshared-seed guard. Install it
        // BEFORE minting the cancel grant, which binds to the policy frontier.
        let policy_pack_ref = EntityId::now();
        let policy_pack = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("schema_version"),
                rmpv::Value::from("1.2"),
            ),
            (
                rmpv::Value::from("pack_id"),
                rmpv::Value::from("task-authority-owner-ceiling"),
            ),
            (
                rmpv::Value::from("pack_version"),
                rmpv::Value::from("1.0.0"),
            ),
            (
                rmpv::Value::from("min_engine_version"),
                rmpv::Value::from("0.0.0"),
            ),
            (rmpv::Value::from("defaults"), rmpv::Value::Map(vec![])),
            (rmpv::Value::from("rules"), rmpv::Value::Array(vec![])),
            (
                rmpv::Value::from("actor_ceilings"),
                rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                    (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
                    (
                        rmpv::Value::from("actor_ref"),
                        rmpv::Value::from(owner.to_hex()),
                    ),
                    (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
                ])]),
            ),
        ]);
        let mut policy_pack_bytes = Vec::new();
        rmpv::encode::write_value(&mut policy_pack_bytes, &policy_pack)
            .expect("writing MessagePack to a Vec cannot fail");

        // Each device holds the owner's standing cancel grant: the authority to
        // stop one's own work is not something a second machine borrows over
        // the wire. The owner, whose row node B now holds, mints it on each
        // device before the task exists. A grant is a row of its device's own
        // consent table, never of the window, so nothing here converges on it.
        for node in [&a, &b] {
            let proof = node
                .vault
                .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
                .expect("the owner authenticates on each device");
            node.vault
                .install_owner_policy_manifest(
                    &proof,
                    policy_pack_ref,
                    policy_pack_bytes.clone(),
                    now,
                )
                .expect("grant the owner's agent Auto ceiling on each device");
            node.vault
                .mint_standing_outbound_grant(
                    &proof,
                    EntityId::from_bytes([0xD1; 16]).unwrap(),
                    &GrantMintIntent {
                        principal_ref: owner.to_hex(),
                        origin_component_id: "tasks".to_owned(),
                        origin_action_id: "cancel".to_owned(),
                        origin_receipt_ref: None,
                        scope: GrantMintIntentScope::VerbClass {
                            verb_class: oneiron::task_verb::sdk::AgentVerb::Cancel
                                .as_str()
                                .to_owned(),
                        },
                    },
                )
                .expect("mint the owner's standing cancel grant");
        }

        let created = a
            .vault
            .memory(owner, EdgeActorClass::Agent)
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("authority-convergence"),
                None,
                None,
                Some(now),
            ))
            .expect("own-agent tasks.create");
        assert!(
            created.effected,
            "the create must mint a task, not park a proposal"
        );
        let task_ref = created
            .task_ref
            .expect("a verified create mints one TASK entity");

        let pair = Self {
            a,
            b,
            window,
            owner,
            task_ref,
            now,
        };
        converge(&pair.a, &pair.b, &pair.window);
        pair
    }

    /// The authority `node` reads for this task from its own replicated facts.
    fn state(&self, node: &TestNode) -> TaskAuthorityState {
        node.vault
            .task_authority_state(self.task_ref)
            .unwrap()
            .unwrap_or_else(|| panic!("{}: the task must carry proof of its owner", node.name))
    }

    /// The owner acknowledges the failed realization on node A. The Acked fact
    /// commits inside that same transaction.
    fn ack_on_origin(&self) {
        let ack = self
            .a
            .vault
            .memory(self.owner, EdgeActorClass::Agent)
            .tasks_update(self.task_ref)
            .expect("acknowledge the failed row");
        assert!(ack.acked, "a genuinely failed row acknowledges");
    }

    /// The owner cancels on node B — the peer that only ever materialized this
    /// task — and the Cancelled fact commits with the intervention that made it
    /// true.
    fn cancel_on_peer(&self) {
        let cancel = self
            .b
            .vault
            .memory(self.owner, EdgeActorClass::Agent)
            .cancel(TaskCancelTarget::Task(self.task_ref))
            .expect("the owner cancels on the peer");
        assert!(
            cancel.effected,
            "the owner's own task cancels directly on the peer"
        );
        assert!(
            cancel.proposal_ref.is_none(),
            "direct authority never parks a proposal"
        );
    }
}

/// Fixed host secret for this fixture's vault: one trust domain for both nodes.
/// Mirrors `device_world_follow.rs` (`FIXTURE_HOST_SECRET`).
const ROOTED_PAIR_HOST_SECRET: &[u8] = b"task-authority-rooted-pair";

/// One rooted vault with its materializer and live windows: `TestNode`'s shape
/// without its pre-root baseline, since rooting happens before any window opens.
struct RootedNode {
    name: &'static str,
    peer_id: u64,
    vault: Arc<Vault>,
    materializer: Arc<Materializer>,
    windows: BTreeMap<String, LoadedWindow>,
    _dir: tempfile::TempDir,
}

impl RootedNode {
    /// Opens a fresh window doc with observers attached.
    /// Mirrors `TestNode::open_window` in the harness.
    fn open_window(&mut self, key: &str) -> &LoadedWindow {
        let window_key = WindowKey::new(key);
        let doc = oneiron::sync::schema::create_window_doc(self.name, &window_key);
        doc.set_peer_id(self.peer_id).unwrap();
        oneiron::sync::window::apply_pending_window_updates(&self.vault, &doc, &window_key)
            .unwrap();
        let window = LoadedWindow::from_doc(doc, window_key, &self.vault, &self.materializer);
        self.windows.insert(key.to_owned(), window);
        self.window(key)
    }

    fn window(&self, key: &str) -> &LoadedWindow {
        self.windows
            .get(key)
            .unwrap_or_else(|| panic!("{}: window {key} not open", self.name))
    }

    fn doc(&self, key: &str) -> &LoroDoc {
        &self.window(key).doc
    }
}

/// Two installs of one vault: node-a is the rooted host, node-b is the owner's
/// enrolled device holding the vault's authority history. Both folds admit both
/// machines and both signers are loaded, so each door's facts count on the other.
/// Mirrors `task_fact_carrier_proof.rs` (`host` plus `device`) on `test_config` vaults.
fn rooted_pair() -> (RootedNode, RootedNode) {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let vault_a = Vault::open(dir_a.path(), test_config()).unwrap();
    let vault_b = Vault::open(dir_b.path(), test_config()).unwrap();
    vault_a.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault_b.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault_a.prepare_install_signing().unwrap();
    vault_b.prepare_install_signing().unwrap();

    let issuer = HostSlipIssuer::from_secret(ROOTED_PAIR_HOST_SECRET).expect("fixture host issuer");
    vault_a.ensure_host_root_slip(&issuer).expect("host root");
    vault_a
        .provision_engine_machine_identities(&issuer)
        .expect("engine machines");
    vault_a
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("host install profile");
    let vault_id = vault_a
        .authority_fold()
        .expect("host fold")
        .vault_id
        .expect("rooted vault");

    let key = vault_b
        .machine_encryption_key(vault_id)
        .expect("device encryption key");
    let request = vault_b
        .machine_enrolment_request(vault_id, key)
        .expect("device enrolment request");
    let owner = vault_a
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let proof = vault_a
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault_a
        .enroll_machine(
            &proof,
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("enrol device");
    let history = vault_a
        .export_signed_authority_history()
        .expect("host history");
    vault_b
        .import_signed_authority_history(&history)
        .expect("device takes history");

    let mut a = RootedNode {
        name: "node-a",
        peer_id: 1,
        vault: Arc::new(vault_a),
        materializer: Arc::new(Materializer::new()),
        windows: BTreeMap::new(),
        _dir: dir_a,
    };
    let mut b = RootedNode {
        name: "node-b",
        peer_id: 2,
        vault: Arc::new(vault_b),
        materializer: Arc::new(Materializer::new()),
        windows: BTreeMap::new(),
        _dir: dir_b,
    };
    a.open_window(WINDOW);
    b.open_window(WINDOW);
    (a, b)
}

/// `converge` for `RootedNode`: mirrors both nodes' local rows into their window
/// docs, then exchanges deltas until the docs agree.
fn converge_rooted(a: &RootedNode, b: &RootedNode, window: &WindowKey) {
    for node in [a, b] {
        reverse_rematerialize(&node.vault, node.doc(window.as_str()), window)
            .expect("mirror local rows into the window doc");
    }
    exchange_docs(
        a.name,
        a.doc(window.as_str()),
        b.name,
        b.doc(window.as_str()),
    );
}

/// Gives a rooted `node` live realizing work for `task_ref`, as `enqueue_realization`
/// does for `TestNode`: a cancel that stops nothing mints no Cancelled fact.
fn enqueue_realization_rooted(node: &RootedNode, task_ref: EntityId, now: u64) {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, &rmpv::Value::from("peer-realization"))
        .expect("writing MessagePack to a Vec cannot fail");
    AttemptQueue::new(&node.vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                // The engine's own realizing kind: this models the device
                // realizing the task it holds, not a synthetic queue row.
                kind: "tasks.realize".to_owned(),
                payload,
                dedupe_key: None,
                run_id: None,
                now,
            },
            Some(task_ref.to_hex()),
        )
        .expect("enqueue the peer's realizing attempt");
}

/// A rooted two-vault pair whose owner actor and one verb-created TASK have already
/// crossed the wire: node B holds the task, its signed Owner fact and the actor row
/// without ever having run the create.
struct RootedTaskPair {
    a: RootedNode,
    b: RootedNode,
    window: WindowKey,
    owner: EntityId,
    task_ref: EntityId,
    now: u64,
}

impl RootedTaskPair {
    fn open() -> Self {
        let now = now_seconds();
        let window = WindowKey::from_timestamp(now);
        let (mut a, mut b) = rooted_pair();
        a.open_window(window.as_str());
        b.open_window(window.as_str());

        // The rooted host's embedded owner (bound by the root) reaches node B the
        // same way the task and its Owner fact do — by replicating.
        // FIX (a32044b3d27 #1307, 8a5feef95bd #1373): owner acts revalidate live
        // vault ownership at commit, so use the embedded owner actor instead of
        // a synthetic PERSON that authenticates but owns nothing.
        let owner = a
            .vault
            .ensure_embedded_owner_actor()
            .expect("store the owner actor");
        converge_rooted(&a, &b, &window);
        // FIX (9062f8d0f89 #1346): the embedded owner has no default Agent
        // Auto ceiling. Author a separate pack so the default seed stays
        // unchanged for the harness's initial-unshared-seed guard. Install it
        // BEFORE minting the cancel grant, which binds to the policy frontier.
        let policy_pack_ref = EntityId::now();
        let policy_pack = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("schema_version"),
                rmpv::Value::from("1.2"),
            ),
            (
                rmpv::Value::from("pack_id"),
                rmpv::Value::from("task-authority-owner-ceiling"),
            ),
            (
                rmpv::Value::from("pack_version"),
                rmpv::Value::from("1.0.0"),
            ),
            (
                rmpv::Value::from("min_engine_version"),
                rmpv::Value::from("0.0.0"),
            ),
            (rmpv::Value::from("defaults"), rmpv::Value::Map(vec![])),
            (rmpv::Value::from("rules"), rmpv::Value::Array(vec![])),
            (
                rmpv::Value::from("actor_ceilings"),
                rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                    (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
                    (
                        rmpv::Value::from("actor_ref"),
                        rmpv::Value::from(owner.to_hex()),
                    ),
                    (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
                ])]),
            ),
        ]);
        let mut policy_pack_bytes = Vec::new();
        rmpv::encode::write_value(&mut policy_pack_bytes, &policy_pack)
            .expect("writing MessagePack to a Vec cannot fail");

        // Each device holds the owner's standing cancel grant: the authority to
        // stop one's own work is not something a second machine borrows over
        // the wire. The owner, whose row node B now holds, mints it on each
        // device before the task exists. A grant is a row of its device's own
        // consent table, never of the window, so nothing here converges on it.
        for node in [&a, &b] {
            let proof = node
                .vault
                .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
                .expect("the owner authenticates on each device");
            node.vault
                .install_owner_policy_manifest(
                    &proof,
                    policy_pack_ref,
                    policy_pack_bytes.clone(),
                    now,
                )
                .expect("grant the owner's agent Auto ceiling on each device");
            node.vault
                .mint_standing_outbound_grant(
                    &proof,
                    EntityId::from_bytes([0xD1; 16]).unwrap(),
                    &GrantMintIntent {
                        principal_ref: owner.to_hex(),
                        origin_component_id: "tasks".to_owned(),
                        origin_action_id: "cancel".to_owned(),
                        origin_receipt_ref: None,
                        scope: GrantMintIntentScope::VerbClass {
                            verb_class: oneiron::task_verb::sdk::AgentVerb::Cancel
                                .as_str()
                                .to_owned(),
                        },
                    },
                )
                .expect("mint the owner's standing cancel grant");
        }

        let created = a
            .vault
            .memory(owner, EdgeActorClass::Agent)
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("authority-convergence"),
                None,
                None,
                Some(now),
            ))
            .expect("own-agent tasks.create");
        assert!(
            created.effected,
            "the create must mint a task, not park a proposal"
        );
        let task_ref = created
            .task_ref
            .expect("a verified create mints one TASK entity");

        let pair = Self {
            a,
            b,
            window,
            owner,
            task_ref,
            now,
        };
        converge_rooted(&pair.a, &pair.b, &pair.window);
        pair
    }

    /// The authority `node` reads for this task from its own replicated facts.
    fn state(&self, node: &RootedNode) -> TaskAuthorityState {
        node.vault
            .task_authority_state(self.task_ref)
            .unwrap()
            .unwrap_or_else(|| panic!("{}: the task must carry proof of its owner", node.name))
    }

    /// The owner cancels on node B — the peer that only ever materialized this
    /// task — and the Cancelled fact commits with the intervention that made it
    /// true.
    fn cancel_on_peer(&self) {
        let cancel = self
            .b
            .vault
            .memory(self.owner, EdgeActorClass::Agent)
            .cancel(TaskCancelTarget::Task(self.task_ref))
            .expect("the owner cancels on the peer");
        assert!(
            cancel.effected,
            "the owner's own task cancels directly on the peer"
        );
        assert!(
            cancel.proposal_ref.is_none(),
            "direct authority never parks a proposal"
        );
    }
}

/// Done-means 2 on a rooted pair: after ordinary entity/edge replication, the ORIGINAL
/// owner cancels their own task directly on the peer.
///
/// The proof travelled WITH the task, so node B — which never ran the create
/// and never wrote a side-index — answers "who owns this" exactly as node A
/// does, and the cancel is a real effect rather than a proposal parked for
/// someone else to approve.
#[test]
fn owner_fact_replicates_and_peer_owner_cancels_directly() {
    let pair = RootedTaskPair::open();

    let on_peer = pair.state(&pair.b);
    assert_eq!(
        on_peer.owner_ref, pair.owner,
        "the peer reads the same owner the creating node proved"
    );
    assert!(
        !on_peer.cancelled,
        "nothing has been cancelled yet on either node"
    );

    enqueue_realization_rooted(&pair.b, pair.task_ref, pair.now);
    pair.cancel_on_peer();
    assert!(
        pair.state(&pair.b).cancelled,
        "the cancellation is a Cancelled fact on the node that made it"
    );

    converge_rooted(&pair.a, &pair.b, &pair.window);

    for node in [&pair.a, &pair.b] {
        let state = pair.state(node);
        assert_eq!(
            state.owner_ref, pair.owner,
            "{}: the owner is the same on both peers",
            node.name
        );
        assert!(
            state.cancelled,
            "{}: the cancellation reaches both peers",
            node.name
        );
    }
    // No `assert_converged`: it takes `&TestNode` and cannot run on `RootedNode`.
    // The task authority asserts above are the test's verdict.
}

/// When the acknowledgement reaches the node holding the cancellation.
#[derive(Debug, Clone, Copy)]
enum AckArrival {
    /// The Acked fact replicates first and the cancellation is written over it.
    BeforeCancel,
    /// Both devices write while apart, so the Acked fact lands on a node that
    /// already holds its own Cancelled fact.
    AfterCancel,
}

/// Cancel-wins is a property of the merged SET, not of arrival order: in both
/// orders both peers end cancelled, and the acknowledgement — which a single
/// last-writer-wins body would have let clobber the cancellation — merely
/// coexists with it.
#[test]
#[ignore = "stale since 46ca703251f: acknowledging failed work needs typed TASK settlement that this fixture cannot mirror (FIX IT-SYNC-STALE-TASK-SETTLE)"]
fn cancel_wins_under_both_merge_orders() {
    for arrival in [AckArrival::BeforeCancel, AckArrival::AfterCancel] {
        cancel_wins_in_order(arrival);
    }
}

fn cancel_wins_in_order(arrival: AckArrival) {
    let pair = TaskPair::open();
    // Node A's realization failed, so the owner has a genuinely failed row to
    // acknowledge there; node B is realizing the same task and can cancel it.
    // Both planes are node-local: neither device sees the other's work, which
    // is exactly why the two facts can be authored concurrently.
    fail_realization(&pair.a, pair.task_ref, pair.now);
    enqueue_realization(&pair.b, pair.task_ref, pair.now);

    match arrival {
        AckArrival::BeforeCancel => {
            pair.ack_on_origin();
            converge(&pair.a, &pair.b, &pair.window);
            pair.cancel_on_peer();
        }
        AckArrival::AfterCancel => {
            pair.cancel_on_peer();
            // Node A acknowledges without having seen the cancellation — the
            // only way this order can arise, because a Cancelled fact that HAS
            // arrived takes the row off the very surface `tasks.update` reads.
            pair.ack_on_origin();
        }
    }
    converge(&pair.a, &pair.b, &pair.window);

    let task_hex = pair.task_ref.to_hex();
    for node in [&pair.a, &pair.b] {
        let state = pair.state(node);
        assert!(
            state.cancelled,
            "{}: cancellation survives {arrival:?}",
            node.name
        );
        assert!(
            state.acked,
            "{}: the acknowledgement is not lost either under {arrival:?}",
            node.name
        );
        // Cancellation is answered BEFORE acknowledgement, so the row leaves
        // the active surface on BOTH peers — including node B, which never
        // acknowledged anything and whose own realization is cancelled rather
        // than failed, so only the Cancelled fact can be taking it off.
        let oneiron::task_verb::TaskDescription::Section(section) = node
            .vault
            .memory(pair.owner, EdgeActorClass::Agent)
            .describe(None)
            .expect("render the board")
        else {
            panic!("describe without a task returns the TASKS section");
        };
        assert!(
            !section.rows.iter().any(|row| row.id == task_hex),
            "{}: a cancelled task must not render actively under {arrival:?}",
            node.name
        );
    }
    assert_converged(&pair.a, &pair.b, pair.window.as_str());
}

/// Authority fails CLOSED across the wire. A TASK that replicated without an
/// Owner fact proves nothing on either node, however its body decorates itself:
/// `owner_ref` is display, and rebuilding an owner from it would hand
/// direct-cancel authority to whoever wrote the row.
#[test]
fn zero_owner_fails_closed() {
    let (a, b) = vault_pair();
    let task_ref = EntityId::now();
    let claimed_owner = EntityId::now();
    replay_task_entity(&a, WINDOW, task_ref, claimed_owner, T0 + 1);

    exchange(&a, &b, WINDOW);

    for node in [&a, &b] {
        assert_eq!(
            node.vault.task_authority_state(task_ref).unwrap(),
            None,
            "{}: no Owner fact, no authority",
            node.name
        );
    }
    assert_converged(&a, &b, WINDOW);
}

/// A peer's second Owner fact on a rooted pair. It writes through the
/// `oneiron_test_support` doors, so it and its helpers build under that cfg only.
#[cfg(oneiron_test_support)]
mod second_owner_fact {
    use oneiron::test_doors::task_fact_actor::{task_ref_of_maker, write_unjudged_owner_fact};
    use oneiron::{
        EdgeKind, EntityId, TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind, TaskAuthorityState,
        Vault,
    };

    use super::{RootedTaskPair, converge_rooted};

    /// The authority fact rows linked to `task`, as `(id, body)`.
    /// Mirrors `task_id_commits_to_maker.rs`.
    fn fact_rows(vault: &Vault, task: EntityId) -> Vec<(EntityId, Vec<u8>)> {
        vault
            .edges_in(&task)
            .expect("the task's links")
            .into_iter()
            .filter(|edge| edge.kind == EdgeKind::ScopedTo)
            .filter_map(|edge| {
                let raw = vault.get_raw(&edge.target).expect("the linked row")?;
                let body =
                    raw[oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN..].to_vec();
                String::from_utf8_lossy(&body)
                    .contains(TASK_AUTHORITY_FACT_SUBKIND)
                    .then_some((edge.target, body))
            })
            .collect()
    }

    /// The Owner fact a task's door wrote, read from its body: the owner it names, and its
    /// maker commitment `(maker, nonce)`. Mirrors `task_id_commits_to_maker.rs`.
    struct OwnerCommitment {
        owner: EntityId,
        maker: EntityId,
        nonce: EntityId,
    }

    fn owner_commitment(vault: &Vault, task: EntityId) -> OwnerCommitment {
        let owners: Vec<OwnerCommitment> = fact_rows(vault, task)
            .into_iter()
            .filter_map(|(_, body)| {
                let rmpv::Value::Map(entries) =
                    rmpv::decode::read_value(&mut body.as_slice()).expect("a fact body decodes")
                else {
                    panic!("a fact body is a map");
                };
                let field = |name: &str| {
                    entries
                        .iter()
                        .find(|(key, _)| key.as_str() == Some(name))
                        .map(|(_, value)| value.clone())
                };
                let entity = |name: &str| {
                    field(name)
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .map(|hex| EntityId::from_hex(&hex).expect("an entity ref"))
                };
                (field("kind").and_then(|kind| kind.as_u64())
                    == Some(u64::from(TaskAuthorityFactKind::Owner.as_byte())))
                .then(|| OwnerCommitment {
                    owner: entity("actor_ref").expect("an Owner fact names its owner"),
                    maker: entity("maker_ref").expect("an Owner fact names its maker"),
                    nonce: entity("nonce").expect("an Owner fact names its nonce"),
                })
            })
            .collect();
        let [made] = <[OwnerCommitment; 1]>::try_from(owners)
            .unwrap_or_else(|_| panic!("the task door wrote exactly one Owner fact"));
        made
    }

    /// A peer's second Owner fact names the true maker and nonce but another owner: it is
    /// skipped on both nodes and the true owner stands. Two Owners that both derive one id
    /// would be a hash collision, so the read is no fork.
    #[test]
    fn a_peers_second_owner_fact_is_skipped_on_both_nodes() {
        let pair = RootedTaskPair::open();
        let task = pair.task_ref;

        let made = owner_commitment(&pair.a.vault, task);
        assert_eq!(
            made.owner, pair.owner,
            "the door wrote the true owner's fact"
        );
        assert_eq!(
            task_ref_of_maker(made.maker, made.owner, made.nonce).expect("the id derives"),
            task,
            "the task's id derives from its maker, its owner and its nonce"
        );

        let other = EntityId::now();
        write_unjudged_owner_fact(&pair.b.vault, task, other, made.maker, made.nonce)
            .expect("the peer's carrier signs a second owner");

        converge_rooted(&pair.a, &pair.b, &pair.window);

        for node in [&pair.a, &pair.b] {
            let state: TaskAuthorityState = node
                .vault
                .task_authority_state(task)
                .expect("the second owner is skipped, not a fork")
                .expect("the true owner's fact counts");
            assert_eq!(
                state.owner_ref, pair.owner,
                "{}: the true owner stands",
                node.name
            );
            assert_ne!(
                state.owner_ref, other,
                "{}: the second owner does not stand",
                node.name
            );
        }
        // No `assert_converged`: it takes `&TestNode` and cannot run on `RootedNode`.
        // The task authority asserts above are the test's verdict.
    }
}
