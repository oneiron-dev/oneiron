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
//! Window choice: the two fail-closed cases write only through the window doc
//! and stay in the harness's fixed [`WINDOW`]. The two verb-driven cases
//! cannot — `tasks.cancel` and `tasks.ack` stamp their facts with the wall
//! clock at the instant they run, so the live window is the only one that can
//! carry them, and those tests open it on both nodes.

#![cfg(feature = "sync")]

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, FailAttempt,
};
use oneiron::edge::EdgeActorClass;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::habit::TaskRole;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::task_verb::{TaskCancelTarget, TaskCreateSpec, TasksVerb};
use oneiron::{
    EdgeKind, EntityId, Error, TASK_AUTHORITY_FACT_SCHEMA_VERSION, TASK_AUTHORITY_FACT_SUBKIND,
    TaskAuthorityFactKind, TaskAuthorityState, Vad,
};

use crate::sync_harness::{
    T0, TestNode, WINDOW, assert_converged, entity_blob, exchange, time_range, vault_pair,
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

/// One strict-v1 authority fact body from LITERAL parts — a peer's fact as it
/// arrives on the wire, not a round trip through the engine's own encoder
/// (which is crate-private precisely because minting is the engine's alone).
fn authority_fact_body(
    task_ref: EntityId,
    kind: TaskAuthorityFactKind,
    actor_ref: EntityId,
    occurred_at: u64,
) -> Vec<u8> {
    let body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("role"),
            rmpv::Value::from(TaskRole::AuthorityFact.role_byte()),
        ),
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(TASK_AUTHORITY_FACT_SCHEMA_VERSION),
        ),
        (
            rmpv::Value::from("subkind"),
            rmpv::Value::from(TASK_AUTHORITY_FACT_SUBKIND),
        ),
        (
            rmpv::Value::from("task_ref"),
            rmpv::Value::from(task_ref.to_hex()),
        ),
        (rmpv::Value::from("kind"), rmpv::Value::from(kind.as_byte())),
        (
            rmpv::Value::from("actor_ref"),
            rmpv::Value::from(actor_ref.to_hex()),
        ),
        (
            rmpv::Value::from("occurred_at"),
            rmpv::Value::from(occurred_at),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body)
        .expect("writing MessagePack to a Vec cannot fail");
    encoded
}

/// Lands one authority fact on `node` through the door a peer's row comes in
/// by: the fact entity and its `fact --ScopedTo--> task` edge go into the
/// window doc, and Observer B materializes both. The public write doors refuse
/// the reserved role on purpose, so this replication path is the ONLY way a
/// fact this node did not mint can exist in its store — which is exactly the
/// shape a second replica's fact has.
fn replay_authority_fact(
    node: &TestNode,
    window: &str,
    task_ref: EntityId,
    kind: TaskAuthorityFactKind,
    actor_ref: EntityId,
    at: u64,
) -> EntityId {
    let fact_ref = EntityId::now();
    let blob = entity_blob(
        ENTITY_TYPE_TASK,
        time_range(at),
        at,
        &authority_fact_body(task_ref, kind, actor_ref, at),
    );
    node.put_entity_in_window(window, &fact_ref, &blob);
    node.put_edge_in_window(
        window,
        &fact_ref,
        EdgeKind::ScopedTo,
        &task_ref,
        0.7,
        at,
        Vad::NEUTRAL,
    );
    fact_ref
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
/// real run dies. `tasks.ack` acknowledges only a genuinely FAILED row, so this
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

        // The first-party actor: the one id the default policy manifest gives
        // an Auto ceiling, so `tasks.create` takes direct effect instead of
        // parking a proposal. It is authored on node A and reaches node B the
        // same way everything else here does — by replicating.
        let owner = EntityId::from_bytes([0xE1; 16]).unwrap();
        a.vault
            .put_entity(&owner, ENTITY_TYPE_PERSON, time_range(now), now, b"owner")
            .expect("store the owner actor");
        // Each device holds the owner's standing cancel grant: the authority to
        // stop one's own work is not something a second machine borrows over
        // the wire. It PREDATES the task ([`T0`], outside the window under
        // test), which is both what a standing authorization looks like and
        // what keeps it out of this suite's subject: a grant carries a
        // node-local usage stamp, so the two devices' copies legitimately
        // differ once one of them spends it, and nothing here converges on it.
        for node in [&a, &b] {
            node.vault
                .mint_standing_outbound_grant(
                    &EntityId::from_bytes([0xD1; 16]).unwrap(),
                    &GrantMintIntent {
                        principal_ref: owner.to_hex(),
                        origin_component_id: "tasks".to_owned(),
                        origin_action_id: "cancel".to_owned(),
                        origin_receipt_ref: None,
                        scope: GrantMintIntentScope::VerbClass {
                            verb_class: TasksVerb::Cancel.as_str().to_owned(),
                        },
                    },
                    T0,
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
            .tasks_ack(self.task_ref)
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
            .tasks_cancel(TaskCancelTarget::Task(self.task_ref))
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

/// Done-means 2: after ordinary entity/edge replication, the ORIGINAL owner
/// cancels their own task directly on the peer.
///
/// The proof travelled WITH the task, so node B — which never ran the create
/// and never wrote a side-index — answers "who owns this" exactly as node A
/// does, and the cancel is a real effect rather than a proposal parked for
/// someone else to approve.
#[test]
fn owner_fact_replicates_and_peer_owner_cancels_directly() {
    let pair = TaskPair::open();

    let on_peer = pair.state(&pair.b);
    assert_eq!(
        on_peer.owner_ref, pair.owner,
        "the peer reads the same owner the creating node proved"
    );
    assert!(
        !on_peer.cancelled,
        "nothing has been cancelled yet on either node"
    );

    enqueue_realization(&pair.b, pair.task_ref, pair.now);
    pair.cancel_on_peer();
    assert!(
        pair.state(&pair.b).cancelled,
        "the cancellation is a Cancelled fact on the node that made it"
    );

    converge(&pair.a, &pair.b, &pair.window);

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
    assert_converged(&pair.a, &pair.b, pair.window.as_str());
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
            // arrived takes the row off the very surface `tasks.ack` reads.
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
        let section = node
            .vault
            .memory(pair.owner, EdgeActorClass::Agent)
            .tasks_check()
            .expect("render the board");
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

/// Two peers that minted conflicting proofs for one task do not vote: the read
/// refuses on BOTH of them. Picking either owner would hand direct-cancel
/// authority over someone's task to whichever row happened to arrive.
#[test]
fn owner_fork_fails_closed() {
    let (a, b) = vault_pair();
    let task_ref = EntityId::now();
    let first_owner = EntityId::now();
    let second_owner = EntityId::now();

    replay_task_entity(&a, WINDOW, task_ref, first_owner, T0 + 1);
    replay_authority_fact(
        &a,
        WINDOW,
        task_ref,
        TaskAuthorityFactKind::Owner,
        first_owner,
        T0 + 2,
    );
    // Node B needs the subject in its own doc before it can scope a fact to it;
    // the exchange delivers it, and the second proof is authored there.
    exchange(&a, &b, WINDOW);
    replay_authority_fact(
        &b,
        WINDOW,
        task_ref,
        TaskAuthorityFactKind::Owner,
        second_owner,
        T0 + 3,
    );

    exchange(&a, &b, WINDOW);

    for node in [&a, &b] {
        assert!(
            matches!(
                node.vault.task_authority_state(task_ref),
                Err(Error::InvariantViolation("task authority owner fork"))
            ),
            "{}: a forked proof is a refusal, never an arbitrary owner",
            node.name
        );
    }
    assert_converged(&a, &b, WINDOW);
}
