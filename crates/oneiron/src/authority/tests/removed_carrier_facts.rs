//! Removals that cross keep the TASK facts of the removed machine that both saw (blind review
//! round 1 P1 of #10107, REVIEW-10107; row TASK-FACT-REMOVED-CARRIER-NEW-FACTS, lead ruling
//! REMOVED-CARRIER-NEW-FACTS = A: "a removal does not unmake facts made BEFORE it, and cannot
//! be used to make new ones after"). Two owner devices remove one machine at once, each having
//! held its cancel. Each removal names its own carrier, so the roster chain's head conflicts,
//! but the machine's key is in no doubt, and the removals meet.
//!
//! - `a_cancel_both_crossing_removals_saw_still_counts`: red on #10107's head ad3d8792658a (a
//!   conflicted head proves no fact of the machine, so the task reopens). Green on the fix.
//! - `a_cancel_one_crossing_removal_missed_does_not_count_and_is_counted`: red on ad3d8792658a
//!   (a conflicted head proves nothing, so the host counts no fact as arrived after the
//!   removal). Green on the fix.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --lib authority::tests::removed_carrier_facts::`.

use super::machine_identity::{Host, host};
use super::support::RosterHead;
use super::world_floor::{answer_on, next_seq};
use super::world_privacy::{land, other_machine};
use super::*;
use crate::authority::carrier_transcript;
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::client::ImportTier;
use crate::sync::replay::{ReplicatedEntity, replay_entity};
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, carried_fact_acts_in_txn,
    encode_task_authority_fact_body,
};
use crate::task_verb::TaskCreateSpec;
use crate::{EdgeActorClass, EdgeKind};

/// The domain a TASK fact's carrier signs under (`task_authority::fact_proof`).
const TASK_FACT_CARRIER_DOMAIN: &[u8] = b"oneiron/task-fact/v2";

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

/// The host's owner, its task, and three machines of the owner's: `removed`, whose cancel of
/// the task the host holds and counts, and `desk` and `phone`, which carry the removals.
struct Crossing {
    host: Host,
    task: EntityId,
    removed: (EntityId, SigningKey),
    desk: (EntityId, SigningKey),
    phone: (EntityId, SigningKey),
    /// The carried act of `removed`'s cancel, as a removal names it.
    cancel: BTreeSet<AuthorityEntryHash>,
}

fn crossing(seed: u8) -> Crossing {
    let host = host();
    let owner = crate::vault::embedded_owner_actor_id().unwrap();
    let task = host
        .vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::Nil,
            Some("cancelled before the removals".into()),
            Some(owner),
            Some(host.vault.now_recorded_at()),
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let removed = other_machine(&host, seed, MachineRole::Owned(MachineOwnership::Yours));
    let desk = other_machine(&host, seed + 1, MachineRole::Owned(MachineOwnership::Yours));
    let phone = other_machine(&host, seed + 2, MachineRole::Owned(MachineOwnership::Yours));
    let (fact, body) = carried_cancel(&host, task, owner, (removed.0, &removed.1));
    deliver(&host, fact, &body, task);
    assert!(
        cancelled(&host, task),
        "FIXTURE: the machine's cancel counts on the host while the machine stands"
    );
    let txn = host.vault.store.env.read_txn().unwrap();
    let cancel = carried_fact_acts_in_txn(&host.vault, &txn, removed.0).unwrap();
    drop(txn);
    assert_eq!(
        cancel.len(),
        1,
        "FIXTURE: a removal written now names the machine's cancel"
    );
    Crossing {
        host,
        task,
        removed,
        desk,
        phone,
        cancel,
    }
}

/// `actor`'s cancel of `task` on a new fact row, carried as `machine` with a signature by
/// `key` over the row: the signature verifies, whoever holds the key.
fn carried_cancel(
    host: &Host,
    task: EntityId,
    actor: EntityId,
    (machine, key): (EntityId, &SigningKey),
) -> (EntityId, Vec<u8>) {
    let fact_ref = EntityId::now();
    let unsigned = encode_task_authority_fact_body(&TaskAuthorityFact {
        task_ref: task,
        kind: TaskAuthorityFactKind::Cancelled,
        actor_ref: actor,
        assigned_ref: None,
        actor_generation: None,
        assigned_generation: None,
        answered_heads: None,
        occurred_at: host.vault.now_recorded_at(),
        maker: None,
    });
    let transcript = carrier_transcript(
        TASK_FACT_CARRIER_DOMAIN,
        &host.vault_id,
        &fact_ref,
        &machine,
        &unsigned,
    );
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut unsigned.as_slice()).unwrap()
    else {
        panic!("a fact body is a map");
    };
    entries.extend([
        (
            Value::from("carrier_machine"),
            Value::from(machine.to_hex()),
        ),
        (
            Value::from("carrier_key"),
            Value::Binary(key.verifying_key().to_bytes().to_vec()),
        ),
        (
            Value::from("carrier_signature"),
            Value::Binary(key.sign(&transcript).to_bytes().to_vec()),
        ),
    ]);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(entries)).unwrap();
    (fact_ref, body)
}

/// The fact row `fact` with `body` as sync brings it to the host: the row through the
/// own-device replay door, then its link to `task`.
fn deliver(host: &Host, fact: EntityId, body: &[u8], task: EntityId) {
    let now = host.vault.now_recorded_at();
    replay_entity(
        &host.vault,
        ReplicatedEntity {
            id: fact,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: 0,
            body,
        },
        ImportTier::OwnDevice,
    )
    .unwrap();
    host.vault
        .batch()
        .edge(&fact, EdgeKind::ScopedTo, &task, SCOPED_TO_WEIGHT)
        .commit()
        .unwrap();
}

fn cancelled(host: &Host, task: EntityId) -> bool {
    host.vault
        .task_authority_state(task)
        .unwrap()
        .expect("the task has its owner")
        .cancelled
}

impl Crossing {
    /// The owner's removals of `removed`, carried by `desk` and by `phone` from the same
    /// heads, so neither saw the other: `desk_saw` and `phone_saw` are the TASK facts each
    /// names as seen. Both land on the host.
    fn remove_crossing(
        &self,
        desk_saw: BTreeSet<AuthorityEntryHash>,
        phone_saw: BTreeSet<AuthorityEntryHash>,
    ) {
        let fold = self.host.vault.authority_fold().unwrap();
        let heads: Vec<_> = fold.append_heads.iter().copied().collect();
        let profile = fold.machine(self.removed.0).unwrap().head().profile.clone();
        let removal = |(carrier, key): &(EntityId, SigningKey),
                       saw: BTreeSet<AuthorityEntryHash>| {
            answer_on(
                &self.host,
                (*carrier, key),
                next_seq(&fold, key),
                heads.clone(),
                MachineProfile {
                    role: MachineRole::Removed,
                    revision: profile.revision + 1,
                    seen_world_edits: saw,
                    ..profile.clone()
                },
            )
        };
        let desk = removal(&self.desk, desk_saw);
        let phone = removal(&self.phone, phone_saw);
        land(&self.host, &[desk, phone]);
        let fold = self.host.vault.authority_fold().unwrap();
        let roster = fold
            .machine(self.removed.0)
            .and_then(|machine| machine.roster.as_ref())
            .expect("the machine's roster chain");
        assert!(
            roster.removed && roster.conflicted,
            "FIXTURE: both removals stand, and the roster chain's head conflicts"
        );
    }

    fn not_counted(&self) -> u64 {
        self.host
            .vault
            .task_facts_not_counted_after_removal(self.removed.0)
            .unwrap()
    }
}

#[test]
fn a_cancel_both_crossing_removals_saw_still_counts() {
    let crossing = crossing(161);
    crossing.remove_crossing(crossing.cancel.clone(), crossing.cancel.clone());
    assert!(
        cancelled(&crossing.host, crossing.task),
        "removals that cross do not unmake a cancel both saw"
    );
    assert_eq!(
        crossing.not_counted(),
        0,
        "a cancel both removals saw counts, so the answer names no fact as not counted"
    );
}

#[test]
fn a_cancel_one_crossing_removal_missed_does_not_count_and_is_counted() {
    let crossing = crossing(171);
    crossing.remove_crossing(crossing.cancel.clone(), BTreeSet::new());
    assert!(
        !cancelled(&crossing.host, crossing.task),
        "a cancel one of the crossing removals did not see does not count"
    );
    assert_eq!(
        crossing.not_counted(),
        1,
        "the host counts the cancel as one fact that arrived after the removal"
    );
}
