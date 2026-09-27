use super::*;

use crate::config::VaultConfig;
use crate::error::RecordError;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("entity id")
}

fn fact(task_ref: EntityId, kind: TaskAuthorityFactKind, actor_ref: EntityId) -> TaskAuthorityFact {
    TaskAuthorityFact {
        task_ref,
        kind,
        actor_ref,
        assigned_ref: (kind == TaskAuthorityFactKind::HumanAssigned).then(|| id(0xA8)),
        occurred_at: 100,
    }
}

fn put_fact(vault: &Vault, fact: TaskAuthorityFact) -> EntityId {
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    let fact_ref = put_task_authority_fact_in_txn(vault, &mut wtxn, fact).expect("put fact");
    wtxn.commit().expect("commit fact");
    fact_ref
}

fn facts(vault: &Vault, task_ref: EntityId) -> Result<TaskAuthorityFacts> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault.task_authority_facts_in(&rtxn, task_ref)
}

fn rewrite_body(body: &[u8], mutate: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut cursor = body;
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode fact body")
    else {
        panic!("a fact body is a map")
    };
    mutate(&mut entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode fact body");
    out
}

fn body_with(body: &[u8], key: &str, value: Value) -> Vec<u8> {
    rewrite_body(body, move |entries| {
        let index = entries
            .iter()
            .position(|(entry_key, _)| entry_key.as_str() == Some(key))
            .expect("replaced key is present");
        entries[index].1 = value;
    })
}

/// The wire is the contract: every field survives a round trip, and every
/// shape that is not exactly a v1 fact is refused rather than guessed at.
#[test]
fn strict_v1_bodies_round_trip_and_reject_everything_else() {
    let original = TaskAuthorityFact {
        task_ref: id(0xA1),
        kind: TaskAuthorityFactKind::Cancelled,
        actor_ref: id(0xA2),
        assigned_ref: None,
        occurred_at: 1_700_000_000,
    };
    let encoded = encode_task_authority_fact_body(&original);
    assert_eq!(
        decode_task_authority_fact_body(&encoded).expect("round trip"),
        original
    );
    assert_eq!(
        crate::habit::task_role_from_body_bytes(&encoded).expect("role decodes"),
        TaskRole::AuthorityFact
    );

    let mut trailing = encoded.clone();
    trailing.push(0xC0);
    let mut cases: Vec<Vec<u8>> = vec![trailing, b"not msgpack at all".to_vec()];
    for (key, value) in [
        (BODY_KEY_ROLE, Value::from(TaskRole::Task.role_byte())),
        (BODY_KEY_SCHEMA_VERSION, Value::from(2_u8)),
        (BODY_KEY_SUBKIND, Value::from("typed")),
        (BODY_KEY_KIND, Value::from(5_u8)),
        (BODY_KEY_TASK_REF, Value::from("not-a-hex-id")),
        (BODY_KEY_OCCURRED_AT, Value::from("not-a-number")),
    ] {
        cases.push(body_with(&encoded, key, value));
    }
    cases.push(body_with(
        &encoded,
        BODY_KEY_KIND,
        Value::from(TaskAuthorityFactKind::HumanAssigned.as_byte()),
    ));
    // A dropped key and a smuggled extra key are both refusals: the key
    // set is exact, so nothing can ride along unread.
    cases.push(rewrite_body(&encoded, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(BODY_KEY_ACTOR_REF));
    }));
    cases.push(rewrite_body(&encoded, |entries| {
        entries.push((Value::from("extra"), Value::from(1_u8)));
    }));
    for (index, case) in cases.iter().enumerate() {
        assert!(
            decode_task_authority_fact_body(case).is_err(),
            "case {index} must be refused"
        );
    }
}

#[test]
fn human_assignment_witness_requires_matching_owner_and_fails_closed_on_fork() {
    let (_dir, vault) = open_vault();
    let task = id(0xA5);
    let owner = id(0xA6);
    let other = id(0xA7);
    put_fact(&vault, fact(task, TaskAuthorityFactKind::Owner, owner));
    let txn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(vault.task_human_assigner_in(&txn, task).unwrap(), None);
    drop(txn);
    put_fact(
        &vault,
        fact(task, TaskAuthorityFactKind::HumanAssigned, owner),
    );
    let txn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault.task_human_assigner_in(&txn, task).unwrap(),
        Some((owner, id(0xA8)))
    );
    let witness = fact(task, TaskAuthorityFactKind::HumanAssigned, owner);
    let encoded = encode_task_authority_fact_body(&witness);
    assert_eq!(decode_task_authority_fact_body(&encoded).unwrap(), witness);
    let missing_agent = rewrite_body(&encoded, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(BODY_KEY_ASSIGNED_REF));
    });
    assert!(decode_task_authority_fact_body(&missing_agent).is_err());
    drop(txn);
    put_fact(
        &vault,
        fact(task, TaskAuthorityFactKind::HumanAssigned, other),
    );
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(vault.task_human_assigner_in(&txn, task).is_err());
    drop(txn);

    let another = id(0xA9);
    put_fact(&vault, fact(another, TaskAuthorityFactKind::Owner, owner));
    put_fact(
        &vault,
        fact(another, TaskAuthorityFactKind::HumanAssigned, owner),
    );
    let mut changed = fact(another, TaskAuthorityFactKind::HumanAssigned, owner);
    changed.assigned_ref = Some(other);
    put_fact(&vault, changed);
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(vault.task_human_assigner_in(&txn, another).is_err());
}

/// Direct authority fails CLOSED: no Owner fact, no owner — while the
/// cancellation the task really carries stays visible to the render tier.
#[test]
fn zero_owner_facts_prove_no_authority_but_keep_cancellation() {
    let (_dir, vault) = open_vault();
    let task_ref = id(0xB1);
    assert_eq!(
        vault.task_authority_state(task_ref).expect("empty state"),
        None
    );

    put_fact(
        &vault,
        fact(task_ref, TaskAuthorityFactKind::Cancelled, id(0xB2)),
    );
    assert_eq!(
        vault.task_authority_state(task_ref).expect("state"),
        None,
        "a cancellation is not a proof of ownership"
    );
    assert!(facts(&vault, task_ref).expect("facts").cancelled);
}

/// Two facts naming the SAME owner are one owner: replicas that both
/// minted the proof converge instead of forking.
#[test]
fn duplicate_same_owner_facts_are_idempotent() {
    let (_dir, vault) = open_vault();
    let task_ref = id(0xC1);
    let owner = id(0xC2);
    put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, owner));
    put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, owner));

    assert_eq!(
        vault.task_authority_state(task_ref).expect("state"),
        Some(TaskAuthorityState {
            owner_ref: owner,
            cancelled: false,
            acked: false,
        })
    );
}

/// Two owners is not "pick one": it is a refusal.
#[test]
fn conflicting_owner_facts_fail_closed() {
    let (_dir, vault) = open_vault();
    let task_ref = id(0xD1);
    put_fact(
        &vault,
        fact(task_ref, TaskAuthorityFactKind::Owner, id(0xD2)),
    );
    put_fact(
        &vault,
        fact(task_ref, TaskAuthorityFactKind::Owner, id(0xD3)),
    );

    assert!(matches!(
        vault.task_authority_state(task_ref),
        Err(Error::InvariantViolation(_))
    ));
}

/// Set union, not arrival order: both merge orders and the concurrent pair
/// land on the same state, and cancellation is never cleared.
#[test]
fn cancel_wins_under_every_merge_order() {
    let (_dir, vault) = open_vault();
    let actor = id(0xE9);
    let orders: [(EntityId, [TaskAuthorityFactKind; 2]); 2] = [
        (
            id(0xE1),
            [
                TaskAuthorityFactKind::Acked,
                TaskAuthorityFactKind::Cancelled,
            ],
        ),
        (
            id(0xE2),
            [
                TaskAuthorityFactKind::Cancelled,
                TaskAuthorityFactKind::Acked,
            ],
        ),
    ];
    for (task_ref, kinds) in orders {
        put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, actor));
        for kind in kinds {
            put_fact(&vault, fact(task_ref, kind, actor));
        }
        assert_eq!(
            vault.task_authority_state(task_ref).expect("state"),
            Some(TaskAuthorityState {
                owner_ref: actor,
                cancelled: true,
                acked: true,
            }),
            "{}",
            task_ref.to_hex()
        );
    }
}

/// The edge is the index and the body is the claim; a fact reachable from
/// a task it does not name is refused, so a proof cannot be re-pointed at
/// another principal's task.
#[test]
fn fact_body_subject_must_equal_the_edge_target() {
    let (_dir, vault) = open_vault();
    let owned = id(0xF1);
    let foreign = id(0xF2);
    let fact_ref = put_fact(&vault, fact(owned, TaskAuthorityFactKind::Owner, id(0xF3)));
    vault
        .batch()
        .edge(&fact_ref, EdgeKind::ScopedTo, &foreign, 0.7)
        .commit()
        .expect("re-point the proof");

    let state = vault
        .task_authority_state(owned)
        .expect("original task authority")
        .expect("original task owner proof");
    assert_eq!(state.owner_ref, id(0xF3));
    assert!(matches!(
        vault.task_authority_state(foreign),
        Err(Error::Record(RecordError::InvalidTaskBody(_)))
    ));
}

/// Inbound `ScopedTo` is a shared structural relation. Anything that is
/// not a role-6 TASK row is simply not a fact, and must not poison the
/// read of the facts that are.
#[test]
fn non_fact_scoped_edges_are_not_facts() {
    let (_dir, vault) = open_vault();
    let task_ref = id(0x11);
    let owner = id(0x12);
    let neighbour = id(0x13);
    vault
        .put_entity(
            &neighbour,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )
        .expect("store a plain TASK");
    vault
        .batch()
        .edge(&neighbour, EdgeKind::ScopedTo, &task_ref, 0.7)
        .commit()
        .expect("scope it to the task");
    put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, owner));

    assert_eq!(
        vault.task_authority_state(task_ref).expect("state"),
        Some(TaskAuthorityState {
            owner_ref: owner,
            cancelled: false,
            acked: false,
        })
    );
}

/// Only the engine door mints authority. A caller who could write a role-6
/// body through a generic door could prove it owned any task it liked.
#[test]
fn generic_write_doors_refuse_the_reserved_role() {
    let (_dir, vault) = open_vault();
    let forged =
        encode_task_authority_fact_body(&fact(id(0x21), TaskAuthorityFactKind::Owner, id(0x22)));
    let bare_role = crate::habit::task_body_for_test(TaskRole::AuthorityFact);
    let occurred = TimeRange { start: 1, end: 1 };

    for body in [forged, bare_role] {
        let entity = EntityId::now();
        assert!(matches!(
            vault.put_entity(&entity, ENTITY_TYPE_TASK, occurred, 1, &body),
            Err(Error::Record(RecordError::InvalidTaskBody(_)))
        ));
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        let internal = vault
            .batch_in()
            .put_internal(&EntityId::now(), ENTITY_TYPE_TASK, occurred, 1, &body)
            .apply(&mut wtxn);
        assert!(matches!(
            internal,
            Err(Error::Record(RecordError::InvalidTaskBody(_)))
        ));
        drop(wtxn);
        assert!(vault.get(&entity).expect("read back").is_none());
    }
}
