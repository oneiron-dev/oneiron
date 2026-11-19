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
        actor_generation: None,
        assigned_generation: None,
        answered_heads: None,
        occurred_at: 100,
        maker: None,
    }
}

fn put_fact(vault: &Vault, fact: TaskAuthorityFact) -> EntityId {
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    let fact_ref = put_task_authority_fact_in_txn(vault, &mut wtxn, fact).expect("put fact");
    wtxn.commit().expect("commit fact");
    fact_ref
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
        actor_generation: None,
        assigned_generation: None,
        answered_heads: None,
        occurred_at: 1_700_000_000,
        maker: None,
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
        (BODY_KEY_KIND, Value::from(7_u8)),
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
    // A binding generation rides only on a consult's party fact, only as
    // one to eight 32-byte binaries in strictly ascending order, and only
    // for a party the fact names.
    cases.push(rewrite_body(&encoded, |entries| {
        entries.push((
            Value::from(BODY_KEY_ACTOR_GENERATION),
            Value::Binary(vec![0xB1; 32]),
        ));
    }));
    let parties = TaskAuthorityFact {
        kind: TaskAuthorityFactKind::ConsultAssignee,
        actor_generation: BindingGeneration::from_bindings([[0xB1; 32], [0xB0; 32]]),
        ..original
    };
    let parties_encoded = encode_task_authority_fact_body(&parties);
    assert_eq!(
        decode_task_authority_fact_body(&parties_encoded).expect("party round trip"),
        parties
    );
    let binding = |byte: u8| Value::Binary(vec![byte; 32]);
    for generation in [
        Value::from("b1".repeat(32)),
        binding(0xB1),
        Value::Array(Vec::new()),
        Value::Array(vec![binding(0xB1), binding(0xB0)]),
        Value::Array(vec![binding(0xB1), binding(0xB1)]),
        Value::Array(vec![Value::Binary(vec![0xB1; 31])]),
        Value::Array(vec![Value::from("b1".repeat(32))]),
        Value::Array((0..=8).map(binding).collect()),
    ] {
        cases.push(body_with(
            &parties_encoded,
            BODY_KEY_ACTOR_GENERATION,
            generation,
        ));
    }
    cases.push(rewrite_body(&parties_encoded, |entries| {
        entries.push((
            Value::from(BODY_KEY_ASSIGNED_GENERATION),
            Value::Binary(vec![0xB2; 32]),
        ));
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

/// engine-core-04: a fact is immutable. A put at its id, local or replicated,
/// can neither re-point the owner nor replace the fact with an ordinary TASK
/// body; only an exact echo lands.
#[test]
fn an_authority_fact_admits_only_an_exact_echo() {
    let (_dir, vault) = open_vault();
    let task_ref = id(0xD1);
    let owner = id(0xD2);
    let fact_ref = put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, owner));
    let raw = {
        let txn = vault.store.env.read_txn().expect("read txn");
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &fact_ref)
            .expect("read fact")
            .expect("stored fact")
    };
    let header = EntityMetadataHeader::parse(&raw).expect("fact header");
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    let learned_at = header.learned_at;
    let stored = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let forged = body_with(&stored, BODY_KEY_ACTOR_REF, Value::from(id(0xD3).to_hex()));
    let ordinary = crate::habit::task_body_for_test(TaskRole::Task);

    for body in [&forged, &ordinary] {
        assert!(
            vault
                .put_entity(&fact_ref, ENTITY_TYPE_TASK, occurred, learned_at, body)
                .is_err()
        );
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        let internal = vault
            .batch_in()
            .put_internal(&fact_ref, ENTITY_TYPE_TASK, occurred, learned_at, body)
            .apply(&mut wtxn);
        assert!(matches!(
            internal,
            Err(Error::Record(RecordError::InvalidTaskBody(_)))
        ));
        drop(wtxn);
        assert!(
            vault
                .batch()
                .put_replicated(
                    &fact_ref,
                    ENTITY_TYPE_TASK,
                    occurred,
                    learned_at,
                    None,
                    body
                )
                .commit()
                .is_err()
        );
    }
    vault
        .batch()
        .put_replicated(
            &fact_ref,
            ENTITY_TYPE_TASK,
            occurred,
            learned_at,
            None,
            &stored,
        )
        .commit()
        .expect("an exact echo lands");
    assert_eq!(
        vault
            .task_authority_state(task_ref)
            .expect("state")
            .map(|state| state.owner_ref),
        Some(owner)
    );
}

/// F24 round 5 (H219): every class a party holds keeps its binding, so a
/// consult its creator minted as an agent is one it still moves as that
/// agent. The eight-binding cap is gone (c1d228f0fcb, Rule 5): all ten
/// bindings stay named.
#[test]
fn a_generation_at_the_cap_keeps_every_class() {
    let held: Vec<_> = (0..8)
        .map(|byte| ("human", [byte; 32]))
        .chain([("agent", [0xF0; 32]), ("system", [0xF1; 32])])
        .collect();
    let generation = BindingGeneration::from_classed_bindings(&held).expect("a generation");
    assert_eq!(generation.bindings().len(), held.len());
    assert!(generation.names(&[0xF0; 32]), "the agent binding is kept");
    assert!(generation.names(&[0xF1; 32]), "the system binding is kept");
    assert!(
        generation.names(&[0; 32]),
        "the lowest human binding is kept"
    );
}

/// B58 G1: an Acked fact round trips the heads it saw; one from before
/// the field still decodes with none and encodes the base seven keys.
#[test]
fn an_acked_fact_round_trips_its_answered_heads() {
    let task = id(0xB1);
    let actor = id(0xB2);
    let head_a = "00000000000000000000000000000000".to_owned();
    let head_b = "11111111111111111111111111111111".to_owned();

    let mut empty = fact(task, TaskAuthorityFactKind::Acked, actor);
    empty.answered_heads = Some(std::collections::BTreeSet::new());
    let encoded = encode_task_authority_fact_body(&empty);
    assert_eq!(
        decode_task_authority_fact_body(&encoded).expect("empty round trip"),
        empty
    );

    let mut two = fact(task, TaskAuthorityFactKind::Acked, actor);
    two.answered_heads = Some(std::collections::BTreeSet::from([
        head_a.clone(),
        head_b.clone(),
    ]));
    let encoded = encode_task_authority_fact_body(&two);
    assert_eq!(
        decode_task_authority_fact_body(&encoded).expect("two round trip"),
        two
    );

    let none = fact(task, TaskAuthorityFactKind::Acked, actor);
    assert!(none.answered_heads.is_none());
    let encoded = encode_task_authority_fact_body(&none);
    let mut cursor = encoded.as_slice();
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).expect("decode map") else {
        panic!("a fact body is a map")
    };
    assert_eq!(entries.len(), 7);
    assert_eq!(
        decode_task_authority_fact_body(&encoded)
            .expect("none round trip")
            .answered_heads,
        None
    );
}

/// B58 G2: the strict decoder refuses answered heads that are not a
/// sorted unique list of 32-digit lowercase hex attempt ids, and refuses
/// the field on any kind but Acked.
#[test]
fn the_decoder_refuses_malformed_answered_heads() {
    let task = id(0xB1);
    let actor = id(0xB2);
    let head_a = "00000000000000000000000000000000".to_owned();
    let head_b = "11111111111111111111111111111111".to_owned();

    let cancelled = fact(task, TaskAuthorityFactKind::Cancelled, actor);
    let encoded = encode_task_authority_fact_body(&cancelled);
    let with_heads = rewrite_body(&encoded, |entries| {
        entries.push((
            Value::from(BODY_KEY_ANSWERED_HEADS),
            Value::Array(Vec::new()),
        ));
    });
    assert!(
        decode_task_authority_fact_body(&with_heads).is_err(),
        "Cancelled with heads must be refused"
    );

    let mut acked = fact(task, TaskAuthorityFactKind::Acked, actor);
    acked.answered_heads = Some(std::collections::BTreeSet::new());
    let base = encode_task_authority_fact_body(&acked);
    let short = "0".repeat(31);
    let long = "0".repeat(33);
    let cases = [
        (
            "unsorted",
            Value::Array(vec![
                Value::from(head_b.as_str()),
                Value::from(head_a.as_str()),
            ]),
        ),
        (
            "duplicate",
            Value::Array(vec![
                Value::from(head_a.as_str()),
                Value::from(head_a.as_str()),
            ]),
        ),
        (
            "uppercase",
            Value::Array(vec![Value::from("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]),
        ),
        ("31 digits", Value::Array(vec![Value::from(short.as_str())])),
        ("33 digits", Value::Array(vec![Value::from(long.as_str())])),
        ("non-array", Value::from(head_a.as_str())),
        ("non-string", Value::Array(vec![Value::from(1_u8)])),
    ];
    for (label, value) in cases {
        let case = body_with(&base, BODY_KEY_ANSWERED_HEADS, value);
        assert!(
            decode_task_authority_fact_body(&case).is_err(),
            "{label} must be refused"
        );
    }
}

/// B58 G3: acks of one second union the heads they saw, in either fold
/// order; one from before the field answers its whole second; a newer
/// second wins outright, in either fold order.
#[test]
fn same_second_acks_union_and_an_old_fact_answers_its_whole_second() {
    let task = id(0xB1);
    let actor = id(0xB2);
    let head_a = "00000000000000000000000000000000".to_owned();
    let head_b = "11111111111111111111111111111111".to_owned();
    let head_c = "ffffffffffffffffffffffffffffffff".to_owned();
    let empty: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    let mut first = fact(task, TaskAuthorityFactKind::Acked, actor);
    first.occurred_at = 200;
    first.answered_heads = Some(std::collections::BTreeSet::from([head_a.clone()]));
    let mut second = fact(task, TaskAuthorityFactKind::Acked, actor);
    second.occurred_at = 200;
    second.answered_heads = Some(std::collections::BTreeSet::from([head_b.clone()]));
    for swapped in [false, true] {
        let mut facts = TaskAuthorityFacts::default();
        if swapped {
            facts.absorb(&second).expect("absorb second");
            facts.absorb(&first).expect("absorb first");
        } else {
            facts.absorb(&first).expect("absorb first");
            facts.absorb(&second).expect("absorb second");
        }
        let ack = facts.ack.as_ref().expect("an ack");
        assert_eq!(ack.at, 200);
        assert!(
            ack.answers(
                200,
                &std::collections::BTreeSet::from([head_a.clone(), head_b.clone()])
            ),
            "same-second acks answer their union"
        );
        assert!(
            !ack.answers(
                200,
                &std::collections::BTreeSet::from([head_a.clone(), head_b.clone(), head_c.clone()])
            ),
            "same-second acks do not answer an unseen head"
        );
    }

    let mut headed = fact(task, TaskAuthorityFactKind::Acked, actor);
    headed.occurred_at = 200;
    headed.answered_heads = Some(std::collections::BTreeSet::from([head_a.clone()]));
    let mut legacy = fact(task, TaskAuthorityFactKind::Acked, actor);
    legacy.occurred_at = 200;
    legacy.answered_heads = None;
    for swapped in [false, true] {
        let mut facts = TaskAuthorityFacts::default();
        if swapped {
            facts.absorb(&legacy).expect("absorb legacy");
            facts.absorb(&headed).expect("absorb headed");
        } else {
            facts.absorb(&headed).expect("absorb headed");
            facts.absorb(&legacy).expect("absorb legacy");
        }
        let ack = facts.ack.as_ref().expect("an ack");
        assert_eq!(ack.at, 200);
        assert!(
            ack.answers(
                200,
                &std::collections::BTreeSet::from([head_a.clone(), head_b.clone(), head_c.clone()])
            ),
            "an old fact answers its whole second"
        );
    }

    let mut later = fact(task, TaskAuthorityFactKind::Acked, actor);
    later.occurred_at = 201;
    later.answered_heads = Some(std::collections::BTreeSet::new());
    for swapped in [false, true] {
        let mut facts = TaskAuthorityFacts::default();
        if swapped {
            facts.absorb(&later).expect("absorb later");
            facts.absorb(&first).expect("absorb first");
            facts.absorb(&second).expect("absorb second");
        } else {
            facts.absorb(&first).expect("absorb first");
            facts.absorb(&second).expect("absorb second");
            facts.absorb(&later).expect("absorb later");
        }
        let ack = facts.ack.as_ref().expect("an ack");
        assert_eq!(ack.at, 201);
        assert!(
            !ack.answers(201, &std::collections::BTreeSet::from([head_a.clone()])),
            "a newer empty second answers no nonempty heads"
        );
        assert!(
            ack.answers(201, &empty),
            "a newer empty second answers empty"
        );
        assert!(
            ack.answers(
                200,
                &std::collections::BTreeSet::from([head_a.clone(), head_b.clone(), head_c.clone()])
            ),
            "an earlier second stays answered"
        );
        assert!(
            ack.answers(199, &std::collections::BTreeSet::from([head_c.clone()])),
            "any earlier second stays answered"
        );
        assert!(!ack.answers(202, &empty), "nothing answers past the ack");
        assert!(
            !ack.answers(202, &std::collections::BTreeSet::from([head_a.clone()])),
            "nothing answers past the ack"
        );
    }
}
