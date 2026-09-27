//! A real Loro exchange preserves issuer-verified foreign-stated ask evidence.
#![cfg(feature = "sync")]

use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDecision, TaskAskOptionId, TaskAskQuestion, TaskAskSource,
    TaskAskSpec, TaskAskStatus, TaskAskTarget,
};
use oneiron::{EntityId, TimeRange, VaultConfig};

use crate::sync_harness::{TestNode, exchange};

#[test]
fn genuine_link_answer_replicates_without_a_bearer_on_the_reader() {
    let mut a = TestNode::with_config("link-origin", 11, VaultConfig::default());
    let mut b = TestNode::with_config("link-replica", 12, VaultConfig::default());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("replication fixture")
        .as_secs();
    let window = WindowKey::from_timestamp(now);
    a.open_window(window.as_str());
    b.open_window(window.as_str());
    let owner = a
        .vault
        .ensure_embedded_owner_actor()
        .expect("replication fixture");
    let friend = EntityId::from_bytes([0x91; 16]).expect("replication fixture");
    a.vault
        .put_entity(
            &friend,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"friend",
        )
        .expect("replication fixture");
    let question = EntityId::from_bytes([0x92; 16]).expect("replication fixture");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))
        .expect("replication fixture");
    a.vault
        .put_entity(
            &question,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .expect("replication fixture");
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(question));
    what.options.insert(
        TaskAskOptionId::new("yes").expect("replication fixture"),
        "Yes".into(),
    );
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People([friend].into())),
        what,
        Some(now + 3600),
        Default::default(),
    );
    spec.intent_key = "replicated-link".into();
    let memory = a.vault.memory(owner, EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec).expect("replication fixture").handle;
    let link = memory
        .tasks_ask_option_link(ask, friend)
        .expect("replication fixture");
    let answer = a
        .vault
        .answer_ask_option_link(
            &link.token,
            &TaskAskOptionId::new("yes").expect("replication fixture"),
        )
        .expect("replication fixture");
    reverse_rematerialize(&a.vault, a.doc(window.as_str()), &window).expect("replication fixture");
    exchange(&a, &b, window.as_str());
    let evidence = b
        .vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_evidence(ask)
        .expect("replication fixture");
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].source, TaskAskSource::ForeignStated);
    assert_eq!(evidence[0].answer, answer);
    let TaskAskStatus::Settled(result) = b
        .vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_status(ask)
        .expect("replication fixture")
    else {
        panic!("replicated first answer settles");
    };
    assert_eq!(result.decision, TaskAskDecision::First(answer));
    assert!(
        b.vault.ask_option_link_view(&link.token).is_err(),
        "raw bearer never replicated"
    );
}

#[test]
fn voided_link_forgery_is_quarantined_by_real_loro_replay() {
    use crate::sync_harness::{entity_blob, map_insert_bytes};
    use oneiron::habit::TaskRole;
    use oneiron::registry::ENTITY_TYPE_TASK;
    let mut a = TestNode::with_config("link-forgery", 21, VaultConfig::default());
    let mut b = TestNode::with_config("link-observer", 22, VaultConfig::default());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let window = WindowKey::from_timestamp(now);
    a.open_window(window.as_str());
    b.open_window(window.as_str());
    let owner = a.vault.ensure_embedded_owner_actor().expect("owner");
    let friend = EntityId::from_bytes([0xB1; 16]).expect("friend");
    a.vault
        .put_entity(
            &friend,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"friend",
        )
        .expect("person");
    let question = EntityId::from_bytes([0xB2; 16]).expect("question");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))
        .expect("question body");
    a.vault
        .put_entity(
            &question,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .expect("turn");
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(question));
    what.options
        .insert(TaskAskOptionId::new("yes").expect("option"), "Yes".into());
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People([friend].into())),
        what,
        Some(now + 3600),
        Default::default(),
    );
    spec.intent_key = "replicated-forgery".into();
    let memory = a.vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory.tasks_ask(&spec).expect("ask");
    let link = memory
        .tasks_ask_option_link(receipt.handle, friend)
        .expect("link");
    a.vault.void_ask_option_link(&link.token).expect("void");
    reverse_rematerialize(&a.vault, a.doc(window.as_str()), &window).expect("mirror ask");
    exchange(&a, &b, window.as_str());

    let task = receipt.task_refs[0];
    let word = oneiron::task_verb::TaskAskWord {
        result_ref: friend,
        option: Some(TaskAskOptionId::new("yes").expect("option")),
        inform_for: None,
        provenance_refs: Default::default(),
    };
    let material = rmp_serde::to_vec_named(&(task, friend, TaskAskSource::ForeignStated, &word))
        .expect("answer identity");
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.tasks.ask.answer.v1");
    hash.update(receipt.handle.group_ref.as_bytes());
    hash.update(&material);
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    let word_ref = EntityId::from_bytes(id).expect("word id");
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.tasks.ask.option_link.v1\0");
    hash.update(link.token.as_bytes());
    let digest = hash.finalize();
    let forged = serde_json::json!({
        "role": TaskRole::AuthorityFact.role_byte(), "schema_version": 1,
        "subkind": "tasks.ask_answer", "group": receipt.handle.group_ref.to_hex(),
        "task": task.to_hex(), "actor": friend.to_hex(), "source": "foreign_stated",
        "word": {"result_ref":friend.to_hex(),"option":"yes","inform_for":null,"provenance_refs":[]},
        "link_proof": {"token_digest":digest.as_bytes().to_vec(),"revision":1,"signature":vec![0_u8;64]},
        "order":1, "at": now + 1,
    });
    let encoded = rmp_serde::to_vec_named(&forged).expect("forged body");
    let blob = entity_blob(
        ENTITY_TYPE_TASK,
        TimeRange {
            start: now + 1,
            end: now + 1,
        },
        now + 1,
        &encoded,
    );
    // Deliberately bypass TestNode::put_entity_in_window's success assertion:
    // this hostile row MUST be refused by Observer B on BOTH nodes.
    let entities = a.doc(window.as_str()).get_map("entities");
    map_insert_bytes(&entities, &word_ref.to_hex(), &blob);
    a.doc(window.as_str()).commit();
    exchange(&a, &b, window.as_str());
    assert!(b.vault.get_raw(&word_ref).expect("remote raw").is_none());
    assert!(
        b.vault
            .memory(owner, EdgeActorClass::Human)
            .tasks_ask_evidence(receipt.handle)
            .expect("safe evidence")
            .is_empty()
    );
    assert!(matches!(
        b.vault
            .memory(owner, EdgeActorClass::Human)
            .tasks_ask_status(receipt.handle)
            .expect("pending"),
        TaskAskStatus::Pending { .. }
    ));
}
