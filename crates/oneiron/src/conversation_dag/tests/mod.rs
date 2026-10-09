//! Observable DAG invariants, legacy adoption and rejection atomicity.

use super::fixtures as support;
use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{EdgeActorClass, EdgeKind, EntityId, ErrorKind, Vault, WriteActor};
use support::*;

#[test]
fn dag_test_policy_keeps_the_default_manifest() {
    let (_dir, vault, _conv, actor) = fixture();
    grant(&vault, actor, false);
    let id = crate::gate::default_policy_manifest_id().unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let raw = vault
        .store
        .entities
        .get(&txn, id.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        crate::gate::default_policy_manifest().unwrap()
    );
}

#[test]
fn dag_test_policy_refuses_an_actor_the_vault_does_not_hold() {
    let (_dir, vault, _conv, actor) = fixture();
    let missing = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    assert!(
        crate::conversation_dag::test_support::put_dag_test_policy(&vault, missing, true).is_err()
    );
    let mismatch = WriteActor::new(actor.entity_ref(), EdgeActorClass::System);
    assert!(
        crate::conversation_dag::test_support::put_dag_test_policy(&vault, mismatch, true).is_err()
    );
}

#[test]
fn dag_test_policy_refuses_a_manifest_id_owned_by_an_actor() {
    let (_dir, vault, _conv, actor) = fixture();
    let policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "test-id", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {}, "rules": [], "actor_ceilings": []
    });
    assert!(
        crate::conversation_dag::test_support::put_test_policy_manifest(
            &vault,
            actor,
            actor.entity_ref(),
            &policy,
        )
        .is_err()
    );
    assert_eq!(
        vault.get_entity_type(&actor.entity_ref()).unwrap(),
        Some(crate::registry::ENTITY_TYPE_PERSON)
    );
}

#[test]
fn dag_test_policy_refuses_undecodable_policy_before_writing() {
    let (_dir, vault, _conv, actor) = fixture();
    let id = EntityId::now();
    assert!(
        crate::conversation_dag::test_support::put_test_policy_manifest(
            &vault,
            actor,
            id,
            &serde_json::Value::Null,
        )
        .is_err()
    );
    assert_eq!(vault.get_entity_type(&id).unwrap(), None);
    assert!(
        !vault
            .manifest_contributions()
            .unwrap()
            .iter()
            .any(|row| row.id == id.to_hex())
    );
}

#[test]
fn forks_rewrite_canonical_and_preserve_old_branch_and_pages() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_dag_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    let thread = vault
        .append_dag_record(&input(conv, Some(root), false, actor))
        .unwrap()
        .id;
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Branch(thread), false))
            .unwrap()
            .records,
        [root, thread]
    );
    let forks = vault
        .resolve_dag_scope(&scope(conv, ScopePath::Canonical, true))
        .unwrap()
        .records;
    assert_eq!(
        forks.into_iter().collect::<std::collections::BTreeSet<_>>(),
        [root, trunk, thread].into()
    );
    vault.move_head(&conv, &thread).unwrap();
    // A selected fork is a canonical child, never a thread root.
    assert!(vault.thread_roots(root).unwrap().is_empty());
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Canonical, false))
            .unwrap()
            .records,
        [root, thread]
    );
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Branch(trunk), false))
            .unwrap()
            .records,
        [root, trunk]
    );
    let page = vault
        .main_line(
            &conv,
            DagPageRequest {
                after: None,
                limit: 1,
            },
        )
        .unwrap();
    assert_eq!(page.head, Some(thread));
    assert_eq!(page.root, Some(root));
    assert_eq!(page.main_line, [root]);
    assert_eq!(page.next, Some(root));
    let page = vault
        .main_line(
            &conv,
            DagPageRequest {
                after: page.next,
                limit: 1,
            },
        )
        .unwrap();
    assert_eq!(page.main_line, [thread]);
    assert_eq!(page.next, None);
    // A returned main_line also verifies every canonical mark, including HEAD.
    vault.rebuild_conversation_canonical(&conv).unwrap();
    assert_eq!(vault.head(&conv).unwrap(), Some(thread));
}

#[test]
fn addressing_is_stamped_and_validated_atomically() {
    let (_dir, vault, conv, actor) = fixture();
    let recipient = EntityId::now();
    let another = EntityId::now();
    for id in [recipient, another] {
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                time(1),
                1,
                &body("person"),
            )
            .unwrap();
    }
    let mut direct_input = input(conv, None, true, actor);
    direct_input.address = AddressMode::Direct;
    for recipients in [
        vec![],
        vec![recipient, recipient],
        vec![EntityId::now()],
        vec![conv],
    ] {
        direct_input.recipients = recipients;
        assert_eq!(
            vault.append_dag_record(&direct_input).unwrap_err().kind(),
            if direct_input.recipients.len() == 1 && direct_input.recipients[0] != conv {
                ErrorKind::EntityNotFound
            } else {
                ErrorKind::InvalidConversationDag
            }
        );
        assert!(
            vault
                .sources(&conv, EdgeKind::ChildOf, None)
                .unwrap()
                .is_empty()
        );
    }
    direct_input.recipients = vec![recipient, another];
    let direct = vault.append_dag_record(&direct_input).unwrap().id;
    let txn = vault.store.env.read_txn().unwrap();
    let body = super::graph::require_type(&vault.store, &txn, &direct, ENTITY_TYPE_TURN).unwrap();
    let decoded: serde_json::Value = rmp_serde::from_slice(&body).unwrap();
    assert_eq!(decoded["addr"], "direct");
    assert_eq!(
        decoded["to"],
        serde_json::json!([recipient.to_hex(), another.to_hex()])
    );
    drop(txn);
    assert_eq!(
        vault
            .targets(&direct, EdgeKind::AddressedTo, None)
            .unwrap()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [recipient, another].into()
    );
    let mut reply = input(conv, Some(direct), true, actor);
    reply.reply_to = Some(direct);
    reply.recipients = vec![recipient];
    let reply_id = vault.append_dag_record(&reply).unwrap().id;
    let txn = vault.store.env.read_txn().unwrap();
    let body = super::graph::require_type(&vault.store, &txn, &reply_id, ENTITY_TYPE_TURN).unwrap();
    let decoded: serde_json::Value = rmp_serde::from_slice(&body).unwrap();
    assert_eq!(decoded["addr"], "reply");
    assert_eq!(decoded["to"], serde_json::json!([recipient.to_hex()]));
    drop(txn);
    assert_eq!(
        vault
            .targets(&reply_id, EdgeKind::AddressedTo, None)
            .unwrap(),
        [recipient]
    );
    assert_eq!(
        vault.targets(&reply_id, EdgeKind::RepliesTo, None).unwrap(),
        [direct]
    );
    let mut broadcast = input(conv, Some(reply_id), true, actor);
    broadcast.recipients = vec![recipient];
    assert_eq!(
        vault.append_dag_record(&broadcast).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    broadcast.recipients.clear();
    let next = vault.append_dag_record(&broadcast).unwrap().id;
    let txn = vault.store.env.read_txn().unwrap();
    let body = super::graph::require_type(&vault.store, &txn, &next, ENTITY_TYPE_TURN).unwrap();
    let decoded: serde_json::Value = rmp_serde::from_slice(&body).unwrap();
    assert_eq!(decoded["addr"], "broadcast");
    assert_eq!(decoded["to"], serde_json::json!([]));
    drop(txn);
    assert!(
        vault
            .targets(&next, EdgeKind::AddressedTo, None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn append_refuses_cross_conversation_off_trunk_actor_and_policy_without_writes() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_dag_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    assert_eq!(
        vault
            .append_dag_record(&input(conv, Some(root), true, actor))
            .unwrap_err()
            .kind(),
        ErrorKind::HeadAdvanceOffTrunk
    );
    let other = EntityId::now();
    vault
        .put_entity(&other, ENTITY_TYPE_CONVERSATION, time(1), 1, &body("other"))
        .unwrap();
    assert_eq!(
        vault
            .append_dag_record(&input(other, Some(root), false, actor))
            .unwrap_err()
            .kind(),
        ErrorKind::DagParentOutsideConversation
    );
    let wrong = WriteActor::new(actor.entity_ref(), EdgeActorClass::System);
    assert_eq!(
        vault
            .append_dag_record(&input(conv, Some(trunk), true, wrong))
            .unwrap_err()
            .kind(),
        ErrorKind::ActorClassMismatch
    );
    grant(&vault, actor, false);
    assert_eq!(
        vault
            .append_dag_record(&input(conv, Some(trunk), true, actor))
            .unwrap_err()
            .kind(),
        ErrorKind::GateWriteRejected
    );
    assert_eq!(
        vault
            .sources(&conv, EdgeKind::ChildOf, Some(ENTITY_TYPE_TURN))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
}

#[test]
fn corrupted_cycle_cardinality_and_canonical_marks_fail_closed() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let child = vault
        .append_dag_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    // Internal fault fixture models a malformed received graph. Public writes
    // cannot mint Parent at all.
    vault
        .batch()
        .edge_with_value_fields(&root, EdgeKind::Parent, &child, super::writes::value(1))
        .commit()
        .unwrap();
    assert_eq!(
        vault.head(&conv).unwrap_err().kind(),
        ErrorKind::CycleDetected
    );
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Canonical, false))
            .unwrap_err()
            .kind(),
        ErrorKind::CycleDetected
    );
    assert_eq!(
        vault
            .delete_edge(&root, EdgeKind::Parent, &child)
            .unwrap_err()
            .kind(),
        ErrorKind::ReservedEdgeKind
    );
    // The forged Parent cannot be retired, so the canonical-mark fault gets a
    // clean graph of its own.
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let child = vault
        .append_dag_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    vault
        .with_write_txn(|txn| {
            super::graph::CANONICAL.put(&vault.store, txn, &child, &root)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        vault.head(&conv).unwrap_err().kind(),
        ErrorKind::CorruptedIndex
    );
    vault.rebuild_conversation_canonical(&conv).unwrap();
    assert_eq!(vault.head(&conv).unwrap(), Some(child));
    assert_eq!(
        vault
            .put_edge(&child, EdgeKind::Parent, &root, 1.0)
            .unwrap_err()
            .kind(),
        ErrorKind::ReservedEdgeKind
    );
}

#[test]
fn migration_backfills_forward_only_session_membership_and_rejects_bad_marker() {
    let (_dir, vault, conv, _actor) = fixture();
    let asking = EntityId::now();
    let session = EntityId::now();
    let child = EntityId::now();
    // Spawning through the DAG door adopts the conversation and closes legacy
    // ChildOf appends, so the whole legacy sub-session predates adoption.
    vault
        .batch()
        .put(
            &asking,
            ENTITY_TYPE_TURN,
            time(1),
            1,
            &body("legacy asking"),
        )
        .edge_checked(&asking, &conv, 1.0)
        .put(
            &session,
            ENTITY_TYPE_SESSION,
            time(1),
            1,
            &body("legacy session"),
        )
        .edge_with_value_fields(
            &session,
            EdgeKind::SpawnedBy,
            &asking,
            super::writes::value(1),
        )
        .put(&child, ENTITY_TYPE_TURN, time(2), 2, &body("legacy worker"))
        .edge_checked(&child, &conv, 1.0)
        .edge_with_value_fields(&child, EdgeKind::Parent, &asking, super::writes::value(2))
        .commit()
        .unwrap();
    vault
        .with_write_txn(|txn| {
            let key = [
                b"session_lifecycle:v0:turn_session:".as_slice(),
                child.as_bytes(),
            ]
            .concat();
            vault.store.vault_meta.put(txn, &key, session.as_bytes())?;
            Ok(())
        })
        .unwrap();
    assert!(vault.migrate_conversation_dag(&conv).unwrap());
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::SubSession(session), false))
            .unwrap()
            .records,
        [child]
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(asking));
    vault
        .with_write_txn(|txn| {
            super::graph::MIGRATED.put(&vault.store, txn, &conv, &[2])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        vault.migrate_conversation_dag(&conv).unwrap_err().kind(),
        ErrorKind::CorruptedIndex
    );
}

#[test]
fn legacy_childof_append_cannot_orphan_a_record_after_dag_adoption() {
    let (_dir, vault, conversation, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conversation, None, true, actor))
        .unwrap();
    let record = EntityId::now();
    let result = vault
        .batch()
        .put(
            &record,
            crate::registry::ENTITY_TYPE_TURN,
            crate::TimeRange { start: 2, end: 2 },
            2,
            b"legacy",
        )
        .edge(&record, EdgeKind::ChildOf, &conversation, 1.0)
        .commit();
    assert!(matches!(
        result,
        Err(crate::Error::Record(
            crate::error::RecordError::InvalidConversationDag(_)
        ))
    ));
    assert!(vault.get(&record).unwrap().is_none());
    assert_eq!(vault.head(&conversation).unwrap(), Some(root.id));
    let next = vault
        .append_dag_record(&input(conversation, Some(root.id), true, actor))
        .unwrap();
    assert_eq!(vault.head(&conversation).unwrap(), Some(next.id));
}

// The cycle is disconnected from the only root but remains within the same
// conversation. This reaches the Kahn walk, not the multiple-roots guard.
fn legacy_conversations_with_cycle() -> (tempfile::TempDir, Vault, EntityId, EntityId, EntityId) {
    let (dir, vault, _unused, _actor) = fixture();
    let cyclic = EntityId::from_bytes([0x01; 16]).unwrap();
    let healthy = EntityId::from_bytes([0xfe; 16]).unwrap();
    let root = EntityId::now();
    let a = EntityId::now();
    let b = EntityId::now();
    let healthy_root = EntityId::now();
    vault
        .batch()
        .put(
            &cyclic,
            ENTITY_TYPE_CONVERSATION,
            time(1),
            1,
            &body("cyclic"),
        )
        .put(
            &healthy,
            ENTITY_TYPE_CONVERSATION,
            time(1),
            1,
            &body("healthy"),
        )
        .put(&root, ENTITY_TYPE_TURN, time(1), 1, &body("root"))
        .put(&a, ENTITY_TYPE_TURN, time(2), 2, &body("cycle-a"))
        .put(&b, ENTITY_TYPE_TURN, time(3), 3, &body("cycle-b"))
        .put(
            &healthy_root,
            ENTITY_TYPE_TURN,
            time(1),
            1,
            &body("healthy-root"),
        )
        .edge_checked(&root, &cyclic, 1.0)
        .edge_checked(&a, &cyclic, 1.0)
        .edge_checked(&b, &cyclic, 1.0)
        .edge_checked(&healthy_root, &healthy, 1.0)
        .edge_with_value_fields(&a, EdgeKind::Parent, &b, super::writes::value(2))
        .edge_with_value_fields(&b, EdgeKind::Parent, &a, super::writes::value(3))
        .commit()
        .unwrap();
    (dir, vault, cyclic, healthy, healthy_root)
}

#[test]
fn maintenance_skips_a_cyclic_conversation_and_migrates_the_rest() {
    let (_dir, vault, cyclic, healthy, healthy_root) = legacy_conversations_with_cycle();
    assert!(matches!(
        vault.migrate_conversation_dag(&cyclic).unwrap_err(),
        crate::error::Error::Record(crate::error::RecordError::InvalidConversationDag(reason))
            if reason.contains("cycle")
    ));
    let report = vault.maintain().migrate_conversation_dags().run().unwrap();
    assert_eq!(report.conversation_dags_migrated, 1);
    assert_eq!(vault.head(&healthy).unwrap(), Some(healthy_root));
    // The skipped write transaction did not adopt HEAD or mark the cyclic DAG.
    assert!(matches!(
        vault.migrate_conversation_dag(&cyclic).unwrap_err(),
        crate::error::Error::Record(crate::error::RecordError::InvalidConversationDag(_))
    ));
}

#[test]
fn migration_rejects_disconnected_received_roots_without_adopting_the_forest() {
    let (_dir, vault, conv, _actor) = fixture();
    let first = EntityId::now();
    let branch = EntityId::now();
    let separate = EntityId::now();
    vault
        .batch()
        .put(&first, ENTITY_TYPE_TURN, time(1), 1, &body("root"))
        .put(&branch, ENTITY_TYPE_TURN, time(2), 2, &body("child"))
        .put(
            &separate,
            ENTITY_TYPE_TURN,
            time(3),
            3,
            &body("disconnected"),
        )
        .edge_checked(&first, &conv, 1.0)
        .edge_checked(&branch, &conv, 1.0)
        .edge_checked(&separate, &conv, 1.0)
        .edge_with_value_fields(&branch, EdgeKind::Parent, &first, super::writes::value(2))
        .commit()
        .unwrap();
    assert_eq!(
        vault.migrate_conversation_dag(&conv).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    let mut healthy = Vec::new();
    for byte in [0x01, 0xfe] {
        let conversation = EntityId::from_bytes([byte; 16]).unwrap();
        let turn = EntityId::now();
        vault
            .batch()
            .put(
                &conversation,
                ENTITY_TYPE_CONVERSATION,
                time(1),
                1,
                &body("healthy"),
            )
            .put(&turn, ENTITY_TYPE_TURN, time(1), 1, &body("root"))
            .edge_checked(&turn, &conversation, 1.0)
            .commit()
            .unwrap();
        healthy.push((conversation, turn));
    }
    let report = vault.maintain().migrate_conversation_dags().run().unwrap();
    assert_eq!(report.conversation_dags_migrated, 2);
    assert_eq!(report.conversation_dags_skipped_invalid, vec![conv]);
    for (conversation, turn) in healthy {
        assert_eq!(vault.head(&conversation).unwrap(), Some(turn));
    }
    assert_eq!(
        vault.migrate_conversation_dag(&conv).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    // Fixing the supplied topology must still allow adoption: the failed
    // transaction may not leave HEAD, canonical marks or a migration marker.
    vault
        .batch()
        .edge_with_value_fields(
            &separate,
            EdgeKind::Parent,
            &branch,
            super::writes::value(3),
        )
        .commit()
        .unwrap();
    let report = vault.maintain().migrate_conversation_dags().run().unwrap();
    assert_eq!(report.conversation_dags_migrated, 1);
    assert!(report.conversation_dags_skipped_invalid.is_empty());
    assert!(!vault.migrate_conversation_dag(&conv).unwrap());
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Canonical, true))
            .unwrap()
            .records,
        [first, branch, separate]
    );
}

mod replay;

#[test]
fn reply_pointer_rejects_foreign_target_and_reserved_body_fields_atomically() {
    let (_dir, vault, conversation, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conversation, None, true, actor))
        .unwrap()
        .id;
    let other = EntityId::now();
    vault
        .put_entity(&other, ENTITY_TYPE_CONVERSATION, time(1), 1, &body("other"))
        .unwrap();
    let foreign = vault
        .append_dag_record(&input(other, None, true, actor))
        .unwrap()
        .id;
    let mut reply = input(conversation, Some(root), false, actor);
    reply.reply_to = Some(foreign);
    assert_eq!(
        vault.append_dag_record(&reply).unwrap_err().kind(),
        ErrorKind::DagParentOutsideConversation
    );
    reply.reply_to = Some(root);
    for field in ["addr", "to", "reply_to", "summary"] {
        reply.body = rmp_serde::to_vec_named(&serde_json::json!({field: "forged"})).unwrap();
        assert_eq!(
            vault.append_dag_record(&reply).unwrap_err().kind(),
            ErrorKind::InvalidConversationDag
        );
    }
    assert_eq!(
        vault
            .sources(&conversation, EdgeKind::ChildOf, None)
            .unwrap(),
        [root]
    );
    assert_eq!(vault.head(&conversation).unwrap(), Some(root));
}

#[test]
fn head_cannot_select_a_thread_or_escape_through_its_descendant() {
    let (_dir, vault, conversation, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conversation, None, true, actor))
        .unwrap()
        .id;
    let thread = vault
        .reply_in_thread(root, &input(conversation, Some(root), false, actor))
        .unwrap()
        .id;
    assert_eq!(
        vault.move_head(&conversation, &thread).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    assert_eq!(
        vault
            .append_dag_record(&input(conversation, Some(thread), false, actor))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConversationDag
    );
    assert_eq!(vault.head(&conversation).unwrap(), Some(root));
    let next = vault
        .reply_in_thread(thread, &input(conversation, Some(thread), false, actor))
        .unwrap()
        .id;
    assert_eq!(vault.thread(root).unwrap().replies, [thread, next]);
    assert_eq!(
        vault.move_head(&conversation, &next).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
}

#[test]
fn thread_roots_metadata_rebuild_and_summary_cover_the_exact_branch() {
    let (_dir, vault, conversation, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conversation, None, true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_dag_record(&input(conversation, Some(root), true, actor))
        .unwrap()
        .id;
    assert!(vault.thread_roots(root).unwrap().is_empty());
    assert_eq!(vault.thread_meta(root).unwrap(), None);
    let mut reply = input(conversation, None, false, actor);
    reply.occurred = time(21);
    let first = vault.reply_in_thread(root, &reply).unwrap().id;
    let at_head = vault.reply_in_thread(trunk, &reply).unwrap().id;
    assert_eq!(vault.head(&conversation).unwrap(), Some(trunk));
    assert_eq!(vault.thread_roots(trunk).unwrap(), [at_head]);
    reply.occurred = time(23);
    let second = vault.reply_in_thread(root, &reply).unwrap().id;
    reply.occurred = time(22);
    let third = vault.reply_in_thread(root, &reply).unwrap().id;
    assert_eq!(vault.head(&conversation).unwrap(), Some(trunk));
    assert_eq!(vault.thread_roots(root).unwrap(), [first]);
    assert_eq!(vault.thread_roots(root).unwrap(), [first]);
    let meta = vault.thread_meta(root).unwrap().unwrap();
    assert_eq!(meta.root, first);
    assert_eq!(meta.count, 3);
    assert_eq!(meta.last_at, 23);
    assert_eq!(vault.rebuild_thread_meta(root).unwrap(), Some(meta));
    assert_eq!(vault.thread(root).unwrap().replies, [first, second, third]);
    let (summary, header) = vault
        .mint_and_land_thread_summary(root, "summary", actor)
        .unwrap();
    assert_eq!(
        vault.scope_summary_covers(&summary).unwrap(),
        [first, second, third]
    );
    assert_eq!(vault.drill(&header.claim).unwrap(), [first, second, third]);
    assert_eq!(
        vault.get_claim(&header.claim).unwrap().unwrap().subject,
        crate::claim::ClaimSubject::Entity(root)
    );
    assert_eq!(vault.head(&conversation).unwrap(), Some(trunk));
    let mut canonical_reply = input(conversation, Some(trunk), true, actor);
    canonical_reply.reply_to = Some(root);
    let canonical = vault.append_dag_record(&canonical_reply).unwrap().id;
    assert_eq!(vault.thread_roots(root).unwrap(), [first]);
    assert_eq!(vault.head(&conversation).unwrap(), Some(canonical));
}

#[test]
fn inner_worker_thread_summary_excludes_outer_session_ancestry() {
    let (_dir, vault, conv, actor) = fixture();
    let trunk = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let outer = vault.spawn_dag_sub_session(&trunk, actor).unwrap();
    let mut outer_input = input(conv, Some(trunk), false, actor);
    outer_input.session = Some(outer);
    let worker = vault.append_dag_record(&outer_input).unwrap().id;
    let inner = vault.spawn_dag_sub_session(&worker, actor).unwrap();
    let mut inner_input = input(conv, None, false, actor);
    inner_input.session = Some(inner);
    let root = vault.reply_in_thread(worker, &inner_input).unwrap().id;
    let next = vault.reply_in_thread(worker, &inner_input).unwrap().id;
    assert_eq!(vault.thread(worker).unwrap().replies, [root, next]);
    let (summary, header) = vault
        .mint_and_land_thread_summary(worker, "inner worker", actor)
        .unwrap();
    assert_eq!(vault.scope_summary_covers(&summary).unwrap(), [root, next]);
    assert_eq!(vault.drill(&header.claim).unwrap(), [root, next]);
    assert_eq!(
        vault.get_claim(&header.claim).unwrap().unwrap().subject,
        crate::claim::ClaimSubject::Entity(worker)
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
}

#[test]
fn bounded_thread_summary_excludes_room_prefix_and_pins_historic_replies() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let before = vault
        .append_dag_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_dag_record(&input(conv, Some(before), true, actor))
        .unwrap()
        .id;
    let first = vault
        .reply_in_thread(trunk, &input(conv, None, false, actor))
        .unwrap()
        .id;
    let second = vault
        .reply_in_thread(trunk, &input(conv, None, false, actor))
        .unwrap()
        .id;
    let span = scope(
        conv,
        ScopePath::BranchSpan {
            after: trunk,
            through: second,
        },
        false,
    );
    assert_eq!(
        vault.resolve_dag_scope(&span).unwrap().records,
        [first, second]
    );
    let (summary, header) = vault
        .mint_and_land_thread_summary(trunk, "pinned replies", actor)
        .unwrap();
    assert_eq!(
        vault.scope_summary_covers(&summary).unwrap(),
        [first, second]
    );
    assert_eq!(vault.drill(&header.claim).unwrap(), [first, second]);
    assert_eq!(
        vault.get_claim(&header.claim).unwrap().unwrap().subject,
        crate::claim::ClaimSubject::Entity(trunk)
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
    let third = vault
        .reply_in_thread(trunk, &input(conv, None, false, actor))
        .unwrap()
        .id;
    let worker_session = vault.spawn_dag_sub_session(&trunk, actor).unwrap();
    let mut sibling_input = input(conv, None, false, actor);
    sibling_input.session = Some(worker_session);
    let sibling = vault.reply_in_thread(trunk, &sibling_input).unwrap().id;
    assert_eq!(vault.thread(trunk).unwrap().replies, [first, second, third]);
    assert!(vault.thread_roots(trunk).unwrap().contains(&sibling));
    vault.move_head(&conv, &root).unwrap();
    assert_eq!(
        vault.scope_summary_covers(&summary).unwrap(),
        [first, second]
    );
    assert_eq!(vault.drill(&header.claim).unwrap(), [first, second]);
}
