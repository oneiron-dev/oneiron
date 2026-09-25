//! Observable DAG invariants, legacy adoption and rejection atomicity.

use super::fixtures as support;
use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{EdgeActorClass, EdgeKind, EntityId, ErrorKind, Vault, WriteActor};
use proptest::prelude::*;
use support::*;

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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]
    #[test]
    fn threads_never_advance_head(ops in prop::collection::vec(any::<bool>(), 1..40)) {
        let (_dir, vault, conv, actor) = fixture();
        let root = vault.append_dag_record(&input(conv, None, true, actor)).unwrap().id;
        let mut head = root;
        let mut trunk = vec![root];
        for advance in ops {
            let parent = if advance { head } else { root };
            let appended = vault.append_dag_record(&input(conv, Some(parent), advance, actor)).unwrap();
            if advance { head = appended.id; trunk.push(head); }
            prop_assert_eq!(appended.head, Some(head));
            prop_assert_eq!(vault.head(&conv).unwrap(), Some(head));
        }
        prop_assert_eq!(vault.resolve_dag_scope(&scope(conv, ScopePath::Canonical, false)).unwrap().records, trunk);
    }
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
fn legacy_migration_is_time_ordered_lazy_idempotent_and_maintainable() {
    let (_dir, vault, conv, _actor) = fixture();
    let ids: Vec<_> = (0..3).map(|_| EntityId::now()).collect();
    let mut batch = vault.batch();
    for (id, at) in ids.iter().zip([30, 10, 20]) {
        batch = batch
            .put(id, ENTITY_TYPE_TURN, time(at), at, &body("legacy"))
            .edge_checked(id, &conv, 1.0);
    }
    batch.commit().unwrap();
    assert_eq!(vault.head(&conv).unwrap(), Some(ids[0]));
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Canonical, false))
            .unwrap()
            .records,
        [ids[1], ids[2], ids[0]]
    );
    assert!(!vault.migrate_conversation_dag(&conv).unwrap());
    for id in &ids {
        assert!(vault.edge_exists(id, EdgeKind::ChildOf, &conv).unwrap());
    }
    let other = EntityId::now();
    vault
        .put_entity(&other, ENTITY_TYPE_CONVERSATION, time(1), 1, &body("other"))
        .unwrap();
    // Maintenance adopts legacy content; an empty conversation has none.
    let legacy = EntityId::now();
    vault
        .batch()
        .put(&legacy, ENTITY_TYPE_TURN, time(1), 1, &body("legacy"))
        .edge_checked(&legacy, &other, 1.0)
        .commit()
        .unwrap();
    assert_eq!(
        vault
            .maintain()
            .migrate_conversation_dags()
            .run()
            .unwrap()
            .conversation_dags_migrated,
        1
    );
    assert_eq!(
        vault
            .maintain()
            .migrate_conversation_dags()
            .run()
            .unwrap()
            .conversation_dags_migrated,
        0
    );
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
            vault.store.vault_meta.put(
                txn,
                &super::graph::key(super::graph::CANONICAL, &child),
                root.as_bytes(),
            )?;
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
fn walk_work_cap_refuses_a_large_neighborhood_without_partial_results() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let child = vault
        .append_dag_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        super::graph::edge_ids(&vault.store, &txn, &root, EdgeKind::Parent, true, 0)
            .unwrap_err()
            .kind(),
        ErrorKind::IndexOverflow
    );
    assert_eq!(
        super::graph::edge_ids(&vault.store, &txn, &root, EdgeKind::Parent, true, 1).unwrap(),
        [child]
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
            vault.store.vault_meta.put(
                txn,
                &super::graph::key(super::graph::MIGRATED, &conv),
                &[2],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        vault.migrate_conversation_dag(&conv).unwrap_err().kind(),
        ErrorKind::CorruptedIndex
    );
}

#[test]
fn migration_adopts_a_received_chain_without_quadratic_work() {
    let (_dir, vault, conv, _actor) = fixture();
    let mut batch = vault.batch();
    let mut parent = None;
    let mut records = Vec::new();
    for n in 0..160 {
        let id = EntityId::now();
        batch = batch
            .put(&id, ENTITY_TYPE_TURN, time(n), n, &body("received"))
            .edge_checked(&id, &conv, 1.0);
        if let Some(previous) = parent {
            batch = batch.edge_with_value_fields(
                &id,
                EdgeKind::Parent,
                &previous,
                super::writes::value(n),
            );
        }
        parent = Some(id);
        records.push(id);
    }
    batch.commit().unwrap();
    assert!(vault.migrate_conversation_dag(&conv).unwrap());
    assert_eq!(vault.head(&conv).unwrap(), parent);
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Canonical, false))
            .unwrap()
            .records,
        records
    );
    assert!(!vault.migrate_conversation_dag(&conv).unwrap());
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

#[test]
fn branch_scope_with_forks_includes_siblings_but_not_retained_sub_sessions() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_dag_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    let branch = vault
        .append_dag_record(&input(conv, Some(root), false, actor))
        .unwrap()
        .id;
    let leaf = vault
        .append_dag_record(&input(conv, Some(branch), false, actor))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&branch, actor).unwrap();
    let worker = vault
        .append_dag_record(&AppendRecord {
            session: Some(session),
            ..input(conv, Some(branch), false, actor)
        })
        .unwrap()
        .id;
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Branch(leaf), false))
            .unwrap()
            .records,
        [root, branch, leaf]
    );
    let expanded = vault
        .resolve_dag_scope(&scope(conv, ScopePath::Branch(leaf), true))
        .unwrap()
        .records;
    assert_eq!(expanded.len(), 4);
    assert_eq!(
        expanded
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [root, trunk, branch, leaf].into()
    );
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::SubSession(session), false))
            .unwrap()
            .records,
        [worker]
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
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
fn maintenance_names_the_skipped_conversation() {
    let (_dir, vault, cyclic, _healthy, _healthy_root) = legacy_conversations_with_cycle();
    let report = vault.maintain().migrate_conversation_dags().run().unwrap();
    assert_eq!(report.conversation_dags_skipped_invalid, vec![cyclic]);
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
fn thread_walk_rejects_cycles_multiple_targets_and_foreign_replies() {
    for expected in [
        ErrorKind::CycleDetected,
        ErrorKind::InvalidConversationDag,
        ErrorKind::DagParentOutsideConversation,
    ] {
        let (_dir, vault, conversation, actor) = fixture();
        let root = vault
            .append_dag_record(&input(conversation, None, true, actor))
            .unwrap()
            .id;
        let reply = vault
            .reply_in_thread(root, &input(conversation, None, false, actor))
            .unwrap()
            .id;
        let (source, target) = if expected == ErrorKind::CycleDetected {
            (root, reply)
        } else {
            let other = EntityId::now();
            vault
                .put_entity(&other, ENTITY_TYPE_CONVERSATION, time(1), 1, &body("other"))
                .unwrap();
            let foreign = vault
                .append_dag_record(&input(other, None, true, actor))
                .unwrap()
                .id;
            if expected == ErrorKind::InvalidConversationDag {
                (reply, foreign)
            } else {
                (foreign, root)
            }
        };
        vault
            .batch()
            .edge_with_value_fields(
                &source,
                EdgeKind::RepliesTo,
                &target,
                super::writes::value(1),
            )
            .commit()
            .unwrap();
        assert_eq!(vault.thread(root).unwrap_err().kind(), expected);
    }
}

#[test]
fn thread_walk_caps_examined_rows_even_when_replies_are_missing() {
    let (_dir, vault, conversation, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conversation, None, true, actor))
        .unwrap()
        .id;
    let mut batch = vault.batch();
    for _ in 0..=crate::limits::MAX_ANCESTOR_DEPTH {
        batch = batch.edge_with_value_fields(
            &EntityId::now(),
            EdgeKind::RepliesTo,
            &root,
            super::writes::value(1),
        );
    }
    batch.commit().unwrap();
    assert_eq!(
        vault.thread(root).unwrap_err().kind(),
        ErrorKind::IndexOverflow
    );
}

#[test]
fn thread_continuation_keeps_each_session_boundary() {
    let (_dir, vault, conversation, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conversation, None, true, actor))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&root, actor).unwrap();
    let mut worker_input = input(conversation, Some(root), false, actor);
    worker_input.session = Some(session);
    worker_input.reply_to = Some(root);
    let worker = vault.reply_in_thread(root, &worker_input).unwrap().id;
    let ordinary = vault
        .reply_in_thread(root, &input(conversation, None, false, actor))
        .unwrap();
    assert_eq!(ordinary.parent, Some(root));
    let worker_next = vault.reply_in_thread(root, &worker_input).unwrap();
    assert_eq!(worker_next.parent, Some(worker));
    let ordinary_next = vault
        .reply_in_thread(root, &input(conversation, None, false, actor))
        .unwrap();
    assert_eq!(ordinary_next.parent, Some(ordinary.id));
    assert_eq!(vault.head(&conversation).unwrap(), Some(root));
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conversation, ScopePath::SubSession(session), false))
            .unwrap()
            .records,
        [worker, worker_next.id]
    );
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
