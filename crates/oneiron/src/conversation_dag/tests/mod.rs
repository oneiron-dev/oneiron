//! Observable DAG invariants, legacy adoption and rejection atomicity.

use super::fixtures as support;
use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::{EdgeActorClass, EdgeKind, EntityId, ErrorKind, WriteActor};
use proptest::prelude::*;
use support::*;

#[test]
fn forks_rewrite_canonical_and_preserve_old_branch_and_pages() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    let thread = vault
        .append_record(&input(conv, Some(root), false, actor))
        .unwrap()
        .id;
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
    assert_eq!(
        vault
            .resolve_scope(&scope(conv, ScopePath::Branch(thread), false))
            .unwrap()
            .records,
        [root, thread]
    );
    let forks = vault
        .resolve_scope(&scope(conv, ScopePath::Canonical, true))
        .unwrap()
        .records;
    assert_eq!(
        forks.into_iter().collect::<std::collections::BTreeSet<_>>(),
        [root, trunk, thread].into()
    );
    vault.move_head(&conv, &thread).unwrap();
    assert_eq!(
        vault
            .resolve_scope(&scope(conv, ScopePath::Canonical, false))
            .unwrap()
            .records,
        [root, thread]
    );
    assert_eq!(
        vault
            .resolve_scope(&scope(conv, ScopePath::Branch(trunk), false))
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
        let root = vault.append_record(&input(conv, None, true, actor)).unwrap().id;
        let mut head = root;
        let mut trunk = vec![root];
        for advance in ops {
            let parent = if advance { head } else { root };
            let appended = vault.append_record(&input(conv, Some(parent), advance, actor)).unwrap();
            if advance { head = appended.id; trunk.push(head); }
            prop_assert_eq!(appended.head, Some(head));
            prop_assert_eq!(vault.head(&conv).unwrap(), Some(head));
        }
        prop_assert_eq!(vault.resolve_scope(&scope(conv, ScopePath::Canonical, false)).unwrap().records, trunk);
    }
}

#[test]
fn append_refuses_cross_conversation_off_trunk_actor_and_policy_without_writes() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    assert_eq!(
        vault
            .append_record(&input(conv, Some(root), true, actor))
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
            .append_record(&input(other, Some(root), false, actor))
            .unwrap_err()
            .kind(),
        ErrorKind::DagParentOutsideConversation
    );
    let wrong = WriteActor::new(actor.entity_ref(), EdgeActorClass::System);
    assert_eq!(
        vault
            .append_record(&input(conv, Some(trunk), true, wrong))
            .unwrap_err()
            .kind(),
        ErrorKind::ActorClassMismatch
    );
    grant(&vault, actor, false);
    assert_eq!(
        vault
            .append_record(&input(conv, Some(trunk), true, actor))
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
            .resolve_scope(&scope(conv, ScopePath::Canonical, false))
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
        .append_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let child = vault
        .append_record(&input(conv, Some(root), true, actor))
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
            .resolve_scope(&scope(conv, ScopePath::Canonical, false))
            .unwrap_err()
            .kind(),
        ErrorKind::CycleDetected
    );
    vault.delete_edge(&root, EdgeKind::Parent, &child).unwrap();
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
        .append_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let child = vault
        .append_record(&input(conv, Some(root), true, actor))
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
    let (_dir, vault, conv, actor) = fixture();
    let asking = EntityId::now();
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
        .commit()
        .unwrap();
    let session = vault.spawn_sub_session(&asking, actor).unwrap();
    let child = EntityId::now();
    vault
        .batch()
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
            .resolve_scope(&scope(conv, ScopePath::SubSession(session), false))
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
            .resolve_scope(&scope(conv, ScopePath::Canonical, false))
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
        .append_record(&input(conversation, None, true, actor))
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
        .append_record(&input(conversation, Some(root.id), true, actor))
        .unwrap();
    assert_eq!(vault.head(&conversation).unwrap(), Some(next.id));
}

#[test]
fn branch_scope_with_forks_includes_siblings_but_not_retained_sub_sessions() {
    let (_dir, vault, conv, actor) = fixture();
    let root = vault
        .append_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let trunk = vault
        .append_record(&input(conv, Some(root), true, actor))
        .unwrap()
        .id;
    let branch = vault
        .append_record(&input(conv, Some(root), false, actor))
        .unwrap()
        .id;
    let leaf = vault
        .append_record(&input(conv, Some(branch), false, actor))
        .unwrap()
        .id;
    let session = vault.spawn_sub_session(&branch, actor).unwrap();
    let worker = vault
        .append_record(&AppendRecord {
            session: Some(session),
            ..input(conv, Some(branch), false, actor)
        })
        .unwrap()
        .id;
    assert_eq!(
        vault
            .resolve_scope(&scope(conv, ScopePath::Branch(leaf), false))
            .unwrap()
            .records,
        [root, branch, leaf]
    );
    let expanded = vault
        .resolve_scope(&scope(conv, ScopePath::Branch(leaf), true))
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
            .resolve_scope(&scope(conv, ScopePath::SubSession(session), false))
            .unwrap()
            .records,
        [worker]
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
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
    assert!(vault.migrate_conversation_dag(&conv).unwrap());
    assert_eq!(
        vault
            .resolve_scope(&scope(conv, ScopePath::Canonical, true))
            .unwrap()
            .records,
        [first, branch, separate]
    );
}

mod replay;
