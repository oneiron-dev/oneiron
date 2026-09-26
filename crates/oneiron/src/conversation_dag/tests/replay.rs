//! Observable session-carrier replay without exporting local membership indexes.
use super::*;

#[test]
fn sub_session_membership_survives_entity_and_edge_replay() {
    let (_dir, source, conv, actor) = fixture();
    let asking = source
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let session = source.spawn_dag_sub_session(&asking, actor).unwrap();
    let mut worker = input(conv, Some(asking), false, actor);
    worker.session = Some(session);
    let worker = source.append_dag_record(&worker).unwrap().id;
    let trunk = source
        .append_dag_record(&input(conv, Some(asking), true, actor))
        .unwrap()
        .id;
    let dir = tempfile::tempdir().unwrap();
    let peer = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    // Adopt an existing trunk before later worker records arrive.
    for id in [conv, asking, actor.entity_ref()] {
        let raw = source.get_raw_unsealed(&id).unwrap().unwrap();
        let h = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        peer.batch()
            .put_replicated(
                &id,
                h.entity_type,
                crate::TimeRange {
                    start: h.occurred_start,
                    end: h.occurred_end,
                },
                h.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit()
            .unwrap();
    }
    peer.batch()
        .edge_checked(&asking, &conv, 1.0)
        .commit()
        .unwrap();
    assert!(peer.migrate_conversation_dag(&conv).unwrap());
    // Carrier replay deliberately arrives before its session entity/edges.
    // Nothing copies the source vault_meta membership, HEAD or adoption marker.
    let ids = [worker, asking, trunk, session, conv, actor.entity_ref()];
    for id in ids {
        let raw = source.get_raw_unsealed(&id).unwrap().unwrap();
        let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        peer.batch()
            .put_replicated(
                &id,
                header.entity_type,
                crate::TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit()
            .unwrap();
    }
    // Replay writes edge rows, not the intentionally closed local append door.
    for id in ids {
        let edges = source.edges_out(&id).unwrap();
        let source_txn = source.store.env.read_txn().unwrap();
        for edge in edges {
            let out = crate::store::Store::encode_edge_key(&id, edge.kind, &edge.target);
            let incoming = crate::store::Store::encode_edge_key(&edge.target, edge.kind, &id);
            let value = source
                .store
                .edges_out
                .get(&source_txn, &out)
                .unwrap()
                .unwrap();
            peer.with_write_txn(|txn| {
                peer.store.edges_out.put(txn, &out, &value)?;
                peer.store.edges_in.put(txn, &incoming, &value)?;
                Ok(())
            })
            .unwrap();
        }
    }
    assert_eq!(
        peer.resolve_dag_scope(&scope(conv, ScopePath::SubSession(session), false))
            .unwrap()
            .records,
        [worker]
    );
    assert_eq!(
        peer.resolve_dag_scope(&scope(conv, ScopePath::Canonical, true))
            .unwrap()
            .records,
        [asking, trunk]
    );
    assert!(
        peer.resolve_dag_scope(&scope(conv, ScopePath::Branch(worker), false))
            .is_err()
    );
    // Repeated adoption preserves both index directions rather than erasing them.
    assert!(!peer.migrate_conversation_dag(&conv).unwrap());
    assert_eq!(
        peer.resolve_dag_scope(&scope(conv, ScopePath::SubSession(session), false))
            .unwrap()
            .records,
        [worker]
    );
}

#[test]
fn malformed_and_conflicting_session_carriers_refuse_without_changing_the_record() {
    let (_dir, vault, conv, actor) = fixture();
    let asking = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&asking, actor).unwrap();
    let mut append = input(conv, Some(asking), false, actor);
    append.session = Some(session);
    let worker = vault.append_dag_record(&append).unwrap().id;
    let original = vault.get(&worker).unwrap().unwrap();
    for value in [
        rmpv::Value::from(42),
        rmpv::Value::from(EntityId::now().to_hex()),
    ] {
        let mut fields = match rmpv::decode::read_value(&mut original.as_slice()).unwrap() {
            rmpv::Value::Map(fields) => fields,
            _ => unreachable!(),
        };
        fields
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("dag_session_ref"))
            .unwrap()
            .1 = value;
        let mut bad = Vec::new();
        rmpv::encode::write_value(&mut bad, &rmpv::Value::Map(fields)).unwrap();
        assert_eq!(
            vault
                .batch()
                .put_replicated(&worker, ENTITY_TYPE_TURN, time(1), 1, &bad)
                .commit()
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidConversationDag
        );
        assert_eq!(vault.get(&worker).unwrap().unwrap(), original);
    }
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::SubSession(session), false))
            .unwrap()
            .records,
        [worker]
    );
}

#[test]
fn trunk_session_membership_cannot_be_added_by_local_or_replayed_overwrite() {
    let (_dir, vault, conv, actor) = fixture();
    let asking = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&asking, actor).unwrap();
    let mut append = input(conv, Some(asking), false, actor);
    append.session = Some(session);
    let worker = vault.append_dag_record(&append).unwrap().id;
    let trunk = vault
        .append_dag_record(&input(conv, Some(asking), true, actor))
        .unwrap()
        .id;
    let original = vault.get(&trunk).unwrap().unwrap();
    let mut fields = match rmpv::decode::read_value(&mut original.as_slice()).unwrap() {
        rmpv::Value::Map(fields) => fields,
        _ => unreachable!(),
    };
    fields.push((
        rmpv::Value::from("dag_session_ref"),
        rmpv::Value::from(session.to_hex()),
    ));
    let mut changed = Vec::new();
    rmpv::encode::write_value(&mut changed, &rmpv::Value::Map(fields)).unwrap();
    for replay in [false, true] {
        let result = if replay {
            vault
                .batch()
                .put_replicated(&trunk, ENTITY_TYPE_TURN, time(20), 21, &changed)
                .commit()
        } else {
            vault.put_entity(&trunk, ENTITY_TYPE_TURN, time(20), 21, &changed)
        };
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidConversationDag
        );
        assert_eq!(vault.get(&trunk).unwrap().unwrap(), original);
        assert_eq!(
            vault
                .resolve_dag_scope(&scope(conv, ScopePath::Canonical, true))
                .unwrap()
                .records,
            [asking, trunk]
        );
        assert_eq!(
            vault
                .resolve_dag_scope(&scope(conv, ScopePath::SubSession(session), false))
                .unwrap()
                .records,
            [worker]
        );
    }
    // Both absent and present membership remain replayable when unchanged.
    for id in [trunk, worker] {
        let body = vault.get(&id).unwrap().unwrap();
        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_TURN, time(20), 21, &body)
            .commit()
            .unwrap();
    }
    assert_eq!(vault.head(&conv).unwrap(), Some(trunk));
}

#[test]
fn typed_dag_records_refuse_generic_overwrite_and_delete_recreation() {
    let (dir, vault, conv, actor) = fixture();
    let root = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let original = vault.get(&root).unwrap().unwrap();
    for replicated in [false, true] {
        for (kind, occurred, body) in [
            (ENTITY_TYPE_TURN, time(1), body("changed")),
            (ENTITY_TYPE_TURN, time(2), original.clone()),
            (
                crate::registry::ENTITY_TYPE_PERSON,
                time(1),
                original.clone(),
            ),
        ] {
            let builder = vault.batch();
            let builder = if replicated {
                builder.put_replicated(&root, kind, occurred, 2, &body)
            } else {
                builder.put(&root, kind, occurred, 2, &body)
            };
            assert_eq!(
                builder.commit().unwrap_err().kind(),
                ErrorKind::InvalidConversationDag
            );
            assert_eq!(vault.get(&root).unwrap().as_ref(), Some(&original));
        }
    }
    vault
        .batch()
        .put_replicated(&root, ENTITY_TYPE_TURN, time(20), 21, &original)
        .commit()
        .unwrap();
    let sentinel = EntityId::now();
    assert_eq!(
        vault
            .batch()
            .put(&sentinel, ENTITY_TYPE_TURN, time(1), 1, &body("sentinel"))
            .delete(&root)
            .put(&root, ENTITY_TYPE_TURN, time(1), 1, &original)
            .commit()
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConversationDag
    );
    assert!(vault.get(&sentinel).unwrap().is_none());
    assert_eq!(vault.get(&root).unwrap().as_ref(), Some(&original));
    vault.batch().delete(&root).commit().unwrap();
    drop(vault);
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    assert_eq!(
        vault
            .put_entity(&root, ENTITY_TYPE_TURN, time(1), 1, &original)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConversationDag
    );
    assert_eq!(
        vault
            .put_entity(
                &root,
                crate::registry::ENTITY_TYPE_PERSON,
                time(1),
                1,
                b"person"
            )
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConversationDag
    );
    assert!(vault.get(&root).unwrap().is_none());
}

#[test]
fn adoption_pins_an_imported_root_without_freezing_unadopted_turns() {
    let (_dir, vault, conv, _actor) = fixture();
    let root = EntityId::now();
    vault
        .batch()
        .put(&root, ENTITY_TYPE_TURN, time(1), 1, &body("imported"))
        .edge_checked(&root, &conv, 1.0)
        .commit()
        .unwrap();
    vault
        .put_entity(
            &root,
            ENTITY_TYPE_TURN,
            time(1),
            1,
            &body("before adoption"),
        )
        .unwrap();
    assert!(vault.migrate_conversation_dag(&conv).unwrap());
    vault.batch().delete(&root).commit().unwrap();
    assert_eq!(
        vault
            .put_entity(&root, ENTITY_TYPE_TURN, time(1), 1, &body("recreated"))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConversationDag
    );
}

#[test]
fn gdpr_delete_after_user_delete_purges_a_dag_record() {
    let (_dir, vault, conv, actor) = fixture();
    let id = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
        .unwrap();
    vault
        .delete_entity_with_reason(&id, crate::DeleteReason::GdprDelete)
        .unwrap();
    assert!(vault.get(&id).unwrap().is_none());
}

#[cfg(feature = "sync")]
#[test]
fn received_parent_survives_public_window_replay_and_adoption() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("dag-regression", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let edge_key = crate::sync::bridge::format_edge_key(&second, EdgeKind::Parent, &first);
    assert!(doc.get_map("edges").get(&edge_key).is_some());
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert!(peer.get(&first).unwrap().is_some());
    assert!(peer.get(&second).unwrap().is_some());
    assert!(peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());

    // Live first-arrival replay (membership and Parent together) has its own
    // regression below. A raw removal is never an authorized replay door.

    let report = peer.maintain().migrate_conversation_dags().run().unwrap();
    assert!(!report.conversation_dags_skipped_invalid.contains(&room));
    assert_eq!(
        peer.resolve_dag_scope(&scope(room, ScopePath::Branch(second), false))
            .unwrap()
            .records,
        [first, second]
    );
}

#[cfg(feature = "sync")]
#[test]
fn missing_received_session_skips_one_room_and_migrates_later_legacy_room() {
    let (_dir, source, _unused, actor) = fixture();
    let delayed = EntityId::from_bytes([1; 16]).unwrap();
    let healthy = EntityId::from_bytes([254; 16]).unwrap();
    source
        .create_conversation(
            delayed,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(delayed, None, true, actor))
        .unwrap()
        .id;
    let session = source.spawn_dag_sub_session(&first, actor).unwrap();
    let mut worker_input = input(delayed, Some(first), false, actor);
    worker_input.session = Some(session);
    let worker = source.append_dag_record(&worker_input).unwrap().id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("dag-regression", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    assert!(doc.get_map("entities").get(&worker.to_hex()).is_some());
    assert!(doc.get_map("entities").get(&session.to_hex()).is_none());
    let dir = tempfile::tempdir().unwrap();
    let peer = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert!(peer.get(&worker).unwrap().is_some());
    assert!(peer.get(&session).unwrap().is_none());
    let root = EntityId::now();
    peer.batch()
        .put(
            &healthy,
            ENTITY_TYPE_CONVERSATION,
            time(1),
            1,
            &body("healthy"),
        )
        .put(&root, ENTITY_TYPE_TURN, time(1), 1, &body("legacy"))
        .edge_checked(&root, &healthy, 1.0)
        .commit()
        .unwrap();
    let report = peer.maintain().migrate_conversation_dags().run().unwrap();
    assert!(report.conversation_dags_skipped_invalid.contains(&delayed));
    assert_eq!(report.conversation_dags_migrated, 1);
    assert!(!peer.migrate_conversation_dag(&healthy).unwrap());
    assert!(peer.get(&worker).unwrap().is_some());
    assert!(peer.get(&session).unwrap().is_none());

    // Skipping did not set the migration marker: the SESSION and its
    // SpawnedBy edge can arrive in their later window and adoption can retry.
    let raw = source.get_raw_unsealed(&session).unwrap().unwrap();
    let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    let later_key = crate::sync::types::WindowKey::from_timestamp(header.learned_at);
    let later_doc = crate::sync::schema::create_window_doc("dag-session", &later_key);
    crate::sync::window::reverse_rematerialize(&source, &later_doc, &later_key).unwrap();
    assert!(
        later_doc
            .get_map("entities")
            .get(&session.to_hex())
            .is_some()
    );
    crate::sync::window::forward_rematerialize(
        &peer,
        &later_doc,
        &crate::sync::bridge::Materializer::new(),
        &later_key,
    )
    .unwrap();
    assert!(peer.migrate_conversation_dag(&delayed).unwrap());
}

#[cfg(feature = "sync")]
fn received_cycle_fixture(kind: &str) -> (tempfile::TempDir, Vault, EntityId, EntityId, EntityId) {
    let (_source_dir, source, _unused, actor) = fixture();
    let bad = EntityId::from_bytes([1; 16]).unwrap();
    let good = EntityId::from_bytes([254; 16]).unwrap();
    source
        .create_conversation(
            bad,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let root = source
        .append_dag_record(&input(bad, None, true, actor))
        .unwrap()
        .id;
    let session = (kind == "session").then(|| source.spawn_dag_sub_session(&root, actor).unwrap());
    let (first, second) = if kind == "thread" {
        let first = source
            .reply_in_thread(root, &input(bad, Some(root), false, actor))
            .unwrap()
            .id;
        let second = source
            .reply_in_thread(root, &input(bad, Some(first), false, actor))
            .unwrap()
            .id;
        (first, second)
    } else {
        let mut first_input = input(bad, Some(root), session.is_none(), actor);
        first_input.session = session;
        let first = source.append_dag_record(&first_input).unwrap().id;
        let mut second_input = input(bad, Some(first), session.is_none(), actor);
        second_input.session = session;
        let second = source.append_dag_record(&second_input).unwrap().id;
        (first, second)
    };
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("received-cycle", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let edges = doc.get_map("edges");
    let original = crate::sync::bridge::format_edge_key(&first, EdgeKind::Parent, &root);
    assert!(edges.get(&original).is_some());
    edges.delete(&original).unwrap();
    let forged = crate::sync::bridge::format_edge_key(&first, EdgeKind::Parent, &second);
    let value =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::Parent, 1.0, 20, None, None)
            .unwrap();
    crate::sync::loro_support::map_insert_bytes(&edges, &forged, &value).unwrap();
    doc.commit();
    let dir = tempfile::tempdir().unwrap();
    let peer = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert!(peer.get(&first).unwrap().is_some());
    assert!(peer.get(&second).unwrap().is_some());
    if let Some(session) = session {
        let raw = source.get_raw_unsealed(&session).unwrap().unwrap();
        let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        let later_key = crate::sync::types::WindowKey::from_timestamp(header.learned_at);
        let later_doc = crate::sync::schema::create_window_doc("received-session", &later_key);
        crate::sync::window::reverse_rematerialize(&source, &later_doc, &later_key).unwrap();
        crate::sync::window::forward_rematerialize(
            &peer,
            &later_doc,
            &crate::sync::bridge::Materializer::new(),
            &later_key,
        )
        .unwrap();
        assert!(
            peer.edge_exists(&session, EdgeKind::SpawnedBy, &root)
                .unwrap()
        );
    }
    let healthy_root = EntityId::now();
    peer.batch()
        .put(
            &good,
            ENTITY_TYPE_CONVERSATION,
            time(1),
            1,
            &body("healthy"),
        )
        .put(&healthy_root, ENTITY_TYPE_TURN, time(1), 1, &body("root"))
        .edge_checked(&healthy_root, &good, 1.0)
        .commit()
        .unwrap();
    (dir, peer, bad, good, first)
}

#[cfg(feature = "sync")]
#[test]
fn received_sub_session_cycle_skips_only_its_conversation() {
    let (_dir, peer, bad, good, _) = received_cycle_fixture("session");
    let report = peer.maintain().migrate_conversation_dags().run().unwrap();
    assert_eq!(report.conversation_dags_skipped_invalid, [bad]);
    assert!(!peer.migrate_conversation_dag(&good).unwrap());
}

#[cfg(feature = "sync")]
#[test]
fn received_thread_cycle_is_not_marked_migrated() {
    let (_dir, peer, bad, good, first) = received_cycle_fixture("thread");
    let report = peer.maintain().migrate_conversation_dags().run().unwrap();
    assert_eq!(report.conversation_dags_skipped_invalid, [bad]);
    assert!(!peer.migrate_conversation_dag(&good).unwrap());
    assert!(peer.migrate_conversation_dag(&bad).is_err());
    assert!(
        peer.resolve_dag_scope(&scope(bad, ScopePath::Branch(first), false))
            .is_err()
    );
}

#[cfg(feature = "sync")]
fn late_parent_cycle_is_rejected(live_delta: bool) {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("late-parent", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert_eq!(
        peer.main_line(&room, super::DagPageRequest::default())
            .unwrap()
            .main_line,
        [first, second]
    );
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    let _observer = live_delta.then(|| {
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str())
    });
    let back_edge = crate::sync::bridge::format_edge_key(&first, EdgeKind::Parent, &second);
    let value =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::Parent, 1.0, 20, None, None)
            .unwrap();
    crate::sync::loro_support::map_insert_bytes(&doc.get_map("edges"), &back_edge, &value).unwrap();
    doc.commit();
    if !live_delta {
        crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    }
    assert!(!peer.edge_exists(&first, EdgeKind::Parent, &second).unwrap());
    let report = peer.maintain().migrate_conversation_dags().run().unwrap();
    assert!(!report.conversation_dags_skipped_invalid.contains(&room));
    assert_eq!(
        peer.main_line(&room, super::DagPageRequest::default())
            .unwrap()
            .main_line,
        [first, second]
    );
}

#[cfg(feature = "sync")]
#[test]
fn late_parent_cycle_cannot_poison_adopted_main_line_via_observer() {
    late_parent_cycle_is_rejected(true);
}

#[cfg(feature = "sync")]
#[test]
fn late_parent_cycle_cannot_poison_adopted_main_line_via_forward_remat() {
    late_parent_cycle_is_rejected(false);
}

#[cfg(feature = "sync")]
#[test]
fn honest_parent_and_childof_in_one_observer_delta_are_both_received() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("dag-honest-batch", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let edges = doc.get_map("edges");
    let mut exported = Vec::new();
    edges.for_each(|key, value| {
        if let loro::ValueOrContainer::Value(loro::LoroValue::Binary(bytes)) = value {
            exported.push((key.to_string(), bytes.to_vec()));
        }
    });
    for (edge, _) in &exported {
        edges.delete(edge).unwrap();
    }
    doc.commit();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert!(peer.get(&first).unwrap().is_some());
    assert!(peer.get(&second).unwrap().is_some());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    for (edge, value) in exported {
        crate::sync::loro_support::map_insert_bytes(&edges, &edge, &value).unwrap();
    }
    doc.commit();
    assert!(peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
    assert_eq!(
        peer.resolve_dag_scope(&scope(room, ScopePath::Branch(second), false))
            .unwrap()
            .records,
        [first, second]
    );
}

#[cfg(feature = "sync")]
#[test]
fn two_parent_candidates_in_one_delta_keep_single_parent() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let third = source
        .append_dag_record(&input(room, Some(second), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("dag-two-parents", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let original = crate::sync::bridge::format_edge_key(&third, EdgeKind::Parent, &second);
    doc.get_map("edges").delete(&original).unwrap();
    doc.commit();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert!(peer.edge_exists(&third, EdgeKind::ChildOf, &room).unwrap());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let bytes =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::Parent, 1.0, 20, None, None)
            .unwrap();
    let other = crate::sync::bridge::format_edge_key(&third, EdgeKind::Parent, &first);
    let edges = doc.get_map("edges");
    crate::sync::loro_support::map_insert_bytes(&edges, &original, &bytes).unwrap();
    crate::sync::loro_support::map_insert_bytes(&edges, &other, &bytes).unwrap();
    doc.commit();
    assert_eq!(
        peer.edges_out(&third)
            .unwrap()
            .iter()
            .filter(|e| e.kind == EdgeKind::Parent)
            .count(),
        1
    );
    assert!(
        peer.resolve_dag_scope(&scope(room, ScopePath::Branch(third), false))
            .is_ok()
    );
}

#[cfg(feature = "sync")]
#[test]
fn same_delta_parent_cycle_cannot_poison_adopted_branch() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("dag-batched-cycle", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert_eq!(
        peer.main_line(&room, super::DagPageRequest::default())
            .unwrap()
            .main_line,
        [first, second]
    );
    let third = source
        .append_dag_record(&input(room, Some(second), true, actor))
        .unwrap()
        .id;
    let fourth = source
        .append_dag_record(&input(room, Some(third), true, actor))
        .unwrap()
        .id;
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let edges = doc.get_map("edges");
    edges
        .delete(&crate::sync::bridge::format_edge_key(
            &third,
            EdgeKind::Parent,
            &second,
        ))
        .unwrap();
    edges
        .delete(&crate::sync::bridge::format_edge_key(
            &fourth,
            EdgeKind::Parent,
            &third,
        ))
        .unwrap();
    doc.commit();
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert!(peer.edge_exists(&third, EdgeKind::ChildOf, &room).unwrap());
    assert!(peer.edge_exists(&fourth, EdgeKind::ChildOf, &room).unwrap());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let bytes =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::Parent, 1.0, 20, None, None)
            .unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &edges,
        &crate::sync::bridge::format_edge_key(&third, EdgeKind::Parent, &fourth),
        &bytes,
    )
    .unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &edges,
        &crate::sync::bridge::format_edge_key(&fourth, EdgeKind::Parent, &third),
        &bytes,
    )
    .unwrap();
    doc.commit();
    assert!(
        !(peer.edge_exists(&third, EdgeKind::Parent, &fourth).unwrap()
            && peer.edge_exists(&fourth, EdgeKind::Parent, &third).unwrap())
    );
    assert_eq!(
        peer.main_line(&room, super::DagPageRequest::default())
            .unwrap()
            .main_line,
        [first, second]
    );
}

#[cfg(feature = "sync")]
#[test]
fn raw_parent_removal_cannot_truncate_adopted_main_line() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("dag-parent-removal", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    crate::sync::window::forward_rematerialize(
        &peer,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert_eq!(
        peer.main_line(&room, super::DagPageRequest::default())
            .unwrap()
            .main_line,
        [first, second]
    );
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    doc.get_map("edges")
        .delete(&crate::sync::bridge::format_edge_key(
            &second,
            EdgeKind::Parent,
            &first,
        ))
        .unwrap();
    doc.commit();
    assert!(peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
    assert_eq!(
        peer.main_line(&room, super::DagPageRequest::default())
            .unwrap()
            .main_line,
        [first, second]
    );
    // Soft deletion retains ancestry as a shell; the validated hard purge
    // retires the TURN and its incident edge, without a raw CRDT edge delete.
    peer.delete_entity_with_reason(&second, crate::DeleteReason::UserDelete)
        .unwrap();
    peer.delete_entity_with_reason(&second, crate::DeleteReason::GdprDelete)
        .unwrap();
    assert!(!peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
}

#[cfg(feature = "sync")]
#[test]
fn unchanged_parent_retries_when_its_childof_dependencies_arrive() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("unchanged-parent", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let edges = doc.get_map("edges");
    let mut exported = Vec::new();
    edges.for_each(|key, value| {
        if let loro::ValueOrContainer::Value(loro::LoroValue::Binary(buf)) = value {
            exported.push((key.to_string(), buf.to_vec()));
        }
    });
    for (key, _) in &exported {
        edges.delete(key).unwrap();
    }
    doc.commit();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let parent = crate::sync::bridge::format_edge_key(&second, EdgeKind::Parent, &first);
    let value = &exported.iter().find(|(edge, _)| edge == &parent).unwrap().1;
    crate::sync::loro_support::map_insert_bytes(&edges, &parent, value).unwrap();
    doc.commit();
    assert!(!peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
    for (edge, buf) in &exported {
        if edge != &parent {
            crate::sync::loro_support::map_insert_bytes(&edges, edge, buf).unwrap();
        }
    }
    doc.commit();
    assert!(peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
    assert_eq!(
        peer.resolve_dag_scope(&scope(room, ScopePath::Branch(second), false))
            .unwrap()
            .records,
        [first, second]
    );
}

#[cfg(feature = "sync")]
#[test]
fn deferred_parent_marker_survives_partial_membership_drain() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("partial-parent", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let edges = doc.get_map("edges");
    let mut exported = Vec::new();
    edges.for_each(|key, value| {
        if let loro::ValueOrContainer::Value(loro::LoroValue::Binary(buf)) = value {
            exported.push((key.to_string(), buf.to_vec()));
        }
    });
    for (edge, _) in &exported {
        edges.delete(edge).unwrap();
    }
    doc.commit();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    let observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let parent = crate::sync::bridge::format_edge_key(&second, EdgeKind::Parent, &first);
    let source_membership = crate::sync::bridge::format_edge_key(&second, EdgeKind::ChildOf, &room);
    let parent_bytes = &exported.iter().find(|(edge, _)| edge == &parent).unwrap().1;
    let membership_bytes = &exported
        .iter()
        .find(|(edge, _)| edge == &source_membership)
        .unwrap()
        .1;
    crate::sync::loro_support::map_insert_bytes(&edges, &parent, parent_bytes).unwrap();
    doc.commit();
    assert!(
        crate::sync::pending_remat_windows(&peer)
            .unwrap()
            .contains(&key.as_str().to_owned())
    );
    drop(observer);
    crate::sync::loro_support::map_insert_bytes(&edges, &source_membership, membership_bytes)
        .unwrap();
    doc.commit();
    let loaded =
        crate::sync::window::LoadedWindow::from_doc(doc, key.clone(), &peer, &materializer);
    loaded.persist_state(&peer).unwrap();
    let report = crate::sync::drain_remat_markers(&peer, "partial-parent", &materializer).unwrap();
    assert!(peer.edge_exists(&second, EdgeKind::ChildOf, &room).unwrap());
    assert!(!peer.edge_exists(&first, EdgeKind::ChildOf, &room).unwrap());
    assert!(!peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
    assert!(report.still_pending.contains(&key.as_str().to_owned()));
    assert!(
        crate::sync::pending_remat_windows(&peer)
            .unwrap()
            .contains(&key.as_str().to_owned())
    );
}

#[cfg(feature = "sync")]
#[test]
fn soft_deleted_turn_retains_parent_against_raw_removal() {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("soft-parent", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    peer.main_line(&room, super::DagPageRequest::default())
        .unwrap();
    peer.delete_entity_with_reason(&second, crate::DeleteReason::UserDelete)
        .unwrap();
    assert!(peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    doc.get_map("edges")
        .delete(&crate::sync::bridge::format_edge_key(
            &second,
            EdgeKind::Parent,
            &first,
        ))
        .unwrap();
    doc.commit();
    assert!(peer.edge_exists(&second, EdgeKind::Parent, &first).unwrap());
}

#[cfg(feature = "sync")]
#[test]
fn received_parent_respects_full_ancestor_depth() {
    let (_dir, source, _unused, actor) = fixture();
    let extra_room = EntityId::now();
    source
        .create_conversation(
            extra_room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let extra = source
        .append_dag_record(&input(extra_room, None, true, actor))
        .unwrap()
        .id;
    let over_limit = source
        .append_dag_record(&input(extra_room, Some(extra), true, actor))
        .unwrap()
        .id;
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    let room = EntityId::now();
    peer.put_entity(
        &room,
        ENTITY_TYPE_CONVERSATION,
        time(1),
        1,
        &body("legacy room"),
    )
    .unwrap();
    let records: Vec<_> = (1u128..crate::limits::MAX_ANCESTOR_DEPTH as u128)
        .map(|n| EntityId::from_bytes(((0x8100000000000000u128 << 64) | n).to_be_bytes()).unwrap())
        .collect();
    for chunk in records.chunks(500) {
        let mut batch = peer.batch();
        for id in chunk {
            let at = u128::from_be_bytes(*id.as_bytes()) as u64;
            batch = batch
                .put(id, ENTITY_TYPE_TURN, time(at), 1, &body("legacy"))
                .edge_checked(id, &room, 1.0);
        }
        batch.commit().unwrap();
    }
    assert!(peer.migrate_conversation_dag(&room).unwrap());
    let head = *records.last().unwrap();
    assert_eq!(
        peer.resolve_dag_scope(&scope(room, ScopePath::Branch(head), false))
            .unwrap()
            .records
            .len(),
        crate::limits::MAX_ANCESTOR_DEPTH - 1
    );
    let key = crate::sync::types::WindowKey::new("1970-01");
    let exported = crate::sync::schema::create_window_doc("depth-source", &key);
    crate::sync::window::reverse_rematerialize(&source, &exported, &key).unwrap();
    let loro::ValueOrContainer::Value(loro::LoroValue::Binary(raw)) =
        exported.get_map("entities").get(&extra.to_hex()).unwrap()
    else {
        panic!("exported TURN body");
    };
    let doc = crate::sync::schema::create_window_doc("depth-receiver", &key);
    crate::sync::loro_support::map_insert_bytes(&doc.get_map("entities"), &extra.to_hex(), &raw)
        .unwrap();
    let loro::ValueOrContainer::Value(loro::LoroValue::Binary(over_raw)) = exported
        .get_map("entities")
        .get(&over_limit.to_hex())
        .unwrap()
    else {
        panic!("exported over-limit TURN body");
    };
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &over_limit.to_hex(),
        &over_raw,
    )
    .unwrap();
    doc.commit();
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let child_value =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, 1, None, None)
            .unwrap();
    let parent_value =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::Parent, 1.0, 1, None, None)
            .unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("edges"),
        &crate::sync::bridge::format_edge_key(&extra, EdgeKind::ChildOf, &room),
        &child_value,
    )
    .unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("edges"),
        &crate::sync::bridge::format_edge_key(&extra, EdgeKind::Parent, &head),
        &parent_value,
    )
    .unwrap();
    doc.commit();
    assert!(peer.edge_exists(&extra, EdgeKind::ChildOf, &room).unwrap());
    assert!(peer.edge_exists(&extra, EdgeKind::Parent, &head).unwrap());
    assert_eq!(
        peer.resolve_dag_scope(&scope(room, ScopePath::Branch(extra), false))
            .unwrap()
            .records
            .len(),
        crate::limits::MAX_ANCESTOR_DEPTH,
    );
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("edges"),
        &crate::sync::bridge::format_edge_key(&over_limit, EdgeKind::ChildOf, &room),
        &child_value,
    )
    .unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("edges"),
        &crate::sync::bridge::format_edge_key(&over_limit, EdgeKind::Parent, &extra),
        &parent_value,
    )
    .unwrap();
    doc.commit();
    assert!(
        peer.edge_exists(&over_limit, EdgeKind::ChildOf, &room)
            .unwrap()
    );
    assert!(
        !peer
            .edge_exists(&over_limit, EdgeKind::Parent, &extra)
            .unwrap()
    );
}

#[cfg(feature = "sync")]
#[test]
fn forged_replies_to_without_pointer_remains_rejected() {
    let (_dir, source, room, actor) = fixture();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let second = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("forged-reply", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    let _observer =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let value =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::RepliesTo, 1.0, 1, None, None)
            .unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("edges"),
        &crate::sync::bridge::format_edge_key(&second, EdgeKind::RepliesTo, &first),
        &value,
    )
    .unwrap();
    doc.commit();
    assert!(
        !peer
            .edge_exists(&second, EdgeKind::RepliesTo, &first)
            .unwrap()
    );
}

#[cfg(feature = "sync")]
fn cross_session_parent_is_rejected(live_delta: bool) {
    let (_dir, source, _unused, actor) = fixture();
    let room = EntityId::now();
    source
        .create_conversation(
            room,
            &crate::conversation::ConversationBody::default(),
            actor,
            1,
        )
        .unwrap();
    let first = source
        .append_dag_record(&input(room, None, true, actor))
        .unwrap()
        .id;
    let trunk = source
        .append_dag_record(&input(room, Some(first), true, actor))
        .unwrap()
        .id;
    let key = crate::sync::types::WindowKey::new("1970-01");
    let doc = crate::sync::schema::create_window_doc("cross-session-parent", &key);
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let peer = std::sync::Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    let materializer = std::sync::Arc::new(crate::sync::bridge::Materializer::new());
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    assert_eq!(
        peer.main_line(&room, super::DagPageRequest::default())
            .unwrap()
            .main_line,
        [first, trunk]
    );
    let session_a = source.spawn_dag_sub_session(&trunk, actor).unwrap();
    let session_b = source.spawn_dag_sub_session(&trunk, actor).unwrap();
    let mut a_input = input(room, Some(trunk), false, actor);
    a_input.session = Some(session_a);
    let worker_a = source.append_dag_record(&a_input).unwrap().id;
    let mut b_input = input(room, Some(trunk), false, actor);
    b_input.session = Some(session_b);
    let worker_b = source.append_dag_record(&b_input).unwrap().id;
    let current_key = crate::sync::types::WindowKey::from_timestamp(
        crate::batch::EntityMetadataHeader::parse(
            &source.get_raw_unsealed(&session_a).unwrap().unwrap(),
        )
        .unwrap()
        .learned_at,
    );
    let sessions = crate::sync::schema::create_window_doc("cross-session-current", &current_key);
    crate::sync::window::reverse_rematerialize(&source, &sessions, &current_key).unwrap();
    crate::sync::window::forward_rematerialize(&peer, &sessions, &materializer, &current_key)
        .unwrap();
    assert!(
        peer.edge_exists(&session_a, EdgeKind::SpawnedBy, &trunk)
            .unwrap()
    );
    assert!(
        peer.edge_exists(&session_b, EdgeKind::SpawnedBy, &trunk)
            .unwrap()
    );
    crate::sync::window::reverse_rematerialize(&source, &doc, &key).unwrap();
    doc.get_map("edges")
        .delete(&crate::sync::bridge::format_edge_key(
            &worker_a,
            EdgeKind::Parent,
            &trunk,
        ))
        .unwrap();
    doc.commit();
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    assert!(
        peer.edge_exists(&worker_b, EdgeKind::Parent, &trunk)
            .unwrap()
    );
    let _observer = live_delta.then(|| {
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str())
    });
    let value =
        crate::sync::bridge::encode_edge_value_for_crdt(EdgeKind::Parent, 1.0, 20, None, None)
            .unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("edges"),
        &crate::sync::bridge::format_edge_key(&worker_a, EdgeKind::Parent, &worker_b),
        &value,
    )
    .unwrap();
    doc.commit();
    if !live_delta {
        crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &key).unwrap();
    }
    assert!(
        !peer
            .edge_exists(&worker_a, EdgeKind::Parent, &worker_b)
            .unwrap()
    );
    assert_eq!(
        peer.resolve_dag_scope(&scope(room, ScopePath::SubSession(session_b), false))
            .unwrap()
            .records,
        [worker_b]
    );
}

#[cfg(feature = "sync")]
#[test]
fn cross_session_parent_is_rejected_via_observer() {
    cross_session_parent_is_rejected(true);
}

#[cfg(feature = "sync")]
#[test]
fn cross_session_parent_is_rejected_via_forward_remat() {
    cross_session_parent_is_rejected(false);
}
