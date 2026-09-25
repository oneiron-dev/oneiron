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
