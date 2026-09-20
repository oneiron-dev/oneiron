use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use crate::{EdgeActorClass, EdgeKind, ErrorKind, TimeRange, VaultConfig};
fn fixture() -> (tempfile::TempDir, Vault, WriteActor, EntityId, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let config = VaultConfig {
        embedding_model: Some("test/model@v1".to_owned()),
        ..VaultConfig::default()
    };
    let vault = Vault::open(dir.path(), config).unwrap();
    let alice = EntityId::now();
    let bob = EntityId::now();
    for id in [alice, bob] {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 0, end: 0 },
                0,
                &encode(&serde_json::json!({})).unwrap(),
            )
            .commit()
            .unwrap();
    }
    let actor = WriteActor::new(alice, EdgeActorClass::Human);
    let room = EntityId::now();
    vault
        .create_conversation(room, &ConversationBody::default(), actor, 1)
        .unwrap();
    (dir, vault, actor, room, bob)
}
fn record(room: EntityId, actor: WriteActor, at: u64) -> AppendRecord {
    AppendRecord {
        conversation: room,
        id: EntityId::now(),
        parent: None,
        advance: true,
        body: serde_json::json!({"txt":format!("record at {at}")}),
        occurred: TimeRange { start: at, end: at },
        learned_at: at,
        actor,
    }
}
#[test]
fn codec_defaults_validation_and_membership_are_atomic() {
    let (_dir, vault, actor, room, bob) = fixture();
    let legacy =
        ConversationBody::from_bytes(&encode(&serde_json::json!({"custom":"kept"})).unwrap())
            .unwrap();
    let binary = ConversationBody::from_bytes(
        &encode(&rmpv::Value::Map(vec![(
            "world_ref".into(),
            rmpv::Value::Binary(bob.as_bytes().to_vec()),
        )]))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        ConversationBody::from_bytes(&binary.to_bytes().unwrap()).unwrap(),
        binary
    );
    assert_eq!(
        binary.extra.get("world_ref"),
        Some(&rmpv::Value::Binary(bob.as_bytes().to_vec()))
    );
    assert_eq!(legacy.kind, ConversationKind::Direct);
    assert!(!legacy.shares_history());
    assert_eq!(
        ConversationBody::from_bytes(&legacy.to_bytes().unwrap()).unwrap(),
        legacy
    );
    assert_eq!(
        ConversationBody::from_bytes(&encode(&serde_json::json!({"kind":"wrong"})).unwrap())
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConversationBody
    );
    assert!(
        ConversationBody {
            kind: ConversationKind::Mirror,
            ..Default::default()
        }
        .to_bytes()
        .is_err()
    );
    vault
        .join_member(room, actor.entity_ref(), actor, 2, HistoryChoice::None)
        .unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    vault
        .leave_member(room, actor.entity_ref(), actor, 4)
        .unwrap();
    assert_eq!(vault.members(room).unwrap(), vec![bob]);
    assert_eq!(vault.membership_at(room, 3).unwrap().len(), 2);
    assert_eq!(vault.membership_ledger(room).unwrap().len(), 3);
    assert_eq!(vault.conversation_body(room).unwrap().member_ids, vec![bob]);
    let mut forged = vault.conversation_body(room).unwrap();
    forged.member_ids.clear();
    assert_eq!(
        vault
            .batch()
            .put(
                &room,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 1, end: 1 },
                1,
                &forged.to_bytes().unwrap()
            )
            .commit()
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationState
    );
    assert_eq!(vault.members(room).unwrap(), vec![bob]);
}
#[test]
fn membership_windows_survive_kick_rejoin_and_history_revoke() {
    let (_dir, vault, actor, room, bob) = fixture();
    let before = record(room, actor, 2);
    vault.append_record(&before).unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let during = record(room, actor, 4);
    vault.append_record(&during).unwrap();
    assert!(!vault.record_visible_to(before.id, bob).unwrap());
    assert!(vault.record_visible_to(during.id, bob).unwrap());
    vault
        .set_history_visibility(room, bob, actor, 5, 0)
        .unwrap();
    assert!(vault.record_visible_to(before.id, bob).unwrap());
    vault
        .set_history_visibility(room, bob, actor, 6, 3)
        .unwrap();
    assert!(!vault.record_visible_to(before.id, bob).unwrap());
    vault.leave_member(room, bob, actor, 7).unwrap();
    let gap = record(room, actor, 8);
    vault.append_record(&gap).unwrap();
    vault
        .join_member(room, bob, actor, 9, HistoryChoice::None)
        .unwrap();
    let after = record(room, actor, 10);
    vault.append_record(&after).unwrap();
    assert!(vault.record_visible_to(during.id, bob).unwrap());
    assert!(!vault.record_visible_to(gap.id, bob).unwrap());
    assert!(vault.record_visible_to(after.id, bob).unwrap());
    assert_eq!(vault.windows(room, bob).unwrap().len(), 2);
    for kind in [
        ConversationKind::Channel,
        ConversationKind::Mirror,
        ConversationKind::Group,
        ConversationKind::Direct,
        ConversationKind::Agent,
    ] {
        let id = EntityId::now();
        vault
            .create_conversation(
                id,
                &ConversationBody {
                    kind,
                    external_id: Some("room".into()),
                    ..Default::default()
                },
                actor,
                1,
            )
            .unwrap();
        vault
            .join_member(id, bob, actor, 10, HistoryChoice::Inherit)
            .unwrap();
        assert_eq!(
            vault.windows(id, bob).unwrap()[0].from,
            if kind.history_default() { 0 } else { 10 }
        );
    }
}
#[test]
fn threads_never_move_head_and_metadata_rebuilds() {
    let (_dir, vault, actor, room, _bob) = fixture();
    let first = record(room, actor, 1);
    vault.append_record(&first).unwrap();
    let second = record(room, actor, 2);
    vault.append_record(&second).unwrap();
    let fork = AppendRecord {
        parent: Some(first.id),
        advance: false,
        ..record(room, actor, 3)
    };
    vault.append_record(&fork).unwrap();
    assert!(vault.thread_roots(first.id).unwrap().is_empty());
    for trunk in [first.id, second.id] {
        let mut replies = Vec::new();
        for at in 4..7 {
            let reply = record(room, actor, at);
            replies.push(vault.reply_in_thread(trunk, &reply).unwrap());
        }
        assert_eq!(vault.conversation_head(room).unwrap(), Some(second.id));
        let thread = vault.thread(trunk).unwrap();
        assert_eq!(thread.replies, replies);
        assert_eq!(thread.count, 3);
        assert_eq!(thread.last_at, Some(6));
        assert_eq!(
            vault.thread_meta(trunk).unwrap(),
            vault.rebuild_thread_meta(trunk).unwrap()
        );
        assert_eq!(
            vault
                .resolve_scope(&ScopeSelector::Branch(replies[0]), false)
                .unwrap(),
            replies
        );
        assert!(
            vault
                .move_conversation_head(room, replies[0], actor)
                .is_err()
        );
        vault
            .reply_in_thread(replies[0], &record(room, actor, 7))
            .unwrap();
        vault.start_thread(trunk, &record(room, actor, 8)).unwrap();
        assert_eq!(vault.thread_roots(trunk).unwrap().len(), 2);
    }
    vault.move_conversation_head(room, fork.id, actor).unwrap();
    assert_eq!(
        vault
            .resolve_scope(&ScopeSelector::Canonical(room), false)
            .unwrap(),
        vec![first.id, fork.id]
    );
}
#[test]
fn addressing_is_not_visibility_and_presence_is_not_membership() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    vault
        .join_member(room, bob, actor, 1, HistoryChoice::Share)
        .unwrap();
    let mut direct = record(room, actor, 2);
    direct.body = serde_json::json!({"addr":"direct","to":[bob]});
    vault.append_record(&direct).unwrap();
    assert!(
        vault
            .record_visible_to(direct.id, actor.entity_ref())
            .unwrap()
    );
    assert_eq!(
        vault
            .targets(&direct.id, EdgeKind::AddressedTo, None)
            .unwrap(),
        vec![bob]
    );
    let mut invalid_record = record(room, actor, 3);
    invalid_record.body = serde_json::json!({"addr":"direct"});
    assert_eq!(
        vault.append_record(&invalid_record).unwrap_err().kind(),
        ErrorKind::InvalidConversationBody
    );
    let session = EntityId::now();
    vault
        .batch()
        .put(
            &session,
            ENTITY_TYPE_SESSION,
            TimeRange { start: 1, end: 1 },
            1,
            &encode(&serde_json::json!({})).unwrap(),
        )
        .commit()
        .unwrap();
    let ledger = vault.membership_ledger(room).unwrap();
    assert_eq!(
        vault.session_presence(session).unwrap().mode,
        SessionMode::Direct
    );
    vault
        .set_session_mode(session, SessionMode::Council, actor)
        .unwrap();
    vault.set_presence(session, &[bob], actor).unwrap();
    assert_eq!(
        vault
            .session_presence(session)
            .unwrap()
            .active_participant_ids,
        vec![bob]
    );
    vault.set_presence(session, &[], actor).unwrap();
    assert!(
        vault
            .session_presence(session)
            .unwrap()
            .active_participant_ids
            .is_empty()
    );
    assert_eq!(vault.membership_ledger(room).unwrap(), ledger);
}
#[test]
fn audience_all_of_rechecks_ledger_after_kick() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    let early = record(room, actor, 2);
    vault.append_record(&early).unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let middle = record(room, actor, 4);
    vault.append_record(&middle).unwrap();
    let key = crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap();
    let audience = vault
        .scoped_read(key.clone())
        .for_audience(&[actor.entity_ref(), bob]);
    assert!(audience.get(&early.id).unwrap().is_none());
    assert!(audience.get(&middle.id).unwrap().is_some());
    assert!(
        vault
            .scoped_read(key)
            .for_audience(&[actor.entity_ref()])
            .get(&early.id)
            .unwrap()
            .is_some()
    );
    vault.leave_member(room, bob, actor, 5).unwrap();
    let late = record(room, actor, 6);
    vault.append_record(&late).unwrap();
    assert!(audience.get(&late.id).unwrap().is_none());
    assert!(audience.get(&middle.id).unwrap().is_some());
}

#[test]
fn summaries_pin_exact_scope_and_land_on_trunk() {
    let (_dir, vault, actor, room, _bob) = fixture();
    let trunk = record(room, actor, 2);
    vault.append_record(&trunk).unwrap();
    let mut ids = Vec::new();
    for at in 3..6 {
        ids.push(
            vault
                .reply_in_thread(trunk.id, &record(room, actor, at))
                .unwrap(),
        );
    }
    let envelope = crate::WriteEnvelope::new(
        actor,
        crate::ClaimSource::UserStated,
        crate::WriteProvenance::new(rmpv::Value::from("test")).unwrap(),
        crate::ClaimApprovalStatus::Auto,
    );
    let summary = vault
        .summarize_thread(trunk.id, "caller supplied summary", &envelope, 7)
        .unwrap();
    let claim = vault.get_claim(&summary).unwrap().unwrap();
    assert_eq!(claim.subject, crate::ClaimSubject::Entity(trunk.id));
    let covers = match claim.value {
        rmpv::Value::Map(entries) => {
            entries
                .into_iter()
                .find(|(k, _)| k.as_str() == Some("covers"))
                .unwrap()
                .1
        }
        _ => panic!("summary map"),
    };
    assert_eq!(
        covers,
        rmpv::Value::Array(
            ids.iter()
                .map(|id| rmpv::Value::Binary(id.as_bytes().to_vec()))
                .collect()
        )
    );
    assert_eq!(
        vault.targets(&summary, EdgeKind::ClaimOf, None).unwrap(),
        vec![trunk.id]
    );
}
#[test]
fn assembled_context_and_edge_peers_share_the_audience_predicate() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    let mut early = record(room, actor, 2);
    early.body = serde_json::json!({"txt":"needle PRIVATE_BEFORE_JOIN"});
    vault.append_record(&early).unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let mut late = record(room, actor, 4);
    late.body = serde_json::json!({"txt":"needle public current"});
    vault.append_record(&late).unwrap();
    vault
        .put_edge(&late.id, EdgeKind::Mentions, &early.id, 0.6)
        .unwrap();
    let key = crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap();
    let read = vault
        .scoped_read(key)
        .for_audience(&[actor.entity_ref(), bob]);
    assert!(
        !read
            .edges_out(&late.id)
            .unwrap()
            .unwrap()
            .iter()
            .any(|e| e.target == early.id)
    );
    assert_eq!(
        read.search_text("needle", 10, None)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![late.id]
    );
    let mut query = vec![0.0; VaultConfig::default().dimensions];
    query[0] = 1.0;
    vault.put_vector(&early.id, &query).unwrap();
    vault.put_vector(&late.id, &query).unwrap();
    assert_eq!(
        read.search_vector(&query, 10, None)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![late.id]
    );
    let mut pack = vault
        .context_pack()
        .search_text("needle", 10)
        .hydrate(true)
        .include_edges(true)
        .edge_hop(1)
        .run()
        .unwrap();
    assert!(pack.results.iter().any(|r| r.id == early.id));
    read.filter_context_pack(&mut pack).unwrap();
    let fields: Vec<_> = pack
        .results
        .iter()
        .chain(&pack.neighbors)
        .filter_map(|row| row.fields.as_ref())
        .collect();
    let assembled = serde_json::to_string(&fields).unwrap();
    assert!(!assembled.contains("PRIVATE_BEFORE_JOIN"));
}
#[test]
fn audience_ledger_snapshot_budget_is_per_room_not_per_hit() {
    let (_dir, vault, actor, room, bob) = fixture();
    let other = EntityId::now();
    vault
        .create_conversation(other, &ConversationBody::default(), actor, 1)
        .unwrap();
    let mut ids = Vec::new();
    for room in [room, other] {
        vault
            .join_member(room, bob, actor, 1, HistoryChoice::Share)
            .unwrap();
        let r = record(room, actor, 2);
        vault.append_record(&r).unwrap();
        ids.push(r.id);
    }
    let read = vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap())
        .for_audience(&[bob]);
    let hits = (0..500)
        .map(|i| crate::pipeline::ScoredEntity {
            id: ids[i % 2],
            score: 1.0,
        })
        .collect();
    assert_eq!(read.filter_scored_entities(hits).unwrap().len(), 500);
    assert_eq!(read.audience_ledger_reads().unwrap(), 2);
}
#[test]
fn entity_id_wire_round_trip_rejects_sentinels() {
    let id = EntityId::now();
    assert_eq!(
        serde_json::from_str::<EntityId>(&serde_json::to_string(&id).unwrap()).unwrap(),
        id
    );
    assert!(serde_json::from_str::<EntityId>(&format!("\"{}\"", "0".repeat(32))).is_err());
}

#[test]
fn scope_forks_and_sub_session_results_keep_their_origin() {
    let (_dir, vault, actor, room, _) = fixture();
    let first = record(room, actor, 2);
    vault.append_record(&first).unwrap();
    let current = record(room, actor, 3);
    vault.append_record(&current).unwrap();
    let mut branch = record(room, actor, 4);
    branch.parent = Some(first.id);
    branch.advance = false;
    vault.append_record(&branch).unwrap();
    assert_eq!(
        vault
            .resolve_scope(&ScopeSelector::Canonical(room), false)
            .unwrap(),
        vec![first.id, current.id]
    );
    let mut all = vault
        .resolve_scope(&ScopeSelector::Canonical(room), true)
        .unwrap();
    all.sort();
    let mut expected = vec![first.id, current.id, branch.id];
    expected.sort();
    assert_eq!(all, expected);
    let session = EntityId::now();
    vault
        .spawn_sub_session(session, first.id, actor, 4)
        .unwrap();
    vault
        .attach_sub_session_record(session, branch.id, actor, 4)
        .unwrap();
    let envelope = crate::WriteEnvelope::new(
        actor,
        crate::ClaimSource::UserStated,
        crate::WriteProvenance::new(rmpv::Value::from("scope fixture")).unwrap(),
        crate::ClaimApprovalStatus::Auto,
    );
    let summary = vault
        .mint_scope_summary(
            &ScopeSelector::SubSession(session),
            first.id,
            "retained finding",
            &envelope,
            5,
        )
        .unwrap();
    assert_eq!(
        vault.targets(&summary, EdgeKind::RepliesTo, None).unwrap(),
        vec![first.id]
    );
    assert_eq!(vault.conversation_head(room).unwrap(), Some(current.id));
    assert_eq!(
        vault
            .resolve_scope(&ScopeSelector::SubSession(session), false)
            .unwrap(),
        vec![branch.id]
    );
    assert!(
        vault
            .mint_scope_summary(
                &ScopeSelector::SubSession(session),
                current.id,
                "wrong landing",
                &envelope,
                6
            )
            .is_err()
    );
}

#[test]
fn relationship_audience_is_all_of_and_unscoped_single_reader_is_unchanged() {
    let (_dir, vault, actor, _room, bob) = fixture();
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            crate::registry::ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            &encode(&serde_json::json!({"participant_ids":[actor.entity_ref()]})).unwrap(),
        )
        .unwrap();
    let id = EntityId::now();
    let mut body = crate::ClaimBody::new(
        "preference.food",
        crate::ClaimSubject::Entity(actor.entity_ref()),
        rmpv::Value::from("private relationship memory"),
        1.0,
        crate::ClaimApprovalStatus::Auto,
        crate::ClaimLifecycleStatus::Active,
    );
    body.source = Some(crate::ClaimSource::Observed);
    body.rel = Some(relationship);
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 2, end: 2 },
            2,
            &crate::claim::encode_claim_body(&body).unwrap(),
        )
        .text(&id, &[("body", "private relationship memory")])
        .commit()
        .unwrap();
    let key = crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap();
    let before = vault.scoped_read(key.clone()).get(&id).unwrap();
    assert!(before.is_some());
    assert_eq!(
        vault
            .scoped_read(key.clone())
            .for_audience(&[actor.entity_ref()])
            .get(&id)
            .unwrap(),
        before
    );
    let group = vault
        .scoped_read(key)
        .for_audience(&[actor.entity_ref(), bob]);
    assert!(group.get(&id).unwrap().is_none());
    assert!(
        group
            .search_text("private relationship", 10, None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn legacy_dag_initializes_on_read_and_nonadvancing_roots_stay_off_head() {
    let (_dir, vault, actor, room, _) = fixture();
    let later = EntityId::now();
    let earlier = EntityId::now();
    for (id, at) in [(later, 20), (earlier, 10)] {
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: at, end: at },
                at,
                b"legacy",
            )
            .edge(&id, EdgeKind::ChildOf, &room, 1.0)
            .commit()
            .unwrap();
    }
    assert_eq!(
        vault
            .resolve_scope(&ScopeSelector::Canonical(room), false)
            .unwrap(),
        vec![earlier, later]
    );
    assert_eq!(vault.conversation_head(room).unwrap(), Some(later));
    assert_eq!(vault.canonical_child(earlier).unwrap(), Some(later));
    assert!(
        vault
            .edge_exists(&later, EdgeKind::Parent, &earlier)
            .unwrap()
    );
    let empty = EntityId::now();
    vault
        .create_conversation(empty, &ConversationBody::default(), actor, 1)
        .unwrap();
    for at in [2, 3] {
        let mut branch = record(empty, actor, at);
        branch.advance = false;
        vault.append_record(&branch).unwrap();
        assert_eq!(vault.conversation_head(empty).unwrap(), None);
    }
    assert!(
        vault
            .resolve_scope(&ScopeSelector::Canonical(empty), false)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn deleted_dag_records_cannot_be_recreated_by_generic_put() {
    let (_dir, vault, actor, room, _) = fixture();
    let row = record(room, actor, 2);
    vault.append_record(&row).unwrap();
    vault.batch().delete(&row.id).commit().unwrap();
    assert!(!vault.entity_exists(&row.id).unwrap());
    let result = vault.put_entity(
        &row.id,
        crate::registry::ENTITY_TYPE_TURN,
        TimeRange { start: 3, end: 3 },
        3,
        &encode(&serde_json::json!({"txt":"rewritten"})).unwrap(),
    );
    assert!(matches!(
        result,
        Err(Error::Record(RecordError::ConversationState(_)))
    ));
    assert!(!vault.entity_exists(&row.id).unwrap());
}

#[test]
fn moving_head_to_a_room_or_sub_session_is_atomic_and_refused() {
    let (_dir, vault, actor, room, _) = fixture();
    let first = record(room, actor, 2);
    vault.append_record(&first).unwrap();
    let second = record(room, actor, 3);
    vault.append_record(&second).unwrap();
    let session = EntityId::now();
    vault
        .spawn_sub_session(session, first.id, actor, 4)
        .unwrap();
    for target in [room, session] {
        assert!(matches!(
            vault.move_conversation_head(room, target, actor),
            Err(Error::Record(RecordError::InvalidConversationBody(_)))
        ));
        assert_eq!(vault.conversation_head(room).unwrap(), Some(second.id));
        assert_eq!(vault.canonical_child(first.id).unwrap(), Some(second.id));
        assert_eq!(
            vault
                .resolve_scope(&ScopeSelector::Canonical(room), false)
                .unwrap(),
            vec![first.id, second.id]
        );
    }
}

#[test]
fn membership_rows_without_their_revision_never_grant_audience_reads() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, bob, actor, 2, HistoryChoice::Share)
        .unwrap();
    let row = record(room, actor, 3);
    vault.append_record(&row).unwrap();
    let reader = vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(bob.to_hex()).unwrap())
        .for_audience(&[bob]);
    assert!(reader.get(&row.id).unwrap().is_some());
    for revision in [None, Some(0_u64), Some(2_u64)] {
        vault
            .with_write_txn(|txn| {
                let k = key(b"conversation_membership:seq:v1:", room);
                if let Some(revision) = revision {
                    vault
                        .store
                        .vault_meta
                        .put(txn, &k, &revision.to_be_bytes())?;
                } else {
                    vault.store.vault_meta.delete(txn, &k)?;
                }
                Ok(())
            })
            .unwrap();
        assert!(matches!(reader.get(&row.id), Err(Error::CorruptedIndex(_))));
        assert!(matches!(
            vault.membership_at(room, 3),
            Err(Error::CorruptedIndex(_))
        ));
    }
}

#[test]
fn dangling_ancestry_is_hidden_without_aborting_other_audience_results() {
    let (_dir, vault, actor, room, _) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    let mut good = record(room, actor, 2);
    good.body = serde_json::json!({"txt":"needle healthy record"});
    vault.append_record(&good).unwrap();
    let mut hidden = Vec::new();
    let mut missing = Vec::new();
    for missing_room in [true, false] {
        let broken_room = EntityId::now();
        vault
            .create_conversation(
                broken_room,
                &ConversationBody {
                    member_ids: vec![actor.entity_ref()],
                    ..Default::default()
                },
                actor,
                1,
            )
            .unwrap();
        let parent = record(broken_room, actor, 2);
        vault.append_record(&parent).unwrap();
        let mut child = record(broken_room, actor, 3);
        child.body = serde_json::json!({"txt":"needle broken ancestor"});
        vault.append_record(&child).unwrap();
        assert!(
            vault
                .record_visible_to(child.id, actor.entity_ref())
                .unwrap()
        );
        missing.push(if missing_room { broken_room } else { parent.id });
        hidden.push(child.id);
    }
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &encode(&serde_json::json!({})).unwrap(),
        )
        .unwrap();
    missing.push(subject);
    let claim = EntityId::now();
    let mut body = crate::ClaimBody::new(
        "preference.food",
        crate::ClaimSubject::Entity(subject),
        rmpv::Value::from("needle missing subject"),
        1.0,
        crate::ClaimApprovalStatus::Auto,
        crate::ClaimLifecycleStatus::Active,
    );
    body.source = Some(crate::ClaimSource::Observed);
    vault
        .batch()
        .put_replicated(
            &claim,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 2, end: 2 },
            2,
            &crate::claim::encode_claim_body(&body).unwrap(),
        )
        .text(&claim, &[("body", "needle missing subject")])
        .commit()
        .unwrap();
    hidden.push(claim);
    // Assemble while references are valid; the unscoped builder deliberately
    // rejects missing payloads. Then prove the audience filter drops stale data.
    let mut pack = vault
        .context_pack()
        .search_text("needle", 20)
        .hydrate(true)
        .run()
        .unwrap();
    vault
        .with_write_txn(|txn| {
            for id in &missing {
                vault.store.entities.delete(txn, id.as_bytes())?;
            }
            Ok(())
        })
        .unwrap();
    let read = vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap())
        .for_audience(&[actor.entity_ref()]);
    for id in hidden {
        assert!(read.get(&id).unwrap().is_none());
    }
    assert_eq!(
        read.search_text("needle", 20, None)
            .unwrap()
            .iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>(),
        vec![good.id],
    );
    read.filter_context_pack(&mut pack).unwrap();
    assert_eq!(
        pack.results.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![good.id]
    );
}

#[path = "tests/audience_boundaries.rs"]
mod audience_boundaries;

#[test]
fn room_members_reject_non_person_and_agent_def_atomically() {
    let (_dir, vault, actor, room, bob) = fixture();
    let agent = EntityId::now();
    vault
        .batch()
        .put(
            &agent,
            crate::registry::ENTITY_TYPE_AGENT_DEF,
            TimeRange { start: 1, end: 1 },
            1,
            &encode(&serde_json::json!({
                "agentId": "oneiron.agent.room_fixture",
                "desc": "Room member type fixture",
                "version": "1.0.0",
                "skills": [],
                "connectors": [],
                "codeModeMcps": [],
                "scope": "all",
                "approvalStatus": "approved",
                "lifecycleStatus": "active",
                "source": "user_stated",
                "confidence": 1.0,
                "generated": false,
                "humanAuthored": true,
                "provenance": {"definedVia": "define_agent"}
            }))
            .unwrap(),
        )
        .commit()
        .unwrap();
    for non_person in [room, agent] {
        let new_room = EntityId::now();
        let body = ConversationBody {
            // A valid member is staged first, so refusal must roll back its ledger row.
            member_ids: vec![bob, non_person],
            ..Default::default()
        };
        assert_eq!(
            vault
                .create_conversation(new_room, &body, actor, 2)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidConversationBody
        );
        assert!(vault.get_raw(&new_room).unwrap().is_none());
        // Ledger reads require a live room. Reuse the refused ID to expose any
        // membership row that incorrectly survived the failed transaction.
        vault
            .create_conversation(new_room, &ConversationBody::default(), actor, 2)
            .unwrap();
        assert!(vault.membership_ledger(new_room).unwrap().is_empty());
        assert_eq!(
            vault
                .join_member(room, non_person, actor, 2, HistoryChoice::None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidConversationBody
        );
        assert!(vault.members(room).unwrap().is_empty());
        assert!(vault.membership_ledger(room).unwrap().is_empty());
    }
    vault
        .join_member(room, bob, actor, 2, HistoryChoice::None)
        .unwrap();
    assert_eq!(vault.members(room).unwrap(), vec![bob]);
}

#[test]
fn thread_replies_obey_membership_time_windows() {
    let (_dir, vault, actor, room, bob) = fixture();
    let trunk = record(room, actor, 1);
    vault.append_record(&trunk).unwrap();
    let before = vault
        .reply_in_thread(trunk.id, &record(room, actor, 2))
        .unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let during = vault
        .reply_in_thread(trunk.id, &record(room, actor, 4))
        .unwrap();
    vault.leave_member(room, bob, actor, 5).unwrap();
    let gap = vault
        .reply_in_thread(trunk.id, &record(room, actor, 6))
        .unwrap();
    vault
        .join_member(room, bob, actor, 7, HistoryChoice::None)
        .unwrap();
    let after = vault
        .reply_in_thread(trunk.id, &record(room, actor, 8))
        .unwrap();

    assert_eq!(
        vault.thread(trunk.id).unwrap().replies,
        vec![before, during, gap, after]
    );
    assert_eq!(vault.conversation_head(room).unwrap(), Some(trunk.id));
    // Visibility is evaluated at each reply's time, not at the older trunk/root.
    assert!(!vault.record_visible_to(trunk.id, bob).unwrap());
    assert!(!vault.record_visible_to(before, bob).unwrap());
    assert!(vault.record_visible_to(during, bob).unwrap());
    assert!(!vault.record_visible_to(gap, bob).unwrap());
    assert!(vault.record_visible_to(after, bob).unwrap());
}
