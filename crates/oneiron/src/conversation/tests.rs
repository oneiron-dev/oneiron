use super::*;
use crate::conversation_dag::AppendRecord;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use crate::{EdgeActorClass, EdgeKind, ErrorKind, TimeRange, VaultConfig};
fn audience_admits(vault: &Vault, record: EntityId, person: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    visibility::AudienceCache::default().readable(vault, &txn, record, &[person])
}

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
    crate::conversation_dag::fixtures::grant(&vault, actor, true);
    let room = EntityId::now();
    vault
        .create_conversation(room, &ConversationBody::default(), actor, 1)
        .unwrap();
    (dir, vault, actor, room, bob)
}
fn record(vault: &Vault, room: EntityId, actor: WriteActor, at: u64) -> AppendRecord {
    AppendRecord {
        conversation: room,
        parent: vault.head(&room).unwrap(),
        reply_to: None,
        kind: crate::registry::ENTITY_TYPE_TURN,
        session: None,
        text: vec![],
        advance: true,
        body: encode(&serde_json::json!({"txt":format!("record at {at}")})).unwrap(),
        occurred: TimeRange { start: at, end: at },
        learned_at: at,
        actor,
    }
}
/// Scoped reads are default-deny: a reader needs an explicit `core:read` grant.
/// The grants ride a second manifest so the fixture's write policy stays in
/// force for later appends.
fn permit_reads(vault: &Vault, readers: &[EntityId]) {
    let scope = crate::federation::scope_codec::encode_scope_value(
        &crate::federation::scope_codec::read_preset(),
    )
    .unwrap();
    let grants = readers
        .iter()
        .map(|reader| {
            rmpv::Value::Map(vec![
                ("actor_ref".into(), reader.to_hex().into()),
                ("effector".into(), "core:read".into()),
                ("scope".into(), scope.clone()),
                ("receipt_required".into(), false.into()),
            ])
        })
        .collect::<Vec<_>>();
    let policy = rmpv::Value::Map(vec![
        ("schema_version".into(), "1.2".into()),
        ("pack_id".into(), "conversation-reader-test".into()),
        ("pack_version".into(), "1".into()),
        ("min_engine_version".into(), "0.0.0".into()),
        ("defaults".into(), rmpv::Value::Map(vec![])),
        ("rules".into(), rmpv::Value::Array(vec![])),
        ("actor_ceilings".into(), rmpv::Value::Array(vec![])),
        ("scoped_grants".into(), rmpv::Value::Array(grants)),
    ]);
    crate::test_util::put_policy_manifest_bytes(vault, EntityId::now(), &encode(&policy).unwrap())
        .unwrap();
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
    let before = record(&vault, room, actor, 2);
    let before = vault.append_dag_record(&before).unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let during = record(&vault, room, actor, 4);
    let during = vault.append_dag_record(&during).unwrap();
    assert!(!audience_admits(&vault, before.id, bob).unwrap());
    assert!(audience_admits(&vault, during.id, bob).unwrap());
    vault
        .set_history_visibility(room, bob, actor, 5, 0)
        .unwrap();
    assert!(audience_admits(&vault, before.id, bob).unwrap());
    vault
        .set_history_visibility(room, bob, actor, 6, 3)
        .unwrap();
    assert!(!audience_admits(&vault, before.id, bob).unwrap());
    vault.leave_member(room, bob, actor, 7).unwrap();
    let gap = record(&vault, room, actor, 8);
    let gap = vault.append_dag_record(&gap).unwrap();
    vault
        .join_member(room, bob, actor, 9, HistoryChoice::None)
        .unwrap();
    let after = record(&vault, room, actor, 10);
    let after = vault.append_dag_record(&after).unwrap();
    assert!(audience_admits(&vault, during.id, bob).unwrap());
    assert!(!audience_admits(&vault, gap.id, bob).unwrap());
    assert!(audience_admits(&vault, after.id, bob).unwrap());
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
fn threads_never_move_head_and_metadata_is_derived() {
    let (_dir, vault, actor, room, _) = fixture();
    let first = vault
        .append_dag_record(&record(&vault, room, actor, 1))
        .unwrap();
    let second = vault
        .append_dag_record(&record(&vault, room, actor, 2))
        .unwrap();
    let mut fork = record(&vault, room, actor, 3);
    fork.parent = Some(first.id);
    fork.advance = false;
    let fork = vault.append_dag_record(&fork).unwrap();
    assert!(vault.thread(first.id).unwrap().replies.is_empty());
    for trunk in [first.id, second.id] {
        let mut replies = Vec::new();
        for at in 4..7 {
            replies.push(
                vault
                    .reply_in_thread(trunk, &record(&vault, room, actor, at))
                    .unwrap()
                    .id,
            );
        }
        assert_eq!(vault.head(&room).unwrap(), Some(second.id));
        let thread = vault.thread(trunk).unwrap();
        assert_eq!(thread.root, replies.first().copied());
        assert_eq!(thread.replies, replies);
        assert_eq!(thread.count, 3);
        assert_eq!(thread.last_at, Some(6));
        for (reply, target) in replies.iter().zip(std::iter::once(&trunk).chain(&replies)) {
            assert_eq!(
                vault.targets(reply, EdgeKind::RepliesTo, None).unwrap(),
                [*target]
            );
            let strip = vault.reply_strip(reply).unwrap().unwrap();
            assert_eq!(strip.record, *target);
            assert!(!strip.stale);
        }
        let nested = vault
            .reply_in_thread(replies[0], &record(&vault, room, actor, 7))
            .unwrap();
        assert_eq!(
            vault.thread(trunk).unwrap().replies.last(),
            Some(&nested.id)
        );
    }
    vault.move_head(&room, &fork.id).unwrap();
    assert_eq!(
        vault
            .main_line(&room, Default::default())
            .unwrap()
            .main_line,
        [first.id, fork.id]
    );
}
#[test]
fn presence_is_not_membership() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    vault
        .join_member(room, bob, actor, 1, HistoryChoice::Share)
        .unwrap();
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
    let early = record(&vault, room, actor, 2);
    let early = vault.append_dag_record(&early).unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let middle = record(&vault, room, actor, 4);
    let middle = vault.append_dag_record(&middle).unwrap();
    permit_reads(&vault, &[actor.entity_ref()]);
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
    let late = record(&vault, room, actor, 6);
    let late = vault.append_dag_record(&late).unwrap();
    assert!(audience.get(&late.id).unwrap().is_none());
    assert!(audience.get(&middle.id).unwrap().is_some());
}

#[test]
fn assembled_context_and_edge_peers_share_the_audience_predicate() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    let mut early = record(&vault, room, actor, 2);
    early.body = encode(&serde_json::json!({"txt":"needle PRIVATE_BEFORE_JOIN"})).unwrap();
    early.text = vec![(
        "body".into(),
        serde_json::json!({"txt":"needle PRIVATE_BEFORE_JOIN"})["txt"]
            .as_str()
            .unwrap()
            .into(),
    )];
    let early = vault.append_dag_record(&early).unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let mut late = record(&vault, room, actor, 4);
    late.body = encode(&serde_json::json!({"txt":"needle public current"})).unwrap();
    late.text = vec![(
        "body".into(),
        serde_json::json!({"txt":"needle public current"})["txt"]
            .as_str()
            .unwrap()
            .into(),
    )];
    let late = vault.append_dag_record(&late).unwrap();
    vault
        .put_edge(&late.id, EdgeKind::Mentions, &early.id, 0.6)
        .unwrap();
    permit_reads(&vault, &[actor.entity_ref()]);
    let key = crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap();
    let read = vault
        .scoped_read(key)
        .for_audience(&[actor.entity_ref(), bob]);
    assert!(
        !read
            .edges_out(&late.id)
            .unwrap()
            .value
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
        let r = record(&vault, room, actor, 2);
        let r = vault.append_dag_record(&r).unwrap();
        ids.push(r.id);
    }
    permit_reads(&vault, &[actor.entity_ref()]);
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
    permit_reads(&vault, &[actor.entity_ref()]);
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
fn moving_head_to_a_room_or_sub_session_is_atomic_and_refused() {
    let (_dir, vault, actor, room, _) = fixture();
    let first = record(&vault, room, actor, 2);
    let first = vault.append_dag_record(&first).unwrap();
    let second = record(&vault, room, actor, 3);
    let second = vault.append_dag_record(&second).unwrap();
    let session = vault.spawn_dag_sub_session(&first.id, actor).unwrap();
    for target in [room, session] {
        assert!(matches!(
            vault.move_head(&room, &target),
            Err(Error::Record(RecordError::InvalidConversationDag(_)))
        ));
        assert_eq!(vault.head(&room).unwrap(), Some(second.id));
        assert_eq!(
            vault
                .main_line(&room, Default::default())
                .unwrap()
                .main_line,
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
    let row = record(&vault, room, actor, 3);
    let row = vault.append_dag_record(&row).unwrap();
    permit_reads(&vault, &[bob]);
    let reader = vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(bob.to_hex()).unwrap())
        .for_audience(&[bob]);
    assert!(reader.get(&row.id).unwrap().is_some());
    for revision in [None, Some(0_u64), Some(2_u64)] {
        vault
            .with_write_txn(|txn| {
                if let Some(revision) = revision {
                    membership::MEMBERSHIP_SEQ.put(&vault.store, txn, &room, &revision)?;
                } else {
                    membership::MEMBERSHIP_SEQ.delete(&vault.store, txn, &room)?;
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
    let mut good = record(&vault, room, actor, 2);
    good.body = encode(&serde_json::json!({"txt":"needle healthy record"})).unwrap();
    good.text = vec![(
        "body".into(),
        serde_json::json!({"txt":"needle healthy record"})["txt"]
            .as_str()
            .unwrap()
            .into(),
    )];
    let good = vault.append_dag_record(&good).unwrap();
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
        let parent = record(&vault, broken_room, actor, 2);
        let parent = vault.append_dag_record(&parent).unwrap();
        let mut child = record(&vault, broken_room, actor, 3);
        child.body = encode(&serde_json::json!({"txt":"needle broken ancestor"})).unwrap();
        child.text = vec![(
            "body".into(),
            serde_json::json!({"txt":"needle broken ancestor"})["txt"]
                .as_str()
                .unwrap()
                .into(),
        )];
        let child = vault.append_dag_record(&child).unwrap();
        assert!(audience_admits(&vault, child.id, actor.entity_ref()).unwrap());
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
    permit_reads(&vault, &[actor.entity_ref()]);
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
    let trunk = record(&vault, room, actor, 1);
    let trunk = vault.append_dag_record(&trunk).unwrap();
    let before = vault
        .reply_in_thread(trunk.id, &record(&vault, room, actor, 2))
        .unwrap()
        .id;
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let during = vault
        .reply_in_thread(trunk.id, &record(&vault, room, actor, 4))
        .unwrap()
        .id;
    vault.leave_member(room, bob, actor, 5).unwrap();
    let gap = vault
        .reply_in_thread(trunk.id, &record(&vault, room, actor, 6))
        .unwrap()
        .id;
    vault
        .join_member(room, bob, actor, 7, HistoryChoice::None)
        .unwrap();
    let after = vault
        .reply_in_thread(trunk.id, &record(&vault, room, actor, 8))
        .unwrap()
        .id;

    assert_eq!(
        vault.thread(trunk.id).unwrap().replies,
        vec![before, during, gap, after]
    );
    assert_eq!(vault.head(&room).unwrap(), Some(trunk.id));
    // Visibility is evaluated at each reply's time, not at the older trunk/root.
    assert!(!audience_admits(&vault, trunk.id, bob).unwrap());
    assert!(!audience_admits(&vault, before, bob).unwrap());
    assert!(audience_admits(&vault, during, bob).unwrap());
    assert!(!audience_admits(&vault, gap, bob).unwrap());
    assert!(audience_admits(&vault, after, bob).unwrap());
}

#[test]
fn scope_summary_and_merge_header_require_every_covered_membership_window() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    let before = vault
        .append_dag_record(&record(&vault, room, actor, 2))
        .unwrap()
        .id;
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let after = vault
        .append_dag_record(&record(&vault, room, actor, 4))
        .unwrap()
        .id;
    let scope = crate::conversation_dag::ScopeSelector {
        conversation: room,
        session: None,
        path: crate::conversation_dag::ScopePath::Canonical,
        include_forks: false,
    };
    let (summary, landed) = vault
        .mint_and_land_scope_summary(&scope, "caller summary", actor, Some(after), true)
        .unwrap();
    let landed = landed.unwrap();
    let claim = landed.claim;
    let record = landed.record.unwrap();
    assert_eq!(
        vault.scope_summary_covers(&summary).unwrap(),
        [before, after]
    );
    assert_eq!(vault.drill(&claim).unwrap(), [before, after]);
    for id in [summary, claim, record] {
        assert!(audience_admits(&vault, id, actor.entity_ref()).unwrap());
        assert!(!audience_admits(&vault, id, bob).unwrap());
    }
    let reader = vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(bob.to_hex()).unwrap())
        .for_audience(&[bob]);
    for id in [summary, claim, record] {
        assert!(reader.get(&id).unwrap().is_none());
    }
    assert!(
        reader
            .search_text("caller summary", 10, None)
            .unwrap()
            .is_empty()
    );
    vault
        .set_history_visibility(room, bob, actor, 5, 0)
        .unwrap();
    for id in [summary, claim, record] {
        assert!(audience_admits(&vault, id, bob).unwrap());
    }
    vault
        .set_history_visibility(room, bob, actor, 6, 3)
        .unwrap();
    for id in [summary, claim, record] {
        assert!(!audience_admits(&vault, id, bob).unwrap());
    }
    vault.batch().delete(&before).commit().unwrap();
    for id in [summary, claim, record] {
        assert!(!audience_admits(&vault, id, actor.entity_ref()).unwrap());
    }
}

#[test]
fn conversation_summary_claim_needs_every_covered_turn_readable() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    let turn = vault
        .append_dag_record(&record(&vault, room, actor, 10))
        .unwrap()
        .id;
    vault
        .join_member(room, bob, actor, 100, HistoryChoice::None)
        .unwrap();
    let claim = EntityId::now();
    let mut body = crate::ClaimBody::new(
        "conversation.summary",
        crate::ClaimSubject::Entity(room),
        rmpv::Value::Map(vec![
            ("text".into(), "summary of the early turns".into()),
            (
                "covers".into(),
                rmpv::Value::Array(vec![rmpv::Value::Binary(turn.as_bytes().to_vec())]),
            ),
        ]),
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
            TimeRange {
                start: 150,
                end: 150,
            },
            150,
            &crate::claim::encode_claim_body(&body).unwrap(),
        )
        .commit()
        .unwrap();
    assert!(!audience_admits(&vault, claim, bob).unwrap());
}

#[test]
fn thread_metadata_survives_reopen_without_side_tables() {
    let (dir, vault, actor, room, _) = fixture();
    let trunk = vault
        .append_dag_record(&record(&vault, room, actor, 1))
        .unwrap()
        .id;
    let first = vault
        .reply_in_thread(trunk, &record(&vault, room, actor, 3))
        .unwrap()
        .id;
    let second = vault
        .reply_in_thread(trunk, &record(&vault, room, actor, 2))
        .unwrap()
        .id;
    drop(vault);
    let config = VaultConfig {
        embedding_model: Some("test/model@v1".to_owned()),
        ..VaultConfig::default()
    };
    let vault = Vault::open(dir.path(), config).unwrap();
    let thread = vault.thread(trunk).unwrap();
    assert_eq!(thread.replies, [first, second]);
    assert_eq!(thread.count, 2);
    assert_eq!(thread.last_at, Some(3));
    assert_eq!(vault.head(&room).unwrap(), Some(trunk));
}

#[test]
fn summary_families_and_unavailable_dependencies_do_not_hide_healthy_hits() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, bob, actor, 1, HistoryChoice::Share)
        .unwrap();
    let mut input = record(&vault, room, actor, 2);
    input.body = encode(&serde_json::json!({"txt": "needle healthy"})).unwrap();
    input.text = vec![("body".into(), "needle healthy".into())];
    let turn = vault.append_dag_record(&input).unwrap().id;
    let scope = crate::conversation_dag::ScopeSelector {
        conversation: room,
        session: None,
        path: crate::conversation_dag::ScopePath::Canonical,
        include_forks: false,
    };
    let (summary, landed) = vault
        .mint_and_land_scope_summary(&scope, "needle summary", actor, Some(turn), true)
        .unwrap();
    let landed = landed.unwrap();
    let ordinary = EntityId::now();
    let epoch = EntityId::now();
    for (id, bytes) in [
        (
            ordinary,
            encode(&serde_json::json!({"txt":"needle ordinary","lvl":0})).unwrap(),
        ),
        (
            epoch,
            crate::compaction::encode_epoch_summary_body(&crate::compaction::EpochSummaryBody {
                v: 1,
                session: EntityId::now().to_hex(),
                epoch: 1,
                turn_start: 1,
                turn_end: 1,
                level: 0,
                text: "needle epoch".into(),
                actor: actor.entity_ref().to_hex(),
            })
            .unwrap(),
        ),
    ] {
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_SUMMARY,
                TimeRange { start: 2, end: 2 },
                2,
                &bytes,
            )
            .text(&id, &[("body", "needle")])
            .commit()
            .unwrap();
    }
    let read = vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(bob.to_hex()).unwrap())
        .for_audience(&[bob]);
    assert!(audience_admits(&vault, summary, bob).unwrap());
    assert!(read.get(&summary).unwrap().is_none());
    let read_scope = crate::federation::scope_codec::encode_scope_value(
        &crate::federation::scope_codec::read_preset(),
    )
    .unwrap();
    let policy = rmpv::Value::Map(vec![
        ("schema_version".into(), "1.2".into()),
        ("pack_id".into(), "summary-reader-test".into()),
        ("pack_version".into(), "1".into()),
        ("min_engine_version".into(), "0.0.0".into()),
        ("defaults".into(), rmpv::Value::Map(vec![])),
        ("rules".into(), rmpv::Value::Array(vec![])),
        ("actor_ceilings".into(), rmpv::Value::Array(vec![])),
        (
            "scoped_grants".into(),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                ("actor_ref".into(), bob.to_hex().into()),
                ("effector".into(), "core:read".into()),
                ("scope".into(), read_scope),
                (
                    "selectors".into(),
                    rmpv::Value::Map(vec![("world_ref".into(), "base".into())]),
                ),
                ("receipt_required".into(), false.into()),
            ])]),
        ),
    ]);
    crate::test_util::put_policy_manifest_bytes(&vault, EntityId::now(), &encode(&policy).unwrap())
        .unwrap();
    for id in [
        summary,
        landed.claim,
        landed.record.unwrap(),
        ordinary,
        epoch,
    ] {
        assert!(read.get(&id).unwrap().is_some());
    }
    vault.batch().delete(&summary).commit().unwrap();
    for id in [landed.claim, landed.record.unwrap()] {
        assert!(read.get(&id).unwrap().is_none());
    }
    let hits: std::collections::BTreeSet<_> = read
        .search_text("needle", 20, None)
        .unwrap()
        .iter()
        .map(|hit| hit.id)
        .collect();
    assert_eq!(hits, [turn, ordinary, epoch].into());
    let malformed = EntityId::now();
    let error = vault
        .put_entity(
            &malformed,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange { start: 2, end: 2 },
            2,
            &encode(&serde_json::json!({"scope": "broken", "text": "needle"})).unwrap(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidScopeSummary);
    assert!(read.get(&malformed).unwrap().is_none());
}
