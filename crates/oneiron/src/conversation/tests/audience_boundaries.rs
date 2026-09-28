use super::*;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_RELATIONSHIP};

#[derive(Clone, Copy)]
enum Unavailable {
    Missing,
    DeletedShell,
    Archived,
    InvalidBody,
    WrongKind,
}

fn make_unavailable(vault: &Vault, id: EntityId, state: Unavailable) {
    match state {
        Unavailable::DeletedShell => {
            vault
                .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
                .unwrap();
        }
        Unavailable::Archived => {
            // Replay/legacy fixture: retain the row and edges with an archive
            // marker, even for kinds the current cleanup writer cannot archive.
            let tombstone = crate::deletion::TombstoneValueV2 {
                reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
                deleted_at: 5,
                request_id: [1; 16],
            };
            vault
                .with_write_txn(|txn| {
                    vault.store.sync_state.put(
                        txn,
                        &crate::deletion::archive_tombstone_key(&id),
                        &tombstone.encode(),
                    )?;
                    Ok(())
                })
                .unwrap();
        }
        state => vault
            .with_write_txn(|txn| {
                // Retain the reference edges so the audience door must resolve the
                // unavailable target rather than seeing an unrelated standalone row.
                let mut raw = vault
                    .store
                    .entities
                    .get(txn, id.as_bytes())?
                    .unwrap()
                    .to_vec();
                match state {
                    Unavailable::Missing => {
                        vault.store.entities.delete(txn, id.as_bytes())?;
                    }
                    Unavailable::InvalidBody => {
                        raw.truncate(ENTITY_METADATA_HEADER_LEN);
                        raw.extend_from_slice(&encode(&"legacy room string")?);
                        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
                    }
                    Unavailable::WrongKind => {
                        raw[0] = ENTITY_TYPE_PERSON;
                        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })
            .unwrap(),
    }
}

#[test]
fn unavailable_room_and_relationship_targets_only_hide_their_candidates() {
    let (_dir, vault, actor, room, _) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 1, HistoryChoice::Share)
        .unwrap();
    let mut good = record(&vault, room, actor, 2);
    good.body = encode(&serde_json::json!({"txt":"needle healthy"})).unwrap();
    good.text = vec![(
        "body".into(),
        serde_json::json!({"txt":"needle healthy"})["txt"]
            .as_str()
            .unwrap()
            .into(),
    )];
    let good = vault.append_dag_record(&good).unwrap();
    let mut hidden = Vec::new();
    let mut unavailable = Vec::new();
    for state in [
        Unavailable::Missing,
        Unavailable::DeletedShell,
        Unavailable::Archived,
        Unavailable::InvalidBody,
    ] {
        let room = EntityId::now();
        vault
            .create_conversation(
                room,
                &ConversationBody {
                    member_ids: vec![actor.entity_ref()],
                    ..Default::default()
                },
                actor,
                1,
            )
            .unwrap();
        let mut candidate = record(&vault, room, actor, 2);
        candidate.body = encode(&serde_json::json!({"txt":"needle room"})).unwrap();
        candidate.text = vec![(
            "body".into(),
            serde_json::json!({"txt":"needle room"})["txt"]
                .as_str()
                .unwrap()
                .into(),
        )];
        let candidate = vault.append_dag_record(&candidate).unwrap();
        assert!(audience_admits(&vault, candidate.id, actor.entity_ref()).unwrap());
        hidden.push(candidate.id);
        unavailable.push((room, state));
    }
    for state in [
        Unavailable::Missing,
        Unavailable::DeletedShell,
        Unavailable::Archived,
        Unavailable::WrongKind,
    ] {
        let rel = EntityId::now();
        vault
            .put_entity(
                &rel,
                ENTITY_TYPE_RELATIONSHIP,
                TimeRange { start: 1, end: 1 },
                1,
                &encode(&serde_json::json!({"participant_ids":[actor.entity_ref()]})).unwrap(),
            )
            .unwrap();
        let claim = EntityId::now();
        let mut body = crate::ClaimBody::new(
            "preference.food",
            crate::ClaimSubject::Entity(actor.entity_ref()),
            rmpv::Value::from("needle relationship"),
            1.0,
            crate::ClaimApprovalStatus::Auto,
            crate::ClaimLifecycleStatus::Active,
        );
        body.source = Some(crate::ClaimSource::Observed);
        body.rel = Some(rel);
        vault
            .batch()
            .put_replicated(
                &claim,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 2, end: 2 },
                2,
                &crate::claim::encode_claim_body(&body).unwrap(),
            )
            .text(&claim, &[("body", "needle relationship")])
            .commit()
            .unwrap();
        assert!(audience_admits(&vault, claim, actor.entity_ref()).unwrap());
        hidden.push(claim);
        unavailable.push((rel, state));
    }
    // A stale assembled pack must apply the same per-candidate rule as direct
    // and indexed reads; unscoped hydration itself requires valid references.
    let mut pack = vault
        .context_pack()
        .search_text("needle", 20)
        .hydrate(true)
        .run()
        .unwrap();
    for (id, state) in unavailable {
        make_unavailable(&vault, id, state);
    }
    permit_reads(&vault, &[actor.entity_ref()]);
    let read = vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap())
        .for_audience(&[actor.entity_ref()]);
    for id in hidden {
        assert!(
            read.read(&[crate::claim::PointRead::id(id)], None)
                .unwrap()
                .single()
                .is_none()
        );
    }
    assert!(
        read.read(&[crate::claim::PointRead::id(good.id)], None)
            .unwrap()
            .single()
            .is_some()
    );
    assert_eq!(
        read.search_text("needle", 20, None)
            .unwrap()
            .iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>(),
        vec![good.id]
    );
    read.filter_context_pack(&mut pack).unwrap();
    assert_eq!(
        pack.results.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![good.id]
    );
}

#[cfg(feature = "sync")]
#[test]
fn replicated_rooms_before_members_do_not_wedge_live_or_recovery_replay() {
    use crate::sync::{
        WindowKey,
        bridge::Materializer,
        loro_support::map_insert_bytes,
        schema::create_window_doc,
        window::{LoadedWindow, forward_rematerialize},
    };
    use std::sync::Arc;
    for live_observer in [true, false] {
        let (_dir, vault, actor, _, _) = fixture();
        let vault = Arc::new(vault);
        let materializer = Arc::new(Materializer::new());
        let key = WindowKey::new("2023-11");
        let window =
            live_observer.then(|| LoadedWindow::new("remote", key.clone(), &vault, &materializer));
        let bare = create_window_doc("remote", &key);
        let doc = window.as_ref().map_or(&bare, |window| &window.doc);
        let replay = || {
            if !live_observer {
                forward_rematerialize(&vault, doc, &materializer, &key).unwrap();
            }
        };
        let blob = |kind, body: &[u8]| {
            let mut raw = vec![kind];
            for _ in 0..3 {
                raw.extend_from_slice(&2_u64.to_be_bytes());
            }
            raw.extend_from_slice(body);
            raw
        };
        let room = EntityId::now();
        let member = EntityId::now();
        let body = ConversationBody {
            member_ids: vec![member],
            ..Default::default()
        }
        .to_bytes()
        .unwrap();
        assert_eq!(
            vault
                .put_entity(
                    &room,
                    ENTITY_TYPE_CONVERSATION,
                    TimeRange { start: 2, end: 2 },
                    2,
                    &body
                )
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidConversationBody
        );
        let entities = doc.get_map("entities");
        map_insert_bytes(
            &entities,
            &room.to_hex(),
            &blob(ENTITY_TYPE_CONVERSATION, &body),
        )
        .unwrap();
        let invalid = EntityId::now();
        map_insert_bytes(
            &entities,
            &invalid.to_hex(),
            &blob(
                ENTITY_TYPE_CONVERSATION,
                &encode(&serde_json::json!({"kind":"legacy-non-room"})).unwrap(),
            ),
        )
        .unwrap();
        let control = EntityId::now();
        map_insert_bytes(
            &entities,
            &control.to_hex(),
            &blob(ENTITY_TYPE_PERSON, b"ordinary metadata"),
        )
        .unwrap();
        doc.commit();
        replay();
        assert_eq!(vault.get(&room).unwrap().as_deref(), Some(body.as_slice()));
        assert_eq!(
            vault.get(&control).unwrap().as_deref(),
            Some(b"ordinary metadata".as_slice())
        );
        assert!(vault.get(&invalid).unwrap().is_none());
        let quarantined = crate::sync::quarantine::quarantined_records(&vault).unwrap();
        assert!(
            quarantined
                .iter()
                .any(|(_, row)| row.reason_code == "InvalidConversationBody"
                    && row.crdt_key_hash
                        == xxhash_rust::xxh3::xxh3_64(invalid.to_hex().as_bytes()))
        );
        assert!(vault.membership_ledger(room).unwrap().is_empty());
        assert!(!audience_admits(&vault, room, member).unwrap());
        // Later metadata arrival alone must not manufacture local authority.
        map_insert_bytes(
            &entities,
            &member.to_hex(),
            &blob(ENTITY_TYPE_PERSON, b"member"),
        )
        .unwrap();
        doc.commit();
        replay();
        assert_eq!(
            vault.get(&member).unwrap().as_deref(),
            Some(b"member".as_slice())
        );
        assert!(vault.membership_ledger(room).unwrap().is_empty());
        assert!(!audience_admits(&vault, room, member).unwrap());
        vault
            .join_member(room, member, actor, 3, HistoryChoice::Share)
            .unwrap();
        assert!(audience_admits(&vault, room, member).unwrap());
    }
}

#[test]
fn scoped_read_for_room_narrows_to_the_members_with_a_receipt() {
    let (_dir, vault, actor, room, bob) = fixture();
    vault
        .join_member(room, actor.entity_ref(), actor, 2, HistoryChoice::None)
        .unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    // A relationship memory only the actor is party to.
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            &encode(&serde_json::json!({"participant_ids":[actor.entity_ref()]})).unwrap(),
        )
        .unwrap();
    let private = EntityId::now();
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
            &private,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 4, end: 4 },
            4,
            &crate::claim::encode_claim_body(&body).unwrap(),
        )
        .commit()
        .unwrap();
    permit_reads(&vault, &[actor.entity_ref()]);
    let key = crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex()).unwrap();
    let reads = [crate::claim::PointRead::id(private)];

    let alone = vault.scoped_read(key.clone()).read(&reads, None).unwrap();
    assert!(alone.value[0].is_some());
    assert_eq!(alone.receipt.suppressed_count, 0);
    // The room's audience is its membership: Bob is not party to the
    // relationship, so the room read withholds it and counts it.
    let in_room = vault
        .scoped_read_for_room(key, room)
        .unwrap()
        .read(&reads, None)
        .unwrap();
    assert!(in_room.value[0].is_none());
    assert_eq!(in_room.receipt.suppressed_count, 1);
    assert!(
        in_room
            .receipt
            .narrowed_axes
            .contains(&"row_authority".to_owned())
    );
}
