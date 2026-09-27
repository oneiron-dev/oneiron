use super::*;
use crate::EntityId;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_REACTION, EntityClassification, TypeByteFamily, entity_type_registry_entry,
};

#[test]
fn reaction_body_pins_glyph_limits_and_mirror_identity() {
    let id = EntityId::now();
    let mut row = ReactionBody {
        v: 1,
        msg: id,
        by: id,
        glyph: "👀".to_owned(),
        at: 42,
        ext: Some(ReactionExternalId {
            connector: "telegram".into(),
            id: "event-1".into(),
        }),
    };
    assert_eq!(
        ReactionBody::from_bytes(&row.to_bytes().unwrap()).unwrap(),
        row
    );
    row.glyph.clear();
    assert_eq!(
        row.to_bytes().unwrap_err().kind(),
        ErrorKind::InvalidReactionBody
    );
    row.glyph = "x".repeat(65);
    assert_eq!(
        row.to_bytes().unwrap_err().kind(),
        ErrorKind::InvalidReactionBody
    );
    row.glyph = "🫶".into();
    assert!(row.to_bytes().is_ok());
}

#[test]
fn reaction_is_public_pack_kind_with_unique_prefix() {
    let row = entity_type_registry_entry(ENTITY_TYPE_REACTION).unwrap();
    assert_eq!(row.kind, "REACTION");
    assert_eq!(row.short_id_prefix, Some("rx"));
    assert_eq!(row.classification, EntityClassification::Pack);
    assert_eq!(row.family, Some(TypeByteFamily::PackOverflow));
}

fn fixture_room(
    external_id: Option<&str>,
) -> (
    tempfile::TempDir,
    crate::Vault,
    EntityId,
    EntityId,
    EntityId,
) {
    use crate::conversation::{ConversationBody, ConversationKind, HistoryChoice};
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
    use crate::{EdgeActorClass, TimeRange, Vault, VaultConfig, WriteActor};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let alice = EntityId::now();
    let bob = EntityId::now();
    for person in [alice, bob] {
        vault
            .put_entity(
                &person,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .unwrap();
    }
    let actor = WriteActor::new(alice, EdgeActorClass::Human);
    let room = EntityId::now();
    vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: if external_id.is_some() {
                    ConversationKind::Mirror
                } else {
                    ConversationKind::Direct
                },
                external_id: external_id.map(ToOwned::to_owned),
                ..Default::default()
            },
            actor,
            1,
        )
        .unwrap();
    vault
        .join_member(room, alice, actor, 2, HistoryChoice::None)
        .unwrap();
    vault
        .join_member(room, bob, actor, 3, HistoryChoice::None)
        .unwrap();
    let message = EntityId::now();
    vault
        .memory(alice, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 10,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "hello".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    (dir, vault, alice, bob, message)
}

fn fixture() -> (
    tempfile::TempDir,
    crate::Vault,
    EntityId,
    EntityId,
    EntityId,
) {
    fixture_room(None)
}
fn mirror_fixture() -> (
    tempfile::TempDir,
    crate::Vault,
    EntityId,
    EntityId,
    EntityId,
) {
    fixture_room(Some("slack:room-1"))
}

#[test]
fn toggles_new_immutable_id_and_groups_contributors() {
    let (_dir, vault, alice, bob, message) = fixture();
    let request = |by| ReactionInput {
        message,
        by,
        glyph: "👀".into(),
        occurred_at: 20,
        external_id: None,
        actor: crate::WriteActor::new(by, crate::EdgeActorClass::Human),
    };
    let first = vault.react(request(alice)).unwrap();
    assert_eq!(first.state, ReactionState::Put);
    let second = vault.react(request(bob)).unwrap();
    assert_eq!(second.state, ReactionState::Put);
    let pill = &vault.reaction_pills(&[message], alice).unwrap()[&message][0];
    assert_eq!(pill.glyph, "👀");
    assert_eq!(pill.by, vec![alice, bob]);
    assert_eq!(pill.count, 2);
    assert!(pill.mine);
    let signals = vault.reactions_since(alice, 0).unwrap();
    assert_eq!(signals.iter().filter(|row| !row.revoked).count(), 2);
    assert_eq!(
        vault.react(request(alice)).unwrap(),
        ReactionChange {
            id: first.id,
            state: ReactionState::Revoked,
        }
    );
    assert!(vault.is_deleted_shell(&first.id).unwrap());
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|row| { row.reaction == first.id && row.revoked })
    );
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].by,
        vec![bob]
    );
    let again = vault.react(request(alice)).unwrap();
    assert_ne!(again.id, first.id);
    assert_eq!(again.state, ReactionState::Put);
}

#[test]
fn mirrored_event_replay_does_not_toggle_twice() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let input = ReactionInput {
        message,
        by: alice,
        glyph: "👍".into(),
        occurred_at: 20,
        external_id: Some(ReactionExternalId {
            connector: "slack".into(),
            id: "r-1".into(),
        }),
        actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
    };
    let first = vault.react(input.clone()).unwrap();
    let retry = vault.react(input).unwrap();
    assert_eq!(retry.id, first.id);
    assert_eq!(retry.state, ReactionState::Replayed);
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].count,
        1
    );
}

#[test]
fn surface_reaction_is_source_idempotent_and_revoke_is_a_signal() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let event = |event_id: &str, revoked| -> crate::surface_event::SurfaceEvent {
        serde_json::from_value(serde_json::json!({
            "schema_version": crate::surface_event::SURFACE_EVENT_SCHEMA_VERSION,
            "event_id": event_id, "channel": "slack",
            "receiving_address_or_handle": "room-1",
            "receiving_identity_ref": alice.to_hex(), "actor_ref": alice.to_hex(),
            "counterparty": {"state":"known", "counterparty_ref":alice.to_hex()},
            "source": {"app":"slack", "user_ref":"U1"},
            "action": {"kind":"interaction", "interaction":"reaction",
                "target_ref":message.to_hex(), "glyph":"👍",
                "external_reaction_id":"provider-r1", "revoked":revoked,
                "reaction_occurred_at":if revoked {None} else {Some(20u64)}},
            "correlation_id": event_id, "received_at": 20,
            "foreign_inbound":true, "claims_not_instructions":true,
            "identity_retiring":false
        }))
        .unwrap()
    };
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let first = vault
        .ingest_surface_reaction(&event("delivery-1", false), alice, actor)
        .unwrap();
    assert_eq!(first.state, ReactionState::Put);
    assert_eq!(
        vault
            .ingest_surface_reaction(&event("delivery-2", false), alice, actor)
            .unwrap()
            .state,
        ReactionState::Replayed
    );
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].count,
        1
    );
    let removed = vault
        .ingest_surface_reaction(&event("delivery-3", true), alice, actor)
        .unwrap();
    assert_eq!(removed.id, first.id);
    assert_eq!(removed.state, ReactionState::Revoked);
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    assert_eq!(
        vault
            .ingest_surface_reaction(&event("delivery-4", true), alice, actor)
            .unwrap()
            .state,
        ReactionState::Replayed
    );
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|row| row.revoked)
    );
}

#[test]
fn generic_raw_reaction_put_cannot_forge_the_typed_edges() {
    let (_dir, vault, alice, _, message) = fixture();
    let id = EntityId::now();
    let body = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 20,
        ext: None,
    };
    let error = vault
        .put_entity(
            &id,
            ENTITY_TYPE_REACTION,
            crate::TimeRange { start: 20, end: 20 },
            20,
            &body.to_bytes().unwrap(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidReactionBody);
    assert!(vault.get(&id).unwrap().is_none());
}

#[test]
fn supported_mirror_queues_a_connector_neutral_attempt() {
    use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
    use crate::conversation::{ConversationBody, ConversationKind, HistoryChoice};
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
    use crate::{EdgeActorClass, TimeRange, Vault, VaultConfig, WriteActor};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let room = EntityId::now();
    vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Mirror,
                external_id: Some("telegram:chat-1".into()),
                ..Default::default()
            },
            actor,
            1,
        )
        .unwrap();
    vault
        .join_member(room, person, actor, 2, HistoryChoice::None)
        .unwrap();
    let message = EntityId::now();
    vault
        .memory(person, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 10,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "mirror".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    assert_eq!(vault.reactions_outbound(room).unwrap(), "mirrored");
    let changed = vault
        .react(ReactionInput {
            message,
            by: person,
            glyph: "👍".into(),
            occurred_at: 20,
            external_id: None,
            actor,
        })
        .unwrap();
    let ClaimOutcome::Claimed(attempt) = AttemptQueue::new(&vault)
        .claim_kind(
            REACTION_OUTBOUND_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "test-worker".into(),
                now: vault.store.clock.now_recorded_at(),
            },
        )
        .unwrap()
    else {
        panic!("missing queued attempt")
    };
    let payload: ReactionOutboundAttempt = rmp_serde::from_slice(&attempt.payload).unwrap();
    assert_eq!(payload.reaction, changed.id);
    assert_eq!(payload.room_external_id, "telegram:chat-1");
    assert!(!payload.revoked);
}

#[test]
fn late_member_cannot_react_or_read_prejoin_message_pills() {
    let (_dir, vault, alice, _, message) = fixture();
    let room = vault
        .targets(&message, crate::EdgeKind::BelongsTo, None)
        .unwrap()[0];
    let late = EntityId::now();
    vault
        .put_entity(
            &late,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 25, end: 25 },
            25,
            b"late",
        )
        .unwrap();
    vault
        .join_member(
            room,
            late,
            crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
            30,
            crate::conversation::HistoryChoice::None,
        )
        .unwrap();
    vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert!(
        !vault
            .reaction_pills(&[message], late)
            .unwrap()
            .contains_key(&message)
    );
    assert_eq!(
        vault
            .react(ReactionInput {
                message,
                by: late,
                glyph: "👍".into(),
                occurred_at: 31,
                external_id: None,
                actor: crate::WriteActor::new(late, crate::EdgeActorClass::Human)
            })
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidReactionBody
    );
}

#[test]
fn provider_echo_aliases_first_party_reaction_instead_of_toggling_it() {
    use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let first = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 20,
            external_id: None,
            actor,
        })
        .unwrap();
    let echo = vault
        .acknowledge_reaction(ReactionAcknowledgment {
            original: first.id,
            generation: ReactionGeneration {
                connector: "slack".into(),
                id: "r-1".into(),
            },
            actor,
        })
        .unwrap();
    assert_ne!(
        echo.id, first.id,
        "the canonical binding has its own record ID"
    );
    assert_eq!(echo.state, ReactionState::Replayed);
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].count,
        1
    );
    let removal: crate::surface_event::SurfaceEvent = serde_json::from_value(serde_json::json!({
        "schema_version":crate::surface_event::SURFACE_EVENT_SCHEMA_VERSION,
        "event_id":"delivery-remove","channel":"slack",
        "receiving_address_or_handle":"room-1",
        "receiving_identity_ref":alice.to_hex(),"actor_ref":alice.to_hex(),
        "counterparty":{"state":"known","counterparty_ref":alice.to_hex()},
        "source":{"app":"slack","user_ref":"U1"},
        "action":{"kind":"interaction","interaction":"reaction",
            "target_ref":message.to_hex(),"glyph":"👍",
            "external_reaction_id":"r-1","revoked":true},
        "correlation_id":"delivery-remove","received_at":22,
        "foreign_inbound":true,"claims_not_instructions":true,"identity_retiring":false
    }))
    .unwrap();
    let forged = crate::WriteActor::new(EntityId::now(), crate::EdgeActorClass::Human);
    assert!(
        vault
            .ingest_surface_reaction(&removal, alice, forged)
            .is_err()
    );
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].count,
        1
    );
    assert_eq!(
        vault
            .ingest_surface_reaction(&removal, alice, actor)
            .unwrap()
            .state,
        ReactionState::Revoked
    );
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(first_attempt) = queue
        .claim_kind(
            REACTION_OUTBOUND_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "test-worker".into(),
                now: vault.store.clock.now_recorded_at(),
            },
        )
        .unwrap()
    else {
        panic!("first-party put must queue")
    };
    let payload: ReactionOutboundAttempt = rmp_serde::from_slice(&first_attempt.payload).unwrap();
    assert!(!payload.revoked);
    assert!(
        matches!(
            queue
                .claim_kind(
                    REACTION_OUTBOUND_ATTEMPT_KIND,
                    ClaimAttempt {
                        lease_owner: "test-worker".into(),
                        now: vault.store.clock.now_recorded_at()
                    }
                )
                .unwrap(),
            ClaimOutcome::Empty
        ),
        "provider-origin revoke must not echo outbound"
    );
}

#[test]
fn simultaneous_toggles_are_serialized_at_the_live_triple() {
    let (_dir, vault, alice, _, message) = fixture();
    let input = || ReactionInput {
        message,
        by: alice,
        glyph: "👀".into(),
        occurred_at: 20,
        external_id: None,
        actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
    };
    vault.react(input()).unwrap();
    let barrier = std::sync::Barrier::new(3);
    let states = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    vault.react(input()).unwrap().state
                })
            })
            .collect();
        barrier.wait();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(states.contains(&ReactionState::Revoked));
    assert!(states.contains(&ReactionState::Put));
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].count,
        1
    );
}

#[cfg(feature = "sync")]
#[test]
fn replicated_external_body_rebuilds_local_idempotency_index() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let id = EntityId::now();
    let ext = ReactionExternalId {
        connector: "slack".into(),
        id: "remote-r1".into(),
    };
    let body = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 20,
        ext: Some(ext.clone()),
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    20,
                    &body.to_bytes()?,
                )
                .edge(&id, crate::EdgeKind::About, &message, 1.0)
                .edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0)
                .apply(txn)
        })
        .unwrap();
    vault
        .acknowledge_reaction(ReactionAcknowledgment {
            original: id,
            generation: ext.clone().into(),
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    vault
        .delete_entity_with_reason(&id, crate::deletion::DeleteReason::UserDelete)
        .unwrap();
    let retry = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: Some(ext),
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert_eq!(
        retry,
        ReactionChange {
            id,
            state: ReactionState::Replayed
        }
    );
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
}

#[cfg(feature = "sync")]
#[test]
fn replicated_put_and_tombstone_feed_the_authors_signal_index() {
    let (_dir, vault, alice, _, message) = fixture();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "🎉".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    vault
        .put_edge(&id, crate::EdgeKind::About, &message, 1.0)
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|signal| { signal.reaction == id && !signal.revoked })
    );
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 30,
        request_id: [7; 16],
    };
    vault
        .apply_replayed_tombstone(&id, &tombstone.encode())
        .unwrap();
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|signal| { signal.reaction == id && signal.revoked && signal.recorded_at == 30 })
    );
}

#[test]
fn former_member_does_not_see_post_leave_reaction_or_signal() {
    let (_dir, vault, alice, bob, message) = fixture();
    let room = vault
        .targets(&message, crate::EdgeKind::BelongsTo, None)
        .unwrap()[0];
    vault
        .leave_member(
            room,
            alice,
            crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
            30,
        )
        .unwrap();
    let put = vault
        .react(ReactionInput {
            message,
            by: bob,
            glyph: "🎉".into(),
            occurred_at: 40,
            external_id: None,
            actor: crate::WriteActor::new(bob, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert_eq!(put.state, ReactionState::Put);
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    assert_eq!(
        vault.reaction_pills(&[message], bob).unwrap()[&message][0].by,
        vec![bob]
    );
}

#[cfg(feature = "sync")]
#[test]
fn reaction_signal_survives_body_and_tombstone_before_author_edge() {
    let (_dir, vault, alice, _, message) = fixture();
    vault
        .delete_edge(&message, crate::EdgeKind::AuthoredBy, &alice)
        .unwrap();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::About, &message, 1.0)
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 30,
        request_id: [8; 16],
    };
    vault
        .apply_replayed_tombstone(&id, &tombstone.encode())
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    vault
        .put_edge(&message, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    let signals = vault.reactions_since(alice, 0).unwrap();
    assert!(
        signals
            .iter()
            .any(|r| r.reaction == id && !r.revoked && r.recorded_at == 22)
    );
    assert!(
        signals
            .iter()
            .any(|r| r.reaction == id && r.revoked && r.recorded_at == 30)
    );
}

#[test]
fn generic_edge_cannot_retarget_an_existing_reaction() {
    let (_dir, vault, alice, bob, message) = fixture();
    let created = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert_eq!(
        vault
            .put_edge(&created.id, crate::EdgeKind::About, &bob, 1.0)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidReactionBody
    );
    assert_eq!(
        vault
            .delete_edge(&created.id, crate::EdgeKind::About, &message)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidReactionBody
    );
    assert_eq!(
        vault
            .delete_edge(&created.id, crate::EdgeKind::AuthoredBy, &alice)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidReactionBody
    );
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].by,
        vec![alice]
    );
}

#[cfg(feature = "sync")]
#[test]
fn replicated_reput_cannot_rewrite_recorded_time() {
    let (_dir, vault, alice, _, message) = fixture();
    let created = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    let raw = vault.get_raw(&created.id).unwrap().unwrap();
    let h = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    let err = vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &created.id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    h.learned_at + 1,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                )
                .apply(txn)
        })
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidReactionBody);
}

#[test]
fn contributor_order_uses_first_put_not_provider_occurrence_time() {
    let (_dir, vault, alice, bob, message) = fixture();
    for (by, at) in [(alice, 40), (bob, 20)] {
        vault
            .react(ReactionInput {
                message,
                by,
                glyph: "👀".into(),
                occurred_at: at,
                external_id: None,
                actor: crate::WriteActor::new(by, crate::EdgeActorClass::Human),
            })
            .unwrap();
    }
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].by,
        vec![alice, bob]
    );
}

#[test]
fn shared_history_includes_prejoin_reactions_when_message_is_readable() {
    let (_dir, vault, alice, _, message) = fixture();
    let room = vault
        .targets(&message, crate::EdgeKind::BelongsTo, None)
        .unwrap()[0];
    let put = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert_eq!(put.state, ReactionState::Put);
    let late = EntityId::now();
    vault
        .put_entity(
            &late,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 29, end: 29 },
            29,
            b"late",
        )
        .unwrap();
    vault
        .join_member(
            room,
            late,
            crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
            30,
            crate::conversation::HistoryChoice::Share,
        )
        .unwrap();
    assert_eq!(
        vault.reaction_pills(&[message], late).unwrap()[&message][0].by,
        vec![alice]
    );
}

#[test]
fn agent_person_uses_the_same_reaction_primitive() {
    let (_dir, vault, alice, _, message) = fixture();
    let change = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Agent),
        })
        .unwrap();
    assert_eq!(change.state, ReactionState::Put);
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message][0].mine);
}

#[test]
fn future_reaction_time_is_refused_before_a_leave_can_poison_pills() {
    let (_dir, vault, alice, bob, message) = fixture();
    let room = vault
        .targets(&message, crate::EdgeKind::BelongsTo, None)
        .unwrap()[0];
    let future = vault.store.clock.now_recorded_at().saturating_add(3_600);
    let rejected = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: future,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap_err();
    assert_eq!(rejected.kind(), ErrorKind::InvalidReactionBody);
    vault
        .leave_member(
            room,
            alice,
            crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
            future - 1,
        )
        .unwrap();
    assert!(vault.reaction_pills(&[message], bob).unwrap()[&message].is_empty());
}

#[test]
fn delayed_provider_removal_revokes_a_pre_leave_reaction() {
    let (_dir, vault, alice, bob, message) = mirror_fixture();
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let ext = ReactionExternalId {
        connector: "slack".into(),
        id: "provider-r2".into(),
    };
    let put = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 20,
            external_id: Some(ext),
            actor,
        })
        .unwrap();
    let room = vault
        .targets(&message, crate::EdgeKind::BelongsTo, None)
        .unwrap()[0];
    vault.leave_member(room, alice, actor, 30).unwrap();
    assert_eq!(
        vault.reaction_pills(&[message], bob).unwrap()[&message][0].count,
        1
    );
    let removal: crate::surface_event::SurfaceEvent = serde_json::from_value(serde_json::json!({
        "schema_version": crate::surface_event::SURFACE_EVENT_SCHEMA_VERSION,
        "event_id": "delivery-after-leave", "channel": "slack",
        "receiving_address_or_handle": "room-1",
        "receiving_identity_ref": alice.to_hex(), "actor_ref": alice.to_hex(),
        "counterparty": {"state":"known", "counterparty_ref":alice.to_hex()},
        "source": {"app":"slack", "user_ref":"U1"},
        "action": {"kind":"interaction", "interaction":"reaction",
            "target_ref":message.to_hex(), "glyph":"👍",
            "external_reaction_id":"provider-r2", "revoked":true},
        "correlation_id":"delivery-after-leave", "received_at":40,
        "foreign_inbound":true, "claims_not_instructions":true, "identity_retiring":false
    }))
    .unwrap();
    let removed = vault
        .ingest_surface_reaction(&removal, alice, actor)
        .unwrap();
    assert_eq!(removed.id, put.id);
    assert_eq!(removed.state, ReactionState::Revoked);
    assert!(vault.reaction_pills(&[message], bob).unwrap()[&message].is_empty());
}

#[test]
fn hard_erase_removes_signal_and_outbound_reaction_content() {
    for soft_first in [false, true] {
        let (_dir, vault, alice, _, message) = mirror_fixture();
        let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
        let glyph = "sensitive🫶";
        let input = || ReactionInput {
            message,
            by: alice,
            glyph: glyph.into(),
            occurred_at: 20,
            external_id: None,
            actor,
        };
        let put = vault.react(input()).unwrap();
        assert!(
            vault
                .reactions_since(alice, 0)
                .unwrap()
                .iter()
                .any(|row| row.reaction == put.id && row.glyph == glyph)
        );
        if soft_first {
            assert_eq!(vault.react(input()).unwrap().state, ReactionState::Revoked);
        }
        vault
            .delete_entity_with_reason(&put.id, crate::deletion::DeleteReason::UserHardDelete)
            .unwrap();
        assert!(
            vault
                .reactions_since(alice, 0)
                .unwrap()
                .iter()
                .all(|row| row.reaction != put.id)
        );
        assert!(
            crate::attempt_queue::AttemptQueue::new(&vault)
                .list()
                .unwrap()
                .iter()
                .filter(|row| row.kind == REACTION_OUTBOUND_ATTEMPT_KIND)
                .all(|row| !row
                    .payload
                    .windows(glyph.len())
                    .any(|window| window == glyph.as_bytes()))
        );
    }
}

#[cfg(feature = "sync")]
#[test]
fn replayed_hard_erase_discards_pending_signal_and_outbound_payload() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    vault
        .delete_edge(&message, crate::EdgeKind::AuthoredBy, &alice)
        .unwrap();
    let glyph = "pending🫶";
    let put = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: glyph.into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 30,
        request_id: [42; 16],
    };
    vault
        .apply_replayed_tombstone(&put.id, &tombstone.encode())
        .unwrap();
    vault
        .put_edge(&message, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    assert!(
        crate::attempt_queue::AttemptQueue::new(&vault)
            .list()
            .unwrap()
            .iter()
            .filter(|row| row.kind == REACTION_OUTBOUND_ATTEMPT_KIND)
            .all(|row| !row
                .payload
                .windows(glyph.len())
                .any(|window| window == glyph.as_bytes()))
    );
}

#[cfg(feature = "sync")]
#[test]
fn replicated_reaction_stays_pending_until_both_edges_arrive() {
    let (_dir, vault, alice, _, message) = fixture();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    assert!(
        vault.reactions_since(alice, 0).unwrap().is_empty(),
        "a body without its reaction bindings is not an event"
    );
    vault
        .put_edge(&id, crate::EdgeKind::About, &message, 1.0)
        .unwrap();
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    vault
        .put_edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].by,
        vec![alice]
    );
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|signal| signal.reaction == id && !signal.revoked)
    );
}

#[cfg(feature = "sync")]
#[test]
fn replicated_reaction_completes_when_author_edge_precedes_about() {
    let (_dir, vault, alice, _, message) = fixture();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "👍".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    vault
        .put_edge(&id, crate::EdgeKind::About, &message, 1.0)
        .unwrap();
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|signal| signal.reaction == id && !signal.revoked)
    );
}

#[cfg(feature = "sync")]
#[test]
fn missing_or_wrong_kind_remote_reactor_never_poison_pills() {
    let (_dir, vault, alice, _, message) = fixture();
    let bad = EntityId::now();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: bad,
        glyph: "👀".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::About, &message, 1.0)
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::AuthoredBy, &bad, 1.0)
        .unwrap();
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    vault
        .put_entity(
            &bad,
            crate::registry::ENTITY_TYPE_MACHINE,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"machine",
        )
        .unwrap();
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
}

#[cfg(feature = "sync")]
#[test]
fn nonmember_remote_reaction_does_not_poison_other_pills() {
    let (_dir, vault, alice, bob, message) = fixture();
    let id = EntityId::now();
    // Bob joined at 3, so his claimed reaction at 2 predates membership.
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: bob,
        glyph: "👀".into(),
        at: 2,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 2, end: 2 },
                    22,
                    &row.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::About, &message, 1.0)
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::AuthoredBy, &bob, 1.0)
        .unwrap();
    let valid = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert_eq!(valid.state, ReactionState::Put);
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].by,
        vec![alice]
    );
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .all(|signal| signal.reaction != id)
    );
    let later = vault
        .react(ReactionInput {
            message,
            by: bob,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: None,
            actor: crate::WriteActor::new(bob, crate::EdgeActorClass::Human),
        })
        .unwrap();
    assert_eq!(
        later.state,
        ReactionState::Put,
        "an invalid pre-join peer row must not toggle away a new valid put"
    );
    assert_ne!(later.id, id);
    assert!(
        vault.reaction_pills(&[message], bob).unwrap()[&message]
            .iter()
            .any(|pill| pill.glyph == "👀" && pill.by == vec![bob])
    );
}

#[cfg(feature = "sync")]
#[test]
fn reaction_inbox_over_1000_equal_time_events_remains_consumable() {
    let (_dir, vault, alice, _, message) = fixture();
    let mut batch = vault.batch_in();
    for n in 0..1001 {
        let id = vault.store.clock.entity_id().unwrap();
        let body = ReactionBody {
            v: 1,
            msg: message,
            by: alice,
            glyph: format!("glyph-{n}"),
            at: 20,
            ext: None,
        };
        batch = batch
            .put_replicated(
                &id,
                ENTITY_TYPE_REACTION,
                crate::TimeRange { start: 20, end: 20 },
                22,
                &body.to_bytes().unwrap(),
            )
            .edge(&id, crate::EdgeKind::About, &message, 1.0)
            .edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0);
    }
    vault.with_write_txn(|txn| batch.apply(txn)).unwrap();
    let first = vault
        .reactions_since(alice, 0)
        .expect("first page must not overflow");
    assert_eq!(first.len(), 1000);
    assert!(first.iter().all(|row| row.recorded_at == 22));
    let after = first.next.as_deref().expect("continuation after 1000");
    let second = vault
        .reactions_since_page(alice, 0, Some(after), 1000)
        .unwrap();
    assert_eq!(second.len(), 1);
    assert!(second.next.is_none());
    assert_eq!(second[0].recorded_at, 22);
    assert!(!first.iter().any(|row| row.reaction == second[0].reaction));
}

#[cfg(feature = "sync")]
#[test]
fn concurrent_replica_adds_project_one_pill_and_toggle_all_known_adds() {
    let (_dir, vault, alice, _, message) = fixture();
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let local = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: None,
            actor,
        })
        .unwrap();
    let peer = EntityId::now();
    let body = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 21,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &peer,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 21, end: 21 },
                    22,
                    &body.to_bytes()?,
                )
                .edge(&peer, crate::EdgeKind::About, &message, 1.0)
                .edge(&peer, crate::EdgeKind::AuthoredBy, &alice, 1.0)
                .apply(txn)
        })
        .unwrap();
    let pills = vault.reaction_pills(&[message], alice).unwrap();
    assert_eq!(pills[&message][0].count, 1);
    assert_eq!(pills[&message][0].by, vec![alice]);
    let changed = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 23,
            external_id: None,
            actor,
        })
        .unwrap();
    assert_eq!(changed.state, ReactionState::Revoked);
    assert!(vault.is_deleted_shell(&local.id).unwrap());
    assert!(vault.is_deleted_shell(&peer).unwrap());
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
}

#[cfg(feature = "sync")]
#[test]
fn two_peers_accept_opposite_order_adds_then_converge_after_toggle_replay() {
    use crate::conversation::{ConversationBody, HistoryChoice};
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
    use crate::{EdgeActorClass, Vault, VaultConfig, WriteActor};
    fn peer(
        person: EntityId,
        room: EntityId,
        turn: EntityId,
        message: EntityId,
    ) -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        vault
            .put_entity(
                &person,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .unwrap();
        let actor = WriteActor::new(person, EdgeActorClass::Human);
        vault
            .create_conversation(room, &ConversationBody::default(), actor, 1)
            .unwrap();
        vault
            .join_member(room, person, actor, 2, HistoryChoice::None)
            .unwrap();
        vault
            .memory(person, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                occurred_at: 10,
                messages: vec![WitnessMessage {
                    id: Some(message.to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "dialogue".into(),
                    content: "shared".into(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
            })
            .unwrap();
        (dir, vault)
    }
    fn carry(source: &Vault, target: &Vault, id: EntityId, person: EntityId, msg: EntityId) {
        let raw = source.get_raw(&id).unwrap().unwrap();
        let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        target
            .with_write_txn(|txn| {
                target
                    .batch_in()
                    .put_replicated(
                        &id,
                        ENTITY_TYPE_REACTION,
                        crate::TimeRange {
                            start: header.occurred_start,
                            end: header.occurred_end,
                        },
                        header.learned_at,
                        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                    )
                    .edge(&id, crate::EdgeKind::About, &msg, 1.0)
                    .edge(&id, crate::EdgeKind::AuthoredBy, &person, 1.0)
                    .apply(txn)
            })
            .unwrap();
    }
    let person = EntityId::now();
    let room = EntityId::now();
    let turn = EntityId::now();
    let message = EntityId::now();
    let (_ad, a) = peer(person, room, turn, message);
    let (_bd, b) = peer(person, room, turn, message);
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let first = a
        .react(ReactionInput {
            message,
            by: person,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: None,
            actor,
        })
        .unwrap()
        .id;
    let second = b
        .react(ReactionInput {
            message,
            by: person,
            glyph: "👀".into(),
            occurred_at: 21,
            external_id: None,
            actor,
        })
        .unwrap()
        .id;
    assert_ne!(first, second);
    carry(&a, &b, first, person, message);
    carry(&b, &a, second, person, message);
    assert_eq!(
        a.reaction_pills(&[message], person).unwrap()[&message][0].count,
        1
    );
    assert_eq!(
        b.reaction_pills(&[message], person).unwrap()[&message][0].count,
        1
    );
    assert_eq!(
        a.react(ReactionInput {
            message,
            by: person,
            glyph: "👀".into(),
            occurred_at: 22,
            external_id: None,
            actor
        })
        .unwrap()
        .state,
        ReactionState::Revoked
    );
    for id in [first, second] {
        assert!(a.is_deleted_shell(&id).unwrap());
        let value = crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserDelete,
            deleted_at: 30,
            request_id: [9; 16],
        };
        b.apply_replayed_tombstone(&id, &value.encode()).unwrap();
    }
    assert!(a.reaction_pills(&[message], person).unwrap()[&message].is_empty());
    assert!(b.reaction_pills(&[message], person).unwrap()[&message].is_empty());
}

#[cfg(feature = "sync")]
#[test]
fn target_body_arriving_after_both_binding_edges_flushes_pending_signal() {
    let (_dir, vault, alice, _, original) = fixture();
    let source_turn = vault
        .edges_out(&original)
        .unwrap()
        .into_iter()
        .find(|edge| edge.kind == crate::EdgeKind::PartOf)
        .unwrap()
        .target;
    let message = EntityId::now();
    for edge in vault.edges_out(&source_turn).unwrap() {
        vault
            .put_edge(&message, edge.kind, &edge.target, edge.weight)
            .unwrap();
    }
    vault
        .put_edge(&message, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .edge(&id, crate::EdgeKind::About, &message, 1.0)
                .edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0)
                .apply(txn)
        })
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    let raw = vault.get_raw(&source_turn).unwrap().unwrap();
    let h = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &message,
                    crate::registry::ENTITY_TYPE_TURN,
                    crate::TimeRange {
                        start: h.occurred_start,
                        end: h.occurred_end,
                    },
                    h.learned_at,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                )
                .apply(txn)
        })
        .unwrap();
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|event| event.reaction == id)
    );
}

#[cfg(feature = "sync")]
#[test]
fn reactor_person_arriving_after_reaction_edges_flushes_pending_signal() {
    let (_dir, vault, alice, _, message) = fixture();
    let turn = vault
        .edges_out(&message)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == crate::EdgeKind::PartOf)
        .unwrap()
        .target;
    let room = vault
        .edges_out(&turn)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == crate::EdgeKind::ChildOf)
        .unwrap()
        .target;
    let reactor = EntityId::now();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: message,
        by: reactor,
        glyph: "👀".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .edge(&id, crate::EdgeKind::About, &message, 1.0)
                .edge(&id, crate::EdgeKind::AuthoredBy, &reactor, 1.0)
                .apply(txn)
        })
        .unwrap();
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    vault
        .put_entity(
            &reactor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 5, end: 5 },
            5,
            b"person",
        )
        .unwrap();
    vault
        .join_member(
            room,
            reactor,
            crate::WriteActor::new(alice, crate::EdgeActorClass::Human),
            10,
            crate::conversation::HistoryChoice::None,
        )
        .unwrap();
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|event| event.reaction == id)
    );
}

#[path = "tests/identity.rs"]
mod identity_tests;

#[path = "tests/signal.rs"]
mod signal_tests;
