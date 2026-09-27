//! Canonical generation receipts: provider causality is not a vault_meta alias.
use super::*;
use crate::registry::ENTITY_TYPE_REACTION_BINDING;

#[test]
fn provider_acknowledgment_persists_canonical_binding_and_survives_soft_revoke() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let original = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 20,
            external_id: None,
            actor,
        })
        .unwrap()
        .id;
    let generation = ReactionGeneration {
        connector: "slack".into(),
        id: "provider-1".into(),
    };
    let receipt = vault
        .acknowledge_reaction(ReactionAcknowledgment {
            original,
            generation: generation.clone(),
            actor,
        })
        .unwrap();
    assert_eq!(receipt.state, ReactionState::Replayed);
    let binding = vault.get_raw(&receipt.id).unwrap().unwrap();
    assert_eq!(binding[0], ENTITY_TYPE_REACTION_BINDING);
    assert_eq!(
        vault
            .acknowledge_reaction(ReactionAcknowledgment {
                original,
                generation: generation.clone(),
                actor,
            })
            .unwrap(),
        receipt
    );
    let revoked = vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 21,
            external_id: None,
            actor,
        })
        .unwrap();
    assert_eq!(revoked.state, ReactionState::Revoked);
    assert_eq!(
        vault
            .acknowledge_reaction(ReactionAcknowledgment {
                original,
                generation,
                actor,
            })
            .unwrap(),
        receipt,
        "a delayed echo must not recreate a revoked generation"
    );
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
}

#[test]
fn provider_generation_is_deterministic_and_new_generation_can_readd_after_remove() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let generation = ReactionGeneration {
        connector: "slack".into(),
        id: "gen-1".into(),
    };
    let add = || ReactionIngress::ProviderAdd {
        message,
        by: alice,
        glyph: "👀".into(),
        occurred_at: 20,
        generation: generation.clone(),
        actor,
    };
    let first = vault.ingest_reaction(add()).unwrap();
    assert!(vault.get_raw(&first.id).unwrap().is_some());
    assert_eq!(
        vault.ingest_reaction(add()).unwrap().state,
        ReactionState::Replayed
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_REACTION_BINDING)
            .unwrap()
            .len(),
        1
    );
    let remove = || ReactionIngress::Remove {
        message,
        by: alice,
        glyph: "👀".into(),
        generation: generation.clone(),
        actor,
    };
    assert_eq!(
        vault.ingest_reaction(remove()).unwrap().state,
        ReactionState::Revoked
    );
    assert_eq!(
        vault.ingest_reaction(remove()).unwrap().state,
        ReactionState::Replayed
    );
    assert_eq!(
        vault.ingest_reaction(add()).unwrap().state,
        ReactionState::Replayed,
        "redelivered old generation does not resurrect a revoked add"
    );
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    let next = vault
        .ingest_reaction(ReactionIngress::ProviderAdd {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 22,
            generation: ReactionGeneration {
                connector: "slack".into(),
                id: "gen-2".into(),
            },
            actor,
        })
        .unwrap();
    assert_eq!(next.state, ReactionState::Put);
    assert_ne!(first.id, next.id);
    assert_eq!(
        vault.reaction_pills(&[message], alice).unwrap()[&message][0].count,
        1
    );
}

#[test]
fn hard_erase_purges_canonical_binding_and_blocks_late_echo() {
    for soft_first in [false, true] {
        let (_dir, vault, alice, _, message) = mirror_fixture();
        let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
        let original = vault
            .react(ReactionInput {
                message,
                by: alice,
                glyph: "👀".into(),
                occurred_at: 20,
                external_id: None,
                actor,
            })
            .unwrap()
            .id;
        let generation = ReactionGeneration {
            connector: "slack".into(),
            id: "hard-gen".into(),
        };
        let ack = || ReactionAcknowledgment {
            original,
            generation: generation.clone(),
            actor,
        };
        let binding = vault.acknowledge_reaction(ack()).unwrap().id;
        let canonical = vault.get_raw(&binding).unwrap().unwrap();
        if soft_first {
            vault
                .delete_entity_with_reason(&original, crate::deletion::DeleteReason::UserDelete)
                .unwrap();
        }
        vault
            .delete_entity_with_reason(&original, crate::deletion::DeleteReason::UserHardDelete)
            .unwrap();
        assert!(
            vault.get_raw(&binding).unwrap().is_none(),
            "hard erase must purge the content-bearing receipt"
        );
        assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
        assert!(vault.acknowledge_reaction(ack()).is_err());
        let h = crate::batch::EntityMetadataHeader::parse(&canonical).unwrap();
        assert!(
            vault
                .with_write_txn(|txn| vault
                    .batch_in()
                    .put_replicated(
                        &binding,
                        ENTITY_TYPE_REACTION_BINDING,
                        crate::TimeRange {
                            start: h.occurred_start,
                            end: h.occurred_end
                        },
                        h.learned_at,
                        &canonical[crate::batch::ENTITY_METADATA_HEADER_LEN..]
                    )
                    .apply(txn))
                .is_ok(),
            "late replica receipt is consumed only as an opaque suppression fact"
        );
        let redacted = vault.get_raw(&binding).unwrap().unwrap();
        assert_eq!(
            redacted.len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN,
            "no content-bearing receipt survives a hard marker"
        );
        assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
        assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    }
}

#[cfg(feature = "sync")]
use crate::conversation::{ConversationBody, ConversationKind, HistoryChoice};
#[cfg(feature = "sync")]
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
#[cfg(feature = "sync")]
use crate::{EdgeActorClass, Vault, VaultConfig, WriteActor};
#[cfg(feature = "sync")]
fn mirror_peer(
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
        .create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Mirror,
                external_id: Some("slack:room".into()),
                ..Default::default()
            },
            actor,
            1,
        )
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
                content: "hello".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    (dir, vault)
}
#[cfg(feature = "sync")]
fn carry_add(
    source: &Vault,
    target: &Vault,
    id: EntityId,
    person: EntityId,
    message: EntityId,
    kind: u8,
) {
    let raw = source.get_raw(&id).unwrap().unwrap();
    let h = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    let mut batch = target.batch_in().put_replicated(
        &id,
        kind,
        crate::TimeRange {
            start: h.occurred_start,
            end: h.occurred_end,
        },
        h.learned_at,
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    if kind == ENTITY_TYPE_REACTION {
        batch = batch.edge(&id, crate::EdgeKind::About, &message, 1.0).edge(
            &id,
            crate::EdgeKind::AuthoredBy,
            &person,
            1.0,
        );
    }
    target.with_write_txn(|txn| batch.apply(txn)).unwrap();
}

#[cfg(feature = "sync")]
#[test]
fn two_offline_provider_adds_of_one_generation_are_aliases_and_remove_together() {
    let person = EntityId::now();
    let room = EntityId::now();
    let turn = EntityId::now();
    let message = EntityId::now();
    let (_ad, a) = mirror_peer(person, room, turn, message);
    let (_bd, b) = mirror_peer(person, room, turn, message);
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let generation = ReactionGeneration {
        connector: "slack".into(),
        id: "same-gen".into(),
    };
    let add = || ReactionIngress::ProviderAdd {
        message,
        by: person,
        glyph: "🫶".into(),
        occurred_at: 20,
        generation: generation.clone(),
        actor,
    };
    let first = a.ingest_reaction(add()).unwrap().id;
    let second = b.ingest_reaction(add()).unwrap().id;
    assert_ne!(first, second);
    let a_binding = a.entities_by_type(ENTITY_TYPE_REACTION_BINDING).unwrap()[0];
    let b_binding = b.entities_by_type(ENTITY_TYPE_REACTION_BINDING).unwrap()[0];
    carry_add(&a, &b, first, person, message, ENTITY_TYPE_REACTION);
    carry_add(
        &a,
        &b,
        a_binding,
        person,
        message,
        ENTITY_TYPE_REACTION_BINDING,
    );
    carry_add(&b, &a, second, person, message, ENTITY_TYPE_REACTION);
    carry_add(
        &b,
        &a,
        b_binding,
        person,
        message,
        ENTITY_TYPE_REACTION_BINDING,
    );
    for vault in [&a, &b] {
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_REACTION_BINDING)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            vault.reaction_pills(&[message], person).unwrap()[&message][0].count,
            1
        );
    }
    let remove = || ReactionIngress::Remove {
        message,
        by: person,
        glyph: "🫶".into(),
        generation: generation.clone(),
        actor,
    };
    assert_eq!(
        a.ingest_reaction(remove()).unwrap().state,
        ReactionState::Revoked
    );
    assert_eq!(
        b.ingest_reaction(remove()).unwrap().state,
        ReactionState::Revoked
    );
    for vault in [&a, &b] {
        assert!(vault.reaction_pills(&[message], person).unwrap()[&message].is_empty());
        assert_eq!(
            vault.ingest_reaction(add()).unwrap().state,
            ReactionState::Replayed
        );
    } // Erasing one physical alias erases the provider generation, not merely
    // that peer's local add while another alias retains the glyph/receipt.
    a.delete_entity_with_reason(&first, crate::deletion::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(a.get_raw(&second).unwrap().is_none());
    assert!(
        a.entities_by_type(ENTITY_TYPE_REACTION_BINDING)
            .unwrap()
            .is_empty()
    );
    assert!(a.reactions_since(person, 0).unwrap().is_empty());
}

#[test]
fn ambiguous_late_echo_without_correlation_returns_typed_reconciliation() {
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
        .unwrap()
        .id;
    vault
        .react(ReactionInput {
            message,
            by: alice,
            glyph: "👍".into(),
            occurred_at: 21,
            external_id: None,
            actor,
        })
        .unwrap();
    let err = vault
        .acknowledge_reaction(ReactionAcknowledgment {
            original: first,
            generation: ReactionGeneration {
                connector: "slack".into(),
                id: "unknown".into(),
            },
            actor,
        })
        .unwrap_err();
    assert_eq!(err.kind(), crate::ErrorKind::ReactionNeedsReconciliation);
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    let event: crate::surface_event::SurfaceEvent = serde_json::from_value(serde_json::json!({
        "schema_version":crate::surface_event::SURFACE_EVENT_SCHEMA_VERSION,
        "event_id":"ambiguous-delivery","channel":"slack",
        "receiving_address_or_handle":"room-1","receiving_identity_ref":alice.to_hex(),
        "actor_ref":alice.to_hex(),
        "counterparty":{"state":"known","counterparty_ref":alice.to_hex()},
        "source":{"app":"slack","user_ref":"U1"},
        "action":{"kind":"interaction","interaction":"reaction",
            "target_ref":message.to_hex(),"glyph":"👍",
            "external_reaction_id":"unknown","revoked":false},
        "correlation_id":"delivery-only-not-generation","received_at":22,
        "foreign_inbound":true,"claims_not_instructions":true,"identity_retiring":false
    }))
    .unwrap();
    assert_eq!(
        vault
            .ingest_surface_reaction(&event, alice, actor)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::ReactionNeedsReconciliation
    );
}

#[cfg(feature = "sync")]
#[test]
fn headerless_hard_erase_before_receipt_suppresses_an_already_materialized_alias() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let original = EntityId::now();
    let hard = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 30,
        request_id: [9; 16],
    };
    vault
        .apply_replayed_tombstone(&original, &hard.encode())
        .unwrap();
    let generation = ReactionGeneration {
        connector: "slack".into(),
        id: "late-erase-gen".into(),
    };
    let alias = vault
        .ingest_reaction(ReactionIngress::ProviderAdd {
            message,
            by: alice,
            glyph: "👀".into(),
            occurred_at: 20,
            generation: generation.clone(),
            actor,
        })
        .unwrap()
        .id;
    assert!(
        vault.get_raw(&alias).unwrap().is_some(),
        "without the receipt the peer cannot know which generation was erased"
    );
    let receipt = ReactionBindingBody {
        v: 1,
        generation: generation.clone(),
        reaction: original,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 20,
    };
    let receipt_id = crate::reaction::identity::binding_id(&receipt).unwrap();
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &receipt_id,
                    ENTITY_TYPE_REACTION_BINDING,
                    crate::TimeRange { start: 20, end: 20 },
                    25,
                    &receipt.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    assert!(vault.get_raw(&alias).unwrap().is_none());
    assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
    assert!(
        vault
            .ingest_reaction(ReactionIngress::ProviderAdd {
                message,
                by: alice,
                glyph: "👀".into(),
                occurred_at: 20,
                generation,
                actor,
            })
            .is_err(),
        "opaque suppression survives a later old-generation delivery"
    );
    assert_eq!(
        vault
            .ingest_reaction(ReactionIngress::ProviderAdd {
                message,
                by: alice,
                glyph: "👀".into(),
                occurred_at: 31,
                generation: ReactionGeneration {
                    connector: "slack".into(),
                    id: "fresh-gen".into()
                },
                actor,
            })
            .unwrap()
            .state,
        ReactionState::Put
    );
}

#[cfg(feature = "sync")]
#[test]
fn provider_alias_arriving_after_generation_revoke_stays_logically_revoked() {
    let person = EntityId::now();
    let room = EntityId::now();
    let turn = EntityId::now();
    let message = EntityId::now();
    let (_ad, a) = mirror_peer(person, room, turn, message);
    let (_bd, b) = mirror_peer(person, room, turn, message);
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let generation = ReactionGeneration {
        connector: "slack".into(),
        id: "late-alias-gen".into(),
    };
    let add = || ReactionIngress::ProviderAdd {
        message,
        by: person,
        glyph: "🫶".into(),
        occurred_at: 20,
        generation: generation.clone(),
        actor,
    };
    let first = a.ingest_reaction(add()).unwrap().id;
    let second = b.ingest_reaction(add()).unwrap().id;
    assert_ne!(first, second);
    let second_binding = b.entities_by_type(ENTITY_TYPE_REACTION_BINDING).unwrap()[0];
    assert_eq!(
        a.ingest_reaction(ReactionIngress::Remove {
            message,
            by: person,
            glyph: "🫶".into(),
            generation: generation.clone(),
            actor,
        })
        .unwrap()
        .state,
        ReactionState::Revoked
    );
    carry_add(&b, &a, second, person, message, ENTITY_TYPE_REACTION);
    carry_add(
        &b,
        &a,
        second_binding,
        person,
        message,
        ENTITY_TYPE_REACTION_BINDING,
    );
    assert!(
        a.reaction_pills(&[message], person).unwrap()[&message].is_empty(),
        "generation revoke suppresses even an unobserved late physical alias"
    );
    assert_eq!(
        a.ingest_reaction(add()).unwrap().state,
        ReactionState::Replayed
    );
}

#[cfg(feature = "sync")]
#[test]
fn unresolved_remote_binding_never_steals_a_valid_provider_add() {
    let (_dir, vault, alice, _, message) = mirror_fixture();
    let actor = crate::WriteActor::new(alice, crate::EdgeActorClass::Human);
    let origin = EntityId::now();
    let generation = ReactionGeneration {
        connector: "slack".into(),
        id: "pending-gen".into(),
    };
    let binding = ReactionBindingBody {
        v: 1,
        generation: generation.clone(),
        reaction: origin,
        msg: message,
        by: alice,
        glyph: "👀".into(),
        at: 20,
    };
    let binding_id = crate::reaction::identity::binding_id(&binding).unwrap();
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &binding_id,
                    ENTITY_TYPE_REACTION_BINDING,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &binding.to_bytes()?,
                )
                .apply(txn)
        })
        .unwrap();
    let input = || ReactionIngress::ProviderAdd {
        message,
        by: alice,
        glyph: "👀".into(),
        occurred_at: 20,
        generation: generation.clone(),
        actor,
    };
    assert_eq!(
        vault.ingest_reaction(input()).unwrap_err().kind(),
        crate::ErrorKind::ReactionNeedsReconciliation
    );
    vault
        .put_entity(
            &origin,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"wrong kind",
        )
        .unwrap();
    assert_eq!(
        vault.ingest_reaction(input()).unwrap_err().kind(),
        crate::ErrorKind::ReactionNeedsReconciliation
    );
    assert!(vault.reaction_pills(&[message], alice).unwrap()[&message].is_empty());
}
