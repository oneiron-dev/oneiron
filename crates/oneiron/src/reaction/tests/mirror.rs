//! Acceptance 3: connector-mirrored reactions go through the signed-writer
//! path; the provider echo of our own reaction binds to the original; a
//! provider remove retracts; a re-add after remove is a new generation.
use super::*;
use crate::error::ErrorKind;

const MIRROR: &str = "slack:room-1";

fn generation(id: &str) -> ReactionExternalId {
    ReactionExternalId {
        connector: "slack".to_owned(),
        id: id.to_owned(),
    }
}

fn add(room: &Room, by: EntityId, id: &str) -> ReactionIngress {
    add_at(room, by, id, 20)
}

fn add_at(room: &Room, by: EntityId, id: &str, occurred_at: u64) -> ReactionIngress {
    ReactionIngress::ProviderAdd {
        message: room.message,
        by,
        glyph: "👍".to_owned(),
        occurred_at,
        generation: generation(id),
    }
}

fn remove(room: &Room, by: EntityId, id: &str) -> ReactionIngress {
    ReactionIngress::Remove {
        message: room.message,
        by,
        glyph: "👍".to_owned(),
        generation: generation(id),
    }
}

fn thumbs(room: &Room) -> Vec<ReactionPill> {
    room.vault
        .reaction_pills(&[room.message], room.alice)
        .unwrap()[&room.message]
        .clone()
}

#[test]
fn mirrored_reaction_is_written_by_the_signed_mirror_machine() {
    let room = room_with(Some(MIRROR));
    let put = room
        .vault
        .ingest_reaction(add(&room, room.bob, "g-1"))
        .unwrap();
    assert_eq!(put.state, ReactionState::Put);
    let body = claim(&room.vault, put.id);
    assert_eq!(
        crate::memory::claim_author(&body),
        Some(conversation_mirror_actor_id().unwrap()),
        "a mirrored claim is attested by the mirror MACHINE"
    );
    assert!(super::super::value::machine_written(&body), "and signed");
    let value = ReactionValue::from_value(&body.value).unwrap();
    assert_eq!(value.by, room.bob, "authored for the reacting person");
    assert_eq!(value.external_id, Some(generation("g-1")));
    assert_eq!(body.approval, crate::claim::ClaimApprovalStatus::Auto);
    // A replayed delivery of the same add does not add twice.
    assert_eq!(
        room.vault
            .ingest_reaction(add(&room, room.bob, "g-1"))
            .unwrap(),
        ReactionChange {
            id: put.id,
            state: ReactionState::Replayed
        }
    );
    assert_eq!(thumbs(&room)[0].count, 1);
    // Mirrored ingress never loops back to the provider.
    assert!(
        crate::attempt_queue::AttemptQueue::new(&room.vault)
            .list()
            .unwrap()
            .iter()
            .all(|attempt| attempt.kind != REACTION_OUTBOUND_ATTEMPT_KIND)
    );
}

#[test]
fn unsigned_machine_reaction_is_refused() {
    // A mirror room on a vault whose host never provisioned the MACHINE
    // writers: the mirror actor holds no signer, so the door refuses.
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let alice = person(&vault, "Alice");
    let bob = person(&vault, "Bob");
    let room = EntityId::now();
    vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Mirror,
                external_id: Some(MIRROR.to_owned()),
                ..Default::default()
            },
            human(alice),
            1,
        )
        .unwrap();
    for member in [alice, bob] {
        vault
            .join_member(room, member, human(alice), 2, HistoryChoice::Share)
            .unwrap();
    }
    let message = witness(&vault, room, alice, PLAN);
    // The MACHINE row exists, but no host retained a signer for it.
    crate::reaction::ensure_conversation_mirror_actor(&vault, 1).unwrap();
    let err = vault
        .ingest_reaction(ReactionIngress::ProviderAdd {
            message,
            by: bob,
            glyph: "👍".to_owned(),
            occurred_at: 20,
            generation: generation("g-1"),
        })
        .unwrap_err();
    assert!(
        matches!(
            err.kind(),
            ErrorKind::ActorLacksClaimAuthority | ErrorKind::InvalidClaimBody
        ),
        "{err}"
    );
    assert!(
        vault
            .reaction_history(message, bob, "👍")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn provider_echo_binds_to_the_original_and_never_adds_a_second_reaction() {
    let room = room_with(Some(MIRROR));
    let original = react(&room, room.bob, "👍");
    let echo = ReactionIngress::Echo {
        original: original.id,
        message: room.message,
        by: room.bob,
        glyph: "👍".to_owned(),
        generation: generation("echo-1"),
    };
    for _ in 0..2 {
        assert_eq!(
            room.vault.ingest_reaction(echo.clone()).unwrap(),
            ReactionChange {
                id: original.id,
                state: ReactionState::Replayed
            }
        );
    }
    // An echo delivered as a plain add of the same generation also binds.
    assert_eq!(
        room.vault
            .ingest_reaction(add(&room, room.bob, "echo-1"))
            .unwrap()
            .id,
        original.id
    );
    assert_eq!(thumbs(&room)[0].count, 1);
    assert_eq!(
        room.vault
            .reaction_history(room.message, room.bob, "👍")
            .unwrap()
            .len(),
        1,
        "no second reaction claim"
    );
    assert_eq!(
        room.vault
            .reactions_since(room.alice, 0)
            .unwrap()
            .signals
            .len(),
        1,
        "and no second put signal"
    );
    // The provider removes it: the original claim is retracted.
    assert_eq!(
        room.vault
            .ingest_reaction(remove(&room, room.bob, "echo-1"))
            .unwrap(),
        ReactionChange {
            id: original.id,
            state: ReactionState::Revoked
        }
    );
    assert!(thumbs(&room).is_empty());
}

#[test]
fn provider_remove_retracts_and_a_readd_is_a_new_generation() {
    let room = room_with(Some(MIRROR));
    let first = room
        .vault
        .ingest_reaction(add(&room, room.bob, "g-1"))
        .unwrap();
    let removed = room
        .vault
        .ingest_reaction(remove(&room, room.bob, "g-1"))
        .unwrap();
    assert_eq!(
        removed,
        ReactionChange {
            id: first.id,
            state: ReactionState::Revoked
        }
    );
    assert!(thumbs(&room).is_empty());
    // A replayed add of the removed generation never resurrects it.
    assert_eq!(
        room.vault
            .ingest_reaction(add(&room, room.bob, "g-1"))
            .unwrap()
            .state,
        ReactionState::Replayed
    );
    assert!(thumbs(&room).is_empty());
    let second = room
        .vault
        .ingest_reaction(add(&room, room.bob, "g-2"))
        .unwrap();
    assert_eq!(second.state, ReactionState::Put);
    assert_ne!(second.id, first.id);
    // A late duplicate of the first removal leaves the new generation live.
    assert_eq!(
        room.vault
            .ingest_reaction(remove(&room, room.bob, "g-1"))
            .unwrap()
            .state,
        ReactionState::Replayed
    );
    assert_eq!(thumbs(&room)[0].by, vec![room.bob]);
    let history = room
        .vault
        .reaction_history(room.message, room.bob, "👍")
        .unwrap();
    assert_eq!(
        history
            .iter()
            .map(|entry| (entry.id, entry.removed_at.is_some()))
            .collect::<Vec<_>>(),
        vec![(first.id, true), (second.id, false)]
    );
}

#[test]
fn a_newer_provider_generation_replaces_a_live_one_and_an_older_one_is_stale() {
    let room = room_with(Some(MIRROR));
    let first = room
        .vault
        .ingest_reaction(add(&room, room.bob, "g-1"))
        .unwrap();
    // The provider's removal of g-1 was missed; its newer add g-2 arrives.
    let second = room
        .vault
        .ingest_reaction(add_at(&room, room.bob, "g-2", 30))
        .unwrap();
    assert_eq!(second.state, ReactionState::Put);
    let stale = room
        .vault
        .ingest_reaction(add_at(&room, room.bob, "g-0", 25))
        .unwrap();
    assert_eq!(
        stale,
        ReactionChange {
            id: second.id,
            state: ReactionState::Replayed
        }
    );
    assert_eq!(
        room.vault
            .ingest_reaction(remove(&room, room.bob, "g-1"))
            .unwrap()
            .state,
        ReactionState::Replayed,
        "the late removal of the replaced generation changes nothing"
    );
    let history = room
        .vault
        .reaction_history(room.message, room.bob, "👍")
        .unwrap();
    assert_eq!(
        history
            .iter()
            .map(|entry| (entry.id, entry.removed_at.is_some()))
            .collect::<Vec<_>>(),
        vec![(first.id, true), (second.id, false)]
    );
}

#[test]
fn a_removal_before_its_add_is_unresolved_and_a_foreign_connector_is_refused() {
    let room = room_with(Some(MIRROR));
    let err = room
        .vault
        .ingest_reaction(remove(&room, room.bob, "unknown"))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConversationState);
    let err = room
        .vault
        .ingest_reaction(ReactionIngress::ProviderAdd {
            generation: ReactionExternalId {
                connector: "discord".to_owned(),
                id: "g-9".to_owned(),
            },
            message: room.message,
            by: room.bob,
            glyph: "👍".to_owned(),
            occurred_at: 20,
        })
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    let err = room
        .vault
        .ingest_reaction(add(&room, room.carol, "g-3"))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConversationDenied, "{err}");
}

#[test]
fn surface_reaction_event_normalizes_add_echo_and_removal() {
    let room = room_with(Some(MIRROR));
    let event =
        |delivery: &str, reaction: serde_json::Value| -> crate::surface_event::SurfaceEvent {
            serde_json::from_value(serde_json::json!({
                "schema_version": crate::surface_event::SURFACE_EVENT_SCHEMA_VERSION,
                "event_id": delivery, "channel": "slack",
                "receiving_address_or_handle": "room-1",
                "receiving_identity_ref": room.alice.to_hex(), "actor_ref": room.alice.to_hex(),
                "counterparty": {"state": "known", "counterparty_ref": room.bob.to_hex()},
                "source": {"app": "slack", "user_ref": "U1"},
                "action": {"kind": "interaction", "interaction": "reaction",
                    "target_ref": room.message.to_hex(), "reaction": reaction},
                "correlation_id": delivery, "received_at": 20,
                "foreign_inbound": true, "claims_not_instructions": true,
                "identity_retiring": false
            }))
            .unwrap()
        };
    let added = room
        .vault
        .ingest_surface_reaction(
            &event(
                "d-1",
                serde_json::json!({"glyph": "👍", "external_id": "p-1", "occurred_at": 20}),
            ),
            room.bob,
        )
        .unwrap();
    assert_eq!(added.state, ReactionState::Put);
    let redelivered = room
        .vault
        .ingest_surface_reaction(
            &event(
                "d-2",
                serde_json::json!({"glyph": "👍", "external_id": "p-1", "occurred_at": 20}),
            ),
            room.bob,
        )
        .unwrap();
    assert_eq!(redelivered.state, ReactionState::Replayed);
    let removed = room
        .vault
        .ingest_surface_reaction(
            &event(
                "d-3",
                serde_json::json!({"glyph": "👍", "external_id": "p-1", "removed": true}),
            ),
            room.bob,
        )
        .unwrap();
    assert_eq!(
        removed,
        ReactionChange {
            id: added.id,
            state: ReactionState::Revoked
        }
    );
    let own = react(&room, room.dave, "🎉");
    let echoed = room
        .vault
        .ingest_surface_reaction(
            &event(
                "d-4",
                serde_json::json!({"glyph": "🎉", "external_id": "p-2",
                    "origin_ref": own.id.to_hex()}),
            ),
            room.dave,
        )
        .unwrap();
    assert_eq!(
        echoed,
        ReactionChange {
            id: own.id,
            state: ReactionState::Replayed
        }
    );
    let err = room
        .vault
        .ingest_surface_reaction(
            &event(
                "d-5",
                serde_json::json!({"glyph": "👍", "external_id": "p-3"}),
            ),
            room.bob,
        )
        .unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::ConversationState,
        "an add needs its time"
    );
}
