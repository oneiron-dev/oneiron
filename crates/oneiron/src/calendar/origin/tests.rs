use super::*;
use crate::calendar::query::{CalendarReadRequest, read_event};
use crate::edge::EdgeActorClass;

fn fixture() -> (tempfile::TempDir, Vault, WriteActor) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let actor = WriteActor::new(
        vault.ensure_embedded_owner_actor().unwrap(),
        EdgeActorClass::Human,
    );
    (dir, vault, actor)
}
fn input() -> CalendarEventInput {
    CalendarEventInput {
        name: "event".into(),
        ..Default::default()
    }
}
fn time() -> TimeRange {
    TimeRange {
        start: 100,
        end: 200,
    }
}
#[test]
fn origin_field_matrix_and_atomic_admission() {
    let (_dir, vault, actor) = fixture();
    assert!(
        vault
            .create_calendar_event(&input(), time(), actor)
            .is_err()
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_EVENT)
            .unwrap()
            .is_empty()
    );
    let native = vault
        .create_native_calendar_event(&input(), time(), actor)
        .unwrap();
    assert_eq!(
        vault.calendar_event_origin(native).unwrap(),
        CalendarOrigin::Native
    );
    assert_eq!(
        read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: native.to_hex()
            }
        )
        .unwrap()
        .unwrap()
        .origin,
        "native"
    );
    assert!(
        vault
            .create_native_calendar_event(
                &CalendarEventInput {
                    evidence_turn_ids: vec![actor.entity_ref()],
                    ..input()
                },
                time(),
                actor
            )
            .is_err()
    );
    for fields in [
        CalendarEventInput {
            origin: Some(CalendarOrigin::Dreamer),
            ..input()
        },
        CalendarEventInput {
            origin: Some(CalendarOrigin::Imported),
            ..input()
        },
        CalendarEventInput {
            origin: Some(CalendarOrigin::Imported),
            import_source: Some("feed".into()),
            external_id: Some("uid".into()),
            evidence_turn_ids: vec![actor.entity_ref()],
            ..input()
        },
    ] {
        assert!(fields.validate().is_err());
    }
    let imported = vault
        .create_calendar_event(
            &CalendarEventInput {
                origin: Some(CalendarOrigin::Imported),
                import_source: Some("feed".into()),
                external_id: Some("uid".into()),
                ..input()
            },
            time(),
            actor,
        )
        .unwrap();
    assert_eq!(
        vault.calendar_event_origin(imported).unwrap(),
        CalendarOrigin::Imported
    );
}
#[test]
fn source_delete_invalidates_dreamer_but_not_native() {
    let (_dir, vault, actor) = fixture();
    let turn = EntityId::now();
    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, time(), 1, b"turn")
        .unwrap();
    let extracted = CalendarEventInput {
        evidence_turn_ids: vec![turn],
        source_frontiers: vec!["v1".into()],
        ..input()
    };
    assert!(
        vault
            .create_dreamer_calendar_event(
                &CalendarEventInput {
                    rrule: Some("FREQ=DAILY".into()),
                    ..extracted.clone()
                },
                time(),
                actor
            )
            .is_err()
    );
    let dreamer = vault
        .create_dreamer_calendar_event(&extracted, time(), actor)
        .unwrap();
    let native = vault
        .create_native_calendar_event(&input(), time(), actor)
        .unwrap();
    assert_eq!(
        vault.calendar_event_origin(dreamer).unwrap(),
        CalendarOrigin::Dreamer
    );
    assert!(
        read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: dreamer.to_hex()
            }
        )
        .unwrap()
        .is_some()
    );
    // A provenance link must not turn authored calendar state into a derived row.
    vault
        .put_edge(&native, EdgeKind::DerivedFrom, &turn, 1.0)
        .unwrap();
    vault.delete_entity(&turn).unwrap();
    assert!(
        read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: dreamer.to_hex()
            }
        )
        .unwrap()
        .is_none()
    );
    assert!(
        read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: native.to_hex()
            }
        )
        .unwrap()
        .is_some()
    );
}
#[test]
fn legacy_reads_default_but_originless_calendar_overwrite_refuses() {
    let (_dir, vault, _) = fixture();
    let event = EntityId::now();
    let body = encode(&Value::Map(vec![(
        Value::from("name"),
        Value::from("legacy"),
    )]))
    .unwrap();
    vault
        .put_entity(&event, ENTITY_TYPE_EVENT, time(), 1, &body)
        .unwrap();
    let claim = ClaimBody::new(
        super::super::claims::PREDICATE_CALENDAR_TIME_KIND,
        ClaimSubject::Entity(event),
        Value::Map(vec![
            (Value::from("kind"), Value::from("absolute")),
            (Value::from("busy_transparency"), Value::from("busy")),
        ]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&EntityId::now(), &claim, time(), 1)
        .unwrap();
    assert_eq!(
        read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: event.to_hex()
            }
        )
        .unwrap()
        .unwrap()
        .origin,
        "dreamer"
    );
    assert!(
        vault
            .put_entity(&event, ENTITY_TYPE_EVENT, time(), 2, &body)
            .is_err()
    );
    assert_eq!(vault.get(&event).unwrap().unwrap(), body);
}

#[test]
fn calendar_fields_without_origin_refuse_and_conflicting_origins_fail_closed() {
    let (_dir, vault, actor) = fixture();
    for field in [
        "evidenceTurnIds",
        "sourceFrontiers",
        "rrule",
        "calendarName",
        "importSource",
        "externalId",
    ] {
        let id = EntityId::now();
        let bytes = encode(&Value::Map(vec![
            (Value::from("name"), Value::from("event")),
            (Value::from(field), Value::from("value")),
        ]))
        .unwrap();
        assert!(matches!(
            vault.put_entity(&id, ENTITY_TYPE_EVENT, time(), 1, &bytes),
            Err(Error::InvalidClaimBody(_))
        ));
        assert!(vault.get(&id).unwrap().is_none());
    }
    let event = vault
        .create_native_calendar_event(&input(), time(), actor)
        .unwrap();
    let conflicting = ClaimBody::new(
        PREDICATE_CALENDAR_ORIGIN,
        ClaimSubject::Entity(event),
        Value::from("imported"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&EntityId::now(), &conflicting, time(), 1)
        .unwrap();
    assert!(matches!(
        vault.calendar_event_origin(event),
        Err(Error::InvalidClaimBody(_))
    ));
}

#[test]
fn known_calendar_bodies_reject_malformed_originless_and_conflicting_replays() {
    let (_dir, vault, actor) = fixture();
    let event = vault
        .create_native_calendar_event(&input(), time(), actor)
        .unwrap();
    let original = vault.get(&event).unwrap().unwrap();
    let mut trailing = original.clone();
    trailing.push(0xc0);
    let imported = CalendarEventInput {
        origin: Some(CalendarOrigin::Imported),
        import_source: Some("feed".into()),
        external_id: Some("uid".into()),
        ..input()
    }
    .encode()
    .unwrap();
    let originless = encode(&Value::Map(vec![(
        Value::from("name"),
        Value::from("erased"),
    )]))
    .unwrap();
    for body in [vec![0x81], vec![0xc0], trailing, imported, originless] {
        for replay in [false, true] {
            let result = if replay {
                vault
                    .batch()
                    .put_replicated(&event, ENTITY_TYPE_EVENT, time(), 2, &body)
                    .commit()
            } else {
                vault.put_entity(&event, ENTITY_TYPE_EVENT, time(), 2, &body)
            };
            assert!(
                matches!(result, Err(Error::InvalidClaimBody(_))),
                "{replay}: {result:?}"
            );
            assert_eq!(vault.get(&event).unwrap().unwrap(), original);
            assert_eq!(
                vault.calendar_event_origin(event).unwrap(),
                CalendarOrigin::Native
            );
        }
    }
    // Replay can arrive before its origin claim, and matching replays stay legal.
    let incoming = EntityId::now();
    vault
        .batch()
        .put_replicated(&incoming, ENTITY_TYPE_EVENT, time(), 2, &original)
        .commit()
        .unwrap();
    vault
        .batch()
        .put_replicated(&event, ENTITY_TYPE_EVENT, time(), 2, &original)
        .commit()
        .unwrap();
    assert_eq!(vault.get(&incoming).unwrap().unwrap(), original);
    assert_eq!(vault.get(&event).unwrap().unwrap(), original);
    // EVENT also represents non-calendar opaque records; this rule must not
    // accidentally impose the calendar union on those unrelated records.
    let opaque = EntityId::now();
    vault
        .put_entity(&opaque, ENTITY_TYPE_EVENT, time(), 2, b"opaque event")
        .unwrap();
    assert_eq!(vault.get(&opaque).unwrap().unwrap(), b"opaque event");
}

#[cfg(feature = "sync")]
#[test]
fn replay_reconciles_late_origin_claims_without_defaulting_to_dreamer() {
    use crate::sync::{bridge::Materializer, loro_support::map_insert_bytes, types::WindowKey};
    let (_dir, source, actor) = fixture();
    let event = source
        .create_native_calendar_event(&input(), time(), actor)
        .unwrap();
    let doc = loro::LoroDoc::new();
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &event.to_hex(),
        &source.get_raw_unsealed(&event).unwrap().unwrap(),
    )
    .unwrap();
    doc.commit();
    let dir = tempfile::tempdir().unwrap();
    let peer = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let window = WindowKey::try_new("1970-01").unwrap();
    let materializer = Materializer::new();
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &window).unwrap();
    assert_eq!(
        peer.calendar_event_origin(event).unwrap_err().kind(),
        crate::ErrorKind::InvalidClaimBody
    );
    assert!(
        crate::sync::quarantine::pending_remat_entities(&peer, window.as_str())
            .unwrap()
            .contains(&event.to_hex())
    );
    // An unbound typed EVENT is not treated as a derived Dreamer by deletion.
    let origin_guard = peer.store.env.read_txn().unwrap();
    assert!(survives_source_deletion(&peer.store, &origin_guard, event).unwrap());
    drop(origin_guard);
    map_insert_bytes(
        &entities,
        &actor.entity_ref().to_hex(),
        &source
            .get_raw_unsealed(&actor.entity_ref())
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    for claim in source.claims_for_subject(&event).unwrap() {
        map_insert_bytes(
            &entities,
            &claim.to_hex(),
            &source.get_raw_unsealed(&claim).unwrap().unwrap(),
        )
        .unwrap();
        for edge in source.edges_out(&claim).unwrap() {
            let key = crate::sync::bridge::format_edge_key(&claim, edge.kind, &edge.target);
            let value = crate::sync::bridge::encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )
            .unwrap();
            map_insert_bytes(&doc.get_map("edges"), &key, &value).unwrap();
        }
    }
    doc.commit();
    crate::sync::window::forward_rematerialize(&peer, &doc, &materializer, &window).unwrap();
    assert_eq!(
        peer.calendar_event_origin(event).unwrap(),
        CalendarOrigin::Native
    );
    assert!(
        !crate::sync::quarantine::pending_remat_entities(&peer, window.as_str())
            .unwrap()
            .contains(&event.to_hex())
    );
}
