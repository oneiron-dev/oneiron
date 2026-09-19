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
