//! Accept/reject fixtures and per-type contract tests for the calendar claim family.

use super::*;
use core::assert_matches;
use std::collections::BTreeSet;

use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, encode_claim_body, validate_claim_body_bytes,
};
use crate::config::VaultConfig;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::test_util::{entity, open_test_vault_with};

/// Subject EVENT for value-shape fixtures.
const SUBJECT_SEED: u8 = 0x51;
/// A second EVENT referenced by series/successor values.
const REF_SEED: u8 = 0x52;

fn subject() -> EntityId {
    entity(SUBJECT_SEED)
}

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), value.clone()))
            .collect(),
    )
}

fn body(predicate: &str, value: Value) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject()),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
}

/// Round-trips through the same codec storage uses, then through the
/// write-only validator chokepoint.
fn through_chokepoint(body: &ClaimBody) -> Result<()> {
    validate_claim_body_bytes(&encode_claim_body(body)?, false)
}

fn canonical_time_kind() -> Value {
    map(&[
        (KEY_KIND, Value::from(CalendarTimeKind::Zoned.as_str())),
        (
            KEY_BUSY_TRANSPARENCY,
            Value::from(CalendarBusyTransparency::Busy.as_str()),
        ),
    ])
}

fn canonical_wall_time() -> Value {
    map(&[
        (KEY_YEAR, Value::from(2026)),
        (KEY_MONTH, Value::from(8)),
        (KEY_DAY, Value::from(5)),
        (KEY_HOUR, Value::from(14)),
        (KEY_MINUTE, Value::from(30)),
        (KEY_SECOND, Value::from(0)),
    ])
}

fn canonical_passport() -> Value {
    map(&[
        (KEY_SYSTEM, Value::from("google")),
        (KEY_UID, Value::from("uid-1@example.com")),
        (KEY_LAST_SEQUENCE, Value::from(3)),
        (KEY_CONTENT_HASH, Value::Binary(vec![7u8; CONTENT_HASH_LEN])),
        (
            KEY_DIRECTION,
            Value::from(CalendarPassportDirection::TwoWay.as_str()),
        ),
        (KEY_LAST_SEEN_AT, Value::from(1_754_400_000_u64)),
        (
            KEY_PRESENCE,
            Value::from(CalendarPassportPresence::Live.as_str()),
        ),
    ])
}

fn canonical_series_master() -> Value {
    map(&[
        (KEY_RRULE, Value::from("FREQ=WEEKLY;BYDAY=MO")),
        (KEY_DTSTART_UTC, Value::from(1_754_400_000_u64)),
        (KEY_TZ, Value::from("Europe/Warsaw")),
    ])
}

fn canonical_series_exception() -> Value {
    map(&[
        (KEY_MASTER_REF, Value::from(entity(REF_SEED).to_hex())),
        (KEY_UID, Value::from("uid-1@example.com")),
        (KEY_ORIGINAL_START_UTC, Value::from(1_754_400_000_u64)),
    ])
}

fn canonical_successor() -> Value {
    map(&[(KEY_PREDECESSOR_REF, Value::from(entity(REF_SEED).to_hex()))])
}

fn canonical_attendee() -> Value {
    map(&[
        (KEY_WHO, Value::from("mailto:person@example.com")),
        (KEY_ROLE, Value::from("REQ-PARTICIPANT")),
        (KEY_PARTSTAT, Value::from("ACCEPTED")),
    ])
}

fn canonical_status() -> Value {
    map(&[
        (KEY_STATUS, Value::from(CalendarStatus::Confirmed.as_str())),
        (KEY_BASIS, Value::from(CalendarStatusBasis::Owner.as_str())),
        (KEY_RECORDED_AT, Value::from(1_754_400_000_u64)),
    ])
}

fn canonical_event_outcome() -> Value {
    map(&[
        (KEY_OUTCOME, Value::from(EventOutcome::Held.as_str())),
        (KEY_BASIS, Value::from(EventOutcomeBasis::Machine.as_str())),
        (KEY_RECORDED_AT, Value::from(1_754_400_000_u64)),
    ])
}

/// One canonical value per predicate, in table order.
fn canonical_values() -> Vec<(&'static str, Value)> {
    vec![
        (PREDICATE_CALENDAR_TIME_KIND, canonical_time_kind()),
        (PREDICATE_CALENDAR_WALL_TIME, canonical_wall_time()),
        (PREDICATE_CALENDAR_TZ, Value::from("Europe/Warsaw")),
        (
            PREDICATE_CALENDAR_RRULE,
            Value::from("FREQ=WEEKLY;BYDAY=MO"),
        ),
        (PREDICATE_CALENDAR_SERIES_MASTER, canonical_series_master()),
        (
            PREDICATE_CALENDAR_SERIES_EXCEPTION,
            canonical_series_exception(),
        ),
        (PREDICATE_CALENDAR_SUCCESSOR, canonical_successor()),
        (PREDICATE_CALENDAR_ATTENDEE, canonical_attendee()),
        (
            PREDICATE_CALENDAR_MEETING_LINK,
            Value::from("https://meet.example.com/abc-defg-hij"),
        ),
        (PREDICATE_CALENDAR_PASSPORT, canonical_passport()),
        (
            PREDICATE_CALENDAR_ORIGIN,
            Value::from(CalendarOrigin::Imported.as_str()),
        ),
        (PREDICATE_CALENDAR_STATUS, canonical_status()),
        (PREDICATE_CALENDAR_EVENT_OUTCOME, canonical_event_outcome()),
    ]
}

#[test]
fn calendar_claim_predicate_table_is_exact() {
    let minted: BTreeSet<&str> = CALENDAR_CLAIM_PREDICATES.iter().copied().collect();
    let expected: BTreeSet<&str> = BTreeSet::from([
        "calendar.time_kind",
        "calendar.wall_time",
        "calendar.tz",
        "calendar.rrule",
        "calendar.series_master",
        "calendar.series_exception",
        "calendar.successor",
        "calendar.attendee",
        "calendar.meeting_link",
        "calendar.passport",
        "calendar.origin",
        "calendar.status",
        "calendar.event_outcome",
    ]);
    // Set-compare scoped "at this layer": CAL-00's twelve plus CAL-07's
    // `calendar.event_outcome`, each exactly once.
    assert_eq!(minted, expected);
    // Once each: no duplicate rows hiding behind the set compare.
    assert_eq!(CALENDAR_CLAIM_PREDICATES.len(), minted.len());
    assert_eq!(CALENDAR_CLAIM_PREDICATES.len(), 13);

    for predicate in CALENDAR_CLAIM_PREDICATES {
        assert!(is_calendar_claim_predicate(predicate));
    }
    // Exact-table membership, never a `calendar.` prefix match.
    assert!(!is_calendar_claim_predicate("calendar.unknown"));
    assert!(!is_calendar_claim_predicate("calendar.outcome"));
    assert!(!is_calendar_claim_predicate("calendar."));
}

#[test]
fn calendar_claims_require_event_subjects() -> Result<()> {
    // Half 1 (byte level): a non-entity subject is rejected structurally.
    let edge_subject = ClaimBody::new(
        PREDICATE_CALENDAR_ORIGIN,
        ClaimSubject::Edge {
            source: entity(REF_SEED),
            target: subject(),
            kind: crate::edge::EdgeKind::ClaimOf,
        },
        Value::from(CalendarOrigin::Native.as_str()),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    assert_matches!(
        through_chokepoint(&edge_subject),
        Err(Error::InvalidClaimBody(_))
    );

    // Half 2 (store level): an entity subject that is not an EVENT row is
    // rejected. The byte validator cannot reach storage, so this is the
    // comm.rs-style family assertion.
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let (_dir, vault) = open_test_vault_with(config);

    let event = subject();
    let person = entity(REF_SEED);
    let missing = entity(0x53);
    let occurred = TimeRange { start: 1, end: 1 };
    vault.put_entity(&event, ENTITY_TYPE_EVENT, occurred, 1, b"event")?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, 1, b"person")?;

    require_event_subject(&vault, &event)?;
    assert_matches!(
        require_event_subject(&vault, &person),
        Err(Error::EntityNotFound)
    );
    assert_matches!(
        require_event_subject(&vault, &missing),
        Err(Error::EntityNotFound)
    );
    Ok(())
}

#[test]
fn calendar_claim_validator_accepts_canonical_shapes() -> Result<()> {
    for (predicate, value) in canonical_values() {
        through_chokepoint(&body(predicate, value))?;
    }
    Ok(())
}

#[test]
fn calendar_claim_validator_rejects_malformed_shapes() {
    let reject = |predicate: &str, value: Value| {
        assert_matches!(
            through_chokepoint(&body(predicate, value)),
            Err(Error::InvalidClaimBody(_)),
            "{predicate} must reject this value"
        );
    };

    // Extra key on an exact map.
    let mut extra = canonical_status();
    if let Value::Map(entries) = &mut extra {
        entries.push((Value::from("surprise"), Value::from(1)));
    }
    reject(PREDICATE_CALENDAR_STATUS, extra);

    // Unknown key replacing a required one.
    reject(
        PREDICATE_CALENDAR_SUCCESSOR,
        map(&[("successor_ref", Value::from(entity(REF_SEED).to_hex()))]),
    );

    // Duplicate key.
    reject(
        PREDICATE_CALENDAR_SUCCESSOR,
        Value::Map(vec![
            (
                Value::from(KEY_PREDECESSOR_REF),
                Value::from(entity(REF_SEED).to_hex()),
            ),
            (
                Value::from(KEY_PREDECESSOR_REF),
                Value::from(entity(REF_SEED).to_hex()),
            ),
        ]),
    );

    // Wrong scalar types.
    reject(PREDICATE_CALENDAR_TZ, Value::from(7));
    reject(PREDICATE_CALENDAR_ORIGIN, Value::from(true));
    reject(
        PREDICATE_CALENDAR_STATUS,
        map(&[
            (KEY_STATUS, Value::from(CalendarStatus::Confirmed.as_str())),
            (KEY_BASIS, Value::from(CalendarStatusBasis::Owner.as_str())),
            (KEY_RECORDED_AT, Value::from("not-a-timestamp")),
        ]),
    );
    // A map where a scalar is required.
    reject(PREDICATE_CALENDAR_MEETING_LINK, Value::Map(Vec::new()));

    // Invalid closed-set strings.
    reject(
        PREDICATE_CALENDAR_TIME_KIND,
        map(&[
            (KEY_KIND, Value::from("relative")),
            (
                KEY_BUSY_TRANSPARENCY,
                Value::from(CalendarBusyTransparency::Busy.as_str()),
            ),
        ]),
    );
    reject(
        PREDICATE_CALENDAR_TIME_KIND,
        map(&[
            (KEY_KIND, Value::from(CalendarTimeKind::Zoned.as_str())),
            (KEY_BUSY_TRANSPARENCY, Value::from("maybe")),
        ]),
    );
    reject(PREDICATE_CALENDAR_ORIGIN, Value::from("synthesized"));
    reject(
        PREDICATE_CALENDAR_PASSPORT,
        passport_with(KEY_DIRECTION, Value::from("bidirectional")),
    );
    reject(
        PREDICATE_CALENDAR_PASSPORT,
        passport_with(KEY_PRESENCE, Value::from("gone")),
    );
    reject(
        PREDICATE_CALENDAR_STATUS,
        map(&[
            (KEY_STATUS, Value::from("tentative")),
            (KEY_BASIS, Value::from(CalendarStatusBasis::Owner.as_str())),
            (KEY_RECORDED_AT, Value::from(1_u64)),
        ]),
    );
    reject(
        PREDICATE_CALENDAR_STATUS,
        map(&[
            (KEY_STATUS, Value::from(CalendarStatus::Cancelled.as_str())),
            (KEY_BASIS, Value::from("imported")),
            (KEY_RECORDED_AT, Value::from(1_u64)),
        ]),
    );

    reject(
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        map(&[
            (KEY_OUTCOME, Value::from("rescheduled")),
            (KEY_BASIS, Value::from(EventOutcomeBasis::Machine.as_str())),
            (KEY_RECORDED_AT, Value::from(1_u64)),
        ]),
    );
    reject(
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        map(&[
            (KEY_OUTCOME, Value::from(EventOutcome::Held.as_str())),
            (KEY_BASIS, Value::from("inferred")),
            (KEY_RECORDED_AT, Value::from(1_u64)),
        ]),
    );

    // Empty text.
    reject(PREDICATE_CALENDAR_TZ, Value::from(""));
    reject(PREDICATE_CALENDAR_RRULE, Value::from(""));
    reject(PREDICATE_CALENDAR_MEETING_LINK, Value::from(""));
    reject(
        PREDICATE_CALENDAR_ATTENDEE,
        map(&[
            (KEY_WHO, Value::from("")),
            (KEY_ROLE, Value::from("REQ-PARTICIPANT")),
            (KEY_PARTSTAT, Value::from("ACCEPTED")),
        ]),
    );
    // Control characters in a URL.
    reject(
        PREDICATE_CALENDAR_MEETING_LINK,
        Value::from("https://meet.example.com/a\u{0}b"),
    );

    // Invalid wall-date field ranges.
    for (key, bad) in [
        (KEY_MONTH, 0_u64),
        (KEY_MONTH, 13),
        (KEY_DAY, 0),
        (KEY_DAY, 32),
        (KEY_HOUR, 24),
        (KEY_MINUTE, 60),
        (KEY_SECOND, 61),
    ] {
        let mut value = canonical_wall_time();
        if let Value::Map(entries) = &mut value {
            for (candidate, slot) in entries.iter_mut() {
                if candidate.as_str() == Some(key) {
                    *slot = Value::from(bad);
                }
            }
        }
        reject(PREDICATE_CALENDAR_WALL_TIME, value);
    }

    // Non-32-byte passport hashes, and a non-binary hash.
    reject(
        PREDICATE_CALENDAR_PASSPORT,
        passport_with(KEY_CONTENT_HASH, Value::Binary(vec![7u8; 31])),
    );
    reject(
        PREDICATE_CALENDAR_PASSPORT,
        passport_with(KEY_CONTENT_HASH, Value::Binary(vec![7u8; 33])),
    );
    reject(
        PREDICATE_CALENDAR_PASSPORT,
        passport_with(KEY_CONTENT_HASH, Value::from("7".repeat(64))),
    );

    // Malformed entity references.
    reject(
        PREDICATE_CALENDAR_SUCCESSOR,
        map(&[(KEY_PREDECESSOR_REF, Value::from("not-hex"))]),
    );
}

fn passport_with(key: &str, replacement: Value) -> Value {
    let mut value = canonical_passport();
    if let Value::Map(entries) = &mut value {
        for (candidate, slot) in entries.iter_mut() {
            if candidate.as_str() == Some(key) {
                *slot = replacement.clone();
            }
        }
    }
    value
}

#[test]
fn calendar_time_kind_busy_transparency_contract_round_trips() -> Result<()> {
    // Canonical map keys, both wire tokens, every kind.
    for kind in [
        CalendarTimeKind::Absolute,
        CalendarTimeKind::Zoned,
        CalendarTimeKind::Floating,
        CalendarTimeKind::AllDay,
    ] {
        for transparency in [
            CalendarBusyTransparency::Busy,
            CalendarBusyTransparency::Free,
        ] {
            let value = map(&[
                (KEY_KIND, Value::from(kind.as_str())),
                (KEY_BUSY_TRANSPARENCY, Value::from(transparency.as_str())),
            ]);
            through_chokepoint(&body(PREDICATE_CALENDAR_TIME_KIND, value.clone()))?;
            assert_eq!(
                decode_time_kind_value(&value)?,
                CalendarTimeKindValue {
                    kind,
                    busy_transparency: transparency,
                }
            );
        }
    }

    // Missing-field back-compat default is busy.
    let legacy = map(&[(KEY_KIND, Value::from(CalendarTimeKind::Floating.as_str()))]);
    through_chokepoint(&body(PREDICATE_CALENDAR_TIME_KIND, legacy.clone()))?;
    assert_eq!(
        decode_time_kind_value(&legacy)?,
        CalendarTimeKindValue {
            kind: CalendarTimeKind::Floating,
            busy_transparency: CalendarBusyTransparency::Busy,
        }
    );

    // Ingest mapping from ICS TRANSP.
    assert_eq!(
        CalendarBusyTransparency::from_ics_transp(Some(ICS_TRANSP_TRANSPARENT)),
        CalendarBusyTransparency::Free
    );
    assert_eq!(
        CalendarBusyTransparency::from_ics_transp(Some(ICS_TRANSP_OPAQUE)),
        CalendarBusyTransparency::Busy
    );
    assert_eq!(
        CalendarBusyTransparency::from_ics_transp(None),
        CalendarBusyTransparency::Busy
    );
    // Kinds are never coerced into one another.
    assert_eq!(
        CalendarTimeKind::parse("all_day"),
        Some(CalendarTimeKind::AllDay)
    );
    assert_eq!(CalendarTimeKind::parse("allday"), None);
    Ok(())
}

#[test]
fn calendar_passport_contract_round_trips() -> Result<()> {
    // This test never builds the UID index: CAL-02 owns that.
    for direction in [
        CalendarPassportDirection::Inbound,
        CalendarPassportDirection::Outbound,
        CalendarPassportDirection::TwoWay,
    ] {
        for presence in [
            CalendarPassportPresence::Live,
            CalendarPassportPresence::Absent,
        ] {
            let mut value = passport_with(KEY_DIRECTION, Value::from(direction.as_str()));
            value = {
                let mut rebuilt = value.clone();
                if let Value::Map(entries) = &mut rebuilt {
                    for (candidate, slot) in entries.iter_mut() {
                        if candidate.as_str() == Some(KEY_PRESENCE) {
                            *slot = Value::from(presence.as_str());
                        }
                    }
                }
                rebuilt
            };
            through_chokepoint(&body(PREDICATE_CALENDAR_PASSPORT, value.clone()))?;
            assert_eq!(
                decode_passport_value(&value)?,
                CalendarPassportValue {
                    system: "google".to_owned(),
                    uid: "uid-1@example.com".to_owned(),
                    last_sequence: 3,
                    content_hash: [7u8; CONTENT_HASH_LEN],
                    direction,
                    last_seen_at: 1_754_400_000,
                    presence,
                }
            );
        }
    }

    // Missing presence decodes as Live for back-compat.
    let legacy = map(&[
        (KEY_SYSTEM, Value::from("google")),
        (KEY_UID, Value::from("uid-1@example.com")),
        (KEY_LAST_SEQUENCE, Value::from(3)),
        (KEY_CONTENT_HASH, Value::Binary(vec![7u8; CONTENT_HASH_LEN])),
        (
            KEY_DIRECTION,
            Value::from(CalendarPassportDirection::Inbound.as_str()),
        ),
        (KEY_LAST_SEEN_AT, Value::from(1_754_400_000_u64)),
    ]);
    through_chokepoint(&body(PREDICATE_CALENDAR_PASSPORT, legacy.clone()))?;
    assert_eq!(
        decode_passport_value(&legacy)?.presence,
        CalendarPassportPresence::Live
    );

    // Only inbound-bearing passports vote in imported-absence cancellation.
    assert!(CalendarPassportDirection::Inbound.is_inbound_bearing());
    assert!(CalendarPassportDirection::TwoWay.is_inbound_bearing());
    assert!(!CalendarPassportDirection::Outbound.is_inbound_bearing());
    Ok(())
}

#[test]
fn calendar_status_contract_round_trips() -> Result<()> {
    for status in [CalendarStatus::Confirmed, CalendarStatus::Cancelled] {
        for basis in [
            CalendarStatusBasis::ImportedCancel,
            CalendarStatusBasis::ImportedAbsence,
            CalendarStatusBasis::Owner,
            CalendarStatusBasis::Booking,
        ] {
            let value = map(&[
                (KEY_STATUS, Value::from(status.as_str())),
                (KEY_BASIS, Value::from(basis.as_str())),
                (KEY_RECORDED_AT, Value::from(1_754_400_000_u64)),
            ]);
            through_chokepoint(&body(PREDICATE_CALENDAR_STATUS, value.clone()))?;
            assert_eq!(
                decode_status_value(&value)?,
                CalendarStatusValue {
                    status,
                    basis,
                    recorded_at: 1_754_400_000,
                }
            );
        }
    }
    // Exact value: recorded_at is required, not optional.
    assert_matches!(
        decode_status_value(&map(&[
            (KEY_STATUS, Value::from(CalendarStatus::Cancelled.as_str())),
            (
                KEY_BASIS,
                Value::from(CalendarStatusBasis::ImportedAbsence.as_str())
            ),
        ])),
        Err(Error::InvalidClaimBody(_))
    );
    Ok(())
}

#[test]
fn calendar_series_master_is_claim_shaped() -> Result<()> {
    let value = canonical_series_master();
    let body = body(PREDICATE_CALENDAR_SERIES_MASTER, value.clone());
    assert_matches!(body.subject, ClaimSubject::Entity(id) if id == subject());
    through_chokepoint(&body)?;
    assert_eq!(
        decode_series_master_value(&value)?,
        CalendarSeriesMasterValue {
            rrule: "FREQ=WEEKLY;BYDAY=MO".to_owned(),
            dtstart_utc: 1_754_400_000,
            tz: "Europe/Warsaw".to_owned(),
        }
    );
    // RRULE text is stored verbatim; CAL-03 owns parsing, so a
    // structurally-bounded but semantically odd rule still stores.
    through_chokepoint(&body_series_master("FREQ=SECONDLY;COUNT=1"))?;
    Ok(())
}

fn body_series_master(rrule: &str) -> ClaimBody {
    body(
        PREDICATE_CALENDAR_SERIES_MASTER,
        map(&[
            (KEY_RRULE, Value::from(rrule)),
            (KEY_DTSTART_UTC, Value::from(1_754_400_000_u64)),
            (KEY_TZ, Value::from("Europe/Warsaw")),
        ]),
    )
}

#[test]
fn calendar_series_exception_is_claim_shaped() -> Result<()> {
    let value = canonical_series_exception();
    let body = body(PREDICATE_CALENDAR_SERIES_EXCEPTION, value.clone());
    assert_matches!(body.subject, ClaimSubject::Entity(id) if id == subject());
    through_chokepoint(&body)?;
    let decoded = decode_series_exception_value(&value)?;
    assert_eq!(
        decoded,
        CalendarSeriesExceptionValue {
            master_ref: entity(REF_SEED),
            uid: "uid-1@example.com".to_owned(),
            original_start_utc: 1_754_400_000,
        }
    );
    // Exception identity is self-contained: (uid, original_start_utc) is
    // carried by the claim value, so masking never needs a second read.
    assert_eq!(
        (decoded.uid.as_str(), decoded.original_start_utc),
        ("uid-1@example.com", 1_754_400_000)
    );
    Ok(())
}

#[test]
fn calendar_successor_is_claim_shaped() -> Result<()> {
    let value = canonical_successor();
    let body = body(PREDICATE_CALENDAR_SUCCESSOR, value.clone());
    assert_matches!(body.subject, ClaimSubject::Entity(id) if id == subject());
    through_chokepoint(&body)?;
    assert_eq!(
        decode_successor_value(&value)?,
        CalendarSuccessorValue {
            predecessor_ref: entity(REF_SEED),
        }
    );
    Ok(())
}

#[test]
fn calendar_descriptor_rows_cover_predicates_once() {
    let rows = claim_class_descriptors();
    let covered: BTreeSet<&str> = rows.iter().map(|row| row.predicate).collect();
    let predicates: BTreeSet<&str> = CALENDAR_CLAIM_PREDICATES.iter().copied().collect();
    // One-to-one: no predicate is missing and none is described twice.
    assert_eq!(covered, predicates);
    assert_eq!(rows.len(), covered.len());

    for row in &rows {
        assert!(
            !row.enforcement,
            "{} must not be enforcement-gated",
            row.predicate
        );
        assert!(
            !row.restrictive,
            "{} must not be restrictive",
            row.predicate
        );
        assert!(
            matches!(row.write_class, "recorded" | "human_ruled" | "ordinary"),
            "{} has write_class outside the allowed tokens",
            row.predicate
        );
        let expect_recorded = matches!(
            row.predicate,
            PREDICATE_CALENDAR_PASSPORT | PREDICATE_CALENDAR_ORIGIN
        );
        if expect_recorded {
            assert_eq!(row.write_class, "recorded", "{}", row.predicate);
            assert!(row.projector_only, "{}", row.predicate);
        } else {
            assert_eq!(row.write_class, "ordinary", "{}", row.predicate);
            assert!(!row.projector_only, "{}", row.predicate);
        }
    }
}
