//! Accept/reject fixtures and per-type contract tests for the calendar claim family.

use super::*;
use core::assert_matches;

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
    .unwrap()
}

/// Round-trips through the same codec storage uses, then through the
/// write-only validator chokepoint.
fn through_chokepoint(body: &ClaimBody) -> Result<()> {
    validate_claim_body_bytes(&encode_claim_body(body)?, false)
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

fn canonical_status() -> Value {
    map(&[
        (KEY_STATUS, Value::from(CalendarStatus::Confirmed.as_str())),
        (KEY_BASIS, Value::from(CalendarStatusBasis::Owner.as_str())),
        (KEY_RECORDED_AT, Value::from(1_754_400_000_u64)),
    ])
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
    )?;
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
