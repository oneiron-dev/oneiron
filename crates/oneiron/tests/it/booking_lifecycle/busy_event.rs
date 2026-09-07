//! Imported busy-event fixture and its source-permit binding oracle.

use super::{ACTOR_SEED, BOOKER_SEED, BUSY_SEED, Fixture, at, hour, test_id};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

/// Fixture claim ids are keyed `(0xB2, seed, index)` so none can alias a generic
/// `entity(seed)` id.
fn claim_id(seed: u8, index: u8) -> EntityId {
    let mut bytes = [0xB2_u8; 16];
    bytes[1] = seed;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

/// One busy calendar EVENT over `occupied`, written through the ordinary
/// claim-candidate door under an explicit Imported auto permit.
pub(super) fn store_busy_event(
    fixture: &Fixture,
    seed: u8,
    occupied: TimeRange,
) -> Result<(), oneiron::Error> {
    let id = test_id(seed);
    fixture
        .vault
        .put_entity(&id, ENTITY_TYPE_EVENT, occupied, 1, b"busy elsewhere")
        .expect("put busy event");
    // This fixture has an explicit auto permit, not a human review receipt.
    // Batch preflight omits source/sensitivity for Approved claims, while
    // Imported lineage still requires a permit. Auto keeps those axes visible
    // so the gate can match this actor's row; it does not relabel the source.
    let envelope = WriteEnvelope::new(
        WriteActor::new(fixture.actor, EdgeActorClass::Human),
        ClaimSource::Imported,
        WriteProvenance::new(Value::from("one-1813-oracle")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    fixture
        .vault
        .batch()
        .claim_candidate(
            &claim_id(seed, 0),
            ClaimCandidate::new(
                "calendar.time_kind",
                ClaimSubject::Entity(id),
                Value::Map(vec![
                    (Value::from("kind"), Value::from("absolute")),
                    (Value::from("busy_transparency"), Value::from("busy")),
                ]),
                1.0,
            ),
            &envelope,
            at(1),
            1,
        )
        .commit()
}

#[test]
fn busy_event_requires_matching_imported_source_permit() {
    for (label, permit_seed) in [
        ("missing permit", None),
        ("wrong actor permit", Some(BOOKER_SEED)),
        ("matching actor permit", Some(ACTOR_SEED)),
    ] {
        let fixture = Fixture::open();
        if let Some(seed) = permit_seed {
            fixture
                .vault
                .install_imported_source_permit_for_test(test_id(seed))
                .expect("install actor-bound Imported permit");
        }
        let result = store_busy_event(
            &fixture,
            BUSY_SEED,
            TimeRange {
                start: hour(9),
                end: hour(10) - 1,
            },
        );
        let allowed = permit_seed == Some(ACTOR_SEED);
        if allowed {
            result.expect("the matching permit admits the busy-event fixture");
        } else {
            match result.expect_err(label) {
                oneiron::Error::GateWriteRejected {
                    outcome,
                    reason_codes,
                } => {
                    assert_eq!(outcome, "pending", "{label}");
                    assert_eq!(
                        reason_codes.as_slice(),
                        ["gate.pending.source_trust"],
                        "{label}"
                    );
                }
                other => panic!("expected source-trust pending for {label}, got {other:?}"),
            }
        }
        let body = fixture
            .vault
            .get_claim(&claim_id(BUSY_SEED, 0))
            .expect("read busy claim");
        assert_eq!(body.is_some(), allowed, "{label}");
        if let Some(body) = body {
            assert_eq!(body.predicate, "calendar.time_kind");
            assert_eq!(body.source, Some(ClaimSource::Imported));
            assert_eq!(body.approval, ClaimApprovalStatus::Auto);
        }
        assert_eq!(
            fixture
                .vault
                .claims_for_subject(&test_id(BUSY_SEED))
                .expect("busy claim index")
                .len(),
            usize::from(allowed),
            "{label}"
        );
    }
}
