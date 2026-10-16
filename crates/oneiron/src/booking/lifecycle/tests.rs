//! Crate-internal invariants.
//!
//! These assertions need to read `vault_meta` bytes, to call the family
//! validator directly, or to hold a fact for its owner's confirm, none of
//! which crosses the public API. Every
//! BEHAVIOURAL oracle lives in `tests/booking_lifecycle.rs`; only what a
//! black-box test structurally cannot see is asserted here.

use super::*;
use crate::test_util::entity as id;

const PAGE: u8 = 0x51;
const NOW: u64 = 1_772_409_600;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("open booking vault");
    (dir, vault)
}

fn hold_spec(session_key: SessionKey) -> HoldSpec {
    HoldSpec {
        page_ref: id(PAGE),
        event_type: EventTypeKey("intro-call".to_owned()),
        slot: TimeRange {
            start: NOW + 3_600,
            end: NOW + 5_400,
        },
        session_key,
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        lease: HoldLeaseSpec::Ordinary,
        idempotency_key: None,
    }
}

/// Every byte in `vault_meta`, so a search for a raw secret cannot miss a
/// row by looking under the wrong prefix.
fn all_meta_bytes(vault: &Vault) -> Vec<u8> {
    let rtxn = read_txn(vault).expect("read txn");
    let mut bytes = Vec::new();
    for entry in vault.store.vault_meta.iter(&rtxn).expect("meta scan") {
        let (key, value) = entry.expect("meta row");
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&value);
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|slice| slice == needle)
}

#[test]
fn raw_bearer_tokens_never_enter_vault_meta() {
    let (_dir, vault) = open_vault();
    let session = SessionKey::derive(b"session-one");
    let receipt = execute_hold(&vault, &hold_spec(session), NOW, None).expect("hold");
    let (lease, _) = issue_checkout_lease(&vault, &session, 600, NOW).expect("lease");

    let stored = all_meta_bytes(&vault);
    assert!(
        !contains(&stored, receipt.token.0.as_bytes()),
        "the raw hold token must never be at rest; only its digest is stored"
    );
    assert!(
        !contains(&stored, lease.0.as_bytes()),
        "the raw checkout lease must never be at rest; only its digest is stored"
    );
    // The digests, by contrast, ARE there — otherwise the assertions above
    // would pass on an empty store. The hold token's digest sits in the row
    // as hex; the lease's digest is also the row's key.
    assert!(contains(
        &stored,
        hex_lower(&token_digest(&receipt.token)).as_bytes()
    ));
    assert!(contains(&stored, &lease_digest(&lease)));
}

#[test]
fn hold_rows_key_on_the_session_and_never_on_the_token() {
    let (_dir, vault) = open_vault();
    let session = SessionKey::derive(b"session-one");
    let receipt = execute_hold(&vault, &hold_spec(session), NOW, None).expect("hold");

    let rtxn = read_txn(&vault).expect("read txn");
    let digest = super::token::hold_digest(&session);
    assert!(
        super::storage::HOLD
            .contains(&vault.store, &rtxn, &digest)
            .expect("hold row read"),
        "the row is reachable from the session alone"
    );
    let key = super::storage::HOLD.key_bytes(&digest);
    assert!(
        !contains(&key, &token_digest(&receipt.token)),
        "the hold key is derived from the session, not from the credential"
    );
    assert_eq!(
        key.len(),
        BOOKING_HOLD_META_PREFIX.len() + 32,
        "prefix + one 32-byte digest"
    );
    assert!(key.starts_with(BOOKING_HOLD_META_PREFIX));
}

#[test]
fn booking_lifecycle_validator_is_exact_at_the_family_door() {
    let subject = ClaimSubject::Entity(id(0x52));
    let body = |predicate: &str, value: rmpv::Value| {
        ClaimBody::new(
            predicate,
            subject,
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .unwrap()
    };
    let status = encode_claim_value(&BookingStatusValue {
        status: BookingStatus::Confirmed,
        recorded_at: NOW,
    })
    .expect("encode status");

    validate_lifecycle_claim(&body(BOOKING_STATUS_PREDICATE, status.clone()))
        .expect("a well-formed status value passes");
    // A value from a sibling predicate is refused: the validator routes on
    // the exact predicate and then checks THAT predicate's schema.
    assert!(
        validate_lifecycle_claim(&body(BOOKING_SOURCE_PAGE_PREDICATE, status)).is_err(),
        "one family member's value must not satisfy another's schema"
    );
    // An unknown `booking.*` predicate is never adopted by the family.
    assert!(
        validate_lifecycle_claim(&body(
            "booking.something_new",
            rmpv::Value::from("whatever")
        ))
        .is_err()
    );
    // An edge subject is refused before any value is decoded.
    let mut edge_subject = body(
        BOOKING_STATUS_PREDICATE,
        encode_claim_value(&BookingStatusValue {
            status: BookingStatus::Cancelled,
            recorded_at: NOW,
        })
        .expect("encode status"),
    );
    edge_subject.subject = ClaimSubject::Edge {
        source: id(0x52),
        kind: crate::edge::EdgeKind::ClaimOf,
        target: id(0x53),
    };
    assert!(validate_lifecycle_claim(&edge_subject).is_err());
}

/// One confirmed booking of `PAGE`, recorded as the confirm writer records it.
fn booked(vault: &Vault, event: u8, start: u64) -> EntityId {
    let hold = SoftHoldRow {
        page_ref: id(PAGE),
        event_type: EventTypeKey("intro-call".to_owned()),
        slot: TimeRange {
            start,
            end: start + 1_800,
        },
        session_key: SessionKey::derive(&[event]),
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        token_hash: [event; 32],
        expires_at: NOW + 600,
        checkout_lease_hash: None,
    };
    booking_writer(vault, |wtxn| {
        write_booking_event(vault, wtxn, &id(event), &hold, id(0x53), NOW)
    })
    .expect("record a confirmed booking");
    id(event)
}

/// A second live head beside the booking's own, as a competing writer leaves it.
fn add_head(vault: &Vault, event: EntityId, predicate: &str, value: rmpv::Value) -> EntityId {
    booking_writer(vault, |wtxn| {
        put_claim(vault, wtxn, &event, predicate, value, NOW)
    })
    .expect("competing head")
}

/// The booking's own live head for `predicate`.
fn head(vault: &Vault, event: EntityId, predicate: &str) -> EntityId {
    let rtxn = read_txn(vault).expect("read txn");
    claims_for_subject(vault, &rtxn, &event)
        .expect("booking claims")
        .into_iter()
        .find(|claim| {
            vault
                .get_claim_in_txn(&rtxn, claim)
                .expect("claim read")
                .is_some_and(|body| body.predicate == predicate)
        })
        .expect("the booking carries this head")
}

fn status_value(status: BookingStatus) -> rmpv::Value {
    encode_claim_value(&BookingStatusValue {
        status,
        recorded_at: NOW,
    })
    .expect("encode status")
}

#[test]
fn a_held_status_head_cancels_a_booking_but_never_confirms_one() {
    let (_dir, vault) = open_vault();
    let plain = booked(&vault, 0x61, NOW + 3_600);
    let contested = booked(&vault, 0x62, NOW + 7_200);
    let cancel = add_head(
        &vault,
        contested,
        BOOKING_STATUS_PREDICATE,
        status_value(BookingStatus::Cancelled),
    );
    crate::test_util::hold_claim_for_critical_confirm(&vault, cancel, 0x71);
    let unconfirmed = booked(&vault, 0x63, NOW + 10_800);
    let confirmed = head(&vault, unconfirmed, BOOKING_STATUS_PREDICATE);
    crate::test_util::hold_claim_for_critical_confirm(&vault, confirmed, 0x72);

    assert_eq!(
        confirmed_start_for_reminder(&vault, &plain).expect("plain reminder read"),
        Some(NOW + 3_600)
    );
    let rtxn = read_txn(&vault).expect("read txn");
    assert_eq!(
        read_booking_facts(&vault, &rtxn, &contested)
            .expect("contested booking")
            .status,
        BookingStatus::Cancelled,
        "a held cancellation beside a settled Confirmed head still cancels"
    );
    assert!(
        read_booking_facts(&vault, &rtxn, &unconfirmed).is_err(),
        "a held Confirmed head alone confirms nothing"
    );
    drop(rtxn);
    assert_eq!(
        confirmed_start_for_reminder(&vault, &contested).expect("contested reminder read"),
        None
    );
    assert!(confirmed_start_for_reminder(&vault, &unconfirmed).is_err());
}

#[test]
fn a_held_booking_head_charges_the_cap_but_never_discharges_it() {
    use crate::calendar::claims::{CalendarStatus, PREDICATE_CALENDAR_STATUS};
    let (_dir, vault) = open_vault();
    let starts = [NOW + 3_600, NOW + 7_200, NOW + 10_800, NOW + 14_400];
    // Held cancellations, the booking's and the calendar's, discharge nothing.
    let booking_cancel = booked(&vault, 0x61, starts[0]);
    let held = add_head(
        &vault,
        booking_cancel,
        BOOKING_STATUS_PREDICATE,
        status_value(BookingStatus::Cancelled),
    );
    crate::test_util::hold_claim_for_critical_confirm(&vault, held, 0x71);
    let calendar_cancel = booked(&vault, 0x62, starts[1]);
    let held = add_head(
        &vault,
        calendar_cancel,
        PREDICATE_CALENDAR_STATUS,
        calendar_status_value(CalendarStatus::Cancelled, NOW),
    );
    crate::test_util::hold_claim_for_critical_confirm(&vault, held, 0x72);
    // Held page, type and Confirmed heads still charge.
    let held_heads = booked(&vault, 0x63, starts[2]);
    for (predicate, seed) in [
        (BOOKING_SOURCE_PAGE_PREDICATE, 0x73),
        (BOOKING_EVENT_TYPE_REF_PREDICATE, 0x74),
        (BOOKING_STATUS_PREDICATE, 0x75),
    ] {
        let claim = head(&vault, held_heads, predicate);
        crate::test_util::hold_claim_for_critical_confirm(&vault, claim, seed);
    }
    // A settled cancellation discharges.
    let settled = booked(&vault, 0x64, starts[3]);
    add_head(
        &vault,
        settled,
        BOOKING_STATUS_PREDICATE,
        status_value(BookingStatus::Cancelled),
    );

    let mut charged = confirmed_booking_starts(
        &vault,
        id(PAGE),
        &EventTypeKey("intro-call".to_owned()),
        TimeRange {
            start: NOW,
            end: NOW + 86_400,
        },
        None,
    )
    .expect("cap tally");
    charged.sort_unstable();
    assert_eq!(charged, starts[..3].to_vec());
}
