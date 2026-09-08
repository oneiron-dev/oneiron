//! Crate-internal invariants.
//!
//! These three assertions need to read `vault_meta` bytes and to call the
//! family validator directly, neither of which crosses the public API. Every
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
    let key = hold_key(&session);
    assert!(
        read_meta_bytes(&vault, &rtxn, &key)
            .expect("hold row read")
            .is_some(),
        "the row is reachable from the session alone"
    );
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
