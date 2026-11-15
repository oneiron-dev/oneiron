//! The per-session active hold cap of the `HoldRate` rule row is one (Engine
//! RULING PACK-KEYS-HOLDS-PER-SESSION = A, 15 Nov 23:20; census entry B03).
//!
//! Storage keys a hold by the session digest, so a session holds at most one
//! row, and a new hold for the session replaces the prior one (canon
//! ARCH-0062: "1 active hold/session"). Main's validator refuses only a cap of
//! zero, so a seed row or an amendment could set a cap of 2-255. The rule
//! doors now refuse every cap other than one: the validator, the seed rows
//! built from the owner's config, and the amendment comparator, which
//! validates the proposal first.
//!
//! A vault may already hold a hold row with a cap of 2-255 in a policy
//! manifest. That row keeps the range it was written under, so the manifest
//! still decodes and acts as before (stored change: keep; Engine RULING
//! HOLD-CAP-STORED-MANIFEST = A, 16 Nov 00:48). The write doors are pure, so
//! their tests build rule rows on public paths and need no vault; the stored
//! decode runs through the `oneiron_test_support` door
//! `test_doors::booking_anti_abuse_manifest`. Run with
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_hold_rate_session_cap`.

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use oneiron::EntityId;
use oneiron::booking::BookingError;
use oneiron::booking::anti_abuse::{
    AmendmentDirection, BookingAntiAbuseOwnerConfig, BookingAntiAbuseRule, BookingAntiAbuseRuleRow,
    BookingRuleScope, amendment_direction, booking_rule_row_id, default_booking_anti_abuse_rows,
    validate_rule_row,
};

const PAGE: u8 = 0x61;
const OWNER: u8 = 0x62;

fn page() -> EntityId {
    EntityId::from_bytes([PAGE; 16]).expect("page id")
}

fn hold_rule(max_active_per_session: u8) -> BookingAntiAbuseRule {
    BookingAntiAbuseRule::HoldRate {
        max_active_per_session,
        per_minute_per_ip: NonZeroU32::new(10).expect("non-zero rate"),
    }
}

fn hold_row(max_active_per_session: u8, version: u64) -> BookingAntiAbuseRuleRow {
    let scope = BookingRuleScope {
        page_ref: page(),
        event_type: None,
    };
    let rule = hold_rule(max_active_per_session);
    BookingAntiAbuseRuleRow {
        row_id: booking_rule_row_id(&scope, &rule),
        scope,
        rule,
        version,
        amended_at: 1_777_777_777,
        amended_by: EntityId::from_bytes([OWNER; 16]).expect("owner id"),
        owner_stamp_ref: None,
    }
}

fn owner_config(max_active_holds_per_session: u8) -> BookingAntiAbuseOwnerConfig {
    BookingAntiAbuseOwnerConfig {
        min_intake_chars: NonZeroU16::new(20).expect("non-zero"),
        normal_notice_secs: NonZeroU64::new(3_600).expect("non-zero"),
        high_value_notice_secs: NonZeroU64::new(172_800).expect("non-zero"),
        min_submit_millis: NonZeroU64::new(1_500).expect("non-zero"),
        slot_list_per_minute_per_ip: NonZeroU32::new(30).expect("non-zero"),
        slot_list_cache_ttl_secs: NonZeroU64::new(60).expect("non-zero"),
        book_per_minute_per_ip: NonZeroU32::new(5).expect("non-zero"),
        max_active_future_per_email: 3,
        max_active_holds_per_session,
        hold_per_minute_per_ip: NonZeroU32::new(10).expect("non-zero"),
        tentative_confirm_ttl_secs: NonZeroU64::new(86_400).expect("non-zero"),
    }
}

fn is_refusal<T>(result: &Result<T, BookingError>) -> bool {
    matches!(result, Err(BookingError::InvalidConstraint(_)))
}

#[test]
fn a_hold_row_with_a_per_session_cap_of_two_is_refused() {
    let result = validate_rule_row(&hold_row(2, 1));
    assert!(
        is_refusal(&result),
        "a per-session hold cap of 2 is refused, got {result:?}"
    );
    let result = validate_rule_row(&hold_row(u8::MAX, 1));
    assert!(
        is_refusal(&result),
        "a per-session hold cap of 255 is refused, got {result:?}"
    );
}

#[test]
fn a_hold_row_with_a_per_session_cap_of_one_is_admitted() {
    validate_rule_row(&hold_row(1, 1)).expect("a per-session hold cap of 1 is valid");
}

#[test]
fn a_hold_row_with_a_per_session_cap_of_zero_stays_refused() {
    let result = validate_rule_row(&hold_row(0, 1));
    assert!(
        is_refusal(&result),
        "a per-session hold cap of 0 is refused, got {result:?}"
    );
}

#[test]
fn seed_rows_from_an_owner_config_with_a_hold_cap_of_two_are_refused() {
    let result = default_booking_anti_abuse_rows(page(), None, &owner_config(2));
    assert!(
        is_refusal(&result),
        "seed rows with a per-session hold cap of 2 are refused, got {result:?}"
    );
}

#[test]
fn seed_rows_from_an_owner_config_with_a_hold_cap_of_one_are_admitted() {
    let rows = default_booking_anti_abuse_rows(page(), None, &owner_config(1))
        .expect("seed rows with a per-session hold cap of 1 are valid");
    let caps: Vec<u8> = rows
        .iter()
        .filter_map(|row| match row.rule {
            BookingAntiAbuseRule::HoldRate {
                max_active_per_session,
                ..
            } => Some(max_active_per_session),
            _ => None,
        })
        .collect();
    assert_eq!(caps, vec![1], "one hold row, with the cap of 1");
}

#[test]
fn an_amendment_raising_the_per_session_hold_cap_to_two_is_refused() {
    let result = amendment_direction(&hold_row(1, 1), &hold_row(2, 2));
    assert!(
        is_refusal(&result),
        "an amendment to a per-session hold cap of 2 is refused, got {result:?}"
    );
}

#[test]
fn an_amendment_that_keeps_the_per_session_hold_cap_of_one_is_equivalent() {
    let direction = amendment_direction(&hold_row(1, 1), &hold_row(1, 2))
        .expect("re-asserting a per-session hold cap of 1 is valid");
    assert_eq!(direction, AmendmentDirection::Equivalent);
}

/// The rule field's value as a policy manifest stores it.
#[cfg(oneiron_test_support)]
fn stored_rule_field(rows: &[BookingAntiAbuseRuleRow]) -> rmpv::Value {
    let bytes = rmp_serde::to_vec_named(rows).expect("encode the rule rows");
    rmpv::decode::read_value(&mut bytes.as_slice()).expect("the rule rows as a value")
}

#[cfg(oneiron_test_support)]
#[test]
fn a_stored_manifest_hold_row_with_a_per_session_cap_of_two_still_decodes() {
    use oneiron::test_doors::booking_anti_abuse_manifest::decode_stored_rule_field;
    let rows = vec![hold_row(2, 1)];
    let decoded = decode_stored_rule_field(stored_rule_field(&rows))
        .expect("a stored hold row with a cap of 2 still decodes");
    assert_eq!(decoded, rows, "the stored row reads as it was written");
}

#[cfg(oneiron_test_support)]
#[test]
fn a_stored_manifest_hold_row_with_a_per_session_cap_of_zero_does_not_decode() {
    use oneiron::test_doors::booking_anti_abuse_manifest::decode_stored_rule_field;
    assert_eq!(
        decode_stored_rule_field(stored_rule_field(&[hold_row(0, 1)])),
        None,
        "a stored hold row with a cap of 0 stays malformed"
    );
}
