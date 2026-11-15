//! BK-DEPOSITS PR 1: an event type's deposit terms are the owner's setting,
//! carried by its configuration and by its public card (Engine ruling, Sun
//! 15 Nov 01:10: the owner sets the amount and the refund rule per event
//! type, with stated defaults).
//!
//! Every value here is built from JSON, so main plus this file builds: main's
//! `deny_unknown_fields` refuses the `deposit` key, and each test's first
//! parse of a value that carries one fails there by its `expect`.

use oneiron::EntityId;
use oneiron::booking::{
    BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue, EventTypeCard, EventTypeConfig,
    booking_config_hash, decode_event_type_claim_value, encode_event_type_claim_value,
};
use serde_json::{Value, json};

const DAY_SECS: u64 = 24 * 3_600;

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

/// An ordinary intro configuration with no deposit, as JSON.
fn base_config_json() -> Value {
    json!({
        "key": "consult",
        "duration_min": 60,
        "slot_step_min": 30,
        "pre_buffer_min": 0,
        "post_buffer_min": 0,
        "min_notice_secs": DAY_SECS,
        "booking_window_secs": 14 * DAY_SECS,
        "daily_cap": null,
        "weekly_cap": null,
        "routing": "either",
        "hosts": [{
            "host_ref": id(0x21).to_hex(),
            "calendar_refs": [id(0x22).to_hex()],
            "host_tz": "Asia/Tokyo",
            "working_hours": [{ "weekday": 0, "start_minute": 540, "end_minute": 1020 }],
            "preferred_hours": []
        }],
        "flex_windows": []
    })
}

fn config_with_deposit(deposit: Value) -> Value {
    let mut config = base_config_json();
    config["deposit"] = deposit;
    config
}

fn parse_config(value: Value) -> EventTypeConfig {
    serde_json::from_value(value).expect("an event type configuration with deposit terms parses")
}

#[test]
fn deposit_terms_ride_the_event_type_config_with_stated_defaults() {
    let base: EventTypeConfig =
        serde_json::from_value(base_config_json()).expect("the base configuration parses");
    let with_deposit = parse_config(config_with_deposit(json!({
        "amount_minor": 5_000,
        "currency": "jpy"
    })));
    with_deposit
        .validate()
        .expect("a 5000 jpy deposit is a usable configuration");

    // The owner named only the amount and the currency: the refund rule
    // takes its stated defaults, a full refund a day ahead and none later.
    let encoded = serde_json::to_value(&with_deposit).expect("encode");
    assert_eq!(
        encoded["deposit"],
        json!({
            "amount_minor": 5_000,
            "currency": "jpy",
            "refund": { "full_refund_notice_secs": DAY_SECS, "late_cancel_refund_percent": 0 }
        }),
        "the stored terms spell out the stated refund defaults"
    );

    // No deposit encodes exactly as before, so every existing configuration
    // keeps its hash; terms change the hash a publication pins.
    let base_encoded = serde_json::to_value(&base).expect("encode");
    assert!(
        base_encoded.get("deposit").is_none(),
        "a configuration without a deposit carries no deposit key"
    );
    assert_ne!(
        booking_config_hash(&with_deposit).expect("hash"),
        booking_config_hash(&base).expect("hash"),
        "the publication's configuration hash covers the deposit terms"
    );

    // The claim codec keeps the terms, and its decode door validates them.
    let page = id(0x11);
    let value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config: with_deposit.clone(),
    })
    .expect("encode the claim value");
    let decoded = decode_event_type_claim_value(&value).expect("decode the claim value");
    assert_eq!(decoded.config, with_deposit);
}

#[test]
fn deposit_terms_defects_are_refused() {
    let page = id(0x11);
    let cases = [
        (
            json!({ "amount_minor": 0, "currency": "usd" }),
            "amount_minor",
        ),
        (
            json!({ "amount_minor": 100_000_000_u64, "currency": "usd" }),
            "amount_minor",
        ),
        (
            json!({ "amount_minor": 2_500, "currency": "USD" }),
            "currency",
        ),
        (
            json!({ "amount_minor": 2_500, "currency": "us" }),
            "currency",
        ),
        (
            json!({
                "amount_minor": 2_500,
                "currency": "usd",
                "refund": { "late_cancel_refund_percent": 101 }
            }),
            "late_cancel_refund_percent",
        ),
        (
            json!({
                "amount_minor": 2_500,
                "currency": "usd",
                "refund": { "full_refund_notice_secs": 367 * DAY_SECS }
            }),
            "full_refund_notice_secs",
        ),
    ];
    for (deposit, field) in cases {
        let config = parse_config(config_with_deposit(deposit.clone()));
        let refusal = config
            .validate()
            .expect_err("bad deposit terms are not a usable configuration");
        assert!(
            refusal.to_string().contains(field),
            "the refusal of {deposit} names {field}: {refusal}"
        );
        // The claim decode door refuses the same value.
        let value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: page,
            config,
        })
        .expect("the codec itself encodes any shape");
        assert!(
            decode_event_type_claim_value(&value).is_err(),
            "the stored claim with {deposit} does not decode as a live configuration"
        );
    }
}

#[test]
fn public_card_carries_deposit_terms() {
    let card: EventTypeCard = serde_json::from_value(json!({
        "key": "consult",
        "title": "Consultation",
        "deposit": {
            "amount_minor": 3_000,
            "currency": "usd",
            "refund": { "full_refund_notice_secs": 2 * DAY_SECS, "late_cancel_refund_percent": 50 }
        },
        "duration_min": 60,
        "description": "One hour"
    }))
    .expect("a public card with deposit terms parses");
    let encoded = serde_json::to_value(&card).expect("encode");
    assert_eq!(encoded["deposit"]["amount_minor"], json!(3_000));
    assert_eq!(encoded["deposit"]["currency"], json!("usd"));
    assert_eq!(
        encoded["deposit"]["refund"]["late_cancel_refund_percent"],
        json!(50)
    );

    let plain: EventTypeCard = serde_json::from_value(json!({
        "key": "intro",
        "title": "Introduction",
        "duration_min": 30,
        "description": "Half an hour"
    }))
    .expect("a card without a deposit parses");
    assert!(
        serde_json::to_value(&plain)
            .expect("encode")
            .get("deposit")
            .is_none(),
        "a card without a deposit carries no deposit key"
    );
}
