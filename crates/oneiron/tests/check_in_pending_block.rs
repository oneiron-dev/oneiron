//! P38 pending block (Engine ruling P38-PENDING-BLOCK-REACH = A): a refused
//! act that waits on a check-in carries the wait as a typed block beside its
//! reason code, so no client parses the code.
//!
//! - `Error::CheckInPending` maps to `CHECK_IN_PENDING` with the one reason
//!   code `check_in:<32 hex>` it always carried, and now also with
//!   `pending` naming that same check-in as a typed block.
//! - On the wire `pending` is `{kind: "check_in", check_in: "<32 hex>"}`,
//!   and it round-trips through the error's own serde.
//! - No other refusal carries a `pending` block.
//!
//! On main this file does not build: `MemoryError` has no `pending` field
//! and there is no `MemoryPending`.
//!
//! `cargo test --locked -p oneiron --all-features --test check_in_pending_block`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{
    CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_CHECK_IN_PENDING,
    MemoryError, MemoryPending,
};

const ID: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn a_check_in_wait_carries_the_typed_pending_block() {
    let error = oneiron::memory::MemoryError::from(oneiron::Error::CheckInPending(ID.to_owned()));
    assert_eq!(error.code, MEMORY_CODE_CHECK_IN_PENDING);
    assert_eq!(
        error.reason_codes,
        vec![format!("{CHECK_IN_PENDING_REASON_PREFIX}{ID}")]
    );
    assert_eq!(
        error.pending,
        Some(Box::new(MemoryPending::CheckIn {
            check_in: ID.to_owned(),
        }))
    );
}

#[test]
fn the_pending_block_is_kind_and_check_in_on_the_wire() {
    let error = oneiron::memory::MemoryError::from(oneiron::Error::CheckInPending(ID.to_owned()));
    let value = serde_json::to_value(&error).expect("a MemoryError serializes");
    assert_eq!(
        value["pending"],
        serde_json::json!({"kind": "check_in", "check_in": ID})
    );
    assert_eq!(
        serde_json::from_value::<MemoryError>(value).expect("a MemoryError round-trips"),
        error
    );
}

#[test]
fn no_other_refusal_carries_a_pending_block() {
    let error = MemoryError::new(MEMORY_CODE_BAD_REQUEST, "x", &[]);
    assert_eq!(error.pending, None);
    let value = serde_json::to_value(&error).expect("a MemoryError serializes");
    assert!(
        value.get("pending").is_none(),
        "no pending block off the wait path: {value}"
    );
}
