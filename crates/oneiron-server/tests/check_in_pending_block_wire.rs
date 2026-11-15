//! P38 pending block on the wire (Engine ruling P38-PENDING-BLOCK-REACH =
//! A): a refused act that waits on a check-in answers `CHECK_IN_PENDING`
//! with its reason code and the same id as a typed `pending` block, through
//! the facade and through the MCP gateway.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test check_in_pending_block_wire`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_server::test_doors::refusal_wire::{facade_refusal, mcp_refusal};
use serde_json::json;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn waiting() -> oneiron::MemoryError {
    oneiron::MemoryError::from(oneiron::Error::CheckInPending(ID.to_owned()))
}

#[tokio::test]
async fn the_facade_answers_202_with_the_pending_block() {
    let (status, body) = facade_refusal(waiting()).await;
    assert_eq!(status, 202);
    let error = &body["error"];
    assert_eq!(
        error["pending"],
        json!({"kind": "check_in", "check_in": ID})
    );
    assert_eq!(error["reasonCodes"], json!([format!("check_in:{ID}")]));
}

#[tokio::test]
async fn the_mcp_error_data_carries_the_pending_block() {
    let value = mcp_refusal(waiting());
    assert_eq!(
        value["error"]["data"]["pending"],
        json!({"kind": "check_in", "check_in": ID})
    );
    assert_eq!(
        value["error"]["data"]["reason_codes"],
        json!([format!("check_in:{ID}")])
    );
}
