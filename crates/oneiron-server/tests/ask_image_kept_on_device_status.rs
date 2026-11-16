#![cfg(oneiron_test_support)]
//! A model call kept on its device (`kept_on_device`) or refused by its
//! world's route order (`world_route_not_admitted`) answers 503 on every door
//! (UC-11, ruling UC11-KEPT-ON-DEVICE-STATUS = C): the raw `/v1/ai/*` media
//! routes, `POST /v1/ai/ask_image` among them, as `/v1/llm` and the OpenAI
//! wire already do; `ai.ask_image`'s table, so the facade door keeps the
//! code; and the facade. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test ask_image_kept_on_device_status`.

use oneiron::{LlmError, RetryableLlmError};
use oneiron_server::test_doors::memory_code_status::{
    ask_image_table_status, facade_status, raw_media_status,
};

#[test]
fn kept_on_device_answers_503_on_every_door() {
    let refusals = [
        (
            "kept_on_device",
            LlmError::Retryable(RetryableLlmError::KeptOnDevice {
                retry_after: None,
                resets_at: Vec::new(),
                reason: None,
            }),
        ),
        (
            "world_route_not_admitted",
            LlmError::Retryable(RetryableLlmError::WorldRouteNotAdmitted),
        ),
    ];
    let mut moved = Vec::new();
    for (code, error) in &refusals {
        let raw = raw_media_status(error);
        let table = ask_image_table_status(code);
        let facade = facade_status(code);
        if (raw, table, facade) != (503, Some(503), 503) {
            moved.push(format!(
                "{code}: raw media route {raw}, ask_image table {table:?}, facade {facade}"
            ));
        }
    }
    assert!(moved.is_empty(), "doors answering off 503: {moved:#?}");
}
