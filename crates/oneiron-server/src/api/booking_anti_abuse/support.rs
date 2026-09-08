//! Time, error, JSON, and logging helpers for booking anti-abuse guards.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::ApiError;

pub(super) fn now_secs() -> std::result::Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal_server_error("booking anti-abuse clock unavailable"))
}

pub(super) fn engine_error(error: oneiron::booking::BookingError) -> ApiError {
    tracing::error!(error = %error, "booking anti-abuse engine error");
    ApiError::internal_server_error("booking anti-abuse failure")
}

pub(super) fn correction_body(field: &'static str, message: &str) -> String {
    serde_json::json!({
        "ok": false,
        "action": "correct",
        "field": field,
        "message": message,
    })
    .to_string()
}

pub(super) fn hex_prefix(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(8);
    for byte in &bytes[..4] {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

pub(super) fn log_rate_block(endpoint: &'static str, ip_hash: &[u8; 32], retry_after_secs: u64) {
    tracing::info!(
        endpoint = endpoint,
        ip = hex_prefix(ip_hash),
        retry_after_secs = retry_after_secs,
        "booking anti-abuse rate block"
    );
}
