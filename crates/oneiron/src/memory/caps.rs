//! The boundary cap contract (ONE-1441 §Binding cap contract, I11).
//!
//! These values are INHERITED from the N-API boundary, not re-derived here:
//! `oneiron-napi` has enforced them since ONE-479's precursor work, and this
//! module is the one place they are spelled so bindings and HTTP ingress
//! transports read the same numbers. `oneiron-napi` keeps its `MAX_NAPI_*`
//! names as aliases of these constants so ONE-479 still finds the established
//! seam.
//!
//! Every validator here runs BEFORE the value reaches either the embedded core
//! dispatch or the remote request serializer, so an over-cap input costs one
//! comparison rather than an allocation the caller chose for us.

use super::{ClaimInput, MEMORY_CODE_INTERNAL, MemoryError, WitnessTurn};

#[cfg(test)]
mod tests;

pub(crate) use crate::request_limits::narrowed_candidate_window;
pub use crate::request_limits::{
    MAX_AS_OF_SECONDS, MAX_BATCH_ENTITIES, MAX_CODEBASE_FILES, MAX_ENTITY_PAYLOAD_BYTES,
    MAX_RECALL_DEADLINE_MS, MAX_REMOTE_REQUEST_BYTES, MAX_REMOTE_RESPONSE_BYTES, MAX_SEARCH_LIMIT,
    check_as_of, check_batch_len, check_deadline_ms, check_deadline_ms_number, check_dimensions,
    check_limit_nonzero, check_payload_bytes, check_token_budget_number, check_unix_seconds,
};

/// Rejects a NaN or infinite score before it narrows from `f64` to `f32`.
///
/// Narrowing happens on the way into the engine's `f32` confidence and
/// salience fields. `f64::NAN as f32` is a quiet `NAN`, and an infinity
/// narrows to an infinity: both would reach a comparison that answers `false`
/// to every branch, so they are refused where the caller can still be told.
///
/// Crate-internal, not exported: both bindings narrow their own host `f64` at
/// their own boundary today, so nothing outside this crate calls it and an
/// exported name would claim otherwise. Wiring the bindings through this one
/// validator — which would also put `[0, 1]` behind the SDK rather than behind
/// each binding — is a deliberate follow-on, not a silent change here.
#[allow(dead_code)]
fn check_unit_interval(label: &str, value: f64) -> Result<f32, MemoryError> {
    if !value.is_finite() {
        return Err(MemoryError::bad_request_with(
            format!("{label} must be a finite number"),
            &["NaN and infinity are not confidences; send a value in [0, 1]."],
        ));
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(MemoryError::bad_request_with(
            format!("{label} must be within [0, 1]"),
            &["Confidence and salience are calibrated-absolute values in [0, 1]."],
        ));
    }
    // Proven finite and within [0, 1] above; narrowing loses precision, never
    // magnitude.
    #[allow(clippy::cast_possible_truncation)]
    Ok(value as f32)
}

/// Checks each message of the witness batch before either transport
/// dispatches; the batch takes every message it names.
pub fn check_witness_turn(turn: &WitnessTurn) -> Result<(), MemoryError> {
    for message in &turn.messages {
        check_payload_bytes("message content", message.content.len())?;
    }
    Ok(())
}

/// Validates a claim's boundary-checkable fields before dispatch: finite
/// numbers, and a value that serializes. Its size is never refused here
/// (ABC row 22): the vault's claim door measures it
/// ([`claim_input_json_bytes`]).
pub fn check_claim_input(claim: &ClaimInput) -> Result<(), MemoryError> {
    claim_input_json_bytes(claim).map(|_| ())
}

/// The complete serialized JSON bytes of `claim`, scope and refs included,
/// counted with a fixed memory footprint and never cut short: what the
/// vault's claim door measures against `claim_input_json_bytes` (ABC row
/// 22). `confidence` and `salience` are already `f32` on the engine DTO, so
/// the non-finite refusal for them also happens in the binding layers where
/// the host's `f64` narrows.
///
/// # Errors
///
/// A non-finite confidence or salience, or a value that does not serialize.
pub fn claim_input_json_bytes(claim: &ClaimInput) -> Result<u64, MemoryError> {
    if !claim.confidence.is_finite() {
        return Err(MemoryError::bad_request_with(
            "confidence must be a finite number",
            &["NaN and infinity are not confidences; send a value in [0, 1]."],
        ));
    }
    if claim.salience.is_some_and(|value| !value.is_finite()) {
        return Err(MemoryError::bad_request_with(
            "salience must be a finite number",
            &["NaN and infinity are not salience values; send a value in [0, 1]."],
        ));
    }
    let mut counter = PayloadCounter { len: 0 };
    if let Err(error) = serde_json::to_writer(&mut counter, claim) {
        return Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("claim payload could not be serialized: {error}"),
            &["Send a JSON-representable claim value."],
        ));
    }
    Ok(counter.len)
}

/// Counts serialized bytes with a fixed memory footprint, every byte.
struct PayloadCounter {
    len: u64,
}

impl std::io::Write for PayloadCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.len = self.len.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
