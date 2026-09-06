//! The boundary cap contract (ONE-1441 §Binding cap contract, I11).
//!
//! These values are INHERITED from the N-API boundary, not re-derived here:
//! `oneiron-napi` has enforced them since ONE-479's precursor work, and this
//! crate becomes the one place they are spelled so both bindings and both
//! transports read the same numbers. `oneiron-napi` keeps its `MAX_NAPI_*`
//! names as aliases of these constants so ONE-479 still finds the established
//! seam.
//!
//! Every validator here runs BEFORE the value reaches either the embedded core
//! dispatch or the remote request serializer, so an over-cap input costs one
//! comparison rather than an allocation the caller chose for us.

use oneiron::memory::MemoryError;

use crate::error::bad_request;

/// Maximum query string, in bytes: 8 KiB.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;

/// Maximum rows any list/search verb may be asked for: 1,000.
pub const MAX_SEARCH_LIMIT: usize = 1_000;

/// Maximum serialized body of one entity, claim, or message: 64 KiB.
pub const MAX_ENTITY_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum entities or claims in one batched call: 10,000.
pub const MAX_BATCH_ENTITIES: usize = 10_000;

/// Maximum files in one legacy codebase-snapshot call: 100,000.
pub const MAX_CODEBASE_FILES: usize = 100_000;

/// Maximum embedding vector dimensions: 16,384.
pub const MAX_DIMENSIONS: usize = 16_384;

/// Maximum RAW blob content, in bytes: 32 MiB.
///
/// The base64 length of an encoded blob is bounded against
/// [`MAX_BLOB_BASE64_LEN`] before any decode allocation runs, so an oversized
/// input is refused by measuring the string rather than by exhausting memory
/// decoding it.
pub const MAX_BLOB_CONTENT_BYTES: usize = 32 * 1024 * 1024;

/// Maximum base64 length admitted before a blob decode is attempted.
pub const MAX_BLOB_BASE64_LEN: usize = MAX_BLOB_CONTENT_BYTES / 3 * 4 + 4;

/// Maximum remote REQUEST body, in bytes: 64 MiB.
///
/// Matches the `DefaultBodyLimit` the server's facade nest applies, so a body
/// this client agrees to send is a body that router agrees to read. Sized for
/// the largest legal blob (32 MiB) once base64 and JSON framing are paid for.
pub const MAX_REMOTE_REQUEST_BYTES: usize = 64 * 1024 * 1024;

/// Maximum remote SUCCESS body read, in bytes: 64 MiB.
pub const MAX_REMOTE_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Rejects an over-long query before it reaches retrieval.
pub fn check_query(query: &str) -> Result<(), MemoryError> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(bad_request(
            format!("query exceeds the {MAX_QUERY_BYTES}-byte ceiling"),
            &["Shorten the query; retrieval scores intent, not transcript length."],
        ));
    }
    Ok(())
}

/// Rejects a non-positive or over-large row count.
///
/// Zero is refused rather than silently defaulted: a caller who asks for no
/// rows has a bug the SDK must not paper over by inventing a page size.
pub fn check_limit(limit: usize) -> Result<(), MemoryError> {
    if limit == 0 || limit > MAX_SEARCH_LIMIT {
        return Err(bad_request(
            format!("limit must be between 1 and {MAX_SEARCH_LIMIT}"),
            &["Request a smaller page and paginate."],
        ));
    }
    Ok(())
}

/// Rejects an over-large entity/claim/message body.
///
/// `label` names the field in the caller's own vocabulary so the message is
/// actionable without the caller reading this source.
pub fn check_payload_bytes(label: &str, len: usize) -> Result<(), MemoryError> {
    if len > MAX_ENTITY_PAYLOAD_BYTES {
        return Err(bad_request(
            format!("{label} exceeds the {MAX_ENTITY_PAYLOAD_BYTES}-byte payload ceiling"),
            &["Split the payload, or store the bulk as a blob artifact and claim its ref."],
        ));
    }
    Ok(())
}

/// Rejects an over-large batch.
pub fn check_batch_len(label: &str, len: usize) -> Result<(), MemoryError> {
    if len > MAX_BATCH_ENTITIES {
        return Err(bad_request(
            format!("{label} exceeds the {MAX_BATCH_ENTITIES}-element batch ceiling"),
            &["Send the work in smaller batches."],
        ));
    }
    Ok(())
}

/// Rejects an unusable embedding dimension count.
pub fn check_dimensions(dimensions: usize) -> Result<(), MemoryError> {
    if dimensions == 0 || dimensions > MAX_DIMENSIONS {
        return Err(bad_request(
            format!("dimensions must be between 1 and {MAX_DIMENSIONS}"),
            &["Open the vault with the dimension count its embedding model produces."],
        ));
    }
    Ok(())
}

/// Rejects raw blob content over the 32 MiB ceiling.
///
/// Crate-internal, not exported: no shipped verb carries a blob yet, so a
/// public name here would be a promise with no caller behind it. The ceiling
/// itself ([`MAX_BLOB_CONTENT_BYTES`]) stays public because it is the number
/// both bindings document.
#[allow(dead_code)]
pub(crate) fn check_blob_bytes(len: usize) -> Result<(), MemoryError> {
    if len > MAX_BLOB_CONTENT_BYTES {
        return Err(bad_request(
            format!("blob content exceeds the {MAX_BLOB_CONTENT_BYTES}-byte ceiling"),
            &["Chunk the artifact into versions under 32 MiB each."],
        ));
    }
    Ok(())
}

/// Rejects a timestamp that is not a usable Unix-seconds value (I14).
///
/// The public bindings take timestamps as the host language's number type —
/// JavaScript has no integer type at all — so "non-negative" and "safe
/// integer" are properties this boundary must PROVE rather than assume. A
/// negative or fractional value fails here, before any `f64`-to-integer
/// narrowing could silently truncate it into a plausible-looking date.
pub fn check_unix_seconds(label: &str, value: f64) -> Result<u64, MemoryError> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
        return Err(bad_request(
            format!("{label} must be a non-negative whole number of Unix seconds"),
            &[
                "Pass a whole number of Unix seconds (not milliseconds, not a fraction); the SDK performs no unit conversion.",
            ],
        ));
    }
    // 2^53: the largest integer a host `f64` represents exactly. Beyond it the
    // value the caller wrote and the value we received have already diverged.
    if value > 9_007_199_254_740_992.0 {
        return Err(bad_request(
            format!("{label} is not a safe integer"),
            &["Unix seconds fit comfortably in a safe integer; check for a milliseconds value."],
        ));
    }
    // Proven finite, non-negative, whole and under 2^53 above.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
}

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
pub(crate) fn check_unit_interval(label: &str, value: f64) -> Result<f32, MemoryError> {
    if !value.is_finite() {
        return Err(bad_request(
            format!("{label} must be a finite number"),
            &["NaN and infinity are not confidences; send a value in [0, 1]."],
        ));
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(bad_request(
            format!("{label} must be within [0, 1]"),
            &["Confidence and salience are calibrated-absolute values in [0, 1]."],
        ));
    }
    // Proven finite and within [0, 1] above; narrowing loses precision, never
    // magnitude.
    #[allow(clippy::cast_possible_truncation)]
    Ok(value as f32)
}
