//! JS-boundary guards: error constructors, timestamp/number narrowing, blob ceiling.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use oneiron::MemoryError;

use super::dtos::NapiOutboundDraftInput;

pub(crate) type BoundaryResult<T> = std::result::Result<T, String>;

pub(crate) fn facade_error(err: MemoryError) -> napi::Error {
    napi::Error::from_reason(serde_json::to_string(&err).unwrap_or_else(|_| err.to_string()))
}

pub(crate) fn boundary_error(reason: String) -> napi::Error {
    napi::Error::from_reason(reason)
}

pub(crate) fn ts_to_engine(value: i64, field: &str) -> BoundaryResult<u64> {
    u64::try_from(value).map_err(|_| format!("{field} must be a non-negative Unix timestamp"))
}

pub(super) fn ts_opt_to_engine(value: Option<i64>, field: &str) -> BoundaryResult<Option<u64>> {
    value.map(|v| ts_to_engine(v, field)).transpose()
}

pub(super) fn ts_from_engine(value: u64, field: &str) -> BoundaryResult<i64> {
    i64::try_from(value).map_err(|_| format!("{field} does not fit a signed 64-bit integer"))
}

/// Converts the host's optional clock-authority fields into the engine's
/// schedule context. Fail-closed by construction: every rejection happens here,
/// before the draft reaches the facade, so no invalid offset, label, or level
/// can produce a TASK or attempt write.
///
/// JS has no integer type, so the offset arrives as `f64` and must be proven
/// finite, whole, and inside the current civil range `-840..=840` before it is
/// narrowed to `i16`.
pub(super) fn outbound_schedule_context_to_engine(
    draft: &NapiOutboundDraftInput,
) -> BoundaryResult<oneiron::memory::OutboundScheduleContext> {
    let utc_offset_minutes = match draft.utc_offset_minutes {
        Some(value)
            if !value.is_finite() || value.fract() != 0.0 || !(-840.0..=840.0).contains(&value) =>
        {
            return Err("utc_offset_minutes must be a finite integer in -840..=840".to_owned());
        }
        Some(value) => Some(value as i16),
        None => None,
    };
    let iana_timezone = draft.iana_timezone.clone();
    // An IANA label without an offset is unusable: execution derives local time
    // from the numeric offset alone and never opens a timezone database.
    if iana_timezone.is_some() && utc_offset_minutes.is_none() {
        return Err("iana_timezone requires utc_offset_minutes".to_owned());
    }
    if iana_timezone.as_deref().is_some_and(|label| {
        label.trim().is_empty() || label.chars().any(char::is_control) || label.len() > 255
    }) {
        return Err("iana_timezone must be non-blank and contain no controls".to_owned());
    }
    let apns_interruption_level = match draft.apns_interruption_level.as_deref() {
        Some(label) => Some(
            oneiron::DeliveryWindowApnsInterruptionLevel::parse(label).ok_or_else(|| {
                "unknown APNs interruption level: use passive, active, time_sensitive, or critical"
                    .to_owned()
            })?,
        ),
        None => None,
    };
    let resolved_level = match draft.resolved_level.as_deref() {
        Some(label) => Some(
            oneiron::delivery_window::DeliveryWindowResolvedLevel::parse(label)
                .ok_or_else(|| "unknown resolved level: use plain_chat or push".to_owned())?,
        ),
        None => None,
    };
    Ok(oneiron::memory::OutboundScheduleContext {
        utc_offset_minutes,
        iana_timezone,
        human_explicit_instant: draft.human_explicit_instant.unwrap_or(false),
        apns_interruption_level,
        resolved_level,
    })
}

/// Page size for `forget`'s active-claim drain. `forget` re-lists `active`
/// after each page, so this bounds only per-iteration work, never the total
/// number of claims retracted.
pub(super) const FORGET_PAGE_SIZE: usize = 64;

/// Blob content ceiling for the N-API boundary: 32 MiB raw (double the
/// B8-validated 16 MiB probe). The base64 length is bounded BEFORE any
/// decode allocation, so oversized inputs cannot exhaust process memory.
/// ONE-1441: aliased to the shared boundary contract in `oneiron-remote`, so
/// the N-API and remote transports enforce one number rather than two.
pub(super) const MAX_NAPI_BLOB_CONTENT_BYTES: usize = oneiron_remote::MAX_BLOB_CONTENT_BYTES;

pub(super) const MAX_NAPI_BLOB_BASE64_LEN: usize = oneiron_remote::MAX_BLOB_BASE64_LEN;

pub(super) fn decode_blob_base64(input: &str) -> BoundaryResult<Vec<u8>> {
    if input.len() > MAX_NAPI_BLOB_BASE64_LEN {
        return Err(format!(
            "bytes_base64 exceeds the {MAX_NAPI_BLOB_CONTENT_BYTES}-byte blob content ceiling"
        ));
    }
    BASE64_STANDARD
        .decode(input.as_bytes())
        .map_err(|_| "bytes_base64 is not valid standard base64".to_owned())
}

/// Narrows an f64 to f32 at the N-API boundary, rejecting NaN and ±Inf
/// (including a finite f64 that overflows f32 to ±Inf). A non-finite
/// `min_weight` would otherwise silently disable the filter — NaN compares
/// false against every edge weight — or reject every edge (+Inf).
#[expect(
    clippy::cast_possible_truncation,
    reason = "f64→f32 narrowing at the N-API boundary is intentional"
)]
pub(super) fn narrow_to_f32(value: f64) -> BoundaryResult<f32> {
    let narrowed = value as f32;
    if !narrowed.is_finite() {
        return Err(format!("min_weight must be a finite number, got {value}"));
    }
    Ok(narrowed)
}
