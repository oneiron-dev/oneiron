//! `voice.segment` claim family — the metadata of one committed capture
//! segment: its span, channel count, echo-cancellation mode, and device.
//!
//! Structural only, on the family-module pattern (`comm.rs`): a capture edge
//! lands the audio as an ASSET entity and states what that audio IS with one
//! `voice.segment` claim through the ordinary claim door. This module is the
//! write-time chokepoint that keeps the statement honest — a segment can
//! claim cancellation was active only by spelling one of the pinned modes,
//! and a span that does not advance is not a segment.

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject};
use crate::error::{Error, Result};

/// One captured audio segment, subject = the ASSET entity holding its bytes.
pub const PREDICATE_VOICE_SEGMENT: &str = "voice.segment";

/// Complete voice-segment claim family.
const VOICE_SEGMENT_CLAIM_PREDICATES: [&str; 1] = [PREDICATE_VOICE_SEGMENT];

/// Pinned MessagePack key set for a `voice.segment` claim value. Exactly
/// these keys, no more: an unknown key is a different claim wearing this
/// predicate's name.
pub const VOICE_SEGMENT_VALUE_KEYS: [&str; 5] =
    ["span_start", "span_end", "channels", "aec_mode", "device"];

const KEY_SPAN_START: &str = VOICE_SEGMENT_VALUE_KEYS[0];
const KEY_SPAN_END: &str = VOICE_SEGMENT_VALUE_KEYS[1];
const KEY_CHANNELS: &str = VOICE_SEGMENT_VALUE_KEYS[2];
const KEY_AEC_MODE: &str = VOICE_SEGMENT_VALUE_KEYS[3];
const KEY_DEVICE: &str = VOICE_SEGMENT_VALUE_KEYS[4];

/// Echo cancellation was bypassed because output was on headphones — there
/// is no acoustic echo path to cancel.
pub const AEC_MODE_BYPASSED_HEADPHONES: &str = "bypassed_headphones";
/// Cancellation was bypassed on a non-headphone route.
pub const AEC_MODE_BYPASSED_OTHER: &str = "bypassed_other";
/// Cancellation actually ran over the segment.
pub const AEC_MODE_ACTIVE: &str = "active";
/// No cancellation was available to this build or device; capture continued
/// regardless. Recording is never blocked on cancellation.
pub const AEC_MODE_UNAVAILABLE: &str = "unavailable";

/// Pinned `aec_mode` vocabulary. The recorder encodes the route AND the mode
/// it actually used; anything outside this set is rejected rather than
/// stored as an unreadable claim about how the audio was treated.
pub const VOICE_SEGMENT_AEC_MODES: [&str; 4] = [
    AEC_MODE_BYPASSED_HEADPHONES,
    AEC_MODE_BYPASSED_OTHER,
    AEC_MODE_ACTIVE,
    AEC_MODE_UNAVAILABLE,
];

/// Returns whether `predicate` belongs to the voice-segment claim family.
#[must_use]
pub fn is_voice_segment_claim_predicate(predicate: &str) -> bool {
    VOICE_SEGMENT_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `voice.segment` claim subject and value shape.
pub(crate) fn validate_voice_segment_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_claim("voice.segment subject must be an entity"));
    }
    if !is_voice_segment_claim_predicate(&body.predicate) {
        return Err(invalid_claim("unknown voice segment claim predicate"));
    }
    let entries = value_map(&body.value)?;
    validate_keys(entries, &VOICE_SEGMENT_VALUE_KEYS)?;

    // `as_u64` is the non-negativity check: a negative MessagePack integer
    // decodes as `Value::Integer` but never as `u64`.
    let span_start = required_u64(entries, KEY_SPAN_START)?;
    let span_end = required_u64(entries, KEY_SPAN_END)?;
    if span_start >= span_end {
        return Err(invalid_claim("voice.segment span must advance"));
    }
    if required_u64(entries, KEY_CHANNELS)? < 1 {
        return Err(invalid_claim("voice.segment must carry a channel"));
    }
    let aec_mode = required_str(entries, KEY_AEC_MODE)?;
    if !VOICE_SEGMENT_AEC_MODES.contains(&aec_mode) {
        return Err(invalid_claim("voice.segment aec_mode is invalid"));
    }
    if required_str(entries, KEY_DEVICE)?.is_empty() {
        return Err(invalid_claim("voice.segment device must be named"));
    }
    Ok(())
}

fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_claim("voice.segment value must be a map")),
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches
        .next()
        .ok_or_else(|| invalid_claim("voice.segment value missing required key"))?;
    if matches.next().is_some() {
        return Err(invalid_claim("voice.segment value contains duplicate key"));
    }
    Ok(value)
}

fn required_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(|| invalid_claim("voice.segment value string invalid"))
}

fn required_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    required_value(entries, key)?
        .as_u64()
        .ok_or_else(|| invalid_claim("voice.segment value integer invalid"))
}

fn validate_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    if entries.len() != expected.len() {
        return Err(invalid_claim("voice.segment value key set invalid"));
    }
    for expected_key in expected {
        required_value(entries, expected_key)?;
    }
    if entries
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| !expected.contains(&key)))
    {
        return Err(invalid_claim("voice.segment value key set invalid"));
    }
    Ok(())
}

fn invalid_claim(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
    use crate::test_util::entity;

    /// A well-formed value, then mutated per case — every rejection test
    /// differs from the accepted body in exactly one way.
    fn segment_value() -> Vec<(Value, Value)> {
        vec![
            (Value::from(KEY_SPAN_START), Value::from(1_772_000_000_u64)),
            (Value::from(KEY_SPAN_END), Value::from(1_772_000_060_u64)),
            (Value::from(KEY_CHANNELS), Value::from(2_u64)),
            (
                Value::from(KEY_AEC_MODE),
                Value::from(AEC_MODE_BYPASSED_HEADPHONES),
            ),
            (Value::from(KEY_DEVICE), Value::from("built-in-mic")),
        ]
    }

    fn claim(value: Vec<(Value, Value)>) -> ClaimBody {
        ClaimBody::new(
            PREDICATE_VOICE_SEGMENT,
            ClaimSubject::Entity(entity(0x5E)),
            Value::Map(value),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
    }

    /// Replaces one key's value in place, keeping key order.
    fn with(key: &str, value: Value) -> ClaimBody {
        let mut entries = segment_value();
        let slot = entries
            .iter_mut()
            .find(|entry| entry.0.as_str() == Some(key))
            .expect("key belongs to the well-formed value");
        slot.1 = value;
        claim(entries)
    }

    #[test]
    fn predicate_family_is_exact() {
        assert!(is_voice_segment_claim_predicate(PREDICATE_VOICE_SEGMENT));
        assert!(!is_voice_segment_claim_predicate("voice.segment.extra"));
        assert!(!is_voice_segment_claim_predicate("voice"));
    }

    #[test]
    fn well_formed_segment_passes() {
        validate_voice_segment_claim_structure(&claim(segment_value())).expect("well-formed");
    }

    #[test]
    fn every_aec_mode_is_accepted() {
        for mode in VOICE_SEGMENT_AEC_MODES {
            validate_voice_segment_claim_structure(&with(KEY_AEC_MODE, Value::from(mode)))
                .unwrap_or_else(|err| panic!("aec_mode {mode} must be accepted: {err}"));
        }
    }

    #[test]
    fn missing_key_is_rejected() {
        let entries = segment_value()
            .into_iter()
            .filter(|(key, _)| key.as_str() != Some(KEY_DEVICE))
            .collect();
        assert!(validate_voice_segment_claim_structure(&claim(entries)).is_err());
    }

    #[test]
    fn extra_key_is_rejected() {
        let mut entries = segment_value();
        entries.push((Value::from("transcript"), Value::from("hello")));
        assert!(validate_voice_segment_claim_structure(&claim(entries)).is_err());
    }

    #[test]
    fn non_advancing_span_is_rejected() {
        // Equal bounds and a reversed span are both "no segment happened".
        assert!(
            validate_voice_segment_claim_structure(&with(
                KEY_SPAN_END,
                Value::from(1_772_000_000_u64)
            ))
            .is_err()
        );
        assert!(
            validate_voice_segment_claim_structure(&with(
                KEY_SPAN_START,
                Value::from(1_772_000_061_u64)
            ))
            .is_err()
        );
    }

    #[test]
    fn negative_span_is_rejected() {
        assert!(
            validate_voice_segment_claim_structure(&with(KEY_SPAN_START, Value::from(-1_i64)))
                .is_err()
        );
    }

    #[test]
    fn zero_channels_is_rejected() {
        assert!(
            validate_voice_segment_claim_structure(&with(KEY_CHANNELS, Value::from(0_u64)))
                .is_err()
        );
    }

    #[test]
    fn unknown_aec_mode_is_rejected() {
        assert!(
            validate_voice_segment_claim_structure(&with(KEY_AEC_MODE, Value::from("maybe")))
                .is_err()
        );
    }

    #[test]
    fn empty_device_is_rejected() {
        assert!(
            validate_voice_segment_claim_structure(&with(KEY_DEVICE, Value::from(""))).is_err()
        );
    }

    #[test]
    fn non_map_value_is_rejected() {
        let body = ClaimBody::new(
            PREDICATE_VOICE_SEGMENT,
            ClaimSubject::Entity(entity(0x5E)),
            Value::from("segment"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        assert!(validate_voice_segment_claim_structure(&body).is_err());
    }
}
