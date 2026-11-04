//! Voice-segment claim vocabulary is defined in the core write envelope.

pub(crate) use crate::write_envelope::voice_segment::validate_voice_segment_claim_structure;
pub use crate::write_envelope::voice_segment::{
    AEC_MODE_ACTIVE, AEC_MODE_BYPASSED_HEADPHONES, AEC_MODE_BYPASSED_OTHER, AEC_MODE_UNAVAILABLE,
    PREDICATE_VOICE_SEGMENT, VOICE_SEGMENT_AEC_MODES, VOICE_SEGMENT_VALUE_KEYS,
    is_voice_segment_claim_predicate,
};

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
        .unwrap()
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
        )
        .unwrap();
        assert!(validate_voice_segment_claim_structure(&body).is_err());
    }
}
