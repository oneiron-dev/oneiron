//! JavaScript numbers must be validated before N-API can narrow them.

use oneiron::{ClaimInput, MemoryError};

use super::NapiClaimInput;

/// Refuses fractional, non-finite and out-of-range dimensions before casting.
pub(super) fn dimensions_to_engine(value: f64) -> Result<usize, MemoryError> {
    if !value.is_finite()
        || value.fract() != 0.0
        || !(1.0..=oneiron_remote::MAX_DIMENSIONS as f64).contains(&value)
    {
        return Err(MemoryError {
            code: oneiron::memory::MEMORY_CODE_BAD_REQUEST.to_owned(),
            message: format!(
                "dimensions must be a finite integer between 1 and {}",
                oneiron_remote::MAX_DIMENSIONS
            ),
            suggestions: vec![
                "Open the vault with the dimension count its embedding model produces.".to_owned(),
            ],
            successor_short_id: None,
            gate_denial: None,
        });
    }
    // The whole number is positive and at most MAX_DIMENSIONS (16,384).
    Ok(value as usize)
}

fn claim_timestamp(value: Option<f64>, field: &str) -> Result<Option<u64>, MemoryError> {
    value
        .map(|value| oneiron_remote::check_unix_seconds(field, value))
        .transpose()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "f64→f32 confidence/salience narrowing at the N-API boundary is intentional"
)]
pub(super) fn claim_input_to_engine(input: &NapiClaimInput) -> Result<ClaimInput, MemoryError> {
    Ok(ClaimInput {
        id: input.id.clone(),
        predicate: input.predicate.clone(),
        subject_ref: input.subject_ref.clone(),
        value: input.value.clone(),
        confidence: input.confidence as f32,
        source: input.source.clone(),
        world_ref: input.world_ref.clone(),
        scope: input.scope.clone(),
        valid_from: claim_timestamp(input.valid_from, "valid_from")?,
        valid_to: claim_timestamp(input.valid_to, "valid_to")?,
        occurred_at: claim_timestamp(input.occurred_at, "occurred_at")?,
        learned_at: claim_timestamp(input.learned_at, "learned_at")?,
        salience: input.salience.map(|s| s as f32),
    })
}

#[cfg(test)]
mod tests {
    use super::{NapiClaimInput, claim_input_to_engine, dimensions_to_engine};

    fn claim(timestamps: [Option<f64>; 4]) -> NapiClaimInput {
        NapiClaimInput {
            id: None,
            predicate: "preference.travel.seat".to_owned(),
            subject_ref: "11111111111111111111111111111111".to_owned(),
            value: serde_json::json!({"seat": "window"}),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            scope: None,
            valid_from: timestamps[0],
            valid_to: timestamps[1],
            occurred_at: timestamps[2],
            learned_at: timestamps[3],
            salience: None,
        }
    }

    #[test]
    fn dimensions_are_checked_before_narrowing() {
        for (number, expected) in [(1.0, 1), (256.0, 256), (16_384.0, 16_384)] {
            assert_eq!(
                dimensions_to_engine(number).expect("valid dimensions"),
                expected
            );
        }
        for number in [
            0.0,
            -1.0,
            256.5,
            16_385.0,
            4_294_967_552.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let error = dimensions_to_engine(number).expect_err("invalid dimensions");
            assert_eq!(error.code, "BAD_REQUEST");
            assert!(!error.suggestions.is_empty());
        }
    }

    #[test]
    fn all_claim_timestamps_reject_lossy_numbers() {
        for (index, field) in ["valid_from", "valid_to", "occurred_at", "learned_at"]
            .into_iter()
            .enumerate()
        {
            for number in [
                -1.0,
                1_700_000_000.9,
                9_007_199_254_740_992.0,
                9_007_199_254_740_994.0,
                f64::NAN,
                f64::INFINITY,
                f64::NEG_INFINITY,
            ] {
                let mut timestamps = [None; 4];
                timestamps[index] = Some(number);
                let error =
                    claim_input_to_engine(&claim(timestamps)).expect_err("invalid claim timestamp");
                assert_eq!(error.code, "BAD_REQUEST");
                assert!(error.message.contains(field));
                assert!(!error.suggestions.is_empty());
            }
        }
    }

    #[test]
    fn claim_timestamps_preserve_omission_zero_and_safe_integer_edge() {
        for (number, expected) in [
            (None, None),
            (Some(0.0), Some(0)),
            (Some(1_700_000_000.0), Some(1_700_000_000)),
            (Some(9_007_199_254_740_991.0), Some(9_007_199_254_740_991)),
        ] {
            let input = claim_input_to_engine(&claim([number; 4])).expect("valid timestamps");
            assert_eq!(input.valid_from, expected);
            assert_eq!(input.valid_to, expected);
            assert_eq!(input.occurred_at, expected);
            assert_eq!(input.learned_at, expected);
        }
    }
}
