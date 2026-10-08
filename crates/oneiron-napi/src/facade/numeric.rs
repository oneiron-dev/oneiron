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
            read_receipt: None,
            policy_denial: None,
        });
    }
    // The whole number is positive and at most MAX_DIMENSIONS (16,384).
    Ok(value as usize)
}

/// Validates the original JS count, then applies the shared list/search cap.
pub(super) fn limit_to_engine(value: f64) -> Result<usize, MemoryError> {
    if !value.is_finite() || value.fract() != 0.0 || !(1.0..=f64::from(u32::MAX)).contains(&value) {
        return Err(MemoryError {
            code: oneiron::memory::MEMORY_CODE_BAD_REQUEST.to_owned(),
            message: "limit must be a finite positive integer in the unsigned 32-bit range"
                .to_owned(),
            suggestions: vec![format!(
                "Set limit to a whole number between 1 and {}, or omit it to use the default.",
                oneiron_remote::MAX_SEARCH_LIMIT
            )],
            successor_short_id: None,
            gate_denial: None,
            read_receipt: None,
            policy_denial: None,
        });
    }
    // Positive whole u32 values are exact JS integers and fit usize on N-API targets.
    let limit = value as usize;
    oneiron_remote::check_limit(limit)?;
    Ok(limit)
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
        relationship_ref: input.relationship_ref.clone(),
        scope: input.scope.clone(),
        valid_from: claim_timestamp(input.valid_from, "valid_from")?,
        valid_to: claim_timestamp(input.valid_to, "valid_to")?,
        occurred_at: claim_timestamp(input.occurred_at, "occurred_at")?,
        learned_at: claim_timestamp(input.learned_at, "learned_at")?,
        salience: input.salience.map(|s| s as f32),
    })
}
