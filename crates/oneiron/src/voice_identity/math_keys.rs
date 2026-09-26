//! Vector-math door (normalize/cosine/same-space check) and the digest helper the typed side
//! tables' keys are built from.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub(super) fn invalid_voice(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

pub(super) fn corrupt_voice_row() -> Error {
    Error::CorruptedIndex("voice identity record")
}

pub(super) fn require_non_empty(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_voice(&format!("{what} must be non-empty")));
    }
    Ok(())
}

pub(super) fn require_sha256_hex(value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(invalid_voice(
            "voice enrollment source_sha256 must be 64 hex characters",
        ))
    }
}

/// Rejects a vector whose length, finiteness, or magnitude makes it unusable.
///
/// A zero-magnitude vector has no direction, so it can neither be normalized
/// nor compared; it is rejected on the same footing as a non-finite one.
pub(super) fn validate_voice_vector(vector: &[f32], dimension: usize) -> Result<()> {
    if vector.len() != dimension {
        return Err(Error::DimensionMismatch {
            expected: dimension,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(vector) {
        return Err(error);
    }
    if squared_norm(vector) == 0.0 {
        return Err(Error::InvalidVector {
            index: 0,
            value: vector.first().copied().unwrap_or(0.0),
        });
    }
    Ok(())
}

fn squared_norm(vector: &[f32]) -> f64 {
    vector
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum()
}

/// L2-normalizes a validated vector.
pub(super) fn l2_normalize(vector: &[f32], dimension: usize) -> Result<Vec<f32>> {
    validate_voice_vector(vector, dimension)?;
    let norm = squared_norm(vector).sqrt();
    let normalized: Vec<f32> = vector
        .iter()
        .map(|value| (f64::from(*value) / norm) as f32)
        .collect();
    validate_voice_vector(&normalized, dimension)?;
    Ok(normalized)
}

/// Cosine similarity of two already-normalized, equal-length vectors.
pub(super) fn cosine_similarity(left: &[f32], right: &[f32]) -> Result<f32> {
    if left.len() != right.len() {
        return Err(Error::DimensionMismatch {
            expected: left.len(),
            got: right.len(),
        });
    }
    let dot: f64 = left
        .iter()
        .zip(right.iter())
        .map(|(a, b)| f64::from(*a) * f64::from(*b))
        .sum();
    let score = dot.clamp(-1.0, 1.0) as f32;
    if score.is_finite() {
        Ok(score)
    } else {
        Err(Error::InvalidVector {
            index: 0,
            value: score,
        })
    }
}

/// The ONE comparison door.
///
/// Two vectors may be compared only when they belong to the identical
/// embedding space. A cross-space request is an error, never a low score, so a
/// re-pinned model can never be silently scored against an old centroid.
pub(super) fn voice_cosine_in_space(
    left_space_id: &str,
    left: &[f32],
    right_space_id: &str,
    right: &[f32],
) -> Result<f32> {
    if left_space_id != right_space_id {
        return Err(invalid_voice(
            "cross-space voice comparison rejected: embedding space_id differs",
        ));
    }
    cosine_similarity(left, right)
}

/// A stable 16-byte digest of one domain-separated value, the suffix half of
/// several side-table keys whose full identity would otherwise be unbounded
/// text (a space id, a sample id, an event id, a session ref).
pub(super) fn digest16(domain: &[u8], value: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    let digest = hasher.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}
