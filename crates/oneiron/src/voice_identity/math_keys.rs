//! Vector-math door (normalize/cosine/same-space check) and vault_meta key builders with the pointer==prefix invariant.

use sha2::{Digest, Sha256};

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

use super::types::{
    VOICE_CONSENT_KEY_PREFIX, VOICE_PRINT_KEY_PREFIX, VOICE_ROSTER_KEY_PREFIX,
    VOICE_SAMPLE_KEY_PREFIX,
};

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

fn digest16(domain: &[u8], value: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    let digest = hasher.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn key_with(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + parts.iter().map(|p| p.len()).sum::<usize>());
    key.extend_from_slice(prefix);
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

/// Prefix covering every print-family row of one subject.
pub(super) fn voice_subject_prefix(subject: &EntityId) -> Vec<u8> {
    key_with(VOICE_PRINT_KEY_PREFIX, &[subject.as_bytes()])
}

/// Active-space pointer row: subject -> active space digest.
pub(super) fn voice_active_pointer_key(subject: &EntityId) -> Vec<u8> {
    voice_subject_prefix(subject)
}

/// Print row: one centroid for one (subject, embedding space).
pub(super) fn voice_print_key(subject: &EntityId, space_id: &str) -> Vec<u8> {
    let digest = digest16(b"voice_identity.space", space_id.as_bytes());
    key_with(VOICE_PRINT_KEY_PREFIX, &[subject.as_bytes(), &digest])
}

pub(super) fn voice_sample_key(subject: &EntityId, sample_id: &str) -> Vec<u8> {
    let mut scoped = Vec::with_capacity(ENTITY_ID_LEN + sample_id.len());
    scoped.extend_from_slice(subject.as_bytes());
    scoped.extend_from_slice(sample_id.as_bytes());
    let digest = digest16(b"voice_identity.sample", &scoped);
    key_with(VOICE_SAMPLE_KEY_PREFIX, &[&digest])
}

pub(super) fn voice_consent_prefix(subject: &EntityId) -> Vec<u8> {
    key_with(VOICE_CONSENT_KEY_PREFIX, &[subject.as_bytes()])
}

pub(super) fn voice_consent_key(subject: &EntityId, event_id: &str) -> Vec<u8> {
    let digest = digest16(b"voice_identity.consent", event_id.as_bytes());
    key_with(VOICE_CONSENT_KEY_PREFIX, &[subject.as_bytes(), &digest])
}

pub(super) fn voice_roster_key(voice_session_ref: &str) -> Vec<u8> {
    let digest = digest16(b"voice_identity.roster", voice_session_ref.as_bytes());
    key_with(VOICE_ROSTER_KEY_PREFIX, &[&digest])
}
