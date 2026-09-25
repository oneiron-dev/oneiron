//! Input-bound inference receipts; validation is not a claim of measured quality.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::{AudioError, AudioResult, InferenceExecution, InferenceProvenance, Pcm16};

pub(super) const COMMUNITY1_MODEL: &str = "pyannote/speaker-diarization-community-1";

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Canonical signed 16-bit little-endian mono samples, 16 kHz. No WAV header.
pub(super) fn pcm_sha256(audio: &Pcm16) -> String {
    let mut digest = Sha256::new();
    let mut bytes = [0_u8; 8_192];
    for block in audio.samples.chunks(4_096) {
        for (sample, slot) in block.iter().zip(bytes.chunks_exact_mut(2)) {
            slot.copy_from_slice(&sample.to_le_bytes());
        }
        digest.update(&bytes[..block.len() * 2]);
    }
    format!("{:x}", digest.finalize())
}

pub(super) fn validate_receipt(
    receipt: &InferenceProvenance,
    input_sha256: &str,
    seen: &mut HashSet<String>,
) -> AudioResult<()> {
    if receipt.invocation_id.trim().is_empty()
        || receipt.model_id.trim().is_empty()
        || receipt.input_sha256 != input_sha256
        || !seen.insert(receipt.invocation_id.clone())
    {
        return Err(AudioError::InvalidProvenance);
    }
    Ok(())
}

pub(super) fn execution_mode(receipts: &[&InferenceProvenance]) -> InferenceExecution {
    if receipts
        .iter()
        .any(|r| r.execution == InferenceExecution::Fixture)
    {
        InferenceExecution::Fixture
    } else {
        InferenceExecution::Measured
    }
}
