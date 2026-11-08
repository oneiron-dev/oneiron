//! Resumable envelope and outer hashing of the original bounded canonical buffer.

use super::super::{
    HEADER_LEN, canonical::CANONICAL_SNAPSHOT_ARTIFACT_TYPE, recovery_artifact_checksum_start,
    seal_recovery_artifact_with_checksum,
};

enum Phase {
    Envelope,
    Canonical,
}

pub(super) struct EncodedDigest {
    bytes: Vec<u8>,
    hasher: blake3::Hasher,
    next: usize,
    phase: Phase,
}

impl EncodedDigest {
    /// Owns the validated encoding with its header still reserved and unsealed.
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        let hasher = recovery_artifact_checksum_start(
            CANONICAL_SNAPSHOT_ARTIFACT_TYPE,
            bytes.len() - HEADER_LEN,
        );
        Self {
            bytes,
            hasher,
            next: HEADER_LEN,
            phase: Phase::Envelope,
        }
    }

    pub(super) fn advance(&mut self, max_chunks: usize) -> bool {
        let bytes = max_chunks.max(1).saturating_mul(blake3::CHUNK_LEN);
        let end = self.next.saturating_add(bytes).min(self.bytes.len());
        self.hasher.update(&self.bytes[self.next..end]);
        self.next = end;
        if self.next != self.bytes.len() {
            return false;
        }
        match self.phase {
            Phase::Envelope => {
                seal_recovery_artifact_with_checksum(
                    CANONICAL_SNAPSHOT_ARTIFACT_TYPE,
                    &mut self.bytes,
                    *self.hasher.finalize().as_bytes(),
                );
                self.hasher = blake3::Hasher::new();
                self.next = 0;
                self.phase = Phase::Canonical;
                false
            }
            Phase::Canonical => true,
        }
    }

    pub(super) fn into_digest(self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}
