//! Public validation and codec entry points for canonical snapshots.
//! The entry point is `CanonicalSnapshot::decode`.
//! `super` owns bounded encoding and private codec helpers.

use super::*;

impl CanonicalSnapshot {
    /// Validate every section and reference before any reconstruction or storage write.
    pub fn validate(&self) -> Result<()> {
        validation::validate(self)?;
        row_births::validate(self)?;
        withdrawn_cutoffs::validate(self)
    }

    /// Deterministic MessagePack, protected by the blake3 artifact envelope.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_within(CANONICAL_SNAPSHOT_MAX_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_size(bytes.len())?;
        let artifact = decode_recovery_artifact(bytes, CANONICAL_SNAPSHOT_ARTIFACT_TYPE)?;
        let value: Self =
            rmp_serde::from_slice(artifact.payload()).map_err(|_| invalid("canonical payload"))?;
        value.validate()?;
        if pack(&value)? != artifact.payload() {
            return Err(invalid("noncanonical payload or trailing bytes"));
        }
        Ok(value)
    }

    pub fn blake3(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}
