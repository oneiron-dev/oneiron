//! Where a vector hit counts as evidence in the vault's embedding space, as
//! the host's embedder states it.

use std::sync::PoisonError;

use crate::Vault;
use crate::config::VectorEvidenceFloors;
use crate::error::Result;

impl Vault {
    /// The floors context packs are judged by now: the configured ones
    /// ([`crate::VaultConfig::vector_evidence`]) until the host sets others.
    pub fn vector_evidence(&self) -> VectorEvidenceFloors {
        *self
            .vector_evidence
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets the floors for a host that learns how its provider embeds only
    /// once it is admitted, as a remote embedder says when it answers. Floors
    /// the open would refuse ([`VectorEvidenceFloors::validate`]) are refused
    /// here, and the floors in force stay.
    pub fn set_vector_evidence(&self, floors: VectorEvidenceFloors) -> Result<()> {
        floors.validate()?;
        *self
            .vector_evidence
            .write()
            .unwrap_or_else(PoisonError::into_inner) = floors;
        Ok(())
    }
}
