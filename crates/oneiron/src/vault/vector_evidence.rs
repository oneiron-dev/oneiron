//! Core half of `vault::vector_evidence`: its store-layer items live in `oneiron_store::vault::vector_evidence` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::vault::vector_evidence::*;

use crate::Vault;
use crate::config::VectorEvidenceFloors;
use crate::error::Result;
use std::collections::BTreeMap;
use std::sync::PoisonError;

impl Vault {
    /// The floors context packs are judged by now: the configured ones
    /// ([`crate::VaultConfig::vector_evidence`]) until the host sets others.
    /// A kind with floors of its own in this vault's space
    /// ([`Vault::set_vector_evidence_for`]) is judged by those instead.
    pub fn vector_evidence(&self) -> VectorEvidenceFloors {
        self.vector_evidence
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .pair
    }

    /// Sets the floors for a host that learns how its provider embeds only
    /// once it is admitted, as a remote embedder says when it answers. Floors
    /// the open would refuse ([`VectorEvidenceFloors::validate`]) are refused
    /// here, and the floors in force stay.
    pub fn set_vector_evidence(&self, floors: VectorEvidenceFloors) -> Result<()> {
        floors.validate()?;
        self.vector_evidence
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .pair = floors;
        Ok(())
    }

    /// Sets the floors for one kind of item in one embedding space, as a
    /// host measured them for its model. `space` names the model the vault's
    /// vectors are pinned to ([`crate::VaultConfig::embedding_model`]); floors
    /// set for another space are kept, and judge nothing until the vault's
    /// vectors are in it. Floors [`VectorEvidenceFloors::validate`] refuses
    /// are refused, and the floors in force stay.
    pub fn set_vector_evidence_for(
        &self,
        space: &str,
        entity_type: u8,
        floors: VectorEvidenceFloors,
    ) -> Result<()> {
        floors.validate()?;
        self.vector_evidence
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .keyed
            .entry(space.to_owned())
            .or_default()
            .insert(entity_type, floors);
        Ok(())
    }

    /// Every floor the no-match check reads, at once. A run reads them
    /// once, when it starts, and judges, keys and records by that copy.
    pub(crate) fn no_match_floors(&self) -> NoMatchFloors {
        self.vector_evidence
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The embedding space this vault's vectors are scored in: the model
    /// they are pinned to, empty for a vault with none.
    pub(crate) fn evidence_space(&self) -> &str {
        self.config.embedding_model.as_deref().unwrap_or_default()
    }
}
