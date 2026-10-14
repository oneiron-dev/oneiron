//! Where a vector hit counts as evidence in the vault's embedding space, as
//! the host's embedder states it.

use std::collections::BTreeMap;
use std::sync::PoisonError;

use crate::Vault;
use crate::config::VectorEvidenceFloors;
use crate::error::Result;

/// The floors a context pack's no-match check reads: one pair for every
/// score, and the pairs a host measured for one kind of item in one
/// embedding space, which take its place there (EMBED-PACK). A raw cosine
/// means different things in different spaces, and an item kind can sit
/// higher or lower in one space than another.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NoMatchFloors {
    /// For every score no keyed pair covers.
    pub(crate) pair: VectorEvidenceFloors,
    /// By embedding space (the model a vault's vectors are pinned to), then
    /// by entity type.
    pub(crate) keyed: BTreeMap<String, BTreeMap<u8, VectorEvidenceFloors>>,
}

impl NoMatchFloors {
    pub(super) fn new(pair: VectorEvidenceFloors) -> Self {
        Self {
            pair,
            keyed: BTreeMap::new(),
        }
    }

    /// The floors a score in `space` for an item of `kind` is judged by:
    /// that pair when the host set one, the vault's pair otherwise.
    pub(crate) fn resolve(&self, space: &str, kind: Option<u8>) -> VectorEvidenceFloors {
        kind.and_then(|kind| self.keyed.get(space)?.get(&kind))
            .copied()
            .unwrap_or(self.pair)
    }

    /// Whether any kind in `space` has floors of its own, so a score's kind
    /// has to be known to judge it.
    pub(crate) fn keys_space(&self, space: &str) -> bool {
        self.keyed.contains_key(space)
    }
}

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
