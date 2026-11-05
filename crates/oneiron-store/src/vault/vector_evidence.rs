//! Where a vector hit counts as evidence in the vault's embedding space, as
//! the host's embedder states it.

use std::collections::BTreeMap;
use std::sync::PoisonError;

use crate::config::VectorEvidenceFloors;
use oneiron_base::error::Result;

/// The floors a context pack's no-match check reads: one pair for every
/// score, and the pairs a host measured for one kind of item in one
/// embedding space, which take its place there (EMBED-PACK). A raw cosine
/// means different things in different spaces, and an item kind can sit
/// higher or lower in one space than another.
#[derive(Debug, Clone, PartialEq)]
pub struct NoMatchFloors {
    /// For every score no keyed pair covers.
    pub pair: VectorEvidenceFloors,
    /// By embedding space (the model a vault's vectors are pinned to), then
    /// by entity type.
    pub keyed: BTreeMap<String, BTreeMap<u8, VectorEvidenceFloors>>,
}

impl NoMatchFloors {
    pub fn new(pair: VectorEvidenceFloors) -> Self {
        Self {
            pair,
            keyed: BTreeMap::new(),
        }
    }

    /// The floors a score in `space` for an item of `kind` is judged by:
    /// that pair when the host set one, the vault's pair otherwise.
    pub fn resolve(&self, space: &str, kind: Option<u8>) -> VectorEvidenceFloors {
        kind.and_then(|kind| self.keyed.get(space)?.get(&kind))
            .copied()
            .unwrap_or(self.pair)
    }

    /// Whether any kind in `space` has floors of its own, so a score's kind
    /// has to be known to judge it.
    pub fn keys_space(&self, space: &str) -> bool {
        self.keyed.contains_key(space)
    }
}

