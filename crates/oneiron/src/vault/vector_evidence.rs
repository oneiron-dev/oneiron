//! Where a vector hit counts as evidence in the vault's embedding space, as
//! the host's embedder states it, or as the owner set it for that space
//! (`retrieval.vector_evidence`, [`setting_keys::VECTOR_EVIDENCE`]).

pub(crate) mod setting_keys;

use std::collections::BTreeMap;
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::config::VectorEvidenceFloors;
use crate::error::Result;
use crate::setting::SettingValue;

/// The owner's floors for one embedding space, the value of
/// `retrieval.vector_evidence`: `{floor, strong}`, held to
/// [`VectorEvidenceFloors::validate`] as a host's floors are, or none, where
/// the host's floors judge the space.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct OwnerEvidenceFloors(pub(crate) Option<VectorEvidenceFloors>);

impl OwnerEvidenceFloors {
    /// No floors of the owner's: the host's judge the space. What a space no
    /// row names reads, and what an unreadable row reads as.
    pub(crate) fn unset() -> Self {
        Self(None)
    }
}

impl SettingValue for OwnerEvidenceFloors {
    const CLOSED: bool = true;

    /// Floors outside `0 <= floor <= strong <= 1`, or not numbers, are
    /// refused, never clamped.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` naming the two floors.
    fn check(self) -> Result<Self> {
        if let Some(floors) = &self.0 {
            floors.validate()?;
        }
        Ok(self)
    }
}

/// Whether `item` names an embedding space: a model id, `org/name@revision`
/// ([`crate::store::validate_embedding_model_id`]), as a vault's vectors are
/// pinned to ([`crate::VaultConfig::embedding_model`]).
fn is_embedding_space(item: &str) -> bool {
    crate::store::validate_embedding_model_id(item).is_ok()
}

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
    /// The host's floors context packs are judged by now: the configured ones
    /// ([`crate::VaultConfig::vector_evidence`]) until the host sets others.
    /// A kind with floors of its own in this vault's space
    /// ([`Vault::set_vector_evidence_for`]) is judged by those instead, and
    /// the owner's floors for the space (`retrieval.vector_evidence`), when
    /// set, judge every kind there in place of both.
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
    /// once, when it starts, and judges, keys and records by that copy. The
    /// owner's floors for this vault's space take the place of the host's
    /// ([`Self::with_owner_floors`]). Not for a caller that holds a read
    /// transaction: it opens one ([`Self::no_match_floors_in_txn`]).
    pub(crate) fn no_match_floors(&self) -> NoMatchFloors {
        let host = self.host_no_match_floors();
        match self.store.env.read_txn() {
            Ok(txn) => self.with_owner_floors(host, &txn),
            Err(_) => host,
        }
    }

    /// [`Self::no_match_floors`] inside a transaction the caller holds.
    pub(crate) fn no_match_floors_in_txn(&self, txn: &heed::RoTxn<'_>) -> NoMatchFloors {
        self.with_owner_floors(self.host_no_match_floors(), txn)
    }

    /// The floors the host set: its pair, and the pairs it measured for kinds.
    fn host_no_match_floors(&self) -> NoMatchFloors {
        self.vector_evidence
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `host`, with the owner's floors for this vault's space
    /// ([`setting_keys::VECTOR_EVIDENCE`]) in place of its pair and of every
    /// kind's pair there: the owner's row first, then a host-measured kind
    /// pair, then the host's pair (Engine ANSWER 27 Nov 01:45). A vault with
    /// no space, a space no row names, and a row that does not read keep
    /// `host`.
    fn with_owner_floors(&self, mut host: NoMatchFloors, txn: &heed::RoTxn<'_>) -> NoMatchFloors {
        let space = self.evidence_space();
        if space.is_empty() {
            return host;
        }
        let owner = setting_keys::VECTOR_EVIDENCE
            .read_in_txn(self, txn, &[], Some(space))
            .ok()
            .and_then(|resolved| resolved.value.0);
        if let Some(floors) = owner {
            host.pair = floors;
            host.keyed.remove(space);
        }
        host
    }

    /// The embedding space this vault's vectors are scored in: the model
    /// they are pinned to, empty for a vault with none.
    pub(crate) fn evidence_space(&self) -> &str {
        self.config.embedding_model.as_deref().unwrap_or_default()
    }
}
