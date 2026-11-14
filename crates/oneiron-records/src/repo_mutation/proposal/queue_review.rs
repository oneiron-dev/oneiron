//! Moved from `crates/oneiron/src/repo_mutation/proposal/queue_review.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::critic_lens::LensCatalog;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::collections::BTreeSet;

/// The review a proposal is held to. Stored under the row's `catalog` key
/// with the wire of an optional catalog: every row before FIX 8268 reads as
/// `Explicit`, unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoProposalReview {
    /// The catalog its proposer named: a requirement of its own.
    Explicit(LensCatalog),
    /// The vault's review policy when the queue decides; none set, no
    /// critic hold.
    VaultDefault,
}

impl RepoProposalReview {
    /// Its own catalog, if it named one.
    #[must_use]
    pub fn catalog(&self) -> Option<&LensCatalog> {
        match self {
            Self::Explicit(catalog) => Some(catalog),
            Self::VaultDefault => None,
        }
    }
}

impl Serialize for RepoProposalReview {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.catalog().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RepoProposalReview {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Ok(Option::<LensCatalog>::deserialize(deserializer)?
            .map_or(Self::VaultDefault, Self::Explicit))
    }
}
