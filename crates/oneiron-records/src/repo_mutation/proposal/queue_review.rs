//! Moved from `crates/oneiron/src/repo_mutation/proposal/queue_review.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::repo_mutation::proposal::actor_erase::ProposalActor;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::critic_lens::LensCatalog;
use oneiron_verb_wire::repo_mutation::proposal::settlement::RepoProposalDecision;
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

/// The review a merge stack admitted one member under, sealed in the
/// admission's own writer: replay and the applied claim read it, never a
/// later policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueReviewAdmission {
    /// The batch whose stack admitted it.
    pub batch: String,
    /// Its own catalog's critics were required, and met.
    pub explicit: bool,
    /// The digest of the vault policy catalog it was held to and met, by its
    /// critics or the owner's Approve; `None` when no policy applied.
    pub policy: Option<String>,
}

/// What a removed-name person review is bound to (FIX 4365): the red
/// verdict, its baseline, the exact tree it judged and every proposal on
/// that tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractReviewEvidence {
    /// The content id of the verdict that lists the removed names.
    pub verdict: String,
    /// The contract baseline the verdict compared against.
    pub baseline: String,
    /// The batch whose staged path the verdict judged.
    pub batch: String,
    /// The exact candidate tree the verdict judged.
    pub tree: String,
    /// Every proposal on that tree, as hex ids in batch order.
    pub proposals: Vec<String>,
}

/// One person review a removed public name routed a proposal to (FIX
/// 4365). Its decision answers this evidence only. Approve leaves the
/// verdict red. Reject requires a repair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractReviewRequest {
    pub evidence: ContractReviewEvidence,
    /// The person's decision and its receipt, once a person decided.
    pub decision: Option<ContractReviewSettlement>,
}

/// A person's decision on a removed-name review, with its receipt claim
/// (FIX 4365). An actor erase names no one in its place. The decision and
/// its time stay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractReviewSettlement {
    pub receipt: EntityId,
    /// The owner who decided; [`ProposalActor::Erased`] once that actor
    /// was erased.
    pub actor: ProposalActor,
    pub decision: RepoProposalDecision,
    pub settled_at: u64,
}
