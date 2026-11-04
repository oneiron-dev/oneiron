//! What review a proposal is held to, and whether it met it (FIX 8268).
//!
//! A proposal names its own catalog (`Explicit`: the owner's, sent at his
//! door, or a host's) or none (`VaultDefault`): then the vault's review
//! policy as it stands when the queue decides, and with none set no critic
//! hold at all. A critic's vote on a lens of the proposal's own catalog is
//! kept as before; a vote on a lens of the set vault policy is kept with the
//! digest of the catalog it judged, so a later policy cannot reinterpret
//! it. The owner's Approve settles a vault policy, never an explicit
//! catalog's critics. Only an explicit catalog makes a proposal eligible
//! outside its queue: a vault-default proposal lands through its merge queue
//! alone, whose stack admission seals the review each member met.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::settlement::RepoProposalDecision;
use super::{RepoProposal, invalid};
use crate::critic::{CriticLens, CritiqueArtifact, CritiqueVerdict, LensCatalog, triage_critiques};
use crate::error::{Error, Result};
use crate::merge_queue::{
    ActiveQueueReviewPolicy, QueueReviewRequirement, StoredQueueReviewPolicy,
    review_policy_unreadable_hold,
};

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

/// One critic vote on a lens of the vault policy, with the digest of the
/// policy catalog it judged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoProposalCritique {
    /// 64 lower-hex: the judged policy catalog's digest.
    pub catalog_digest: String,
    pub critique: CritiqueArtifact,
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

/// What a queue decision waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueReviewWait {
    /// Critics on a lens it is held to, or the owner's Approve of a policy.
    Critics,
    /// The vault policy it inherits does not read.
    Unreadable,
}

impl QueueReviewWait {
    /// The driver's hold text for proposal `proposal`.
    pub(crate) fn hold(self, proposal: &str) -> String {
        match self {
            Self::Critics => {
                format!("proposal {proposal} lacks an unused unanimous critic approval")
            }
            Self::Unreadable => {
                format!("{} (proposal {proposal})", review_policy_unreadable_hold())
            }
        }
    }

    /// The stack admission's refusal.
    pub(crate) fn refusal(self) -> Error {
        match self {
            Self::Critics => invalid("every stack member needs unused unanimous critic approval"),
            Self::Unreadable => Error::Refused(review_policy_unreadable_hold()),
        }
    }
}

/// Whether two votes are the same critic's on the same lens.
fn same_vote(stored: &CritiqueArtifact, critique: &CritiqueArtifact) -> bool {
    stored.provenance.critic_ref == critique.provenance.critic_ref
        && stored.lens_id == critique.lens_id
        && stored.domain == critique.domain
}

impl RepoProposal {
    /// The lens a critic may vote on here: its own catalog's, else the set
    /// vault policy's.
    pub(crate) fn review_lens<'a>(
        &'a self,
        policy: &'a StoredQueueReviewPolicy,
        id: &str,
        domain: &str,
    ) -> Option<&'a CriticLens> {
        self.review
            .catalog()
            .and_then(|own| own.lens(id, domain))
            .or_else(|| match policy {
                StoredQueueReviewPolicy::Set(active) => active.policy.catalog.lens(id, domain),
                StoredQueueReviewPolicy::Absent | StoredQueueReviewPolicy::Unreadable => None,
            })
    }

    /// Keeps one authenticated critic vote: on a lens of its own catalog,
    /// every one (its writer asks past a threshold row, rule 5, FIX 8837),
    /// else on a lens of the vault policy `policy` read in the same writer,
    /// bound to that catalog's digest (at most the policy's `votes`). A
    /// critic's vote under one binding is immutable; an identical repeat,
    /// full proposal or not, keeps nothing new and answers `false`.
    ///
    /// # Errors
    /// A proposal full under the vault policy's `votes`, a changed vote, a
    /// lens outside its review, a vault policy that does not read, or a
    /// triage that refuses.
    pub(crate) fn record_critique(
        &mut self,
        critique: CritiqueArtifact,
        policy: &StoredQueueReviewPolicy,
    ) -> Result<bool> {
        if self
            .review
            .catalog()
            .is_some_and(|own| own.lens(&critique.lens_id, &critique.domain).is_some())
        {
            if let Some(existing) = self.critiques.iter().find(|c| same_vote(c, &critique)) {
                return if existing == &critique {
                    Ok(false)
                } else {
                    Err(invalid("critic vote is immutable"))
                };
            }
            self.critiques.push(critique);
            self.triage()?;
            return Ok(true);
        }
        let active = match policy {
            StoredQueueReviewPolicy::Set(active)
                if active
                    .policy
                    .catalog
                    .lens(&critique.lens_id, &critique.domain)
                    .is_some() =>
            {
                active
            }
            StoredQueueReviewPolicy::Unreadable => {
                return Err(QueueReviewWait::Unreadable.refusal());
            }
            StoredQueueReviewPolicy::Set(_) | StoredQueueReviewPolicy::Absent => {
                return Err(invalid(
                    "critique names a lens outside the review this proposal is held to",
                ));
            }
        };
        let mut kept = 0_usize;
        let mut repeat = None;
        for vote in &self.policy_critiques {
            if vote.catalog_digest != active.digest {
                continue;
            }
            kept += 1;
            if repeat.is_none() && same_vote(&vote.critique, &critique) {
                repeat = Some(vote.critique == critique);
            }
        }
        // An exact retry answers before the owner's vote limit (FIX 8837).
        if let Some(identical) = repeat {
            return if identical {
                Ok(false)
            } else {
                Err(invalid("critic vote is immutable"))
            };
        }
        if kept >= active.policy.thresholds.votes as usize {
            return Err(invalid(
                "critic is unbound, self-reviewing, or proposal is closed",
            ));
        }
        self.policy_critiques.push(RepoProposalCritique {
            catalog_digest: active.digest.clone(),
            critique,
        });
        triage_critiques(&active.policy.catalog, &self.policy_votes(active), &[])?;
        Ok(true)
    }

    /// Whether it met `requirement` now: the review a stack admitting it in
    /// `batch` seals, or what it waits for.
    ///
    /// # Errors
    /// A catalog or critique that no longer validates.
    pub(crate) fn queue_review_admission(
        &self,
        requirement: &QueueReviewRequirement,
        batch: &str,
    ) -> Result<std::result::Result<QueueReviewAdmission, QueueReviewWait>> {
        let (explicit, policy) = match requirement {
            QueueReviewRequirement::LandOnGreen => (false, None),
            QueueReviewRequirement::Unreadable => return Ok(Err(QueueReviewWait::Unreadable)),
            QueueReviewRequirement::Review { explicit, policy } => {
                if *explicit && !self.eligible()? {
                    return Ok(Err(QueueReviewWait::Critics));
                }
                if let Some(active) = policy
                    && !self.owner_approved()
                    && !self.policy_eligible(active)?
                {
                    return Ok(Err(QueueReviewWait::Critics));
                }
                (
                    *explicit,
                    policy.as_ref().map(|active| active.digest.clone()),
                )
            }
        };
        Ok(Ok(QueueReviewAdmission {
            batch: batch.to_owned(),
            explicit,
            policy,
        }))
    }

    /// Whether the stack `batch` admitted it under a review it still holds:
    /// the review its admission sealed (an explicit catalog's critics judged
    /// again, a vault policy as sealed), or for a stack admitted before FIX
    /// 8268, its own catalog's critics.
    ///
    /// # Errors
    /// A catalog or critique that no longer validates.
    pub(crate) fn stack_review_admitted(&self, batch: &str) -> Result<bool> {
        match &self.queue_review {
            Some(sealed) if sealed.batch == batch => Ok(!sealed.explicit || self.eligible()?),
            Some(_) => Ok(false),
            None => self.eligible(),
        }
    }

    /// Whether an owner settled it Approve: that settles a vault policy.
    fn owner_approved(&self) -> bool {
        self.settlement
            .as_ref()
            .is_some_and(|settled| settled.decision == RepoProposalDecision::Approve)
    }

    /// The votes that judged `active`'s catalog: those kept under its
    /// digest, and a vote on its own catalog's lens whose definition the
    /// policy holds unchanged.
    fn policy_votes(&self, active: &ActiveQueueReviewPolicy) -> Vec<CritiqueArtifact> {
        let catalog = &active.policy.catalog;
        let own = self.review.catalog();
        self.policy_critiques
            .iter()
            .filter(|vote| vote.catalog_digest == active.digest)
            .map(|vote| vote.critique.clone())
            .chain(
                self.critiques
                    .iter()
                    .filter(|critique| {
                        let theirs = catalog.lens(&critique.lens_id, &critique.domain);
                        theirs.is_some()
                            && own.and_then(|own| own.lens(&critique.lens_id, &critique.domain))
                                == theirs
                    })
                    .cloned(),
            )
            .collect()
    }

    /// The vault policy's own rule over [`Self::policy_votes`]: its
    /// `critics` distinct counted critics, every lens covered, every vote an
    /// in-scope Accept and an Accept triage.
    fn policy_eligible(&self, active: &ActiveQueueReviewPolicy) -> Result<bool> {
        let catalog = &active.policy.catalog;
        let votes = self.policy_votes(active);
        let distinct = votes
            .iter()
            .filter(|critique| self.counts_toward_quorum(critique))
            .map(|critique| critique.provenance.critic_ref.as_str())
            .collect::<BTreeSet<_>>();
        Ok(distinct.len() >= active.policy.thresholds.critics as usize
            && catalog.lenses.iter().all(|lens| {
                votes
                    .iter()
                    .any(|critique| critique.lens_id == lens.id && critique.domain == lens.domain)
            })
            && votes.iter().all(|critique| {
                critique.verdict == CritiqueVerdict::Accept && !critique.out_of_scope
            })
            && triage_critiques(catalog, &votes, &[])?.verdict == CritiqueVerdict::Accept)
    }
}
