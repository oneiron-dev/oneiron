//! What a contribution check measures (FIX 2870, OF-542; ARCH-0037
//! #lineage-credit): a loaded skill, checked with and without its body, or
//! one derived-from edge the run actually used, checked with and without its
//! source, the ancestor. One experiment identity serves both: the run, the
//! exact credited outcome, its goal revision, the axis and the target. The
//! check's key, its receipt, its sample draw and the fork pair's key all read
//! it, so two outcomes or two targets of one run never share a measurement.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::contribution::{ContributionCandidate, ContributionFork, ContributionPair};
use crate::entity_id::EntityId;
use crate::receipt::PackAttributionFields;

/// What one contribution check measures. A loaded skill's checks order
/// before a used edge's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionTarget {
    /// A skill the run loaded: its step with and without the skill's body.
    LoadedSkill(EntityId),
    /// A derived-from edge the run actually used: its step with and without
    /// the edge's source.
    UsedEdge { derived: EntityId, source: EntityId },
}

impl ContributionTarget {
    /// The entity whose exposure the fork without it leaves out: the skill,
    /// or the edge's source.
    #[must_use]
    pub const fn removed(self) -> EntityId {
        match self {
            Self::LoadedSkill(skill) => skill,
            Self::UsedEdge { source, .. } => source,
        }
    }

    /// The target as a check key spells it: the skill's hex, or the edge's
    /// two ends' hex joined by `>`.
    fn spelled(self) -> String {
        match self {
            Self::LoadedSkill(skill) => skill.to_hex(),
            Self::UsedEdge { derived, source } => {
                format!("{}>{}", derived.to_hex(), source.to_hex())
            }
        }
    }

    /// The target's bytes in an identity hash: a tag, then its ids.
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::LoadedSkill(skill) => [b"s".as_slice(), skill.as_bytes().as_slice()].concat(),
            Self::UsedEdge { derived, source } => [
                b"e".as_slice(),
                derived.as_bytes().as_slice(),
                source.as_bytes().as_slice(),
            ]
            .concat(),
        }
    }
}

/// The used edge an ancestor check measured, as recorded: each end `None`
/// once that entity is erased (FIX 8988).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckedEdge {
    pub derived: Option<EntityId>,
    pub source: Option<EntityId>,
}

impl ContributionPair {
    /// The pair `candidate`'s forks make, finished at `at`.
    #[must_use]
    pub fn for_candidate(
        candidate: &ContributionCandidate,
        with_skill: ContributionFork,
        without_skill: ContributionFork,
        at: u64,
    ) -> Self {
        Self {
            attempt_receipt: candidate.attempt_receipt.clone(),
            outcome_receipt: candidate.outcome_receipt.clone(),
            skill: Some(candidate.skill),
            edge: match candidate.target {
                ContributionTarget::LoadedSkill(_) => None,
                ContributionTarget::UsedEdge { derived, source } => Some(CheckedEdge {
                    derived: Some(derived),
                    source: Some(source),
                }),
            },
            axis: candidate.axis.clone(),
            goal_revision: candidate.goal_revision.clone(),
            anchor: candidate.anchor,
            with_skill,
            without_skill,
            at,
        }
    }

    /// What the pair measured; `None` once an erase cleared an id it names.
    #[must_use]
    pub fn target(&self) -> Option<ContributionTarget> {
        match self.edge {
            None => self.skill.map(ContributionTarget::LoadedSkill),
            Some(CheckedEdge {
                derived: Some(derived),
                source: Some(source),
            }) => Some(ContributionTarget::UsedEdge { derived, source }),
            Some(_) => None,
        }
    }
}

/// One contribution experiment's identity.
pub(crate) struct Experiment<'a> {
    attempt_receipt: &'a str,
    outcome_receipt: &'a str,
    goal_revision: Option<&'a str>,
    axis: &'a str,
    target: ContributionTarget,
}

impl<'a> Experiment<'a> {
    pub(crate) fn of_candidate(candidate: &'a ContributionCandidate) -> Self {
        Self {
            attempt_receipt: &candidate.attempt_receipt,
            outcome_receipt: &candidate.outcome_receipt,
            goal_revision: candidate.goal_revision.as_deref(),
            axis: &candidate.axis,
            target: candidate.target,
        }
    }

    pub(super) fn of_pair(pair: &'a ContributionPair, target: ContributionTarget) -> Self {
        Self {
            attempt_receipt: &pair.attempt_receipt,
            outcome_receipt: &pair.outcome_receipt,
            goal_revision: pair.goal_revision.as_deref(),
            axis: &pair.axis,
            target,
        }
    }

    pub(super) const fn target(&self) -> ContributionTarget {
        self.target
    }

    /// A hasher under `context` holding the identity, each part length
    /// prefixed, for a caller to add its own parts to.
    pub(crate) fn hasher(&self, context: &str) -> blake3::Hasher {
        let mut hash = blake3::Hasher::new_derive_key(context);
        let target = self.target.bytes();
        for part in [
            self.attempt_receipt.as_bytes(),
            self.outcome_receipt.as_bytes(),
            self.axis.as_bytes(),
            target.as_slice(),
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        match self.goal_revision {
            None => {
                hash.update(&[0]);
            }
            Some(revision) => {
                hash.update(&[1]);
                hash.update(&(revision.len() as u64).to_be_bytes());
                hash.update(revision.as_bytes());
            }
        }
        hash
    }

    /// The check row's key: attempt receipt NUL target NUL a digest of the
    /// whole identity, so the run's checks share a prefix and an erase can
    /// read the ids the target spells.
    pub(super) fn check_key(&self) -> String {
        let digest = self.hasher("oneiron contribution check key v2").finalize();
        format!(
            "{}\0{}\0{}",
            self.attempt_receipt,
            self.target.spelled(),
            digest.to_hex()
        )
    }

    /// The check's own receipt id: the identity and both forks.
    pub(super) fn check_receipt(&self, pair: &ContributionPair) -> String {
        let mut hash = self.hasher("oneiron contribution check v2");
        for receipt in [&pair.with_skill.receipt, &pair.without_skill.receipt] {
            hash.update(&(receipt.len() as u64).to_be_bytes());
            hash.update(receipt.as_bytes());
        }
        format!("contribution:{}", hash.finalize().to_hex())
    }

    /// Whether the experiment falls in the sample at `rate`: a fixed draw
    /// from its identity, so a rerun samples the same ones.
    pub(super) fn sampled(&self, rate: f64) -> bool {
        let draw = self.hasher("oneiron contribution sample v2").finalize();
        let mut head = [0_u8; 8];
        head.copy_from_slice(&draw.as_bytes()[..8]);
        #[allow(clippy::cast_precision_loss)]
        let unit = u64::from_be_bytes(head) as f64 / u64::MAX as f64;
        unit < rate
    }
}

/// Each used edge `fields` holds that no check has measured yet, as a
/// target.
pub(super) fn unchecked_edges(fields: &PackAttributionFields) -> BTreeSet<ContributionTarget> {
    fields
        .used_edges
        .iter()
        .filter(|edge| edge.check.is_none())
        .map(|edge| ContributionTarget::UsedEdge {
            derived: edge.derived,
            source: edge.source,
        })
        .collect()
}
