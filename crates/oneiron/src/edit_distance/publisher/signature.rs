//! Content-free issue signature record and its judged-outcome inlet.

use std::collections::BTreeMap;

use super::{CountKey, IssueCategory, PublisherError, PublisherResult};
use crate::entity_id::EntityId;
use crate::identity_topology::ProposalOutcome;
use crate::receipt::ReceiptRecord;
use crate::settings::model_versioning::{ModelStackId, ModelStackRegistry};

/// Length of a signature's `content_hash` — blake3 rendered as lowercase hex,
/// the same shape ED-01's Δ refs carry.
pub const CONTENT_HASH_LEN: usize = 64;

/// A content-free issue signature (ARCH-0056 §9, UP rung 1).
///
/// Fields are private and [`IssueSignature::new`] is the only door; see the
/// module docs for why that is what makes the leak structural.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueSignature {
    pub(super) category: IssueCategory,
    pub(super) artifact: EntityId,
    pub(super) version: u32,
    pub(super) model_id: ModelStackId,
    pub(super) counts: BTreeMap<CountKey, u32>,
    pub(super) content_hash: String,
}

impl IssueSignature {
    /// The only door.
    ///
    /// `registry` is the authority `model_id` is checked against — see the
    /// worklog's D1: membership cannot be tested without it, and an unchecked
    /// model id is precisely the smuggling channel this door exists to close.
    ///
    /// # Errors
    ///
    /// [`PublisherError::UnknownModelStack`] for a model id the registry does
    /// not serve, [`PublisherError::DuplicateCountKey`] for a repeated count
    /// name, [`PublisherError::MalformedContentHash`] for a hash that is not
    /// exactly [`CONTENT_HASH_LEN`] lowercase hex characters.
    pub fn new(
        category: IssueCategory,
        artifact: EntityId,
        version: u32,
        registry: &ModelStackRegistry,
        model_id: &str,
        counts: &[(CountKey, u32)],
        content_hash: &str,
    ) -> PublisherResult<Self> {
        let model_id: ModelStackId = model_id
            .parse()
            .map_err(|_| PublisherError::UnknownModelStack)?;
        if registry.get(&model_id).is_none() {
            return Err(PublisherError::UnknownModelStack);
        }
        if !is_content_hash(content_hash) {
            return Err(PublisherError::MalformedContentHash);
        }
        let mut tallies = BTreeMap::new();
        for (key, value) in counts {
            if tallies.insert(*key, *value).is_some() {
                return Err(PublisherError::DuplicateCountKey);
            }
        }
        Ok(Self {
            category,
            artifact,
            version,
            model_id,
            counts: tallies,
            content_hash: content_hash.to_owned(),
        })
    }

    /// The defect class.
    #[must_use]
    pub const fn category(&self) -> IssueCategory {
        self.category
    }

    /// The shipped artifact this is about.
    #[must_use]
    pub const fn artifact(&self) -> EntityId {
        self.artifact
    }

    /// That artifact's version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The registered model stack behind the judged work.
    #[must_use]
    pub fn model_id(&self) -> &ModelStackId {
        &self.model_id
    }

    /// The pattern hash.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// One tally; `None` when this signature carries no count under `key`.
    #[must_use]
    pub fn count(&self, key: CountKey) -> Option<u32> {
        self.counts.get(&key).copied()
    }

    /// Every tally, in [`CountKey`] order.
    pub fn counts(&self) -> impl Iterator<Item = (CountKey, u32)> + '_ {
        self.counts.iter().map(|(key, value)| (*key, *value))
    }
}

/// Whether `value` is exactly [`CONTENT_HASH_LEN`] lowercase hex characters.
pub(super) fn is_content_hash(value: &str) -> bool {
    value.len() == CONTENT_HASH_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Tallies the closed count set over judged proposal-outcome receipts.
///
/// This is the judged-cluster inlet. ED-03/ED-04's clusters do not exist yet,
/// so the door binds the surface that does: `outcome` on a [`ReceiptRecord`],
/// parsed through [`ProposalOutcome`] (ARCH-0055 r7's ratified three states).
/// When the cluster types land they pass their own members' receipts through
/// this same door and nothing here changes.
///
/// Records whose outcome is not a proposal outcome are skipped rather than
/// raised — a mixed receipt slice is the normal case for a caller that queried
/// by artifact, not by kind.
#[must_use]
pub fn tally_judged_outcomes(receipts: &[ReceiptRecord]) -> [(CountKey, u32); 3] {
    let mut judged = 0_u32;
    let mut amended = 0_u32;
    let mut rejected = 0_u32;
    for outcome in receipts
        .iter()
        .filter_map(|record| ProposalOutcome::parse(&record.outcome))
    {
        judged = judged.saturating_add(1);
        match outcome {
            ProposalOutcome::ApprovedAmended => amended = amended.saturating_add(1),
            ProposalOutcome::Rejected => rejected = rejected.saturating_add(1),
            ProposalOutcome::ApprovedUntouched => {}
        }
    }
    [
        (CountKey::Judged, judged),
        (CountKey::Amended, amended),
        (CountKey::Rejected, rejected),
    ]
}
