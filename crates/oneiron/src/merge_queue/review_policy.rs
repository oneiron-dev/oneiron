//! The vault's opt-in review policy for merge queue work (FIX 8268, Engine
//! 10-22 03:1x by canon code-in-oneiron.md ~64/~85).
//!
//! A vault with no review policy lands its queue work on green: no critic
//! hold, and the same checked queue as ever (fast-tested head, slow-tested
//! green, bound checker receipts; with no usable checker the work waits as
//! NeedsConfiguration). A review policy is an opt-in for the whole vault:
//! the setting `merge_queue.review_policy` (`setting_keys.rs`; DESIGN
//! 15-setting-primitive, stage 4), which the owner sets with
//! `vault.settings.set`, and an agent whose Grant lists the key's line
//! (`settings.set:merge_queue.review_policy`) sets as a holder. While it is
//! set, work that inherits it (a proposal that named no catalog of its own)
//! waits for critics on its lenses, or for the owner's Approve; its limits
//! are the owner's to override, never floors. Clearing it releases those
//! waits on work the queue has not admitted yet. A proposal's own explicit
//! catalog stays its requirement, and a set policy applies beside it, never
//! weakened by an easier catalog.
//!
//! [`queue_review_requirement_in_txn`] is the one place a queue decision
//! reads the policy. Only a successful read that finds no row, or a row that
//! chooses it, selects the default. A row that does not read holds inherited
//! work as [`REVIEW_POLICY_UNREADABLE`] until the key is set again; a store
//! failure stays a failure.

use super::setting_keys::{QUEUE_REVIEW_POLICY, QueueReviewChoice};
use crate::Vault;
use crate::error::{Error, Result};
use crate::repo_mutation::proposal::RepoProposalReview;
use crate::setting::SettingSource;
use crate::store::critic_lens::LensCatalog;

/// What a vault with no review policy does with its queue work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueReviewDefault {
    /// No critic hold: the same checked queue lands the work on green.
    LandOnGreen,
}

/// CALL `REVIEW_POLICY_DEFAULT` (FIX 8268): with no review policy set, queue
/// work lands on green through the same checks. Never an unchecked land.
pub const REVIEW_POLICY_DEFAULT: QueueReviewDefault = QueueReviewDefault::LandOnGreen;

/// The typed code inherited queue work holds under while the vault's policy
/// row is present but does not read (Engine 10-22 03:5x).
pub const REVIEW_POLICY_UNREADABLE: &str = "review_policy_unreadable";

#[doc(hidden)]
pub(crate) use oneiron_verb_wire::merge_queue::review_policy::{
    DEFAULT_QUEUE_REVIEW_CRITICS, DEFAULT_QUEUE_REVIEW_VOTES,
};
#[doc(hidden)]
pub use oneiron_verb_wire::merge_queue::review_policy::{QueueReviewPolicy, QueueReviewThresholds};

/// A set policy, with the digest of the catalog a vote under it judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveQueueReviewPolicy {
    pub(crate) policy: QueueReviewPolicy,
    /// 64 lower-hex: [`review_catalog_digest`] of its catalog.
    pub(crate) digest: String,
}

/// What the vault's policy setting holds, as one read found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredQueueReviewPolicy {
    /// [`REVIEW_POLICY_DEFAULT`]: no row, or a row that chooses it.
    Absent,
    Set(ActiveQueueReviewPolicy),
    /// A row that does not decode, or whose catalog no longer validates.
    Unreadable,
}

/// The review one queue decision holds a proposal to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QueueReviewRequirement {
    /// No critic hold ([`REVIEW_POLICY_DEFAULT`]).
    LandOnGreen,
    /// Its own explicit catalog's critics (`explicit`), the set vault
    /// policy, or both.
    Review {
        explicit: bool,
        policy: Option<ActiveQueueReviewPolicy>,
    },
    /// Inherited work under a policy row that does not read.
    Unreadable,
}

/// The digest a policy vote binds to: what its catalog asks, never its
/// limits, so a limit change keeps the votes and a lens change does not.
///
/// # Errors
/// A catalog that does not encode.
pub(crate) fn review_catalog_digest(catalog: &LensCatalog) -> Result<String> {
    let encoded = rmp_serde::to_vec_named(catalog)
        .map_err(|_| Error::InvariantViolation("review policy catalog encoding failed"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:queue-review-policy-catalog:v1");
    hasher.update(&encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

/// The hold text of [`REVIEW_POLICY_UNREADABLE`], naming its way out.
pub(crate) fn review_policy_unreadable_hold() -> String {
    format!(
        "{REVIEW_POLICY_UNREADABLE}: the vault's review policy row is present but does not \
         read, so work that inherits it waits; an Owner sets the setting \
         merge_queue.review_policy again, or clears it with null, at vault.settings.set"
    )
}

impl ActiveQueueReviewPolicy {
    /// `policy` with its catalog digest.
    ///
    /// # Errors
    /// A catalog that does not encode.
    pub(crate) fn of(policy: QueueReviewPolicy) -> Result<Self> {
        let digest = review_catalog_digest(&policy.catalog)?;
        Ok(Self { policy, digest })
    }
}

/// The ONE policy point (FIX 8268): what review a queue decision in `txn`
/// holds a proposal of review `review` to. An explicit catalog stays a
/// requirement, with a set policy beside it; inherited work takes the set
/// policy, [`REVIEW_POLICY_DEFAULT`] when the read finds no row, and holds
/// when the row does not read.
///
/// # Errors
/// A store failure; never a missing or unreadable row.
pub(crate) fn queue_review_requirement_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    review: &RepoProposalReview,
) -> Result<QueueReviewRequirement> {
    let explicit = review.catalog().is_some();
    Ok(match vault.queue_review_policy_in_txn(txn)? {
        StoredQueueReviewPolicy::Set(active) => QueueReviewRequirement::Review {
            explicit,
            policy: Some(active),
        },
        // An explicit catalog keeps its own critics; only inherited work
        // reads the default or holds on a row that does not read.
        StoredQueueReviewPolicy::Absent | StoredQueueReviewPolicy::Unreadable if explicit => {
            QueueReviewRequirement::Review {
                explicit,
                policy: None,
            }
        }
        StoredQueueReviewPolicy::Absent => match REVIEW_POLICY_DEFAULT {
            QueueReviewDefault::LandOnGreen => QueueReviewRequirement::LandOnGreen,
        },
        StoredQueueReviewPolicy::Unreadable => QueueReviewRequirement::Unreadable,
    })
}

impl Vault {
    /// The vault's review policy as `txn` reads it (the setting
    /// `merge_queue.review_policy`). A row that does not decode, or whose
    /// catalog no longer validates, is [`StoredQueueReviewPolicy::Unreadable`],
    /// never absent.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_review_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<StoredQueueReviewPolicy> {
        let read = QUEUE_REVIEW_POLICY.read_in_txn(self, txn, &[], None)?;
        if matches!(read.source, SettingSource::Unreadable(_)) {
            tracing::warn!(
                "the vault's merge queue review policy does not read; inherited work holds"
            );
            return Ok(StoredQueueReviewPolicy::Unreadable);
        }
        Ok(match read.value {
            QueueReviewChoice::LandOnGreen => StoredQueueReviewPolicy::Absent,
            QueueReviewChoice::Review(policy) => {
                if crate::critic::triage_critiques(&policy.catalog, &[], &[]).is_err() {
                    return Ok(StoredQueueReviewPolicy::Unreadable);
                }
                StoredQueueReviewPolicy::Set(ActiveQueueReviewPolicy::of(policy)?)
            }
            // Only the read of a row that does not read gives it.
            QueueReviewChoice::Held => StoredQueueReviewPolicy::Unreadable,
        })
    }

    /// [`Self::queue_review_policy_in_txn`] in its own snapshot.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_review_policy(&self) -> Result<StoredQueueReviewPolicy> {
        let txn = self.store.env.read_txn()?;
        self.queue_review_policy_in_txn(&txn)
    }
}
