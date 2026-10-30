//! The vault's opt-in review policy for merge queue work (FIX 8268, Engine
//! 10-22 03:1x by canon code-in-oneiron.md ~64/~85).
//!
//! A vault with no review policy lands its queue work on green: no critic
//! hold, and the same checked queue as ever (fast-tested head, slow-tested
//! green, bound checker receipts; with no usable checker the work waits as
//! NeedsConfiguration). A review policy is an opt-in a live Owner, or his
//! agent under its own Grant, sets for the whole vault with
//! `vault.code.merge_queue.review_policy.set`. While it is set, work that
//! inherits it (a proposal that named no catalog of its own) waits for
//! critics on its lenses, or for the owner's Approve; its limits are the
//! owner's to override, never floors. Clearing it releases those waits on
//! work the queue has not admitted yet. A proposal's own explicit catalog
//! stays its requirement, and a set policy applies beside it, never
//! weakened by an easier catalog.
//!
//! [`queue_review_requirement_in_txn`] is the one place a queue decision
//! reads the policy. Only a successful read that finds no row selects the
//! default. A present row that does not read holds inherited work as
//! [`REVIEW_POLICY_UNREADABLE`] until an owner sets or clears it; a store
//! failure stays a failure.

use serde::{Deserialize, Serialize};

use crate::critic::LensCatalog;
use crate::error::{Error, Result};
use crate::repo_mutation::proposal::RepoProposalReview;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

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

/// Today's distinct accepting critics a reviewed proposal needs.
pub(crate) const DEFAULT_QUEUE_REVIEW_CRITICS: u32 = 2;
/// Today's most critic votes one proposal keeps.
pub(crate) const DEFAULT_QUEUE_REVIEW_VOTES: u32 = 64;

const fn default_critics() -> u32 {
    DEFAULT_QUEUE_REVIEW_CRITICS
}

const fn default_votes() -> u32 {
    DEFAULT_QUEUE_REVIEW_VOTES
}

/// A review policy's limits: defaults the owner may override, never floors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QueueReviewThresholds {
    /// Distinct accepting critics a proposal needs. Default 2.
    #[serde(default = "default_critics")]
    pub critics: u32,
    /// The most critic votes one proposal keeps under the policy. Default 64.
    #[serde(default = "default_votes")]
    pub votes: u32,
}

impl Default for QueueReviewThresholds {
    fn default() -> Self {
        Self {
            critics: DEFAULT_QUEUE_REVIEW_CRITICS,
            votes: DEFAULT_QUEUE_REVIEW_VOTES,
        }
    }
}

/// The vault's one review policy row: the lenses inherited queue work must
/// pass, its limits, and who set it when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QueueReviewPolicy {
    pub catalog: LensCatalog,
    pub thresholds: QueueReviewThresholds,
    /// The Owner or Granted agent who set it; `None` once that actor was
    /// erased (FIX 8519): the policy stands, its setter no longer named.
    pub set_by: Option<EntityId>,
    /// When it was set, Unix seconds.
    pub set_at: u64,
}

/// The singleton policy row. Key: ().
const MERGE_QUEUE_REVIEW_POLICY: SideTable<(), QueueReviewPolicy, Named> =
    SideTable::new(&side_table::MERGE_QUEUE_REVIEW_POLICY);

/// A set policy, with the digest of the catalog a vote under it judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveQueueReviewPolicy {
    pub(crate) policy: QueueReviewPolicy,
    /// 64 lower-hex: [`review_catalog_digest`] of its catalog.
    pub(crate) digest: String,
}

/// What the vault's policy row holds, as one read found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredQueueReviewPolicy {
    /// No row: [`REVIEW_POLICY_DEFAULT`].
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
         read, so work that inherits it waits; an Owner sets a policy again, or clears it with \
         null, at vault.code.merge_queue.review_policy.set"
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
    /// The vault's review policy row as `txn` reads it. A row that does not
    /// decode, or whose catalog no longer validates, is
    /// [`StoredQueueReviewPolicy::Unreadable`], never absent.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_review_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<StoredQueueReviewPolicy> {
        let Some(bytes) = MERGE_QUEUE_REVIEW_POLICY.get_bytes(&self.store, txn, &())? else {
            return Ok(StoredQueueReviewPolicy::Absent);
        };
        let policy = match MERGE_QUEUE_REVIEW_POLICY.decode_value(&bytes) {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the vault's merge queue review policy does not read; inherited work holds"
                );
                return Ok(StoredQueueReviewPolicy::Unreadable);
            }
        };
        if crate::critic::triage_critiques(&policy.catalog, &[], &[]).is_err() {
            return Ok(StoredQueueReviewPolicy::Unreadable);
        }
        Ok(StoredQueueReviewPolicy::Set(ActiveQueueReviewPolicy::of(
            policy,
        )?))
    }

    /// [`Self::queue_review_policy_in_txn`] in its own snapshot.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_review_policy(&self) -> Result<StoredQueueReviewPolicy> {
        let txn = self.store.env.read_txn()?;
        self.queue_review_policy_in_txn(&txn)
    }

    /// FIX 8519: an erased actor's id leaves the review policy it set, in
    /// the erase's writer. The policy stands; a row that does not read is
    /// left for an owner to set or clear.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn erase_review_policy_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::typed_body::names_no_actor(self, wtxn, actor)? {
            return Ok(());
        }
        let Some(bytes) = MERGE_QUEUE_REVIEW_POLICY.get_bytes(&self.store, wtxn, &())? else {
            return Ok(());
        };
        let Ok(mut policy) = MERGE_QUEUE_REVIEW_POLICY.decode_value(&bytes) else {
            return Ok(());
        };
        if policy.set_by != Some(*actor) {
            return Ok(());
        }
        policy.set_by = None;
        MERGE_QUEUE_REVIEW_POLICY.put(&self.store, wtxn, &(), &policy)
    }

    /// Sets the vault's review policy in the setter's writer `txn`, or with
    /// `None` clears it. No seed and no history row: the row is the policy.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn put_queue_review_policy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        policy: Option<&QueueReviewPolicy>,
    ) -> Result<()> {
        match policy {
            Some(policy) => MERGE_QUEUE_REVIEW_POLICY.put(&self.store, txn, &(), policy),
            None => MERGE_QUEUE_REVIEW_POLICY
                .delete(&self.store, txn, &())
                .map(drop),
        }
    }
}

/// The actor scrub `MERGE_QUEUE_REVIEW_POLICY` declares (FIX 8519).
///
/// # Errors
/// A store failure.
pub(crate) fn erase_review_policy_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault.erase_review_policy_actor_in_txn(wtxn, actor)
}
