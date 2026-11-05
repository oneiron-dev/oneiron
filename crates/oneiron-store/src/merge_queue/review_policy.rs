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

use crate::critic_lens::LensCatalog;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

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
pub const DEFAULT_QUEUE_REVIEW_CRITICS: u32 = 2;
/// Today's most critic votes one proposal keeps.
pub const DEFAULT_QUEUE_REVIEW_VOTES: u32 = 64;

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

/// A set policy, with the digest of the catalog a vote under it judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveQueueReviewPolicy {
    pub policy: QueueReviewPolicy,
    /// 64 lower-hex: [`review_catalog_digest`] of its catalog.
    pub digest: String,
}

/// What the vault's policy row holds, as one read found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredQueueReviewPolicy {
    /// No row: [`REVIEW_POLICY_DEFAULT`].
    Absent,
    Set(ActiveQueueReviewPolicy),
    /// A row that does not decode, or whose catalog no longer validates.
    Unreadable,
}

/// The review one queue decision holds a proposal to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueReviewRequirement {
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
pub fn review_catalog_digest(catalog: &LensCatalog) -> Result<String> {
    let encoded = rmp_serde::to_vec_named(catalog)
        .map_err(|_| Error::InvariantViolation("review policy catalog encoding failed"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:queue-review-policy-catalog:v1");
    hasher.update(&encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

/// The hold text of [`REVIEW_POLICY_UNREADABLE`], naming its way out.
pub fn review_policy_unreadable_hold() -> String {
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
    pub fn of(policy: QueueReviewPolicy) -> Result<Self> {
        let digest = review_catalog_digest(&policy.catalog)?;
        Ok(Self { policy, digest })
    }
}
