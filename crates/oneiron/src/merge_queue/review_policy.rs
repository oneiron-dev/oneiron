//! Core half of `merge_queue::review_policy`: its store-layer items live in `oneiron_store::merge_queue::review_policy` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::review_policy::*;

use crate::error::{Error, Result};
use crate::repo_mutation::proposal::RepoProposalReview;
use crate::side_table::{self, Named, SideTable};
use crate::store::critic_lens::LensCatalog;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// The singleton policy row. Key: ().
const MERGE_QUEUE_REVIEW_POLICY: SideTable<(), QueueReviewPolicy, Named> =
    SideTable::new(&side_table::MERGE_QUEUE_REVIEW_POLICY);

/// Whether a masked copy of a `MERGE_QUEUE_REVIEW_POLICY` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn merge_queue_review_policy_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<QueueReviewPolicy, Named>(bytes)
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
