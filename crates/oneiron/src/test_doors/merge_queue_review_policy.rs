//! The vault's merge queue review policy as the queue's one policy point reads it (FIX 8268), so
//! the `setting_keyed_a_5` test proves what queue work that inherits the policy waits on.

use crate::error::Result;
use crate::merge_queue::StoredQueueReviewPolicy;
use crate::vault::Vault;

/// What inherited queue work gets under the vault's review policy: `land_on_green`, `review` with
/// the policy's limits (critics, votes), or `held` when the policy does not read.
///
/// # Errors
///
/// Storage errors.
pub fn queue_review_mode(vault: &Vault) -> Result<(&'static str, Option<(u32, u32)>)> {
    Ok(match vault.queue_review_policy()? {
        StoredQueueReviewPolicy::Absent => ("land_on_green", None),
        StoredQueueReviewPolicy::Set(active) => (
            "review",
            Some((
                active.policy.thresholds.critics,
                active.policy.thresholds.votes,
            )),
        ),
        StoredQueueReviewPolicy::Unreadable => ("held", None),
    })
}
