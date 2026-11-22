//! Doors to the two erase paths a served claim-refinement door test drives
//! beside the facade (FIX [SKILL-HUB-PROMOTION-VERBS]): a peer's replayed
//! tombstone, which the mounted `GET /ws` replay applies, and the replicated
//! CLAIM put an erased id must stay fenced against.

use crate::Vault;
#[cfg(feature = "sync")]
use crate::claim::{ClaimBody, encode_claim_body};
use crate::deletion::{TombstoneReason, TombstoneValueV2};
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::{registry::ENTITY_TYPE_CLAIM, temporal::TimeRange};

/// Applies a peer's tombstone of `id` with `reason`, deleted at
/// `deleted_at`, as a sync replay applies it. It answers whether the apply
/// erased local state: a soft value that scrubbed the row, or a hard value
/// that purged it.
///
/// # Errors
///
/// The replay's own refusal.
pub fn apply_replayed_tombstone(
    vault: &Vault,
    id: &EntityId,
    reason: TombstoneReason,
    deleted_at: u64,
) -> Result<bool> {
    let tombstone = TombstoneValueV2 {
        reason,
        deleted_at,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode();
    Ok(vault
        .apply_replayed_tombstone(id, &tombstone)?
        .changed_local_state())
}

/// Commits `body` at `id` as a replicated CLAIM put at `at`, as a sync pass
/// stores a peer's row.
///
/// # Errors
///
/// The batch chokepoint's refusal, as an erased id's fence gives it.
#[cfg(feature = "sync")]
pub fn put_replicated_claim(vault: &Vault, id: &EntityId, body: &ClaimBody, at: u64) -> Result<()> {
    vault
        .batch()
        .put_replicated(
            id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: at, end: at },
            at,
            None,
            &encode_claim_body(body)?,
        )
        .commit()
}
