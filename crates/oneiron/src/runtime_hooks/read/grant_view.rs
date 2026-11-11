//! What a hook's current grant shows of one stored row (ARCH-0080 §6): the
//! one check its scoped reads, its verdict's evidence (FIX 10068) and its
//! verb input (FIX 10084) share, on top of what the reading key admits.

use crate::claim::{ClaimReadStatus, ReadRow, ScopedReadResult};
use crate::memory::{EntityView, ImageViewRequest, Memory, MemoryError, MemoryResult, PulledImage};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Result};

use super::super::grant::HookGrant;

/// Whether `grant` shows `row`, a row its reading key already admitted: a
/// claim whose predicate and world the grant names; any other row only
/// under a grant that names no predicate and no world, since such a row
/// carries neither. A row with no body shows nothing.
pub(in crate::runtime_hooks) fn shows_row(grant: &HookGrant, row: &ReadRow) -> Result<bool> {
    let Some(body) = row.body.as_deref() else {
        return Ok(false);
    };
    if row.entity_type == ENTITY_TYPE_CLAIM {
        let claim = crate::claim::decode_claim_body(body, true)?;
        return Ok(grant.admits(&claim));
    }
    Ok(shows_non_claim(grant))
}

/// Hydrates a hook's `ai.verdict` evidence through its grant's reader.
/// The grant judges the exact raw revision projected to each view, in that
/// read's snapshot; a later live revision never admits an older body.
/// Additional grant denials return separately by id, without their bodies.
/// An unrestricted grant keeps ordinary hydration unchanged.
///
/// # Errors
///
/// The ordinary hydration errors, including absent or reader-withheld refs,
/// with its read receipt, or the native claim decoder refusing a body.
pub fn hook_evidence_views(
    memory: &Memory<'_>,
    grant: &HookGrant,
    evidence: &[String],
) -> MemoryResult<(Vec<EntityView>, Vec<EntityId>)> {
    if shows_non_claim(grant) {
        return memory
            .hydrate(evidence)
            .map(|read| (read.value, Vec::new()));
    }
    memory
        .hydrate_filtered(evidence, |row| shows_row(grant, row))
        .map(|read| read.value)
}

/// An ASSET has neither a claim predicate nor a world. A hook sees its
/// pixels only when its grant shows non-claim rows, on top of its reader's
/// ordinary admission. The normal image pull keeps its bytes, version,
/// secret masking and served-form receipt together.
///
/// # Errors
///
/// A narrowed grant, an unavailable reader, or the ordinary image pull
/// refusing the handle.
pub fn hook_pull_image(
    memory: &Memory<'_>,
    grant: &HookGrant,
    request: &ImageViewRequest,
) -> MemoryResult<ScopedReadResult<PulledImage>> {
    if !shows_non_claim(grant) {
        return Err(MemoryError::not_found(
            "the hook's grant does not show this image",
        ));
    }
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    crate::memory::pull_image(&lane, request, true)
}

fn shows_non_claim(grant: &HookGrant) -> bool {
    grant.predicates.is_empty() && grant.worlds.is_empty()
}
