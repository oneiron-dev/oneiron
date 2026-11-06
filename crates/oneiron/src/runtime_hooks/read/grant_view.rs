//! What a hook's current grant shows of one stored row (ARCH-0080 §6): the
//! one check its scoped reads, its verdict's evidence (FIX 10068) and its
//! verb input (FIX 10084) share, on top of what the reading key admits.

use crate::claim::{ClaimReadStatus, PointRead, ReadRow, ScopedReadResult};
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

/// The evidence views of a hook's `ai.verdict` that its grant shows (FIX
/// 10068), judged on the very views `memory`, the grant's reader, hydrated:
/// each is the row its id names in one read of the reader's lane, shown
/// when [`shows_row`] says so. The views the grant does not show come back
/// apart by id, so the host can name them without passing their bodies on.
/// A grant that names no predicate and no world shows every view.
///
/// # Errors
///
/// The reader's lane not building, a view whose id does not parse, or the
/// read failing.
pub fn hook_evidence_views(
    memory: &Memory<'_>,
    grant: &HookGrant,
    views: Vec<EntityView>,
) -> MemoryResult<(Vec<EntityView>, Vec<EntityId>)> {
    if views.is_empty() || shows_non_claim(grant) {
        return Ok((views, Vec::new()));
    }
    let ids = views
        .iter()
        .map(|view| EntityId::from_hex(&view.id_hex))
        .collect::<Result<Vec<_>>>()?;
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let reads: Vec<PointRead<'_>> = ids.iter().map(|id| PointRead::id(*id)).collect();
    let rows = lane.read(&reads, None)?.value;
    let mut shown = Vec::with_capacity(views.len());
    let mut withheld = Vec::new();
    for ((view, id), row) in views.into_iter().zip(ids).zip(rows) {
        let admitted = match &row {
            Some(row) => shows_row(grant, row)?,
            None => false,
        };
        if admitted {
            shown.push(view);
        } else {
            withheld.push(id);
        }
    }
    Ok((shown, withheld))
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
