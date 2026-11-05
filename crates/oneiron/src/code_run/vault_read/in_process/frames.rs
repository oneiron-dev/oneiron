//! A batch hydrate's named reads, frame by frame (FIX 11697): a batch past
//! one frame is read in order, every ref served, none refused for its count.

use crate::claim::{NamedSlot, PointRead, ScopedRead, ScopedReadResult};

use super::super::types::VAULT_READ_MAX_BATCH_REFS;

/// Reads `refs` in frames of [`VAULT_READ_MAX_BATCH_REFS`]: each frame in its
/// own snapshot, the slots in the order the refs were named, and one receipt
/// combining each frame's (`restrict_with`), so neither its ceiling nor its
/// applied scope grows and every frame's suppressed rows count. A batch of
/// no valid ref reads one empty frame, as a single read did.
pub(super) fn read_named_frames(
    scoped_read: &ScopedRead<'_>,
    refs: &[PointRead<'_>],
) -> crate::Result<ScopedReadResult<Vec<NamedSlot>>> {
    let mut frames = refs.chunks(VAULT_READ_MAX_BATCH_REFS);
    let mut read = scoped_read.read_named(frames.next().unwrap_or_default(), None)?;
    for frame in frames {
        let next = scoped_read.read_named(frame, None)?;
        read.receipt.restrict_with(&next.receipt);
        read.value.extend(next.value);
    }
    Ok(read)
}
