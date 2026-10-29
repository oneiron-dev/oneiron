//! A batch hydrate's named reads, frame by frame (FIX 11125): a batch past
//! one frame is read in order, every ref served, none refused for its count.

use super::super::write_shape::CORE_HYDRATE_FRAME_REFS;

/// Reads `refs` in frames of [`CORE_HYDRATE_FRAME_REFS`]: each frame in its
/// own snapshot, the slots in the order the refs were named, and one receipt
/// combining each frame's (`restrict_with`), so neither its ceiling nor its
/// applied scope grows and every frame's suppressed rows count. A batch of
/// no valid ref reads one empty frame, as a single read did.
pub(super) fn read_named_frames(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    refs: &[oneiron::claim::PointRead<'_>],
) -> oneiron::Result<oneiron::claim::ScopedReadResult<Vec<oneiron::claim::NamedSlot>>> {
    let mut frames = refs.chunks(CORE_HYDRATE_FRAME_REFS);
    let mut read = scoped_read.read_named(frames.next().unwrap_or_default(), None)?;
    for frame in frames {
        let next = scoped_read.read_named(frame, None)?;
        read.receipt.restrict_with(&next.receipt);
        read.value.extend(next.value);
    }
    Ok(read)
}
