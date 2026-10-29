//! A Veo clip's length as the clip states it (FIX 1816): the operation names
//! none, so its MP4 movie header (`moov/mvhd`) is read for its duration and
//! timescale. A clip whose bytes state none is charged by its host.

/// The `mvhd` duration a header writes when it does not know the length.
const UNKNOWN_DURATION: u64 = u32::MAX as u64;

/// `clip`'s length in milliseconds, rounded up, as its movie header states
/// it; `None` when the bytes carry no readable one.
pub(super) fn mp4_duration_ms(clip: &[u8]) -> Option<u64> {
    let movie = mp4_box(clip, b"moov")?;
    let header = mp4_box(movie, b"mvhd")?;
    // Version, then three bytes of flags, then the version's own layout.
    let (timescale, duration) = match *header.first()? {
        0 => (be_u32(header, 12)?, u64::from(be_u32(header, 16)?)),
        1 => (be_u32(header, 20)?, be_u64(header, 24)?),
        _ => return None,
    };
    if timescale == 0 || duration == 0 || duration == UNKNOWN_DURATION {
        return None;
    }
    Some(
        duration
            .saturating_mul(1_000)
            .div_ceil(u64::from(timescale)),
    )
}

/// The body of the first box of `kind` among `boxes`, at their top level.
fn mp4_box<'b>(mut boxes: &'b [u8], kind: &[u8; 4]) -> Option<&'b [u8]> {
    while boxes.len() >= 8 {
        let (header, size) = match be_u32(boxes, 0)? {
            // The box runs to the end of its parent.
            0 => (8, boxes.len()),
            // A 64-bit size follows the type.
            1 => (16, usize::try_from(be_u64(boxes, 8)?).ok()?),
            size => (8, usize::try_from(size).ok()?),
        };
        if size < header || size > boxes.len() {
            return None;
        }
        if boxes.get(4..8)? == kind {
            return boxes.get(header..size);
        }
        boxes = &boxes[size..];
    }
    None
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn be_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}
