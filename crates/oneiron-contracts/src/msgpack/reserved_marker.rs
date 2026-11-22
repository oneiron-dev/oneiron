//! The marker walk behind [`super::decode`]'s refusal of the reserved marker `0xc1`.
//!
//! rmpv 1.3 reads `0xc1` as nil, so without this walk `0xc1` and `0xc0` decode to the same
//! value. No writer emits `0xc1` (rmpv and rmp-serde never write it; rmp-serde already
//! refuses it on read), so the reader refuses it wherever a value starts. The walk reads
//! markers only: string, binary and extension payloads (the extension type byte included)
//! are skipped, so a `0xc1` byte inside one is data and reads as before.
//!
//! `oneiron_base::msgpack_shape` walks the same marker table for its size budget; that crate
//! depends on this one, so the table is not shared from there.

/// The marker MessagePack reserves and never assigns.
const RESERVED: u8 = 0xc1;

/// The offset of the first reserved marker in the value at the start of `bytes`, or `None`
/// when it holds none. Bytes that stop being MessagePack also give `None`: [`super::decode`]
/// walks only bytes rmpv has already read as exactly one value.
pub(super) fn reserved_marker_offset(bytes: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    // Values still to read: the top value, then each container's members as it opens.
    let mut owed = 1u64;
    while owed > 0 {
        owed -= 1;
        let marker = *bytes.get(at)?;
        if marker == RESERVED {
            return Some(at);
        }
        at = at.checked_add(1)?;
        let (skip, members) = step(marker, bytes, at)?;
        at = at.checked_add(skip).filter(|end| *end <= bytes.len())?;
        owed = owed.checked_add(members)?;
    }
    None
}

/// A big-endian length of `width` bytes at `at`.
fn length(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    let field = bytes.get(at..at.checked_add(width)?)?;
    Some(
        field
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

/// For one marker other than [`RESERVED`]: the bytes to skip after it (length fields,
/// fixed-width data, payloads) and the values it opens (array members, map keys and values).
fn step(marker: u8, bytes: &[u8], at: usize) -> Option<(usize, u64)> {
    // A string, binary or extension: a `width`-byte length, `extra` bytes (the extension
    // type), then the payload.
    let sized = |width: usize, extra: usize| -> Option<(usize, u64)> {
        let len = usize::try_from(length(bytes, at, width)?).ok()?;
        Some((width.checked_add(extra)?.checked_add(len)?, 0))
    };
    // An array (`per` 1) or a map (`per` 2) with a `width`-byte count.
    let counted = |width: usize, per: u64| -> Option<(usize, u64)> {
        Some((width, length(bytes, at, width)?.checked_mul(per)?))
    };
    match marker {
        // positive and negative fixint, nil, false, true
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Some((0, 0)),
        0x80..=0x8f => Some((0, 2 * u64::from(marker & 0x0f))),
        0x90..=0x9f => Some((0, u64::from(marker & 0x0f))),
        0xa0..=0xbf => Some((usize::from(marker & 0x1f), 0)),
        0xc4 | 0xd9 => sized(1, 0),
        0xc5 | 0xda => sized(2, 0),
        0xc6 | 0xdb => sized(4, 0),
        0xc7 => sized(1, 1),
        0xc8 => sized(2, 1),
        0xc9 => sized(4, 1),
        0xcc | 0xd0 => Some((1, 0)),
        0xcd | 0xd1 => Some((2, 0)),
        0xca | 0xce | 0xd2 => Some((4, 0)),
        0xcb | 0xcf | 0xd3 => Some((8, 0)),
        // fixext 1, 2, 4, 8, 16: the type byte, then the data
        0xd4 => Some((2, 0)),
        0xd5 => Some((3, 0)),
        0xd6 => Some((5, 0)),
        0xd7 => Some((9, 0)),
        0xd8 => Some((17, 0)),
        0xdc => counted(2, 1),
        0xdd => counted(4, 1),
        0xde => counted(2, 2),
        0xdf => counted(4, 2),
        // RESERVED: the caller stops before it.
        0xc1 => None,
    }
}
