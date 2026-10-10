//! A structural check of a MessagePack frame before it is decoded.
//!
//! The frame limit bounds encoded bytes, but a nil is one byte and a decoded
//! value is dozens: a 64 MiB frame of nils would unfold into gigabytes. The
//! check walks the markers once, allocates nothing, and refuses a frame
//! that holds too many values, nests too deep, or does not add up.

/// The most values one frame may hold (maps count keys and values).
pub const MAX_FRAME_VALUES: u64 = 1 << 21;
/// The deepest one frame may nest.
pub const MAX_FRAME_DEPTH: usize = 64;

/// # Errors
/// What is wrong with the frame, in a few words.
pub(crate) fn check(bytes: &[u8]) -> Result<(), &'static str> {
    let mut at = 0usize;
    let mut values = 0u64;
    // What each enclosing container still owes, innermost last.
    let mut open: Vec<u64> = Vec::new();
    let mut owed = 1u64;
    loop {
        while owed == 0 {
            match open.pop() {
                Some(parent) => owed = parent,
                None if at == bytes.len() => return Ok(()),
                None => return Err("bytes after the frame's value"),
            }
        }
        owed -= 1;
        values += 1;
        if values > MAX_FRAME_VALUES {
            return Err("the frame holds too many values");
        }
        let marker = *bytes.get(at).ok_or("the frame is cut short")?;
        at += 1;
        let (skip, children) = step(marker, bytes, at)?;
        at = at
            .checked_add(skip)
            .filter(|end| *end <= bytes.len())
            .ok_or("the frame is cut short")?;
        if children > 0 {
            // Every value takes at least one byte.
            if children > (bytes.len() - at) as u64 {
                return Err("a container claims more values than the frame holds");
            }
            if open.len() >= MAX_FRAME_DEPTH {
                return Err("the frame nests too deep");
            }
            open.push(owed);
            owed = children;
        }
    }
}

/// A big-endian length of `width` bytes at `at`.
fn length(bytes: &[u8], at: usize, width: usize) -> Result<usize, &'static str> {
    let field = bytes
        .get(at..at.checked_add(width).ok_or("the frame is cut short")?)
        .ok_or("the frame is cut short")?;
    let value = field
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    usize::try_from(value).map_err(|_| "a length does not fit")
}

/// For one marker: the bytes to skip after it, and the values it opens.
fn step(marker: u8, bytes: &[u8], at: usize) -> Result<(usize, u64), &'static str> {
    let sized = |width: usize, extra: usize| -> Result<(usize, u64), &'static str> {
        let len = length(bytes, at, width)?;
        Ok((width + extra + len, 0))
    };
    let counted = |width: usize, per: u64| -> Result<(usize, u64), &'static str> {
        Ok((width, length(bytes, at, width)? as u64 * per))
    };
    match marker {
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Ok((0, 0)),
        0x80..=0x8f => Ok((0, 2 * u64::from(marker & 0x0f))),
        0x90..=0x9f => Ok((0, u64::from(marker & 0x0f))),
        0xa0..=0xbf => Ok((usize::from(marker & 0x1f), 0)),
        0xc4 | 0xd9 => sized(1, 0),
        0xc5 | 0xda => sized(2, 0),
        0xc6 | 0xdb => sized(4, 0),
        0xc7 => sized(1, 1),
        0xc8 => sized(2, 1),
        0xc9 => sized(4, 1),
        0xcc | 0xd0 => Ok((1, 0)),
        0xcd | 0xd1 => Ok((2, 0)),
        0xca | 0xce | 0xd2 => Ok((4, 0)),
        0xcb | 0xcf | 0xd3 => Ok((8, 0)),
        0xd4 => Ok((2, 0)),
        0xd5 => Ok((3, 0)),
        0xd6 => Ok((5, 0)),
        0xd7 => Ok((9, 0)),
        0xd8 => Ok((17, 0)),
        0xdc => counted(2, 1),
        0xdd => counted(4, 1),
        0xde => counted(2, 2),
        0xdf => counted(4, 2),
        0xc1 => Err("the reserved marker 0xc1"),
    }
}
