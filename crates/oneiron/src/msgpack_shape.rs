//! A budget check of untrusted MessagePack before it is decoded.
//!
//! A nil is one byte and a decoded `rmpv::Value` is dozens, so a body that
//! is small on disk can unfold into a tree many times its size before any
//! schema check runs. [`over_budget`] walks the markers once, allocates only
//! its depth stack, and names the first budget the bytes would break. It
//! judges nothing else: a cut-short or malformed body passes through, so the
//! decoder keeps its own refusal for those.

/// What one decode door accepts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ShapeBudget {
    /// The most values the body may hold; a map counts its keys and values.
    pub(crate) max_values: u64,
    /// The most containers that may be open at once.
    pub(crate) max_depth: usize,
}

/// Which budget a body breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverBudget {
    Values,
    Depth,
}

/// The first budget `bytes` breaks, or `None` when they fit it (or stop
/// being MessagePack before they break it).
pub(crate) fn over_budget(bytes: &[u8], budget: ShapeBudget) -> Option<OverBudget> {
    let mut at = 0usize;
    let mut values = 0u64;
    // What each enclosing container still owes, innermost last.
    let mut open: Vec<u64> = Vec::new();
    let mut owed = 1u64;
    loop {
        while owed == 0 {
            owed = open.pop()?;
        }
        owed -= 1;
        values += 1;
        if values > budget.max_values {
            return Some(OverBudget::Values);
        }
        let marker = *bytes.get(at)?;
        at += 1;
        let (skip, children) = step(marker, bytes, at)?;
        at = at.checked_add(skip).filter(|end| *end <= bytes.len())?;
        if children > 0 {
            if open.len() >= budget.max_depth {
                return Some(OverBudget::Depth);
            }
            open.push(owed);
            owed = children;
        }
    }
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

/// For one marker: the bytes to skip after it, and the values it opens.
fn step(marker: u8, bytes: &[u8], at: usize) -> Option<(usize, u64)> {
    let sized = |width: usize, extra: usize| -> Option<(usize, u64)> {
        let len = usize::try_from(length(bytes, at, width)?).ok()?;
        Some((width.checked_add(extra)?.checked_add(len)?, 0))
    };
    let counted = |width: usize, per: u64| -> Option<(usize, u64)> {
        Some((width, length(bytes, at, width)?.checked_mul(per)?))
    };
    match marker {
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
        0xd4 => Some((2, 0)),
        0xd5 => Some((3, 0)),
        0xd6 => Some((5, 0)),
        0xd7 => Some((9, 0)),
        0xd8 => Some((17, 0)),
        0xdc => counted(2, 1),
        0xdd => counted(4, 1),
        0xde => counted(2, 2),
        0xdf => counted(4, 2),
        0xc1 => None,
    }
}
