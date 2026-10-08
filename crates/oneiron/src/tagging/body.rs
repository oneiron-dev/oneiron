//! An earlier MESSAGE's text, read from its stored MessagePack row as far as
//! the live window keeps it and no further: the row's keys are walked
//! without decoding a string, and the text is read back from its end, so the
//! work and the copy are bounded by the kept characters, not by the message.

/// How deep a value the walk skips may nest.
const MAX_DEPTH: usize = 32;

/// The keys of a MESSAGE body the window reads. `content` holds the string's
/// bytes as stored, not yet read as text.
#[derive(Default)]
pub(super) struct MessageFields<'a> {
    pub(super) content: &'a [u8],
    pub(super) is_visible: bool,
    pub(super) stale: bool,
    pub(super) order: u32,
}

/// The top-level `content`, `is_visible`, `stale` and `order` keys of a
/// MESSAGE body, each defaulting as the full reader's do; `None` for a body
/// that is not a well-formed map, or whose `content` is not a string,
/// `is_visible` not a boolean or `order` not an integer a `u32` holds. Any
/// other key, and any non-boolean `stale`, is skipped.
pub(super) fn message_fields(body: &[u8]) -> Option<MessageFields<'_>> {
    let mut rd = body;
    let entries = match byte(&mut rd)? {
        marker @ 0x80..=0x8f => usize::from(marker & 0x0f),
        0xde => uint(&mut rd, 2)?,
        0xdf => uint(&mut rd, 4)?,
        _ => return None,
    };
    let mut fields = MessageFields::default();
    for _ in 0..entries {
        let key = if is_string(rd) {
            Some(string(&mut rd)?)
        } else {
            skip(&mut rd, MAX_DEPTH)?;
            None
        };
        match key {
            Some(b"content") => fields.content = string(&mut rd)?,
            Some(b"is_visible") => {
                fields.is_visible = match byte(&mut rd)? {
                    0xc2 => false,
                    0xc3 => true,
                    _ => return None,
                }
            }
            Some(b"stale") if rd.first() == Some(&0xc3) => {
                byte(&mut rd)?;
                fields.stale = true;
            }
            Some(b"order") => fields.order = unsigned(&mut rd)?,
            _ => skip(&mut rd, MAX_DEPTH)?,
        }
    }
    Some(fields)
}

/// The newest characters of `text`, at most `count`, and how many; `None`
/// for bytes that do not end in that many characters of UTF-8. It reads back
/// from the end, at most four bytes for each character it keeps.
pub(super) fn newest_chars(text: &[u8], count: usize) -> Option<(&str, usize)> {
    let mut start = text.len();
    let mut taken = 0;
    for (at, byte) in text.iter().enumerate().rev().take(count.saturating_mul(4)) {
        if taken == count {
            break;
        }
        if byte & 0xc0 != 0x80 {
            start = at;
            taken += 1;
        }
    }
    let kept = std::str::from_utf8(&text[start..]).ok()?;
    Some((kept, taken))
}

fn byte(rd: &mut &[u8]) -> Option<u8> {
    let (first, rest) = rd.split_first()?;
    *rd = rest;
    Some(*first)
}

fn take<'a>(rd: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (head, rest) = rd.split_at_checked(len)?;
    *rd = rest;
    Some(head)
}

/// A big-endian unsigned integer of `width` bytes, at most eight.
fn int(rd: &mut &[u8], width: usize) -> Option<u64> {
    Some(
        take(rd, width)?
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

/// A big-endian length of `width` bytes.
fn uint(rd: &mut &[u8], width: usize) -> Option<usize> {
    usize::try_from(int(rd, width)?).ok()
}

/// An integer of any width that a `u32` holds; `None` for a negative or
/// larger one, or another value.
fn unsigned(rd: &mut &[u8]) -> Option<u32> {
    let (width, signed) = match byte(rd)? {
        marker @ 0x00..=0x7f => return Some(u32::from(marker)),
        0xcc => (1, false),
        0xcd => (2, false),
        0xce => (4, false),
        0xcf => (8, false),
        0xd0 => (1, true),
        0xd1 => (2, true),
        0xd2 => (4, true),
        0xd3 => (8, true),
        _ => return None,
    };
    let negative = signed && rd.first().is_some_and(|byte| byte & 0x80 != 0);
    let value = int(rd, width)?;
    if negative {
        return None;
    }
    u32::try_from(value).ok()
}

fn is_string(rd: &[u8]) -> bool {
    matches!(rd.first(), Some(0xa0..=0xbf | 0xd9..=0xdb))
}

/// A string's bytes, borrowed; `None` for any other value.
fn string<'a>(rd: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = match byte(rd)? {
        marker @ 0xa0..=0xbf => usize::from(marker & 0x1f),
        0xd9 => uint(rd, 1)?,
        0xda => uint(rd, 2)?,
        0xdb => uint(rd, 4)?,
        _ => return None,
    };
    take(rd, len)
}

/// Steps over one value: a string or binary in one step, a container one
/// item at a time, each item at least a byte, so the walk ends with the row.
fn skip(rd: &mut &[u8], depth: usize) -> Option<()> {
    let (bytes, items) = match byte(rd)? {
        0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => (0, 0),
        marker @ 0x80..=0x8f => (0, usize::from(marker & 0x0f) * 2),
        marker @ 0x90..=0x9f => (0, usize::from(marker & 0x0f)),
        marker @ 0xa0..=0xbf => (usize::from(marker & 0x1f), 0),
        0xc1 => return None,
        0xc4 | 0xd9 => (uint(rd, 1)?, 0),
        0xc5 | 0xda => (uint(rd, 2)?, 0),
        0xc6 | 0xdb => (uint(rd, 4)?, 0),
        // An extension's type byte follows its length.
        0xc7 => (uint(rd, 1)?.checked_add(1)?, 0),
        0xc8 => (uint(rd, 2)?.checked_add(1)?, 0),
        0xc9 => (uint(rd, 4)?.checked_add(1)?, 0),
        0xcc | 0xd0 => (1, 0),
        0xcd | 0xd1 => (2, 0),
        0xca | 0xce | 0xd2 => (4, 0),
        0xcb | 0xcf | 0xd3 => (8, 0),
        0xd4 => (2, 0),
        0xd5 => (3, 0),
        0xd6 => (5, 0),
        0xd7 => (9, 0),
        0xd8 => (17, 0),
        0xdc => (0, uint(rd, 2)?),
        0xdd => (0, uint(rd, 4)?),
        0xde => (0, uint(rd, 2)?.checked_mul(2)?),
        0xdf => (0, uint(rd, 4)?.checked_mul(2)?),
    };
    take(rd, bytes)?;
    if items > 0 {
        let depth = depth.checked_sub(1)?;
        for _ in 0..items {
            skip(rd, depth)?;
        }
    }
    Some(())
}
