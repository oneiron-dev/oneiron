//! A body as the door reads it (OF-560): JSON, a whole MessagePack value, or
//! text.

use rmpv::Value;

use super::Masker;
use super::wipe::PlanTree;
use crate::error::{Error, Result};

impl Masker {
    /// A body read as the door reads it: JSON, a whole MessagePack value, or
    /// text. `None` when nothing in it was placed.
    pub(super) fn mask_body(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        // A decoded tree holds the body's secrets too: wiped as it drops.
        if opens_json(data)
            && let Ok(value) = serde_json::from_slice::<Value>(data)
        {
            let mut tree = PlanTree(value);
            if !self.mask_value(&mut tree.0)? {
                return Ok(None);
            }
            return serde_json::to_vec(&tree.0)
                .map(Some)
                .map_err(|_| Error::InvariantViolation("a masked JSON body did not encode"));
        }
        let mut cursor = std::io::Cursor::new(data);
        if opens_whole_messagepack(data)
            && let Ok(value) = rmpv::decode::read_value(&mut cursor)
        {
            let mut tree = PlanTree(value);
            if cursor.position() == data.len() as u64 {
                if !self.mask_value(&mut tree.0)? {
                    return Ok(None);
                }
                let mut out = Vec::with_capacity(data.len());
                rmpv::encode::write_value(&mut out, &tree.0).map_err(|_| {
                    Error::InvariantViolation("a masked MessagePack body did not encode")
                })?;
                return Ok(Some(out));
            }
        }
        match std::str::from_utf8(data) {
            Ok(text) => Ok(self.mask_text(text)?.map(String::into_bytes)),
            Err(_) => Ok(None),
        }
    }
}

/// Whether [`Masker::mask_body`] reads `data` as one text, all of it, and
/// tries no decoder: no decoder can take it, and it is UTF-8.
pub(super) fn reads_as_text(data: &[u8]) -> bool {
    !opens_json(data) && !opens_whole_messagepack(data) && std::str::from_utf8(data).is_ok()
}

/// Whether serde_json can read `data` as a value: past the four blanks it
/// skips, its first byte opens one (`{`, `[`, `"`, `-`, a digit, or the `t`,
/// `f`, `n` of `true`, `false`, `null`). Its parser refuses any other first
/// byte at once, so a body this refuses it refuses too (speed).
fn opens_json(data: &[u8]) -> bool {
    data.iter()
        .find(|&&byte| !matches!(byte, b' ' | b'\n' | b'\t' | b'\r'))
        .is_some_and(|&byte| {
            matches!(byte, b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n')
        })
}

/// Whether `data` can be one whole MessagePack value: a first byte below
/// 0x80 is a positive fixint, a whole value of that one byte, so a longer
/// body that opens with one never reads whole, and an empty one reads as
/// nothing (speed).
fn opens_whole_messagepack(data: &[u8]) -> bool {
    data.len() == 1 || data.first().is_some_and(|&byte| byte >= 0x80)
}
