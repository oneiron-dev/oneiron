//! A body as the door reads it (OF-560): JSON, a whole MessagePack value, or
//! text.

use rmpv::Value;

use crate::batch::secret_scan::mask::wipe::PlanTree;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// Whether [`Masker::mask_body`] reads `data` as one text, all of it, and
/// tries no decoder: no decoder can take it, and it is UTF-8.
pub fn reads_as_text(data: &[u8]) -> bool {
    !opens_json(data) && !opens_whole_messagepack(data) && std::str::from_utf8(data).is_ok()
}

/// Whether serde_json can read `data` as a value: past the four blanks it
/// skips, its first byte opens one (`{`, `[`, `"`, `-`, a digit, or the `t`,
/// `f`, `n` of `true`, `false`, `null`). Its parser refuses any other first
/// byte at once, so a body this refuses it refuses too (speed).
pub fn opens_json(data: &[u8]) -> bool {
    data.iter()
        .find(|&&byte| !matches!(byte, b' ' | b'\n' | b'\t' | b'\r'))
        .is_some_and(|&byte| {
            matches!(
                byte,
                b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n'
            )
        })
}

/// Whether `data` can be one whole MessagePack value: a first byte below
/// 0x80 is a positive fixint, a whole value of that one byte, so a longer
/// body that opens with one never reads whole, and an empty one reads as
/// nothing (speed).
pub fn opens_whole_messagepack(data: &[u8]) -> bool {
    data.len() == 1 || data.first().is_some_and(|&byte| byte >= 0x80)
}
