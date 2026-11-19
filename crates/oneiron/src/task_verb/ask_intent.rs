//! Ask intent keys (UC-06 PR 8; Fable audit FA-08, FB-09). An ask's intent key is its kind's
//! prefix, which ends in `/`, then its parts with `/` between them, for example
//! `training_offer/<offer>/<digest>/<owner>/<turn>`. The key is stored in the ask group's body
//! (and, for a live-edit holder ask, in `LIVE_EDIT_GROUPS`), and an answer is routed to its ask by
//! it. So every ask module writes it with [`join`] and reads it with [`split`] and the part
//! readers, and its text never changes.

use crate::EntityId;

/// The intent key `prefix` then `parts`, with `/` between the parts. `prefix` carries its own
/// closing `/`.
pub(crate) fn join(prefix: &str, parts: &[&str]) -> String {
    format!("{prefix}{}", parts.join("/"))
}

/// The `N` parts of `intent_key` after `prefix`; `None` when the key does not start with
/// `prefix`, or holds fewer or more than `N` parts.
pub(crate) fn split<'k, const N: usize>(intent_key: &'k str, prefix: &str) -> Option<[&'k str; N]> {
    let mut rest = intent_key.strip_prefix(prefix)?.split('/');
    let mut parts = [""; N];
    for part in &mut parts {
        *part = rest.next()?;
    }
    rest.next().is_none().then_some(parts)
}

/// An id part in its one spelling: the 32 lowercase hex characters `EntityId::to_hex` writes.
pub(crate) fn id(part: &str) -> Option<EntityId> {
    EntityId::from_lower_hex(part).ok()
}

/// A digest part in its one spelling: 64 lowercase hex characters.
pub(crate) fn digest(part: &str) -> Option<String> {
    let lower_hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    (part.len() == 64 && part.bytes().all(lower_hex)).then(|| part.to_owned())
}
