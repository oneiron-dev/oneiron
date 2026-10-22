//! A window's persisted snapshot in a physical image (KS-5, FIX 7107): a
//! `sync_state` `d:w:` row goes with its pad rows as their bare references
//! when current custody here holds every pad it references live, as its
//! writers persist it (`sync::window::persisted_window_pads`), and a restore
//! takes those pads from current custody, as it does an entity pad row's.
//! Every other row rides as it rests: the root's content-free metadata, a
//! `u:w:` row (by reference already where its writer could), and a queued
//! `q:` row with its framing, sequence and markers, whose replay may find no
//! open window to inflate a reference back (KEEP TODAY).

use crate::Vault;

/// What the image carries for the row `key` of `database` in place of
/// `value`, a window snapshot whose pads custody here holds: `None` keeps the
/// row as it rests.
#[cfg(feature = "sync")]
pub(super) fn image_window_pads(
    vault: &Vault,
    database: &str,
    key: &[u8],
    value: &[u8],
) -> Option<Vec<u8>> {
    if database != "sync_state" {
        return None;
    }
    let window = key.strip_prefix(crate::sync::window_rows::WINDOW_SNAPSHOT.decl().prefix)?;
    let window = crate::sync::WindowKey::try_new(std::str::from_utf8(window).ok()?)?;
    match crate::sync::window::persisted_window_pads(vault, &window, value, None) {
        std::borrow::Cow::Owned(bytes) => Some(bytes),
        std::borrow::Cow::Borrowed(_) => None,
    }
}

/// Without sync no window is held: every row rides as it rests.
#[cfg(not(feature = "sync"))]
pub(super) fn image_window_pads(
    _vault: &Vault,
    _database: &str,
    _key: &[u8],
    _value: &[u8],
) -> Option<Vec<u8>> {
    None
}
