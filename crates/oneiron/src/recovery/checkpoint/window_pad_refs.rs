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
/// `value`, a window snapshot whose pads custody here holds live: `None`
/// keeps the row as it rests, counted in `kept` when it rests so because a
/// pad it holds was not proven live here (a lookup that faults proves
/// nothing).
#[cfg(feature = "sync")]
pub(super) fn image_window_pads(
    vault: &Vault,
    database: &str,
    key: &[u8],
    value: &[u8],
    kept: &mut usize,
) -> Option<Vec<u8>> {
    use crate::sync::window::{PersistedWindowPads, persisted_window_pads_form};
    if database != "sync_state" {
        return None;
    }
    let window = key.strip_prefix(crate::sync::window_rows::WINDOW_SNAPSHOT.decl().prefix)?;
    let window = crate::sync::WindowKey::try_new(std::str::from_utf8(window).ok()?)?;
    match persisted_window_pads_form(vault, &window, value, None) {
        PersistedWindowPads::ByReference(bytes) => Some(bytes),
        PersistedWindowPads::AsIs(_) => None,
        PersistedWindowPads::Kept(..) => {
            *kept += 1;
            None
        }
    }
}

/// Without sync no window is held: every row rides as it rests.
#[cfg(not(feature = "sync"))]
pub(super) fn image_window_pads(
    _vault: &Vault,
    _database: &str,
    _key: &[u8],
    _value: &[u8],
    _kept: &mut usize,
) -> Option<Vec<u8>> {
    None
}

/// Warns, by their count alone, of the window snapshots an image carries as
/// they rest because a pad they hold was not proven live here (FIX 10467
/// tracks their strict removal).
pub(super) fn warn_kept_window_pads(kept: usize) {
    if kept > 0 {
        tracing::warn!(
            kept,
            "window snapshots ride this image as they rest: a pad they hold is not proven live here"
        );
    }
}
