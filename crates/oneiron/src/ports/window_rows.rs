//! The window deletion-row port: the rows a deletion leaves under a window address.
//!
//! A pending tombstone (`pt:{window}:{id}`) is the local delete intent the window document does
//! not hold yet; the window document is its snapshot (`d:w:{window}`) and the updates appended
//! to it (`u:w:{window}:{seq}`). Values stay undecoded: the tombstone and CRDT codecs belong to
//! the callers.
use super::{PortRows, Transactions};
use crate::EntityId;
use crate::error::Result;

/// A window's storage address as its caller spells it: `<month>` or `<month>@<world>`. Taken
/// byte for byte; nothing here checks or normalises the label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowAddress<'a>(&'a str);

impl<'a> WindowAddress<'a> {
    pub(crate) fn new(label: &'a str) -> Self {
        Self(label)
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }
}

/// One stored pending tombstone. `window_label` is the label its key was read with, which a
/// reader that clears the row must reuse.
pub(crate) struct PendingTombstoneRow {
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) window_label: String,
    pub(crate) id: EntityId,
    pub(crate) raw: Vec<u8>,
}

pub(crate) trait WindowDeletionRows: Transactions {
    /// The stored value of one pending tombstone, undecoded.
    fn port_pending_tombstone(
        &self,
        txn: &Self::Read<'_>,
        window: WindowAddress<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>>;
    /// Presence of one pending tombstone, by key alone.
    fn port_pending_tombstone_present(
        &self,
        txn: &Self::Read<'_>,
        window: WindowAddress<'_>,
        id: &EntityId,
    ) -> Result<bool>;
    /// Every pending tombstone under `{window}:`, in key order, decoded as the caller pulls
    /// them. A key that does not decode is that row's error; the rows after it still come.
    fn port_pending_tombstones_in_window<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        window: WindowAddress<'_>,
    ) -> Result<PortRows<'a, PendingTombstoneRow>>;
    /// Whether any world window of the base month `month` holds a pending tombstone: the first
    /// row under `{month}@`, decoded, so a malformed first key is an error.
    fn port_has_world_pending_tombstone(
        &self,
        txn: &Self::Read<'_>,
        month: WindowAddress<'_>,
    ) -> Result<bool>;
    /// The window document's snapshot, lent to `read` in place. `None` when no snapshot exists.
    #[cfg(feature = "sync")]
    fn port_window_doc_with_raw<R, F>(
        &self,
        txn: &Self::Read<'_>,
        window: WindowAddress<'_>,
        read: F,
    ) -> Result<Option<R>>
    where
        F: FnOnce(&[u8]) -> Result<R>;
    /// The window document's updates in storage order. `inspect` sees each full key and value
    /// in place; no sequence in a key is parsed.
    #[cfg(feature = "sync")]
    fn port_window_updates_raw<'a, R, F>(
        &self,
        txn: &'a Self::Read<'_>,
        window: WindowAddress<'_>,
        inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(&str, &[u8]) -> R + 'a;
    /// The window document's updates in key order, each key decoded as the caller pulls it. A
    /// key that does not decode is that row's error; `inspect` sees the value in place.
    #[cfg(feature = "sync")]
    fn port_window_updates<'a, R, F>(
        &self,
        txn: &'a Self::Read<'_>,
        window: WindowAddress<'_>,
        inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(crate::sync::window_rows::WindowUpdateKey, &[u8]) -> R + 'a;
    /// Every pending tombstone of every window in key order. `inspect` sees each full key and
    /// value in place; no key is decoded, so a malformed key is still a row.
    fn port_pending_tombstone_rows_raw<'a, R, F>(
        &self,
        txn: &'a Self::Read<'_>,
        inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(&str, &[u8]) -> R + 'a;
    /// Every window document's snapshot in key order. `inspect` sees each label as stored and
    /// the value in place; no label is checked.
    fn port_window_doc_rows_raw<'a, R, F>(
        &self,
        txn: &'a Self::Read<'_>,
        inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(WindowAddress<'_>, &[u8]) -> R + 'a;
    /// The full key of every window update in key order, or of one window's when `window` is
    /// named. No key is decoded, so a malformed key is still a row.
    fn port_window_update_keys<'a, R, F>(
        &self,
        txn: &'a Self::Read<'_>,
        window: Option<WindowAddress<'_>>,
        inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(&str) -> R + 'a;
}
