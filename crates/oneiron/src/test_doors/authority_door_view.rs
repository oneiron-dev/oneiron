//! The authority door view the store doors read (FIX
//! [OWNER-RESERVE-PROJECTION-COST], [AUTHORITY-DOOR-VIEW-MID-BATCH-REBUILD]):
//! how many stored rows this thread's door views decoded, and whether the
//! view the doors read equals one built afresh from every stored row, after
//! committed writes and inside one write that stages rows one at a time.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::BTreeSet;

use crate::authority::{AuthorityEntryHash, AuthorityLogEntry};
use crate::{Result, Vault};

/// How many stored rows this thread's door views decoded so far.
#[must_use]
pub fn door_view_rows_decoded() -> u64 {
    crate::authority::door_view_rows_decoded_for_test()
}

/// The first way the door view of `vault`'s committed log differs from one
/// built afresh from every stored row, or None: its structure, its counts,
/// its projected peak, and for each of `probes` (a row's hash and parents)
/// the peak with that row stored too, each exactly and past each of
/// `starts` or not, as the owner's reserve judges it.
///
/// # Errors
///
/// A read of the store or a door view fails.
pub fn door_view_differs_from_rebuild(
    vault: &Vault,
    probes: &[(AuthorityEntryHash, Vec<AuthorityEntryHash>)],
    starts: &[u64],
) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    crate::authority::door_view_differs_from_rebuild_in_txn(&vault.store, &txn, probes, starts)
}

/// Stages each of `entries` in one write that never commits, past the store
/// doors, as an import stages its rows, and after each compares the door view
/// of the write so far with a rebuild, as [`door_view_differs_from_rebuild`]
/// does. A row whose index `rolled_back` holds is staged in a nested write
/// that rolls back once compared. The index of the first row after which the
/// views differ, and how.
///
/// # Errors
///
/// The store refuses a row or holds it for history, or a door view fails.
pub fn staged_door_views_differ_from_rebuild(
    vault: &Vault,
    entries: &[AuthorityLogEntry],
    rolled_back: &BTreeSet<usize>,
    probes: &[(AuthorityEntryHash, Vec<AuthorityEntryHash>)],
    starts: &[u64],
) -> Result<Option<(usize, String)>> {
    crate::authority::staged_door_views_differ_from_rebuild(
        vault,
        entries,
        rolled_back,
        probes,
        starts,
    )
}
