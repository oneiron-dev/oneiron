//! The door view the store doors read beside one built afresh from every
//! stored row (FIX [OWNER-RESERVE-PROJECTION-COST],
//! [AUTHORITY-DOOR-VIEW-MID-BATCH-REBUILD]), for the test door
//! `test_doors::authority_door_view`. Compiled only under
//! `--cfg oneiron_test_support`.

use super::*;
use crate::Vault;

/// The first way the door view `txn`'s doors read differs from one built
/// afresh from every row stored in `txn`, or None: its structure, its
/// counts, its projected peak, and for each of `probes` (a row's hash and
/// parents) the projected peak with that row stored too. Each peak is
/// compared exactly, and as the doors judge it, past each of `starts` or not.
pub(crate) fn door_view_differs_from_rebuild_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    probes: &[(AuthorityEntryHash, Vec<AuthorityEntryHash>)],
    starts: &[u64],
) -> crate::error::Result<Option<String>> {
    let kept = door_view(store, txn)?;
    let rebuilt = rebuilt_door_view(store, txn)?;
    if let Some(field) = kept.structure.differs_from(&rebuilt.structure) {
        return Ok(Some(format!("structure.{field}")));
    }
    let counts = |view: &AuthorityDoorView| {
        (
            view.rows.clone(),
            view.counted,
            view.issuer_handoffs,
            view.strangers,
        )
    };
    if counts(&kept) != counts(&rebuilt) {
        return Ok(Some(format!(
            "counts: kept {:?}, rebuilt {:?}",
            counts(&kept),
            counts(&rebuilt)
        )));
    }
    let (kept_bytes, rebuilt_bytes) = (kept.projection.bytes(), rebuilt.projection.bytes());
    if kept_bytes != rebuilt_bytes {
        return Ok(Some(format!(
            "projection.bytes: kept {kept_bytes}, rebuilt {rebuilt_bytes}"
        )));
    }
    for start in starts {
        let (kept_past, rebuilt_past) = (past_start(&kept, *start), past_start(&rebuilt, *start));
        if kept_past != rebuilt_past {
            return Ok(Some(format!(
                "projection past {start}: kept {kept_past:?}, rebuilt {rebuilt_past:?}"
            )));
        }
    }
    for (hash, parents) in probes {
        let kept_with = kept.projection.bytes_with(hash, parents);
        let rebuilt_with = rebuilt.projection.bytes_with(hash, parents);
        if kept_with != rebuilt_with {
            return Ok(Some(format!(
                "projection.bytes_with({hash:?}): kept {kept_with}, rebuilt {rebuilt_with}"
            )));
        }
        for start in starts {
            let kept_past = past_start_with(&kept, *start, hash, parents);
            let rebuilt_past = past_start_with(&rebuilt, *start, hash, parents);
            if kept_past != rebuilt_past {
                return Ok(Some(format!(
                    "projection.bytes_with({hash:?}) past {start}: kept {kept_past:?}, rebuilt \
                     {rebuilt_past:?}"
                )));
            }
        }
    }
    Ok(None)
}

/// The stored log's projected peak when it is past `start`, as the pickup's
/// reserve check reads it.
fn past_start(view: &AuthorityDoorView, start: u64) -> Option<u64> {
    let bytes = view.projection.bytes();
    (bytes > start).then_some(bytes)
}

/// The projected peak with the row `hash` on `parents` stored too, when it
/// is past `start`, as the store door's reserve check reads it.
fn past_start_with(
    view: &AuthorityDoorView,
    start: u64,
    hash: &AuthorityEntryHash,
    parents: &[AuthorityEntryHash],
) -> Option<u64> {
    let bytes = view.projection.bytes_with(hash, parents);
    (bytes > start).then_some(bytes)
}

/// Stages each of `entries` in one write that never commits, past the store
/// doors, as an import stages its rows, and after each compares the door
/// view of the write so far with a rebuild
/// ([`door_view_differs_from_rebuild_in_txn`]). A row whose index
/// `rolled_back` holds is staged in a nested write that rolls back once
/// compared, as the owner's import drops a refused run. The index of the
/// first row after which the views differ, and how; None when they never do.
///
/// # Errors
///
/// The store refuses a row, or a door view fails.
pub(crate) fn staged_door_views_differ_from_rebuild(
    vault: &Vault,
    entries: &[AuthorityLogEntry],
    rolled_back: &BTreeSet<usize>,
    probes: &[(AuthorityEntryHash, Vec<AuthorityEntryHash>)],
    starts: &[u64],
) -> crate::error::Result<Option<(usize, String)>> {
    let at = crate::TimeRange { start: 2, end: 2 };
    with_authority_doors_open_for_test(|| {
        let mut txn = vault.store.env.write_txn()?;
        for (index, entry) in entries.iter().enumerate() {
            let rows = [(entry.clone(), at, 2)];
            if rolled_back.contains(&index) {
                let mut nested = vault.store.env.nested_write_txn(&mut txn)?;
                stage(vault, &mut nested, &rows)?;
                let differs =
                    door_view_differs_from_rebuild_in_txn(&vault.store, &nested, probes, starts)?;
                drop(nested);
                if let Some(how) = differs {
                    return Ok(Some((index, how)));
                }
            } else {
                stage(vault, &mut txn, &rows)?;
            }
            if let Some(how) =
                door_view_differs_from_rebuild_in_txn(&vault.store, &txn, probes, starts)?
            {
                return Ok(Some((index, how)));
            }
        }
        Ok(None)
    })
}

/// Stages `rows` in `txn`, or refuses a row that waits for history.
fn stage(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    rows: &[(AuthorityLogEntry, crate::TimeRange, u64)],
) -> crate::error::Result<()> {
    match vault.put_authority_log_rows_in_txn(txn, rows, false)? {
        super::super::history_admission::AuthorityPut::Stored(_) => Ok(()),
        super::super::history_admission::AuthorityPut::Pending(_) => Err(
            crate::error::Error::InvariantViolation("a staged row waits for its history"),
        ),
    }
}
