//! A source vault's current pad objects, read with its live custody (PAD-1,
//! the L01 seam approved 10-22 10:3x): what its home keeps of the vault's
//! sealed bundle pad objects (`sync::residence` `rb:g`, `rb:p` pad parts and
//! `rb:a` rows), carried whole and opaque from the same read that read its
//! custody, and installed over a restored copy's or an activated archive's
//! own while that store still holds what the caller saw there.
//!
//! Nothing here is a new refusal. An empty capture means the source keeps no
//! pad object. A read, decode or identity fault leaves the objects
//! `NotCaptured`, with its reason, and the copy keeps the objects it holds,
//! as before (CALLS: PAD_CAPTURE_FAULT). An install that does not fit, or
//! does not read back in its own transaction, is undone in its savepoint
//! before anything else changes: the store keeps its own objects.

use heed::RwTxn;

use crate::side_table;
use crate::store::Store;
#[cfg(feature = "sync")]
use crate::sync::residence::{
    CapturedPadObjects, CurrentPadObjects, PadObjectInstall, install_captured_pad_objects_in_txn,
    read_back_captured_in_txn,
};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// The `sync_state` families a paired read takes: each kept generation, the
/// stored parts, and the grants with the admission outbox.
pub(super) fn pad_object_prefixes() -> [&'static [u8]; 3] {
    [
        side_table::SYNC_RESIDENCE_BUNDLE_GENERATION.prefix,
        side_table::SYNC_RESIDENCE_BUNDLE_PART.prefix,
        side_table::SYNC_RESIDENCE_BUNDLE_ACCESS.prefix,
    ]
}

/// Whether a `sync_state` row under [`pad_object_prefixes`] is one a pad
/// object capture carries: every one but a bundle's stored part, whose key is
/// hex48 (the generation) ":" b|k ":" hex16 after its table prefix.
pub(super) fn is_pad_object_row(key: &[u8]) -> bool {
    const GENERATION_HEX: usize = 48;
    key.strip_prefix(side_table::SYNC_RESIDENCE_BUNDLE_PART.prefix)
        .is_none_or(|rest| rest.get(GENERATION_HEX..GENERATION_HEX + 3) == Some(b":k:".as_slice()))
}

/// What a source's live custody read got of its home's current pad objects.
pub(crate) enum PadObjectsCapture {
    /// Carried whole from the transaction its custody was read in. An empty
    /// capture means the source keeps none, never a fault.
    #[cfg(feature = "sync")]
    Captured(CapturedPadObjects),
    /// Not carried: a restore or an activation keeps the objects it holds.
    NotCaptured { reason: UncapturedPadObjects },
}

/// Why a source's current pad objects were not carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) enum UncapturedPadObjects {
    /// This build syncs nothing, so it keeps no pad object.
    #[cfg(not(feature = "sync"))]
    NoSync,
    /// The pad object rows did not read or decode.
    RowsUnread,
    /// The vault and home its objects are named for did not read in that
    /// transaction.
    IdentityUnread,
    /// A source read off its disk has no authority fold beside the read-only
    /// door, so which vault its objects are for is not proven (CALLS: PAD-1
    /// paired source identity).
    SourceVaultUnfolded,
}

impl UncapturedPadObjects {
    /// The reason, as a note names it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            #[cfg(not(feature = "sync"))]
            Self::NoSync => "this build keeps no pad object",
            Self::RowsUnread => "the source's pad object rows did not read",
            Self::IdentityUnread => "the source's vault and home did not read",
            Self::SourceVaultUnfolded => "the source read off its disk names no folded vault",
        }
    }
}

/// Which vault and home a capture names its objects for (CALLS: PAD-1 paired
/// source identity).
pub(crate) enum PadSourceIdentity {
    /// A vault open in this process: the vault id its authority folds to
    /// and its machine id, read in the transaction its custody and objects
    /// are read in, as its home names them to its machines. A vault read off
    /// its disk: no fold runs beside the read-only door, so objects it keeps
    /// are not carried, and one that keeps none is an empty capture.
    OpenFoldInCustodyReadDiskUnproven,
}

pub(crate) const PAD_SOURCE_IDENTITY: PadSourceIdentity =
    PadSourceIdentity::OpenFoldInCustodyReadDiskUnproven;

/// The capture of a source read off its disk, from the `sync_state` rows of
/// the read that read its custody ([`PAD_SOURCE_IDENTITY`]). A source that
/// keeps no pad object row is an empty capture; one that keeps some names no
/// vault the read proves, so they are not carried
/// ([`UncapturedPadObjects::SourceVaultUnfolded`]).
pub(super) fn disk_capture(rows: crate::error::Result<Rows>) -> PadObjectsCapture {
    match PAD_SOURCE_IDENTITY {
        PadSourceIdentity::OpenFoldInCustodyReadDiskUnproven => {}
    }
    match rows {
        // No row to bind to a vault: the empty capture names none.
        #[cfg(feature = "sync")]
        Ok(rows) if rows.is_empty() => {
            match crate::sync::residence::capture_current_pad_objects_in_rows(
                [0; 32],
                crate::entity_id::EntityId::from_bytes_unchecked([0; 16]),
                &rows,
            ) {
                Ok(captured) => PadObjectsCapture::Captured(captured),
                Err(_) => uncaptured(UncapturedPadObjects::RowsUnread),
            }
        }
        #[cfg(not(feature = "sync"))]
        Ok(_) => uncaptured(UncapturedPadObjects::NoSync),
        #[cfg(feature = "sync")]
        Ok(_) => uncaptured(UncapturedPadObjects::SourceVaultUnfolded),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a side restore's source pad object rows did not read; the copy keeps its own"
            );
            uncaptured(UncapturedPadObjects::RowsUnread)
        }
    }
}

/// Not carried, for `reason`.
fn uncaptured(reason: UncapturedPadObjects) -> PadObjectsCapture {
    PadObjectsCapture::NotCaptured { reason }
}

/// What a store expects of its own pad objects before a source's are
/// installed over them: its current index, read before the writer.
#[cfg(feature = "sync")]
pub(crate) type ExpectedPadObjects = CurrentPadObjects;

/// No pad object is ever expected in a build that syncs nothing.
#[cfg(not(feature = "sync"))]
pub(crate) enum ExpectedPadObjects {}

/// What installing a source's current pad objects over a store's came to.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) enum PadObjectsLanding {
    /// Installed and read back in its own transaction: the objects after it,
    /// to read back once committed.
    #[cfg(feature = "sync")]
    Installed(CurrentPadObjects),
    /// Nothing to install: no capture, an empty one, or no index expected.
    NotAttempted,
    /// The store holds other objects than expected, or the source keeps
    /// another object under a generation kept here: nothing installed.
    CurrentChanged,
    /// A captured object is not whole: nothing installed.
    Unavailable,
    /// What it wrote did not read back in its transaction: undone.
    NotReadBack,
    /// A storage fault: undone.
    Fault,
}

/// Installs `capture` over `store`'s pad objects in a savepoint of `wtxn`,
/// while the store holds `expected`; the savepoint commits only once what it
/// wrote reads back in it. Anything else undoes it, and `wtxn` goes on as if
/// it had not run.
pub(crate) fn install_source_pad_objects_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    capture: &PadObjectsCapture,
    expected: Option<&ExpectedPadObjects>,
) -> PadObjectsLanding {
    #[cfg(feature = "sync")]
    if let (PadObjectsCapture::Captured(captured), Some(expected)) = (capture, expected) {
        return install_in_savepoint(store, wtxn, expected, captured).unwrap_or_else(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "a source's pad objects did not install; the store keeps its own"
            );
            PadObjectsLanding::Fault
        });
    }
    let _ = (store, wtxn, capture, expected);
    PadObjectsLanding::NotAttempted
}

#[cfg(feature = "sync")]
fn install_in_savepoint(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    expected: &CurrentPadObjects,
    captured: &CapturedPadObjects,
) -> crate::error::Result<PadObjectsLanding> {
    let mut savepoint = store.env.nested_write_txn(wtxn)?;
    let landing =
        match install_captured_pad_objects_in_txn(store, &mut savepoint, expected, captured)? {
            PadObjectInstall::Installed(after) => {
                if read_back_captured_in_txn(store, &savepoint, &after, captured)? {
                    PadObjectsLanding::Installed(after)
                } else {
                    PadObjectsLanding::NotReadBack
                }
            }
            PadObjectInstall::CurrentChanged => PadObjectsLanding::CurrentChanged,
            PadObjectInstall::Unavailable(_) => PadObjectsLanding::Unavailable,
        };
    if matches!(landing, PadObjectsLanding::Installed(_)) {
        savepoint.commit()?;
    }
    Ok(landing)
}
