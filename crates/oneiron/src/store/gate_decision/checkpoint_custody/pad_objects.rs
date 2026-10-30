//! A source vault's current pad objects, read with its live custody (PAD-1,
//! the L01 seam approved 10-22 10:3x, its identity and bundle rows FIX 11293
//! and 11294): what its home keeps of the vault's sealed bundle pad objects
//! (`sync::residence` `rb:g`, `rb:p` pad parts and `rb:a` rows), with the
//! bundle parts of the generations a copy may adopt, carried whole and opaque
//! from the same read that read its custody and named for the vault and home
//! that read names, and installed over a restored copy's or an activated
//! archive's own while that store still holds what the caller saw there, its
//! generations first brought to the source's where the source's rows prove
//! them (`PadObjectMembership`).
//!
//! Nothing here is a new refusal. An empty capture means the source keeps no
//! pad object. A read, decode or identity fault leaves the objects
//! `NotCaptured`, with its reason, and the copy keeps the objects it holds,
//! as before (CALLS: PAD_CAPTURE_FAULT). An install that does not fit, or
//! does not read back in its own transaction, is undone in its savepoint
//! before anything else changes: the store keeps its own objects.

use heed::RwTxn;

use crate::error::Result;
use crate::side_table;
use crate::store::{PairedIdentityRows, PairedSourceAsk, PairedSyncRows, Store};
#[cfg(feature = "sync")]
use crate::sync::residence::{
    CapturedPadObjects, CurrentPadObjects, PadObjectInstall, PadObjectMembership,
    capture_current_pad_objects_in_rows, capture_current_pad_objects_in_txn,
    generations_an_install_retires_in_txn, install_captured_pad_objects_in_txn,
    read_back_captured_in_txn,
};

/// A bundle part key's generation, in hex, after its table prefix.
const GENERATION_HEX: usize = 48;

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
    key.strip_prefix(side_table::SYNC_RESIDENCE_BUNDLE_PART.prefix)
        .is_none_or(|rest| rest.get(GENERATION_HEX..GENERATION_HEX + 3) == Some(b":k:".as_slice()))
}

/// Whether a `sync_state` row under [`pad_object_prefixes`] is a bundle's
/// stored part, hex48 ":" b ":" hex16 after its table prefix: a paired read
/// takes these apart from the pad object rows ([`is_pad_object_row`]), for
/// the generations a copy adopts.
pub(super) fn is_bundle_part_row(key: &[u8]) -> bool {
    key.strip_prefix(side_table::SYNC_RESIDENCE_BUNDLE_PART.prefix)
        .is_some_and(|rest| rest.get(GENERATION_HEX..GENERATION_HEX + 3) == Some(b":b:".as_slice()))
}

/// What a paired read takes beside a source's custody: its pad object rows
/// under `prefixes` and, apart from them, its bundle parts; its install's
/// machine id; and its AUTHORITY_LOG records with the checkpoint image it
/// adopted, pin row and image bytes, whose fold names its vault.
pub(super) fn paired_source_ask<'a>(prefixes: &'a [&'a [u8]]) -> PairedSourceAsk<'a> {
    PairedSourceAsk {
        sync_state: prefixes,
        pad_object: is_pad_object_row,
        bundle_part: is_bundle_part_row,
        machine_id: side_table::IDENTITY_MACHINE_ID.prefix,
        entity_type: crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
        adopted_pin: crate::authority::adopted_pin_row_key(),
        adopted_image: crate::authority::adopted_image_row_key,
    }
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
    /// A source whose authority records fold to no one vault (no valid
    /// genesis among them and no adopted checkpoint image, or more than one
    /// root), so which vault its objects are for is not proven (CALLS: PAD-1
    /// paired source identity): a vault read off its disk, or one open in
    /// this process with no genesis yet (FIX 11826).
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
            Self::SourceVaultUnfolded => "the source folds to no one vault",
        }
    }
}

/// Which vault and home a capture names its objects for (CALLS: PAD-1 paired
/// source identity).
pub(crate) enum PadSourceIdentity {
    /// The vault id its authority folds to and its machine id, read in the
    /// transaction its custody and objects are read in, as its home names
    /// them to its machines. A vault open in this process folds its own log
    /// there; a vault read off its disk folds the AUTHORITY_LOG records that
    /// read took, from the checkpoint image it adopted where it adopted one,
    /// Store-free (`authority::folded_vault_id_of_records`, FIX 11823).
    /// A source whose records fold to no one vault keeps its objects
    /// uncarried; a disk source that keeps none is an empty capture.
    FoldedInCustodyRead,
}

pub(crate) const PAD_SOURCE_IDENTITY: PadSourceIdentity = PadSourceIdentity::FoldedInCustodyRead;

/// The capture of a source read off its disk, from the rows of the read that
/// read its custody ([`PAD_SOURCE_IDENTITY`]): its pad object rows and bundle
/// parts, named for the vault its stored authority records fold to and its
/// machine id. A source that keeps no pad object row is an empty capture;
/// one whose records fold to no one vault is not carried
/// ([`UncapturedPadObjects::SourceVaultUnfolded`]).
pub(super) fn disk_capture(
    rows: Result<PairedSyncRows>,
    identity: Result<PairedIdentityRows>,
) -> PadObjectsCapture {
    match PAD_SOURCE_IDENTITY {
        PadSourceIdentity::FoldedInCustodyRead => {}
    }
    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a side restore's source pad object rows did not read; the copy keeps its own"
            );
            return uncaptured(UncapturedPadObjects::RowsUnread);
        }
    };
    #[cfg(feature = "sync")]
    {
        // No row to bind to a vault: the empty capture names none.
        let named = if rows.pad_objects.is_empty() {
            Ok(Some((
                [0; 32],
                crate::entity_id::EntityId::from_bytes_unchecked([0; 16]),
            )))
        } else {
            disk_identity(identity)
        };
        let (vault_id, home) = match named {
            Ok(Some(named)) => named,
            Ok(None) => return uncaptured(UncapturedPadObjects::SourceVaultUnfolded),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a side restore's source vault and home did not read; the copy keeps its own"
                );
                return uncaptured(UncapturedPadObjects::IdentityUnread);
            }
        };
        match capture_current_pad_objects_in_rows(
            vault_id,
            home,
            &rows.pad_objects,
            &rows.bundle_parts,
        ) {
            Ok(captured) => PadObjectsCapture::Captured(captured),
            Err(_) => uncaptured(UncapturedPadObjects::RowsUnread),
        }
    }
    #[cfg(not(feature = "sync"))]
    {
        let _ = (rows, identity);
        uncaptured(UncapturedPadObjects::NoSync)
    }
}

/// The vault and the home a disk source's objects are named for, from the
/// read that read its custody: the vault id its stored authority records
/// fold to, from the checkpoint image it adopted where it adopted one, and
/// its machine id (the zero id before it has one). `None` when the records
/// fold to no one vault.
#[cfg(feature = "sync")]
fn disk_identity(
    identity: Result<PairedIdentityRows>,
) -> Result<Option<([u8; 32], crate::entity_id::EntityId)>> {
    let identity = identity?;
    let home = match identity.machine_id {
        Some(raw) => <[u8; 16]>::try_from(raw.as_slice())
            .ok()
            .and_then(|bytes| crate::entity_id::EntityId::from_bytes(bytes).ok())
            .ok_or(crate::error::Error::CorruptedIndex("machine id row"))?,
        None => crate::entity_id::EntityId::from_bytes_unchecked([0; 16]),
    };
    let vault_id = crate::authority::folded_vault_id_of_records(
        &identity.records,
        identity.adopted_pin.as_deref(),
        identity.adopted_image.as_deref(),
    )?;
    Ok(vault_id.map(|vault_id| (vault_id, home)))
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
    /// to read back once committed, and the store's own objects as that
    /// transaction read them before the install, put back should that read
    /// fail.
    #[cfg(feature = "sync")]
    Installed {
        after: CurrentPadObjects,
        baseline: CapturedPadObjects,
    },
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
        let membership = PadObjectMembership::SourceKeepRuleProvesRetired;
        return install_in_savepoint(store, wtxn, expected, captured, membership).unwrap_or_else(
            |error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a source's pad objects did not install; the store keeps its own"
                );
                PadObjectsLanding::Fault
            },
        );
    }
    let _ = (store, wtxn, capture, expected);
    PadObjectsLanding::NotAttempted
}

/// Puts `baseline`, a store's own pad objects as an install read them, back
/// over what that install wrote (`installed`), in a savepoint of `wtxn`, when
/// the install did not read back once committed. Whether they are back and
/// read back in it.
#[cfg(feature = "sync")]
pub(crate) fn put_back_pad_objects_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    installed: &CurrentPadObjects,
    baseline: &CapturedPadObjects,
) -> bool {
    match install_in_savepoint(
        store,
        wtxn,
        installed,
        baseline,
        PadObjectMembership::StoreOwnPutBack,
    ) {
        Ok(PadObjectsLanding::Installed { .. }) => true,
        Ok(_) => false,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a store's own pad objects did not go back after an install that did not read back"
            );
            false
        }
    }
}

/// How an install over a store's own pad objects is staged (CALLS: PAD-1
/// install staging).
#[cfg(feature = "sync")]
enum PadObjectInstallStaging {
    /// In a savepoint of the caller's writer, committed only once what it
    /// wrote reads back in it, so the store's own objects stay until then;
    /// those objects, with the bundles of the generations the install
    /// retires, captured in the same savepoint first, are kept apart and put
    /// back when the read after the commit fails. An activation's install
    /// runs before its archive lifts, in the same writer, and its read after
    /// the commit comes before the vault is returned.
    SavepointCommittedOnReadBackBaselineKept,
}

#[cfg(feature = "sync")]
const PAD_OBJECT_INSTALL_STAGING: PadObjectInstallStaging =
    PadObjectInstallStaging::SavepointCommittedOnReadBackBaselineKept;

#[cfg(feature = "sync")]
fn install_in_savepoint(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    expected: &CurrentPadObjects,
    captured: &CapturedPadObjects,
    membership: PadObjectMembership,
) -> Result<PadObjectsLanding> {
    match PAD_OBJECT_INSTALL_STAGING {
        PadObjectInstallStaging::SavepointCommittedOnReadBackBaselineKept => {}
    }
    let mut savepoint = store.env.nested_write_txn(wtxn)?;
    let retiring =
        generations_an_install_retires_in_txn(store, &savepoint, expected, captured, membership)?;
    let baseline = capture_current_pad_objects_in_txn(
        store,
        &savepoint,
        expected.vault_id,
        expected.home,
        |generation| retiring.contains(generation),
    )?;
    let landing = match install_captured_pad_objects_in_txn(
        store,
        &mut savepoint,
        expected,
        captured,
        membership,
    )? {
        PadObjectInstall::Installed(after) => {
            if read_back_captured_in_txn(store, &savepoint, &after, captured)? {
                PadObjectsLanding::Installed { after, baseline }
            } else {
                PadObjectsLanding::NotReadBack
            }
        }
        PadObjectInstall::CurrentChanged => PadObjectsLanding::CurrentChanged,
        PadObjectInstall::Unavailable(_) => PadObjectsLanding::Unavailable,
    };
    if matches!(landing, PadObjectsLanding::Installed { .. }) {
        savepoint.commit()?;
    }
    Ok(landing)
}
