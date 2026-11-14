//! The `AUTHORITY_OVERLAY` rows of this vault's AUTHORITY_LOG (census
//! L5-22; DEC-0005 #vault:8, "verifies without naming").
//!
//! A row whose op names something a person typed or chose is stored in its
//! scaffold form; its values and the seed of their commitments are its
//! overlay record, sealed under the erasable key of the subject the row
//! names (`store::authority_overlay_custody`) and kept here under the row's
//! entry hash. The append funnel writes the record in the writer that
//! appends the row, before the batch door reads the row back. An in-vault
//! reader opens a sealed row with its record; once the subject's key is
//! retired, or before the record reaches this install, the row reads as
//! erased: its scaffold still verifies, and nothing it made counts
//! ("Missing history never counts as permission").

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use super::*;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::authority_overlay_custody::{self as custody, SealedOverlay};

const AUTHORITY_OVERLAY: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_OVERLAY);

/// One row's overlay record, prepared before its writer opens: the record's
/// canonical bytes and the subject whose key will seal them.
pub(super) struct PreparedOverlay {
    hash: AuthorityEntryHash,
    subject: EntityId,
    record: Zeroizing<Vec<u8>>,
}

/// Checks `body`, the canonical bytes `entry` encodes to, with the overlay
/// record `entry` carries, and prepares that record for the append funnel.
/// `None` when the entry seals nothing.
///
/// # Errors
/// A body that does not open with its own record, or an op with no overlay
/// subject.
pub(super) fn prepare_overlay(
    entry: &AuthorityLogEntry,
    body: &[u8],
) -> Result<Option<PreparedOverlay>> {
    let record = authority_entry_overlay(entry)?;
    open_authority_log_entry_body(body, record.as_ref())?;
    let Some(record) = record else {
        return Ok(None);
    };
    Ok(Some(PreparedOverlay {
        hash: *blake3::hash(body).as_bytes(),
        subject: authority_overlay_subject(&entry.op)?,
        record: Zeroizing::new(encode_authority_overlay_record(&record)?),
    }))
}

/// Seals `overlay` under its subject's key and stores it in `w`, the writer
/// that appends its row.
///
/// # Errors
/// An archived vault, an erased subject, custody and storage faults.
pub(super) fn put_overlay_in_txn(
    store: &Store,
    w: &mut RwTxn<'_>,
    overlay: &PreparedOverlay,
) -> Result<()> {
    let sealed = custody::seal(store, w, &overlay.subject, &overlay.hash, &overlay.record)?;
    AUTHORITY_OVERLAY.put(store, w, &overlay.hash, &sealed.to_bytes())
}

/// What one signed AUTHORITY_LOG body of this vault reads as here.
// A short-lived per-row read result, as `AuthorityEntryRead` is.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VaultAuthorityBody {
    /// The whole entry: unsealed, or sealed and opened with its record.
    Open(AuthorityLogEntry),
    /// A sealed row whose record is not here, or whose subject's key is
    /// retired: its scaffold verifies, and nothing it made counts.
    Erased(AuthorityEntryScaffold),
}

/// Decodes `body`, a signed AUTHORITY_LOG body of this vault, in `txn`: an
/// unsealed row as before, a sealed one opened with its `AUTHORITY_OVERLAY`
/// record.
///
/// # Errors
/// A body that does not verify; an overlay row that does not open under a
/// live key, or names another subject than the row's op does.
pub(crate) fn decode_vault_authority_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
) -> Result<VaultAuthorityBody> {
    if !authority_body_is_sealed(body)? {
        return Ok(VaultAuthorityBody::Open(open_authority_log_entry_body(
            body, None,
        )?));
    }
    // Each path verifies the body's signatures once: with its record, or
    // over its scaffold when the record does not open here.
    let hash = *blake3::hash(body).as_bytes();
    let opened = match AUTHORITY_OVERLAY.get(store, txn, &hash)? {
        Some(row) => {
            let sealed = SealedOverlay::from_bytes(&row)?;
            custody::open(store, txn, &hash, &sealed)?.map(|record| (sealed, record))
        }
        None => None,
    };
    let Some((sealed, record)) = opened else {
        return Ok(VaultAuthorityBody::Erased(
            verify_authority_log_entry_scaffold(body)?,
        ));
    };
    let record = decode_authority_overlay_record(&record)?;
    let entry = open_authority_log_entry_body(body, Some(&record))?;
    if authority_overlay_subject(&entry.op)? != sealed.subject {
        return Err(Error::CorruptedIndex("authority overlay subject"));
    }
    Ok(VaultAuthorityBody::Open(entry))
}

/// [`decode_vault_authority_body_in_txn`] for a door or reader that needs
/// the whole entry: a sealed row whose record does not open here answers
/// the overlay-unavailable error (`is_authority_overlay_unavailable`).
///
/// # Errors
/// As [`decode_vault_authority_body_in_txn`], and an erased row.
pub(crate) fn open_vault_authority_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
) -> Result<AuthorityLogEntry> {
    match decode_vault_authority_body_in_txn(store, txn, body)? {
        VaultAuthorityBody::Open(entry) => Ok(entry),
        VaultAuthorityBody::Erased(_) => Err(authority_overlay_unavailable()),
    }
}
