//! A typed body's text at an earlier frontier holding a key no mark places
//! (OF-067, FIX 8996). A read at that frontier marks what it can, as the
//! sweep marks the live body's (`typed_body::lift`), and files what it
//! cannot as the sweep files an unplaceable live hit ([`super::retained`]'s
//! `text_done`): one value-free proposal for the owner, on the body's live
//! row, with its needs-you notice. The proposal takes the row's history
//! slot, since the live row may read clean while its history holds the key:
//! a run's clean read of the live row never closes it, and the owner's
//! close or the row's delete does. While it stands, or once the owner
//! closed it, a read files nothing and opens no writer for it.

use heed::{RoTxn, RwTxn};

use super::super::{CarrierText, SecretScanMode, secret_scan_mode_in_txn};
use super::{
    Done, LiftCause, LiftFamily, PROPOSALS, SecretLiftHistoryProposal, carriers, hex, notice,
    proposal_key, proposals, short,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_snapshot::SnapshotSecretLiftProposal;
use crate::side_table;

/// The census cursor of `entity`'s live body row, and the key of the
/// earlier-frontier proposal it holds.
fn keys_of(entity: &EntityId) -> Option<(Vec<u8>, Vec<u8>)> {
    let cursor = carriers::cursor_of(&side_table::TYPED_BODY_DOC, entity.as_bytes())?;
    let row_key = proposal_key(LiftFamily::Carriers, LiftCause::History, &cursor);
    Some((cursor, row_key))
}

/// Whether a key no mark places in `entity`'s typed body at an earlier
/// frontier files a proposal now: the owner's switch is on and the body's
/// row holds no such proposal, open or closed by the owner. One that closed
/// because its row read clean or was gone files again.
pub(crate) fn typed_body_at_proposal_due_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<bool> {
    if secret_scan_mode_in_txn(&vault.store, txn)? == SecretScanMode::Off {
        return Ok(false);
    }
    let Some((_, row_key)) = keys_of(entity) else {
        return Ok(false);
    };
    Ok(match PROPOSALS.get_lenient(&vault.store, txn, &row_key)? {
        None => true,
        Some(held) => !held.is_open() && proposals::reopens(&held),
    })
}

/// Files the owner's proposal for `marked`, the outcome of marking
/// `entity`'s typed body at an earlier frontier, when it is a hit no span
/// places and one is due ([`typed_body_at_proposal_due_in_txn`]), in the
/// caller's transaction: the sweep's `unplaceable` proposal, value-free, and
/// the needs-you notice raised for the proposals open.
pub(crate) fn propose_typed_body_at_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    marked: CarrierText,
) -> Result<()> {
    if !matches!(marked, CarrierText::Unplaceable(_)) {
        return Ok(());
    }
    let Done::Propose(cause, reason) = super::retained::text_done(marked) else {
        return Ok(());
    };
    if !typed_body_at_proposal_due_in_txn(vault, txn, entity)? {
        return Ok(());
    }
    let Some((cursor, row_key)) = keys_of(entity) else {
        return Ok(());
    };
    let path = carriers::path(&cursor);
    let filed_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    // The read that filed it: no run's walk did.
    let filer = vault.store.clock.entity_id()?;
    PROPOSALS.put(
        &vault.store,
        txn,
        &row_key,
        &SecretLiftHistoryProposal {
            id: hex(&row_key),
            family: LiftFamily::Carriers,
            cause,
            proposal: SnapshotSecretLiftProposal {
                suggested_secret_name: format!(
                    "lifted.{}.{}",
                    LiftFamily::Carriers.code(),
                    short(&path)
                ),
                path,
                detector_reason: reason.to_owned(),
                project_id: String::new(),
            },
            run_id: filer.to_hex(),
            filed_at,
            closed_at: None,
            closed_by: None,
            close_reason: None,
            close_receipt: None,
        },
    )?;
    notice::after_run_in_txn(vault, txn, filer, 1, filed_at)
}
