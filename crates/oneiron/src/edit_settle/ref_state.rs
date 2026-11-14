//! The one owner of a settle ref's state (FIX 22386). Three tables share the
//! settlement key: the consume-once ledger, the waiting proposal and the held
//! organ call. Every door that holds, retains, proposes or settles under a
//! ref moves it here, in its own write transaction, so a ref one door holds
//! is held for every other door.
//!
//! | state            | hold organ | land proposal                  | settle  |
//! |------------------|------------|--------------------------------|---------|
//! | absent           | yes        | yes                            | yes     |
//! | waiting organ    | refused    | only the held call's own, once | refused |
//! | waiting proposal | refused    | refused                        | yes     |
//! | settled          | refused    | refused                        | refused |
//!
//! A held call's refusal names the call and how its hold ends: a redrive
//! lands its files, or a release lets it go. Release and purge only delete
//! a held call's row, as before.

use heed::{RoTxn, RwTxn};

use super::codec::{RECORD, settlement_key_parts};
use super::organ_wait::{OrganWait, WAITS, WaitRow};
use super::pending::PENDING;
use super::receipts::already_settled;
use super::records::SettlementRecord;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::store::Store;

/// Where one ref stands. Read in the order ledger, proposal, held call, so a
/// vault that kept a proposal and a held call under one ref before FIX 22386
/// gives the outcome it gave then.
pub(super) enum RefState {
    Absent,
    WaitingOrgan(WaitRow),
    WaitingProposal,
    Settled(SettlementRecord),
}

/// One move a door makes under a ref.
pub(super) enum RefMove<'a> {
    /// An organ call is held under the ref until a node can run it.
    HoldOrgan,
    /// A proposal waits under the ref. `held` is the organ call whose own
    /// output this is, landing at a redrive: it may take the ref its call
    /// holds, and that hold ends in the same writer.
    LandProposal { held: Option<&'a OrganWait> },
    /// The ref is settled: a select, a discard, a split's withdrawal or a
    /// native output's Keep.
    Settle,
}

/// The state of the ref under `key` in `txn`.
pub(super) fn ref_state_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    key: &(EntityId, [u8; 32]),
) -> Result<RefState> {
    if let Some(record) = RECORD.get(store, txn, key)? {
        return Ok(RefState::Settled(record));
    }
    if PENDING.contains(store, txn, key)? {
        return Ok(RefState::WaitingProposal);
    }
    Ok(match WAITS.get(store, txn, key)? {
        Some(row) => RefState::WaitingOrgan(row),
        None => RefState::Absent,
    })
}

/// Checks `change` against the ref under `key` in `txn`, the writer that
/// then writes the row the move names. A held call's landing stands only
/// while that call still holds its own ref, whichever ref the file lands
/// under, and a file under that ref itself deletes the hold here.
///
/// # Errors
///
/// A settled ref answers its prior outcome; a waiting proposal refuses a
/// second one and a hold; a held call refuses every move but its own
/// landing, naming itself ([`ArtifactError::EditRefHeldByOrganCall`]); a
/// landing whose call is not held, or holds its ref as another call or
/// after it failed.
pub(super) fn move_ref_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
    change: RefMove<'_>,
) -> Result<()> {
    if let RefMove::LandProposal { held: Some(wait) } = &change {
        require_held_call_in_txn(store, txn, wait)?;
    }
    match (ref_state_in_txn(store, txn, key)?, change) {
        (RefState::Settled(record), _) => Err(already_settled(&record)),
        (RefState::Absent, _) | (RefState::WaitingProposal, RefMove::Settle) => Ok(()),
        (RefState::WaitingProposal, RefMove::HoldOrgan | RefMove::LandProposal { .. }) => {
            Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "a proposal already waits under this ref",
            )))
        }
        (RefState::WaitingOrgan(row), RefMove::LandProposal { held: Some(wait) })
            if row.is_call(wait) =>
        {
            WAITS.delete(store, txn, key)?;
            Ok(())
        }
        (RefState::WaitingOrgan(row), _) => Err(row.holds_ref()),
    }
}

/// The hold a held call's landing stands on: the row under the call's own
/// ref is exactly this call, not failed. A file `<run_ref>/<n>` lands under
/// a ref of its own, so this is read at the call's ref, not the file's.
fn require_held_call_in_txn(store: &Store, txn: &RoTxn<'_>, wait: &OrganWait) -> Result<()> {
    let source = settlement_key_parts(&wait.artifact_id, &wait.run_ref);
    match WAITS.get(store, txn, &source)? {
        Some(row) if row.is_call(wait) => Ok(()),
        Some(row) => Err(row.holds_ref()),
        None => Err(Error::Artifact(ArtifactError::InvalidEditManifest(
            "no organ call is held under the ref this output names",
        ))),
    }
}
