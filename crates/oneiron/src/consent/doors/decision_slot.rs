//! The owner-decision slots: one 32-byte key per thing an owner decides,
//! taken once beside the approve-once markers (moved out of `doors.rs`,
//! FIX 9397).

use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::store::GateDecisionId;

use super::super::lifecycle_table_imports::*;
use super::super::support::{APPROVE_ONCE_MARKERS, ApproveOnceMarker};
use super::{marker_byte, marker_state};

impl Vault {
    /// Takes the one owner-decision slot `slot` names, in `wtxn`, for the
    /// decision `decision_id`.
    ///
    /// A slot is a 32-byte key the caller derives, domain-separated, from
    /// what is being decided, independent of which owner decides, so the
    /// first decision by any owner is the only one. It lives beside the
    /// approve-once markers, already spent: no effect digest names it, so it
    /// never authorizes anything, and a restore carries it with them.
    ///
    /// # Errors
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent)
    /// when the slot is already taken.
    pub(crate) fn take_decision_slot_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        slot: &[u8; 32],
        decision_id: GateDecisionId,
    ) -> Result<()> {
        let to = self.decision_slot_state_in_txn(wtxn, slot)?;
        let marker = ApproveOnceMarker {
            state: marker_byte(to),
            decision_id,
        };
        APPROVE_ONCE_MARKERS.put(&self.store, wtxn, slot, &marker)?;
        Ok(())
    }

    /// Refuses, without taking it, when the decision slot `slot` names is
    /// already taken: a path that decides nothing still must not act on
    /// something an owner already decided.
    ///
    /// # Errors
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent)
    /// when the slot is taken.
    pub(crate) fn ensure_decision_slot_open_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        slot: &[u8; 32],
    ) -> Result<()> {
        self.decision_slot_state_in_txn(txn, slot).map(|_| ())
    }

    /// The state the marker table gives a slot an owner decision takes, or the refusal of a taken slot.
    fn decision_slot_state_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        slot: &[u8; 32],
    ) -> Result<MarkerState> {
        let from = APPROVE_ONCE_MARKERS
            .get(&self.store, txn, slot)?
            .map(|marker| marker_state(&marker));
        ConsentLifecycle::marker(from, MarkerCommand::TakeDecisionSlot).map_err(|_| {
            Error::Gate(GateError::ConsentApproveOnceSpent(
                "this already carries an owner decision",
            ))
        })
    }
}
