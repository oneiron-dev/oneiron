//! The owner-decision slots: one 32-byte key per thing an owner decides,
//! taken once beside the approve-once markers (moved out of `doors.rs`,
//! FIX 9397).

use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::store::GateDecisionId;

use super::super::support::{APPROVE_ONCE_MARKERS, ApproveOnceMarker, CONSENT_APPROVE_ONCE_SPENT};

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
        self.ensure_decision_slot_open_in_txn(wtxn, slot)?;
        let marker = ApproveOnceMarker {
            state: CONSENT_APPROVE_ONCE_SPENT,
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
        if APPROVE_ONCE_MARKERS.get(&self.store, txn, slot)?.is_some() {
            return Err(Error::Gate(GateError::ConsentApproveOnceSpent(
                "this already carries an owner decision",
            )));
        }
        Ok(())
    }
}
