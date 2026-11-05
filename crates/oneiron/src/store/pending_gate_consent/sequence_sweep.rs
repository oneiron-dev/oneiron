//! Core half of `store::pending_gate_consent::sequence_sweep`: its store-layer items live in `oneiron_store::pending_gate_consent::sequence_sweep` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::pending_gate_consent::sequence_sweep::*;

use super::Store;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use heed::{RoTxn, RwTxn};

/// Pending consent insertion sequence, keyed by claim id.
pub(super) const SEQUENCE: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT_SEQUENCE);

const SEQUENCE_COUNTER: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT_SEQUENCE_COUNTER);

/// Pending consents ordered by sequence; the value is the claim id.
pub(super) const SEQUENCE_INDEX: SideTable<u64, EntityId, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT_SEQUENCE_INDEX);

const CRITICAL_CONFIRM_EXPIRY_CURSOR: SideTable<(), SweepState, Raw> =
    SideTable::new(&side_table::CRITICAL_CONFIRM_EXPIRY_CURSOR);

const CRITICAL_CONFIRM_LIST_CURSOR: SideTable<(), SweepState, Raw> =
    SideTable::new(&side_table::CRITICAL_CONFIRM_LIST_CURSOR);

impl Store {
    pub(super) fn ensure_pending_gate_consent_sequence_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<u64> {
        let claim = EntityId::from_bytes(*claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        if let Some(sequence) = SEQUENCE.get(self, &*wtxn, &claim)? {
            return Ok(sequence);
        }
        let next = SEQUENCE_COUNTER
            .get(self, &*wtxn, &())?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::InvariantViolation(
                "pending gate consent sequence overflow",
            ))?;
        SEQUENCE_COUNTER.put(self, wtxn, &(), &next)?;
        SEQUENCE.put(self, wtxn, &claim, &next)?;
        SEQUENCE_INDEX.put(self, wtxn, &next, &claim)?;
        Ok(next)
    }

    pub(super) fn delete_pending_gate_consent_sequence_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<()> {
        let claim = EntityId::from_bytes(*claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        if let Some(sequence) = SEQUENCE.get(self, &*wtxn, &claim)? {
            SEQUENCE_INDEX.delete(self, wtxn, &sequence)?;
        }
        SEQUENCE.delete(self, wtxn, &claim)?;
        Ok(())
    }

    /// A sweep state is `(last inspected sequence, cycle high-water sequence)`.
    /// Sequence allocation is internal and monotonic, so hostile caller-chosen
    /// claim IDs cannot insert work behind an active fence. This makes a cycle
    /// finite even while new higher-key rows are being inserted.
    fn critical_confirm_sweep_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
        table: SideTable<(), SweepState, Raw>,
    ) -> Result<(Option<u64>, Option<u64>)> {
        let Some(state) = table.get(self, txn, &())? else {
            return Ok((None, None));
        };
        Ok((state.cursor, state.fence))
    }

    fn put_critical_confirm_sweep_state_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        table: SideTable<(), SweepState, Raw>,
        cursor: Option<u64>,
        fence: Option<u64>,
    ) -> Result<()> {
        if cursor.is_none() && fence.is_none() {
            table.delete(self, wtxn, &())?;
            return Ok(());
        }
        let (Some(cursor), Some(fence)) = (cursor, fence) else {
            return Err(Error::InvariantViolation(
                "critical confirm sweep cursor and fence must be paired",
            ));
        };
        if cursor > fence {
            return Err(Error::InvariantViolation(
                "critical confirm sweep cursor exceeds fence",
            ));
        }
        table.put(
            self,
            wtxn,
            &(),
            &SweepState {
                cursor: Some(cursor),
                fence: Some(fence),
            },
        )?;
        Ok(())
    }

    pub(crate) fn critical_confirm_expiry_sweep_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<(Option<u64>, Option<u64>)> {
        self.critical_confirm_sweep_state_in_txn(txn, CRITICAL_CONFIRM_EXPIRY_CURSOR)
    }

    pub(crate) fn put_critical_confirm_expiry_sweep_state_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        cursor: Option<u64>,
        fence: Option<u64>,
    ) -> Result<()> {
        self.put_critical_confirm_sweep_state_in_txn(
            wtxn,
            CRITICAL_CONFIRM_EXPIRY_CURSOR,
            cursor,
            fence,
        )
    }

    pub(crate) fn critical_confirm_list_sweep_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<(Option<u64>, Option<u64>)> {
        self.critical_confirm_sweep_state_in_txn(txn, CRITICAL_CONFIRM_LIST_CURSOR)
    }

    pub(crate) fn put_critical_confirm_list_sweep_state_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        cursor: Option<u64>,
        fence: Option<u64>,
    ) -> Result<()> {
        self.put_critical_confirm_sweep_state_in_txn(
            wtxn,
            CRITICAL_CONFIRM_LIST_CURSOR,
            cursor,
            fence,
        )
    }

    pub(crate) fn pending_gate_consents_high_water_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Option<u64>> {
        SEQUENCE_COUNTER.get(self, txn, &())
    }
}
