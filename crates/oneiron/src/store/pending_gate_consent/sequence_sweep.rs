//! Monotonic sequence allocator, high-water read, and sweep-state cursors for expiry/list sweeps.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};

use super::Store;
use super::keys::{
    CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY, CRITICAL_CONFIRM_LIST_CURSOR_KEY,
    PENDING_GATE_CONSENT_SEQUENCE_COUNTER_KEY, pending_gate_consent_sequence_index_key,
    pending_gate_consent_sequence_key,
};
use super::records::decode_pending_gate_consent_sequence;

impl Store {
    pub(super) fn ensure_pending_gate_consent_sequence_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<u64> {
        let key = pending_gate_consent_sequence_key(claim_id);
        if let Some(value) = self.vault_meta.get(&*wtxn, &key)? {
            return decode_pending_gate_consent_sequence(&value);
        }
        let next = self
            .vault_meta
            .get(&*wtxn, PENDING_GATE_CONSENT_SEQUENCE_COUNTER_KEY)?
            .map(|value| decode_pending_gate_consent_sequence(&value))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::InvariantViolation(
                "pending gate consent sequence overflow",
            ))?;
        let encoded = next.to_be_bytes();
        self.vault_meta
            .put(wtxn, PENDING_GATE_CONSENT_SEQUENCE_COUNTER_KEY, &encoded)?;
        self.vault_meta.put(wtxn, &key, &encoded)?;
        self.vault_meta.put(
            wtxn,
            &pending_gate_consent_sequence_index_key(next),
            claim_id,
        )?;
        Ok(next)
    }

    pub(super) fn delete_pending_gate_consent_sequence_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<()> {
        let key = pending_gate_consent_sequence_key(claim_id);
        if let Some(value) = self.vault_meta.get(&*wtxn, &key)? {
            let sequence = decode_pending_gate_consent_sequence(&value)?;
            self.vault_meta
                .delete(wtxn, &pending_gate_consent_sequence_index_key(sequence))?;
        }
        self.vault_meta.delete(wtxn, &key)?;
        Ok(())
    }

    /// A sweep state is `(last inspected sequence, cycle high-water sequence)`.
    /// Sequence allocation is internal and monotonic, so hostile caller-chosen
    /// claim IDs cannot insert work behind an active fence. This makes a cycle
    /// finite even while new higher-key rows are being inserted.
    pub(crate) fn critical_confirm_sweep_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
        key: &[u8],
    ) -> Result<(Option<u64>, Option<u64>)> {
        let Some(value) = self.vault_meta.get(txn, key)? else {
            return Ok((None, None));
        };
        let value = value.as_ref();
        // Canonical wire form is flag + u64 cursor + flag + u64 fence.
        // Reject malformed metadata rather than making a malformed sweep resume
        // at an arbitrary point.
        if value.len() != 18 || !matches!(value[0], 0 | 1) || !matches!(value[9], 0 | 1) {
            return Err(Error::CorruptedIndex("critical confirm sweep state"));
        }
        let cursor_value = u64::from_be_bytes(value[1..9].try_into().expect("fixed slice"));
        let fence_value = u64::from_be_bytes(value[10..18].try_into().expect("fixed slice"));
        let cursor = (value[0] == 1).then_some(cursor_value);
        let fence = (value[9] == 1).then_some(fence_value);
        if (value[0] == 0 && cursor_value != 0)
            || (value[9] == 0 && fence_value != 0)
            || cursor.is_some() != fence.is_some()
            || cursor
                .zip(fence)
                .is_some_and(|(cursor, fence)| cursor > fence)
        {
            return Err(Error::CorruptedIndex("critical confirm sweep state"));
        }
        Ok((cursor, fence))
    }

    pub(crate) fn put_critical_confirm_sweep_state_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        key: &[u8],
        cursor: Option<u64>,
        fence: Option<u64>,
    ) -> Result<()> {
        if cursor.is_none() && fence.is_none() {
            self.vault_meta.delete(wtxn, key)?;
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
        let mut value = [0_u8; 18];
        value[0] = 1;
        value[1..9].copy_from_slice(&cursor.to_be_bytes());
        value[9] = 1;
        value[10..18].copy_from_slice(&fence.to_be_bytes());
        self.vault_meta.put(wtxn, key, &value)?;
        Ok(())
    }

    pub(crate) fn critical_confirm_expiry_sweep_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<(Option<u64>, Option<u64>)> {
        self.critical_confirm_sweep_state_in_txn(txn, CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY)
    }

    pub(crate) fn put_critical_confirm_expiry_sweep_state_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        cursor: Option<u64>,
        fence: Option<u64>,
    ) -> Result<()> {
        self.put_critical_confirm_sweep_state_in_txn(
            wtxn,
            CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY,
            cursor,
            fence,
        )
    }

    pub(crate) fn critical_confirm_list_sweep_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<(Option<u64>, Option<u64>)> {
        self.critical_confirm_sweep_state_in_txn(txn, CRITICAL_CONFIRM_LIST_CURSOR_KEY)
    }

    pub(crate) fn put_critical_confirm_list_sweep_state_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        cursor: Option<u64>,
        fence: Option<u64>,
    ) -> Result<()> {
        self.put_critical_confirm_sweep_state_in_txn(
            wtxn,
            CRITICAL_CONFIRM_LIST_CURSOR_KEY,
            cursor,
            fence,
        )
    }

    pub(crate) fn pending_gate_consents_high_water_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Option<u64>> {
        self.vault_meta
            .get(txn, PENDING_GATE_CONSENT_SEQUENCE_COUNTER_KEY)?
            .map(|value| decode_pending_gate_consent_sequence(&value))
            .transpose()
    }
}
