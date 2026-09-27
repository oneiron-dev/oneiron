//! Opt-in gate-decision age sweep over the actual ORCB custody unit.
//!
//! ONE-1640 uses one exterior key per claim, not a shared time-bucket key.
//! A claim ID is therefore the indivisible encrypted partition. An unlinked
//! decision has no exterior key and belongs to the separate unlinked partition.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;

use super::orcb;
use super::types::GateDecisionRecord;

const HORIZON_KEY: &[u8] = b"gate_decision:retention_secs:v1";
const HOLD_PREFIX: &[u8] = b"gate_decision:partition_hold:v1:";
const RETAIN_PREFIX: &[u8] = b"gate_decision:partition_retain_until:v1:";
const RETIRE_PENDING_PREFIX: &[u8] = b"gate_decision:partition_retire_pending:v1:";
const MAX_SWEEP_ROWS: usize = 256;

pub(super) fn pending_key(claim: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::from(RETIRE_PENDING_PREFIX);
    key.extend_from_slice(claim);
    key
}

fn retention_secs_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Option<u64>> {
    match store.vault_meta.get(txn, HORIZON_KEY)? {
        None => Ok(None),
        Some(raw) => {
            let bytes: [u8; 8] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("gate decision retention"))?;
            let seconds = u64::from_be_bytes(bytes);
            if seconds == 0 {
                return Err(Error::CorruptedIndex("gate decision retention"));
            }
            Ok(Some(seconds))
        }
    }
}

fn partition_key(prefix: &[u8], claim: Option<&[u8; 16]>) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + claim.map_or(1, |_| 17));
    key.extend_from_slice(prefix);
    match claim {
        Some(id) => {
            key.push(1);
            key.extend_from_slice(id);
        }
        None => key.push(0),
    }
    key
}

impl Store {
    pub(crate) fn gate_partition_held_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: Option<&[u8; 16]>,
    ) -> Result<bool> {
        match self
            .vault_meta
            .get(txn, &partition_key(HOLD_PREFIX, claim))?
        {
            None => Ok(false),
            Some(raw) if raw.as_ref() == [1] => Ok(true),
            Some(_) => Err(Error::CorruptedIndex("gate decision partition hold")),
        }
    }

    pub(in crate::store) fn gate_partition_retire_pending_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: &[u8; 16],
    ) -> Result<bool> {
        match self.vault_meta.get(txn, &pending_key(claim))? {
            None => Ok(false),
            Some(raw) if raw.as_ref() == [1] => Ok(true),
            Some(_) => Err(Error::CorruptedIndex("gate decision retirement intent")),
        }
    }

    pub(crate) fn reject_held_gate_partition_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim: &[u8; 16],
    ) -> Result<()> {
        if self.gate_partition_held_in_txn(txn, Some(claim))? {
            return Err(Error::InvalidConfig(
                "gate decision partition is under legal hold".into(),
            ));
        }
        Ok(())
    }
}

impl Vault {
    /// Set an owner-chosen age limit in seconds. No setting means NO pruning.
    /// Zero is rejected rather than turning a configuration mistake into a
    /// sweep of every historical decision.
    pub fn set_gate_decision_retention_secs(&self, seconds: Option<u64>) -> Result<()> {
        if seconds == Some(0) {
            return Err(Error::InvalidConfig(
                "gate decision retention must be positive".into(),
            ));
        }
        self.with_write_txn(|txn| {
            match seconds {
                Some(seconds) => {
                    self.store
                        .vault_meta
                        .put(txn, HORIZON_KEY, &seconds.to_be_bytes())?;
                }
                None => {
                    self.store.vault_meta.delete(txn, HORIZON_KEY)?;
                }
            }
            Ok(())
        })
    }

    /// The configured age limit, or None if no age sweep is authorized.
    pub fn gate_decision_retention_secs(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        retention_secs_in_txn(&self.store, &txn)
    }

    /// Hold the entire exterior-key partition, not an individual decision.
    /// `None` names the plaintext, claim-free partition. A hold must be
    /// released explicitly; the age sweep never clears it.
    pub fn set_gate_decision_partition_hold(
        &self,
        claim_partition: Option<[u8; 16]>,
        held: bool,
    ) -> Result<()> {
        let key = partition_key(HOLD_PREFIX, claim_partition.as_ref());
        self.with_write_txn(|txn| {
            if held {
                self.store.vault_meta.put(txn, &key, &[1])?;
            } else {
                self.store.vault_meta.delete(txn, &key)?;
            }
            Ok(())
        })
    }

    /// The most recent retain-until stamp for a held partition, if present.
    pub fn gate_decision_partition_retain_until(
        &self,
        claim_partition: Option<[u8; 16]>,
    ) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        let key = partition_key(RETAIN_PREFIX, claim_partition.as_ref());
        self.store
            .vault_meta
            .get(&txn, &key)?
            .map(|raw| {
                let bytes: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("gate decision retain until"))?;
                Ok(u64::from_be_bytes(bytes))
            })
            .transpose()
    }

    /// Complete durable key retirements left after an interrupted sweep.
    /// Never deletes a live row: the pending marker is committed with removal
    /// of every primary in that physical key partition.
    fn finish_gate_decision_retirements(&self) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let mut pending = Vec::new();
        for row in self
            .store
            .vault_meta
            .prefix_iter(&txn, RETIRE_PENDING_PREFIX)?
        {
            let (key, value) = row?;
            let claim: [u8; 16] = key
                .strip_prefix(RETIRE_PENDING_PREFIX)
                .ok_or(Error::CorruptedIndex("gate decision retirement intent"))?
                .try_into()
                .map_err(|_| Error::CorruptedIndex("gate decision retirement intent"))?;
            if value.as_ref() != [1] {
                return Err(Error::CorruptedIndex("gate decision retirement intent"));
            }
            pending.push(claim);
        }
        drop(txn);
        for claim in pending {
            let txn = self.store.env.read_txn()?;
            let mut has_live_row = false;
            self.store.for_each_gate_decision_in_txn(&txn, |record| {
                has_live_row |= record.claim_id == Some(claim);
                Ok(())
            })?;
            if has_live_row {
                return Err(Error::CorruptedIndex(
                    "retiring gate decision partition has live rows",
                ));
            }
            drop(txn);
            orcb::retire_claim_key(&self.store.core.gate_custody_root, &claim)?;
            self.with_write_txn(|txn| {
                // Keep the marker if a concurrent caller has replaced it with
                // an unexpected value; never silently erase a new obligation.
                if !self
                    .store
                    .gate_partition_retire_pending_in_txn(txn, &claim)?
                {
                    return Err(Error::CorruptedIndex("gate decision retirement intent"));
                }
                self.store.vault_meta.delete(txn, &pending_key(&claim))?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Remove decisions strictly older than the owner-selected horizon.
    /// Sidecars and primaries leave together. A key is destroyed only when
    /// *every* decision it decrypts is gone; a held partition is untouched.
    /// Removes at most 256 rows per call; repeat until it returns zero.
    /// Returns the number of decision rows removed.
    pub fn sweep_gate_decision_retention(&self) -> Result<u64> {
        self.finish_gate_decision_retirements()?;
        let now = self.store.clock.now_recorded_at();
        let mut txn = self.store.env.write_txn()?;
        // Read the owner setting UNDER the same writer lock as pruning: an
        // owner who disables or lengthens retention before this pass wins.
        let Some(seconds) = retention_secs_in_txn(&self.store, &txn)? else {
            return Ok(0);
        };
        let cutoff = now.saturating_sub(seconds);
        let retain_until = now
            .checked_add(seconds)
            .ok_or(Error::ArithmeticOverflow("gate decision retain until"))?;
        // Decode BEFORE mutating. A corrupt ciphertext/key aborts the entire
        // sweep instead of quietly miscounting the rows that share that key.
        let mut eligible: Vec<GateDecisionRecord> = Vec::new();
        let mut live_claims = BTreeSet::new();
        let mut removed_claims = BTreeSet::new();
        let mut held_partitions = BTreeSet::new();
        self.store.for_each_gate_decision_in_txn(&txn, |record| {
            let claim = record.claim_id;
            if self
                .store
                .gate_partition_held_in_txn(&txn, claim.as_ref())?
            {
                held_partitions.insert(claim);
                if let Some(claim) = claim {
                    live_claims.insert(claim);
                }
            } else if record.created_at < cutoff && eligible.len() < MAX_SWEEP_ROWS {
                if let Some(claim) = claim {
                    removed_claims.insert(claim);
                }
                eligible.push(record);
            } else if let Some(claim) = claim {
                // A skipped old row is still live until a later bounded pass.
                live_claims.insert(claim);
            }
            Ok(())
        })?;
        for claim in held_partitions {
            let key = partition_key(RETAIN_PREFIX, claim.as_ref());
            let previous = self
                .store
                .vault_meta
                .get(&txn, &key)?
                .map(|raw| -> Result<u64> {
                    let bytes: [u8; 8] = raw
                        .as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("gate decision retain until"))?;
                    Ok(u64::from_be_bytes(bytes))
                })
                .transpose()?
                .unwrap_or(0);
            self.store
                .vault_meta
                .put(&mut txn, &key, &previous.max(retain_until).to_be_bytes())?;
        }
        let removed = eligible.len() as u64;
        for record in &eligible {
            self.store
                .delete_gate_decision_record_in_txn(&mut txn, record)?;
        }
        // Commit the intent WITH row removal, then touch exterior keys.
        // A crash before commit leaves readable rows; a crash after commit
        // leaves a resumable pending marker and no rows that need the key.
        for claim in removed_claims.difference(&live_claims) {
            self.store
                .vault_meta
                .put(&mut txn, &pending_key(claim), &[1])?;
        }
        txn.commit()?;
        self.finish_gate_decision_retirements()?;
        Ok(removed)
    }
}
