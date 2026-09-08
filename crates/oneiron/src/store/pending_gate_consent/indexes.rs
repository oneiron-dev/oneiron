//! Run/group/hash index sidecars, group-alias refresh, and the critical-confirm confirm-id sidecar.

use heed::{RoTxn, RwTxn};

use crate::batch::EntityMetadataHeader;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;

use super::ENTITY_BODY_OFFSET;
use super::Store;
use super::keys::{
    critical_confirm_index_key, index_suffix_id, pending_gate_consent_group_index_key,
    pending_gate_consent_group_index_prefix, pending_gate_consent_hash_index_key,
    pending_gate_consent_hash_index_prefix, pending_gate_consent_index_state_key,
    pending_gate_consent_run_index_key, pending_gate_consent_run_index_prefix,
};
use super::records::{
    PENDING_GATE_CONSENT_INDEX_STATE_VERSION, PendingGateConsentIndexState,
    PendingGateConsentRecord, decode_pending_gate_consent_index_state,
    encode_pending_gate_consent_index_state, sort_pending_gate_consents,
};

impl Store {
    fn pending_gate_consent_index_state_for_record_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<Option<PendingGateConsentIndexState>> {
        let Some(run_id) = record.dreamer_run_id.as_deref() else {
            return Ok(None);
        };
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        // Low-level receipt tests and generic pending asks can legitimately
        // lack a claim body. They remain run-indexed; only readable CLAIM
        // rows participate in the inbox's semantic duplicate sidecar.
        let semantic_claim_hash = match self.entities.get(wtxn, claim_id.as_bytes())? {
            None => None,
            Some(raw) => {
                let Some(header) = EntityMetadataHeader::parse(&raw) else {
                    return Err(Error::CorruptedIndex("entity header"));
                };
                if header.entity_type != ENTITY_TYPE_CLAIM {
                    None
                } else {
                    let body = raw
                        .get(ENTITY_BODY_OFFSET..)
                        .ok_or(Error::CorruptedIndex("pending gate consent"))?;
                    Some(crate::inbox::inbox_claim_hash(
                        &crate::claim::decode_claim_body(body, true)?,
                    )?)
                }
            }
        };
        let group_key = crate::attempt_queue::dreamer_run_root_id_in_txn(self, wtxn, run_id)?
            .map_or_else(
                || run_id.to_owned(),
                |root| bytes_to_hex_lower(root.as_bytes()),
            );
        Ok(Some(PendingGateConsentIndexState {
            version: PENDING_GATE_CONSENT_INDEX_STATE_VERSION,
            run_id: run_id.to_owned(),
            group_key,
            semantic_claim_hash,
        }))
    }

    pub(in crate::store) fn put_pending_gate_consent_indexes_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        let Some(state) = self.pending_gate_consent_index_state_for_record_in_txn(wtxn, record)?
        else {
            return Ok(());
        };
        self.vault_meta.put(
            wtxn,
            &pending_gate_consent_run_index_key(&state.run_id, &record.claim_id),
            b"1",
        )?;
        self.vault_meta.put(
            wtxn,
            &pending_gate_consent_group_index_key(&state.group_key, &record.claim_id),
            b"1",
        )?;
        if let Some(semantic_claim_hash) = state.semantic_claim_hash.as_ref() {
            self.vault_meta.put(
                wtxn,
                &pending_gate_consent_hash_index_key(semantic_claim_hash, &record.claim_id),
                b"1",
            )?;
        }
        let encoded = encode_pending_gate_consent_index_state(&state)?;
        self.vault_meta.put(
            wtxn,
            &pending_gate_consent_index_state_key(&record.claim_id),
            &encoded,
        )?;
        Ok(())
    }

    /// Recomputes the derived group aliases after a run gains an attempt. A
    /// pending consent can predate its durable root, so its old alias may no
    /// longer match the run tree that the inbox projection resolves.
    pub(in crate::store) fn refresh_pending_gate_consent_group_aliases_for_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: &str,
    ) -> Result<()> {
        let prefix = pending_gate_consent_run_index_prefix(run_id);
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(&*wtxn, &prefix)? {
            let (key, _) = row?;
            let claim_id = EntityId::from_bytes(index_suffix_id(
                &key,
                &prefix,
                "pending gate consent run index",
            )?)
            .map_err(|_| Error::CorruptedIndex("pending gate consent run index"))?;
            let Some(record) = self.pending_gate_consent_in_txn(&*wtxn, &claim_id)? else {
                return Err(Error::CorruptedIndex("pending gate consent run index"));
            };
            let Some(state) = self.pending_gate_consent_index_state_in_txn(&*wtxn, &record)? else {
                return Err(Error::CorruptedIndex("pending gate consent run index"));
            };
            if state.run_id != run_id {
                return Err(Error::CorruptedIndex("pending gate consent run index"));
            }
            records.push(record);
        }

        for record in &records {
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, record)?;
            self.put_pending_gate_consent_indexes_in_txn(wtxn, record)?;
        }
        Ok(())
    }

    fn pending_gate_consent_index_state_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<Option<PendingGateConsentIndexState>> {
        let Some(raw) = self
            .vault_meta
            .get(txn, &pending_gate_consent_index_state_key(&record.claim_id))?
        else {
            return Ok(None);
        };
        let state = decode_pending_gate_consent_index_state(&raw)?;
        if record.dreamer_run_id.as_deref() != Some(state.run_id.as_str()) {
            return Err(Error::CorruptedIndex("pending gate consent index state"));
        }
        Ok(Some(state))
    }

    pub(super) fn delete_pending_gate_consent_indexes_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        let Some(state) = self.pending_gate_consent_index_state_in_txn(&*wtxn, record)? else {
            if record.dreamer_run_id.is_some() {
                return Err(Error::CorruptedIndex("pending gate consent index state"));
            }
            return Ok(());
        };
        self.vault_meta.delete(
            wtxn,
            &pending_gate_consent_run_index_key(&state.run_id, &record.claim_id),
        )?;
        self.vault_meta.delete(
            wtxn,
            &pending_gate_consent_group_index_key(&state.group_key, &record.claim_id),
        )?;
        if let Some(semantic_claim_hash) = state.semantic_claim_hash.as_ref() {
            self.vault_meta.delete(
                wtxn,
                &pending_gate_consent_hash_index_key(semantic_claim_hash, &record.claim_id),
            )?;
        }
        self.vault_meta.delete(
            wtxn,
            &pending_gate_consent_index_state_key(&record.claim_id),
        )?;
        Ok(())
    }

    /// Reads all pending consent rows stamped with one exact run id through
    /// the RCPT-1 run-scope sidecar.
    pub(crate) fn pending_gate_consents_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = pending_gate_consent_run_index_prefix(run_id);
        self.pending_gate_consents_for_index_in_txn(
            &rtxn,
            &prefix,
            "pending gate consent run index",
            |state| state.run_id == run_id,
        )
    }

    /// Reads the raw-run rows behind one canonical Dreamer root group.  This
    /// alias is part of the same run-scope index family and lets an RS3 door
    /// use its root attempt hex without falling back to a table scan.
    pub(crate) fn pending_gate_consents_for_group_key(
        &self,
        group_key: &str,
    ) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = pending_gate_consent_group_index_prefix(group_key);
        self.pending_gate_consents_for_index_in_txn(
            &rtxn,
            &prefix,
            "pending gate consent group index",
            |state| state.group_key == group_key,
        )
    }

    /// Reads every open pending row with the inbox's semantic claim hash.
    /// This is a subordinate sidecar of the pending-consent family: it keeps
    /// #386's cross-run duplicate collapse exact without reopening the whole
    /// pending table for an explicit group.
    pub(crate) fn pending_gate_consents_for_semantic_claim_hash(
        &self,
        semantic_claim_hash: &[u8; 32],
    ) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = pending_gate_consent_hash_index_prefix(semantic_claim_hash);
        self.pending_gate_consents_for_index_in_txn(
            &rtxn,
            &prefix,
            "pending gate consent hash index",
            |state| state.semantic_claim_hash.as_ref() == Some(semantic_claim_hash),
        )
    }

    fn pending_gate_consents_for_index_in_txn<F>(
        &self,
        txn: &RoTxn<'_>,
        prefix: &[u8],
        index_name: &'static str,
        state_matches: F,
    ) -> Result<Vec<PendingGateConsentRecord>>
    where
        F: Fn(&PendingGateConsentIndexState) -> bool,
    {
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, prefix)? {
            let (key, _) = row?;
            let claim_id = EntityId::from_bytes(index_suffix_id(&key, prefix, index_name)?)
                .map_err(|_| Error::CorruptedIndex(index_name))?;
            let Some(record) = self.pending_gate_consent_in_txn(txn, &claim_id)? else {
                return Err(Error::CorruptedIndex(index_name));
            };
            let state = self.pending_gate_consent_index_state_in_txn(txn, &record)?;
            let Some(state) = state else {
                return Err(Error::CorruptedIndex(index_name));
            };
            if !state_matches(&state) {
                return Err(Error::CorruptedIndex(index_name));
            }
            records.push(record);
        }
        sort_pending_gate_consents(&mut records);
        Ok(records)
    }

    /// Keep the exact confirm-id sidecar in the same transaction as every
    /// pending-row lifecycle transition. Non-critical rows deliberately have no
    /// sidecar entry.
    pub(super) fn put_pending_gate_consent_critical_confirm_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        let Ok(binding) = crate::gate::critical_write_confirm_binding(record) else {
            return Ok(());
        };
        let key = critical_confirm_index_key(&binding.confirm_id);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &key)?
            && existing.as_ref() != record.claim_id
        {
            return Err(Error::CorruptedIndex("critical confirm index"));
        }
        self.vault_meta.put(wtxn, &key, &record.claim_id)?;
        Ok(())
    }

    pub(super) fn delete_pending_gate_consent_critical_confirm_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        let Ok(binding) = crate::gate::critical_write_confirm_binding(record) else {
            return Ok(());
        };
        self.vault_meta
            .delete(wtxn, &critical_confirm_index_key(&binding.confirm_id))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn put_critical_confirm_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        confirm_id: &[u8; 32],
        claim_id: &[u8; 16],
    ) -> Result<()> {
        self.vault_meta
            .put(wtxn, &critical_confirm_index_key(confirm_id), claim_id)?;
        Ok(())
    }

    pub(crate) fn critical_confirm_claim_id_in_txn(
        &self,
        txn: &RoTxn<'_>,
        confirm_id: &[u8; 32],
    ) -> Result<Option<EntityId>> {
        let Some(value) = self
            .vault_meta
            .get(txn, &critical_confirm_index_key(confirm_id))?
        else {
            return Ok(None);
        };
        EntityId::from_bytes(
            value
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("critical confirm index"))?,
        )
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("critical confirm index"))
    }

    pub(crate) fn delete_critical_confirm_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        confirm_id: &[u8; 32],
    ) -> Result<()> {
        self.vault_meta
            .delete(wtxn, &critical_confirm_index_key(confirm_id))?;
        Ok(())
    }
}
