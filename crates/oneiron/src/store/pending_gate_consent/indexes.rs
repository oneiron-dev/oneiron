//! Run/group/hash index sidecars, group-alias refresh, and the critical-confirm confirm-id sidecar.

use heed::{RoTxn, RwTxn};

use crate::batch::EntityMetadataHeader;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::ENTITY_BODY_OFFSET;
use super::Store;
use super::keys::{
    pending_gate_consent_group_index_key, pending_gate_consent_group_index_prefix,
    pending_gate_consent_run_index_key, pending_gate_consent_run_index_prefix,
};
use super::records::{
    PENDING_GATE_CONSENT_INDEX_STATE_VERSION, PendingGateConsentIndexState,
    PendingGateConsentRecord, decode_pending_gate_consent_index_state,
    encode_pending_gate_consent_index_state, sort_pending_gate_consents,
};
use super::tray::TRAY;

/// Presence marker literal byte `b"1"`, matching the marker already on disk
/// for the run/group/hash secondary indexes.
struct OneMarker;

impl RawValue for OneMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(b"1".to_vec())
    }

    fn from_raw(_bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self)
    }
}

const RUN_INDEX: SideTable<Vec<u8>, OneMarker, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT_RUN_INDEX);
const GROUP_INDEX: SideTable<Vec<u8>, OneMarker, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT_GROUP_INDEX);
const HASH_INDEX: SideTable<([u8; 32], EntityId), OneMarker, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT_HASH_INDEX);
const CRITICAL_CONFIRM_INDEX: SideTable<[u8; 32], EntityId, Raw> =
    SideTable::new(&side_table::CRITICAL_CONFIRM_INDEX);

/// Codec fixed `Raw` (see the decls.rs note): [`RawValue`] delegates to
/// [`encode_pending_gate_consent_index_state`]/
/// [`decode_pending_gate_consent_index_state`].
const INDEX_STATE: SideTable<EntityId, PendingGateConsentIndexState, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT_INDEX_STATE);

impl RawValue for PendingGateConsentIndexState {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_pending_gate_consent_index_state(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_pending_gate_consent_index_state(bytes)?)
    }
}

/// The bytes of a composite index key after its table's own declared prefix:
/// strips `base_prefix` (the module's existing hand-spelled prefix constant,
/// byte-identical to the table's declaration) from a key the module's
/// existing builder already produced in full.
fn suffix_of(full: Vec<u8>, base_prefix: &[u8]) -> Vec<u8> {
    full[base_prefix.len()..].to_vec()
}

/// The trailing 16-byte id of a composite index key, given the raw suffix
/// [`SideTable::scan_keys`] returns for a scan scoped to one string
/// component (so the suffix still carries that component's own encoding
/// ahead of the id).
fn tail_id(bytes: &[u8], context: &'static str) -> Result<[u8; 16]> {
    bytes
        .len()
        .checked_sub(16)
        .and_then(|start| bytes.get(start..))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::CorruptedIndex(context))
}

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
        self.put_pending_gate_consent_index_state_in_txn(wtxn, record, &state)
    }

    fn put_pending_gate_consent_index_state_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
        state: &PendingGateConsentIndexState,
    ) -> Result<()> {
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        RUN_INDEX.put(
            self,
            wtxn,
            &suffix_of(
                pending_gate_consent_run_index_key(&state.run_id, &record.claim_id),
                super::keys::PENDING_GATE_CONSENT_RUN_INDEX_PREFIX,
            ),
            &OneMarker,
        )?;
        GROUP_INDEX.put(
            self,
            wtxn,
            &suffix_of(
                pending_gate_consent_group_index_key(&state.group_key, &record.claim_id),
                super::keys::PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX,
            ),
            &OneMarker,
        )?;
        if let Some(semantic_claim_hash) = state.semantic_claim_hash.as_ref() {
            HASH_INDEX.put(self, wtxn, &(*semantic_claim_hash, claim_id), &OneMarker)?;
        }
        INDEX_STATE.put(self, wtxn, &claim_id, state)?;
        Ok(())
    }

    /// Rebuild checkpoint sidecars from pending rows and their historical
    /// index-state/sequence witnesses, never from a possibly changed claim.
    pub(crate) fn rebuild_pending_gate_consent_sidecars(&self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        let records = TRAY
            .scan(self, &*wtxn)?
            .into_iter()
            .map(|(claim_id, record)| {
                if claim_id != record.claim_id {
                    return Err(Error::CorruptedIndex("pending gate consent"));
                }
                Ok(record)
            })
            .collect::<Result<Vec<_>>>()?;
        for record in records {
            if record.dreamer_run_id.is_some() {
                let state = self
                    .pending_gate_consent_index_state_in_txn(wtxn, &record)?
                    .ok_or(Error::CorruptedIndex("pending gate consent index state"))?;
                self.put_pending_gate_consent_index_state_in_txn(wtxn, &record, &state)?;
            }
            self.put_pending_gate_consent_critical_confirm_index_in_txn(wtxn, &record)?;
            let claim_id = EntityId::from_bytes(record.claim_id)
                .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
            let sequence = super::sequence_sweep::SEQUENCE
                .get(self, &*wtxn, &claim_id)?
                .ok_or(Error::CorruptedIndex("pending gate consent sequence"))?;
            if sequence == 0
                || super::sequence_sweep::SEQUENCE_INDEX.contains(self, &*wtxn, &sequence)?
            {
                return Err(Error::CorruptedIndex("pending gate consent sequence index"));
            }
            super::sequence_sweep::SEQUENCE_INDEX.put(self, wtxn, &sequence, &claim_id)?;
        }
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
        let scan_prefix = suffix_of(
            pending_gate_consent_run_index_prefix(run_id),
            super::keys::PENDING_GATE_CONSENT_RUN_INDEX_PREFIX,
        );
        let mut records = Vec::new();
        for key in RUN_INDEX.scan_keys(self, &*wtxn, &scan_prefix)? {
            let claim_id = EntityId::from_bytes(tail_id(&key, "pending gate consent run index")?)
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
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        let Some(state) = INDEX_STATE.get(self, txn, &claim_id)? else {
            return Ok(None);
        };
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
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        RUN_INDEX.delete(
            self,
            wtxn,
            &suffix_of(
                pending_gate_consent_run_index_key(&state.run_id, &record.claim_id),
                super::keys::PENDING_GATE_CONSENT_RUN_INDEX_PREFIX,
            ),
        )?;
        GROUP_INDEX.delete(
            self,
            wtxn,
            &suffix_of(
                pending_gate_consent_group_index_key(&state.group_key, &record.claim_id),
                super::keys::PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX,
            ),
        )?;
        if let Some(semantic_claim_hash) = state.semantic_claim_hash.as_ref() {
            HASH_INDEX.delete(self, wtxn, &(*semantic_claim_hash, claim_id))?;
        }
        INDEX_STATE.delete(self, wtxn, &claim_id)?;
        Ok(())
    }

    /// Reads all pending consent rows stamped with one exact run id through
    /// the RCPT-1 run-scope sidecar.
    pub(crate) fn pending_gate_consents_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        let scan_prefix = suffix_of(
            pending_gate_consent_run_index_prefix(run_id),
            super::keys::PENDING_GATE_CONSENT_RUN_INDEX_PREFIX,
        );
        self.pending_gate_consents_for_vec_index_in_txn(
            &rtxn,
            RUN_INDEX,
            &scan_prefix,
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
        let scan_prefix = suffix_of(
            pending_gate_consent_group_index_prefix(group_key),
            super::keys::PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX,
        );
        self.pending_gate_consents_for_vec_index_in_txn(
            &rtxn,
            GROUP_INDEX,
            &scan_prefix,
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
        let mut records = Vec::new();
        for ((_hash, claim_id), _marker) in
            HASH_INDEX.scan_from(self, &rtxn, semantic_claim_hash)?
        {
            let Some(record) = self.pending_gate_consent_in_txn(&rtxn, &claim_id)? else {
                return Err(Error::CorruptedIndex("pending gate consent hash index"));
            };
            let Some(state) = self.pending_gate_consent_index_state_in_txn(&rtxn, &record)? else {
                return Err(Error::CorruptedIndex("pending gate consent hash index"));
            };
            if state.semantic_claim_hash.as_ref() != Some(semantic_claim_hash) {
                return Err(Error::CorruptedIndex("pending gate consent hash index"));
            }
            records.push(record);
        }
        sort_pending_gate_consents(&mut records);
        Ok(records)
    }

    fn pending_gate_consents_for_vec_index_in_txn<F>(
        &self,
        txn: &RoTxn<'_>,
        table: SideTable<Vec<u8>, OneMarker, Raw>,
        scan_prefix: &[u8],
        index_name: &'static str,
        state_matches: F,
    ) -> Result<Vec<PendingGateConsentRecord>>
    where
        F: Fn(&PendingGateConsentIndexState) -> bool,
    {
        let mut records = Vec::new();
        for key in table.scan_keys(self, txn, scan_prefix)? {
            let claim_id = EntityId::from_bytes(tail_id(&key, index_name)?)
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
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        if let Some(existing) = CRITICAL_CONFIRM_INDEX.get(self, &*wtxn, &binding.confirm_id)?
            && existing != claim_id
        {
            return Err(Error::CorruptedIndex("critical confirm index"));
        }
        CRITICAL_CONFIRM_INDEX.put(self, wtxn, &binding.confirm_id, &claim_id)?;
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
        CRITICAL_CONFIRM_INDEX.delete(self, wtxn, &binding.confirm_id)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn put_critical_confirm_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        confirm_id: &[u8; 32],
        claim_id: &[u8; 16],
    ) -> Result<()> {
        let claim_id = EntityId::from_bytes(*claim_id)
            .map_err(|_| Error::CorruptedIndex("critical confirm index"))?;
        CRITICAL_CONFIRM_INDEX.put(self, wtxn, confirm_id, &claim_id)?;
        Ok(())
    }

    pub(crate) fn critical_confirm_claim_id_in_txn(
        &self,
        txn: &RoTxn<'_>,
        confirm_id: &[u8; 32],
    ) -> Result<Option<EntityId>> {
        CRITICAL_CONFIRM_INDEX.get(self, txn, confirm_id)
    }

    pub(crate) fn delete_critical_confirm_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        confirm_id: &[u8; 32],
    ) -> Result<()> {
        CRITICAL_CONFIRM_INDEX.delete(self, wtxn, confirm_id)?;
        Ok(())
    }
}
