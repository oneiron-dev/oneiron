//! Pending gate-consent tray lifecycle: put/get/delete, resolution into the decision ledger, and ordered reads.

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::Store;
use super::keys::{
    PENDING_GATE_CONSENT_KEY_PREFIX, PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX,
    pending_gate_consent_claim_id_from_key, pending_gate_consent_key,
    pending_gate_consent_sequence_from_index_key, pending_gate_consent_sequence_index_key,
    pending_gate_consent_sequence_index_upper_bound, pending_gate_consent_upper_bound,
};
use super::records::{
    PendingGateConsentGroup, PendingGateConsentRecord, decode_pending_gate_consent,
    encode_pending_gate_consent, vet_pending_gate_consent_record,
};
use super::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord,
    RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT, decode_gate_decision, gate_decision_key,
};

impl Store {
    pub(crate) fn put_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        vet_pending_gate_consent_record(record)?;
        let key = pending_gate_consent_key(&record.claim_id);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &key)? {
            let existing = decode_pending_gate_consent(&existing)?;
            if existing.claim_id != record.claim_id {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, &existing)?;
            self.delete_pending_gate_consent_critical_confirm_index_in_txn(wtxn, &existing)?;
            // A replacement keeps its insertion order, but an explicit delete
            // removes it; do not allocate a caller-controlled ordering key.
        }
        let value = encode_pending_gate_consent(record)?;
        self.vault_meta.put(wtxn, &key, &value)?;
        self.put_pending_gate_consent_indexes_in_txn(wtxn, record)?;
        self.put_pending_gate_consent_critical_confirm_index_in_txn(wtxn, record)?;
        self.ensure_pending_gate_consent_sequence_in_txn(wtxn, &record.claim_id)?;
        Ok(())
    }

    pub(crate) fn pending_gate_consent_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<Option<PendingGateConsentRecord>> {
        let Some(value) = self
            .vault_meta
            .get(txn, &pending_gate_consent_key(claim_id.as_bytes()))?
        else {
            return Ok(None);
        };
        let record = decode_pending_gate_consent(&value)?;
        if record.claim_id != *claim_id.as_bytes() {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        Ok(Some(record))
    }

    pub(crate) fn delete_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<()> {
        let key = pending_gate_consent_key(claim_id.as_bytes());
        if let Some(value) = self.vault_meta.get(&*wtxn, &key)? {
            let record = decode_pending_gate_consent(&value)?;
            if record.claim_id != *claim_id.as_bytes() {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, &record)?;
            self.delete_pending_gate_consent_critical_confirm_index_in_txn(wtxn, &record)?;
            self.delete_pending_gate_consent_sequence_in_txn(wtxn, &record.claim_id)?;
        }
        self.vault_meta.delete(wtxn, &key)?;
        Ok(())
    }

    pub(crate) fn let_go_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        created_at: u64,
    ) -> Result<Option<GateDecisionRecord>> {
        self.close_pending_gate_consent_in_txn(
            wtxn,
            claim_id,
            created_at,
            "let_go",
            vec!["gate.pending.gap_decayed".to_owned()],
            None,
        )
    }

    /// Closes one pending gate consent with an explicit resolution outcome:
    /// appends a decision-ledger row derived from the original pending
    /// decision, then removes the tray row. `let_go` (lapse) and the OF-234
    /// inbox bundle verbs (`approved`/`rejected`) share this path so every
    /// resolution leaves a per-item receipt.
    pub(crate) fn close_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        created_at: u64,
        outcome: &str,
        reason_codes: Vec<String>,
        grant_ref: Option<String>,
    ) -> Result<Option<GateDecisionRecord>> {
        let Some(pending) = self.pending_gate_consent_in_txn(wtxn, claim_id)? else {
            return Ok(None);
        };
        let Some(value) = self
            .vault_meta
            .get(wtxn, &gate_decision_key(pending.decision_id))?
        else {
            return Err(Error::CorruptedIndex("pending gate consent"));
        };
        let original = decode_gate_decision(&value)?;
        if original.decision_id != pending.decision_id {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::now(),
            created_at,
            outcome: outcome.to_owned(),
            reason_codes,
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: original.actor_class,
            actor_ref: original.actor_ref,
            content_kind: original.content_kind,
            policy_manifest_version: original.policy_manifest_version,
            claim_id: Some(pending.claim_id),
            grant_ref,
            diff_handle: pending.diff_handle,
            read_frontier_hash: pending.read_frontier_hash,
            // A resolution is a NEW decision, born unredacted: never propagate
            // `original.redacted_at`.
            redacted_at: None,
        };
        self.append_gate_decision_in_txn(wtxn, &record)?;
        self.delete_pending_gate_consent_in_txn(wtxn, claim_id)?;
        Ok(Some(record))
    }

    pub fn pending_gate_consents(&self, limit: usize) -> Result<Vec<PendingGateConsentRecord>> {
        let rtxn = self.env.read_txn()?;
        self.pending_gate_consents_in_txn(&rtxn, limit)
    }

    /// Reads one sequence-ordered page of pending gate consents after `cursor`.
    /// The cursor is the last internally allocated sequence returned by the preceding page.
    pub(crate) fn pending_gate_consents_page_in_txn(
        &self,
        txn: &RoTxn<'_>,
        cursor: Option<u64>,
        fence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, PendingGateConsentRecord)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let lower = cursor.map(pending_gate_consent_sequence_index_key);
        let lower: std::ops::Bound<&[u8]> = match lower.as_deref() {
            Some(key) => std::ops::Bound::Excluded(key),
            None => std::ops::Bound::Included(PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX),
        };
        let upper = fence.map_or_else(
            pending_gate_consent_sequence_index_upper_bound,
            pending_gate_consent_sequence_index_key,
        );
        let upper = if fence.is_some() {
            std::ops::Bound::Included(upper.as_slice())
        } else {
            std::ops::Bound::Excluded(upper.as_slice())
        };
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in self.vault_meta.range(txn, &(lower, upper))? {
            let (key, value) = row?;
            let sequence = pending_gate_consent_sequence_from_index_key(&key)?;
            let claim_id = EntityId::from_bytes(
                value
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("pending gate consent sequence index"))?,
            )
            .map_err(|_| Error::CorruptedIndex("pending gate consent sequence index"))?;
            let Some(record) = self.pending_gate_consent_in_txn(txn, &claim_id)? else {
                return Err(Error::CorruptedIndex("pending gate consent sequence index"));
            };
            records.push((sequence, record));
            if records.len() == limit {
                break;
            }
        }
        Ok(records)
    }

    pub(crate) fn pending_gate_consents_in_txn(
        &self,
        txn: &RoTxn<'_>,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let upper = pending_gate_consent_upper_bound();
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in self.vault_meta.range(
            txn,
            &(
                std::ops::Bound::Included(PENDING_GATE_CONSENT_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(PENDING_GATE_CONSENT_KEY_PREFIX) {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            let claim_id = pending_gate_consent_claim_id_from_key(&key)?;
            let record = decode_pending_gate_consent(&value)?;
            if record.claim_id != claim_id {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            records.push(record);
        }

        records.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| {
                    left.decision_id
                        .as_bytes()
                        .cmp(&right.decision_id.as_bytes())
                })
                .then_with(|| left.claim_id.cmp(&right.claim_id))
        });
        records.truncate(limit);
        Ok(records)
    }

    pub fn pending_gate_consent_groups(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentGroup>> {
        let mut groups: Vec<PendingGateConsentGroup> = Vec::new();
        for record in self.pending_gate_consents(limit)? {
            let dreamer_run_id = record.dreamer_run_id.clone();
            if let Some(group) = groups
                .iter_mut()
                .find(|group| group.dreamer_run_id == dreamer_run_id)
            {
                group.records.push(record);
            } else {
                groups.push(PendingGateConsentGroup {
                    dreamer_run_id,
                    records: vec![record],
                });
            }
        }
        Ok(groups)
    }
}
