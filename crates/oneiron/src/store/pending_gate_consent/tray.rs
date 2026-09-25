//! Pending gate-consent tray lifecycle: put/get/delete, resolution into the decision ledger, and ordered reads.

use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::Store;
use super::records::{
    PendingGateConsentGroup, PendingGateConsentRecord, decode_pending_gate_consent,
    encode_pending_gate_consent, vet_pending_gate_consent_record,
};
use super::sequence_sweep::SEQUENCE_INDEX;
use super::{GATE_DECISION_LEDGER_VERSION, GateDecisionRecord, RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT};

/// Pending gate-consent tray row, keyed by claim id. Codec fixed `Raw` (see
/// the decls.rs note): [`RawValue`] delegates to
/// [`encode_pending_gate_consent`]/[`decode_pending_gate_consent`].
pub(super) const TRAY: SideTable<[u8; 16], PendingGateConsentRecord, Raw> =
    SideTable::new(&side_table::PENDING_GATE_CONSENT);

impl RawValue for PendingGateConsentRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_pending_gate_consent(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_pending_gate_consent(bytes)?)
    }
}

impl Store {
    pub(crate) fn put_pending_gate_consent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &PendingGateConsentRecord,
    ) -> Result<()> {
        vet_pending_gate_consent_record(record)?;
        if let Some(existing) = TRAY.get(self, &*wtxn, &record.claim_id)? {
            if existing.claim_id != record.claim_id {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, &existing)?;
            self.delete_pending_gate_consent_critical_confirm_index_in_txn(wtxn, &existing)?;
            // A replacement keeps its insertion order, but an explicit delete
            // removes it; do not allocate a caller-controlled ordering key.
        }
        TRAY.put(self, wtxn, &record.claim_id, record)?;
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
        let Some(record) = TRAY.get(self, txn, claim_id.as_bytes())? else {
            return Ok(None);
        };
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
        if let Some(record) = TRAY.get(self, &*wtxn, claim_id.as_bytes())? {
            if record.claim_id != *claim_id.as_bytes() {
                return Err(Error::CorruptedIndex("pending gate consent"));
            }
            self.delete_pending_gate_consent_indexes_in_txn(wtxn, &record)?;
            self.delete_pending_gate_consent_critical_confirm_index_in_txn(wtxn, &record)?;
            self.delete_pending_gate_consent_sequence_in_txn(wtxn, &record.claim_id)?;
        }
        TRAY.delete(self, wtxn, claim_id.as_bytes())?;
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
        let Some(original) = self.gate_decision_in_txn(wtxn, pending.decision_id)? else {
            return Err(Error::CorruptedIndex("pending gate consent"));
        };
        if original.decision_id != pending.decision_id {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: crate::store::GateDecisionId::from_bytes(self.clock.ulid()?),
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
        let lower = cursor.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        let upper = fence.as_ref().map_or(Bound::Unbounded, Bound::Included);
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in SEQUENCE_INDEX.iter_range(self, txn, lower, upper)? {
            let (sequence, claim_id) = row?;
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

        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for (claim_id, record) in TRAY.scan(self, txn)? {
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
