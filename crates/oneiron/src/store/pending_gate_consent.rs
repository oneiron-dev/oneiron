//! Pending gate-consent claim records — run/group/hash indexes, sequence
//! counter, pagination, sweep-state cursors, and the critical-confirm
//! invalidation rows that share those cursors.

use std::str;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::batch::EntityMetadataHeader;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;

use super::*;

pub(super) const PENDING_GATE_CONSENT_KEY_PREFIX: &[u8] = b"gate_pending:v0:";

/// Durable idempotence marker for a critical-confirm attachment invalidated by
/// a replicated overwrite. It is intentionally separate from the pending row:
/// the latter is consumed, while this closure prevents replaying the same peer
/// bytes from restoring `Auto` without a new local ceremony.
const CRITICAL_CONFIRM_INVALIDATION_KEY_PREFIX: &[u8] = b"gate_critical_invalidation:v0:";

const CRITICAL_CONFIRM_INVALIDATION_VERSION: u8 = 0;

// Independent cursors keep critical-confirm maintenance and lookups bounded.
pub(super) const CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY: &[u8] =
    b"gate_pending:critical_confirm_expiry_cursor:v1";

const CRITICAL_CONFIRM_LIST_CURSOR_KEY: &[u8] = b"gate_pending:critical_confirm_list_cursor:v1";

const CRITICAL_CONFIRM_CONFIRM_INDEX_PREFIX: &[u8] = b"gate_pending:critical_confirm_by_id:v1:";

const PENDING_GATE_CONSENT_SEQUENCE_KEY_PREFIX: &[u8] = b"gate_pending:sequence:v1:";

const PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX: &[u8] = b"gate_pending:sequence_index:v1:";

const PENDING_GATE_CONSENT_SEQUENCE_COUNTER_KEY: &[u8] = b"gate_pending:sequence_counter:v1";

pub(super) const PENDING_GATE_CONSENT_RUN_INDEX_PREFIX: &[u8] = b"gate_pending:run_index:v1:";

pub(super) const PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX: &[u8] = b"gate_pending:group_index:v1:";

pub(super) const PENDING_GATE_CONSENT_HASH_INDEX_PREFIX: &[u8] = b"gate_pending:hash_index:v1:";

pub(super) const PENDING_GATE_CONSENT_INDEX_STATE_PREFIX: &[u8] = b"gate_pending:index_state:v1:";

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(super) const PENDING_GATE_CONSENT_INDEX_STATE_VERSION: u8 = 1;

/// Body version of one pending gate-consent tray row.
///
/// Pinned to the same numeric value the decision ledger happens to carry
/// today, because that is the value already on disk — this names it rather
/// than changing it. The two families are stored, indexed and swept
/// separately, so borrowing [`GATE_DECISION_LEDGER_VERSION`] here would make
/// the NEXT decision-ledger bump decode every stored pending row as corrupt.
///
/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(crate) const PENDING_GATE_CONSENT_VERSION: u8 = 0;

const PENDING_GATE_CONSENT_DREAMER_RUN_ID_MAX_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CriticalConfirmInvalidationRecord {
    version: u8,
    claim_id: [u8; 16],
    invalidated_decision_id: GateDecisionId,
    replacement_body_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGateConsentRecord {
    pub version: u8,
    pub claim_id: [u8; 16],
    pub decision_id: GateDecisionId,
    pub created_at: u64,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dreamer_run_id: Option<String>,
}

/// Internal RCPT-1 deletion state for one run-scoped pending-consent row.
///
/// The primary pending row deliberately keeps its receipt-facing shape.  The
/// sidecar records the derived lookup keys so a later close/delete removes
/// exactly the index entries minted for the original pending body, even if a
/// stale proposal's claim has changed since it was queued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingGateConsentIndexState {
    version: u8,
    run_id: String,
    group_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    semantic_claim_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGateConsentGroup {
    pub dreamer_run_id: Option<String>,
    pub records: Vec<PendingGateConsentRecord>,
}

impl Store {
    pub(crate) fn critical_confirm_invalidation_exists_in_txn(
        &self,
        txn: &RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<bool> {
        let Some(raw) = self
            .vault_meta
            .get(txn, &critical_confirm_invalidation_key(claim_id.as_bytes()))?
        else {
            return Ok(false);
        };
        let record = decode_critical_confirm_invalidation(&raw)?;
        if record.claim_id != *claim_id.as_bytes() {
            return Err(Error::CorruptedIndex("critical confirm invalidation"));
        }
        // The record also retains the first replacement hash for audit, but a
        // closure is claim-scoped: a different later peer body is not a fresh
        // local ceremony and must not re-promote Auto either.
        let _ = record.replacement_body_hash;
        let _ = record.invalidated_decision_id;
        Ok(true)
    }

    /// Clears the claim-scoped invalidation only when a new local critical
    /// ceremony has successfully attached its own pending binding. Ordinary
    /// pending rows, replicated replays, and entity deletion never clear it.
    pub(crate) fn delete_critical_confirm_invalidation_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<()> {
        self.vault_meta.delete(
            wtxn,
            &critical_confirm_invalidation_key(claim_id.as_bytes()),
        )?;
        Ok(())
    }

    pub(crate) fn put_critical_confirm_invalidation_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        invalidated_decision_id: GateDecisionId,
        replacement_body: &[u8],
    ) -> Result<()> {
        let record = CriticalConfirmInvalidationRecord {
            version: CRITICAL_CONFIRM_INVALIDATION_VERSION,
            claim_id: *claim_id.as_bytes(),
            invalidated_decision_id,
            replacement_body_hash: *blake3::hash(replacement_body).as_bytes(),
        };
        self.vault_meta.put(
            wtxn,
            &critical_confirm_invalidation_key(claim_id.as_bytes()),
            &encode_critical_confirm_invalidation(&record)?,
        )?;
        Ok(())
    }

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

    pub(super) fn put_pending_gate_consent_indexes_in_txn(
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
    pub(super) fn refresh_pending_gate_consent_group_aliases_for_run_in_txn(
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

    fn delete_pending_gate_consent_indexes_in_txn(
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

    fn ensure_pending_gate_consent_sequence_in_txn(
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

    fn delete_pending_gate_consent_sequence_in_txn(
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

    /// Keep the exact confirm-id sidecar in the same transaction as every
    /// pending-row lifecycle transition. Non-critical rows deliberately have no
    /// sidecar entry.
    fn put_pending_gate_consent_critical_confirm_index_in_txn(
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

    fn delete_pending_gate_consent_critical_confirm_index_in_txn(
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

fn critical_confirm_invalidation_key(claim_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRITICAL_CONFIRM_INVALIDATION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CRITICAL_CONFIRM_INVALIDATION_KEY_PREFIX);
    key.extend_from_slice(claim_id);
    key
}

fn critical_confirm_index_key(confirm_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRITICAL_CONFIRM_CONFIRM_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(CRITICAL_CONFIRM_CONFIRM_INDEX_PREFIX);
    key.extend_from_slice(confirm_id);
    key
}

fn decode_pending_gate_consent_sequence(value: &[u8]) -> Result<u64> {
    value
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| Error::CorruptedIndex("pending gate consent sequence"))
}

fn pending_gate_consent_sequence_key(claim_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_SEQUENCE_KEY_PREFIX);
    key.extend_from_slice(claim_id);
    key
}

fn pending_gate_consent_sequence_index_key(sequence: u64) -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

fn pending_gate_consent_sequence_index_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX);
    let last = key.last_mut().expect("nonempty prefix");
    *last = last.checked_add(1).expect("prefix upper bound");
    key
}

fn pending_gate_consent_sequence_from_index_key(key: &[u8]) -> Result<u64> {
    decode_pending_gate_consent_sequence(
        key.strip_prefix(PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX)
            .ok_or(Error::CorruptedIndex("pending gate consent sequence index"))?,
    )
}

fn pending_gate_consent_key(claim_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_GATE_CONSENT_KEY_PREFIX.len() + 16);
    key.extend_from_slice(PENDING_GATE_CONSENT_KEY_PREFIX);
    key.extend_from_slice(claim_id);
    key
}

pub(super) fn pending_gate_consent_claim_id_from_key(key: &[u8]) -> Result<[u8; 16]> {
    let bytes = key
        .strip_prefix(PENDING_GATE_CONSENT_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("pending gate consent"))?;
    bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("pending gate consent"))
}

pub(super) fn pending_gate_consent_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("pending gate consent key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("pending gate consent key prefix upper bound must not overflow");
    key
}

pub(super) fn string_index_prefix(prefix: &[u8], value: &str) -> Vec<u8> {
    let value = value.as_bytes();
    let mut key = Vec::with_capacity(prefix.len() + std::mem::size_of::<u64>() + value.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&(value.len() as u64).to_be_bytes());
    key.extend_from_slice(value);
    key
}

pub(super) fn index_key_with_id(prefix: &[u8], id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + id.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(id);
    key
}

pub(super) fn index_suffix_id(
    key: &[u8],
    prefix: &[u8],
    index_name: &'static str,
) -> Result<[u8; 16]> {
    key.strip_prefix(prefix)
        .ok_or(Error::CorruptedIndex(index_name))?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(index_name))
}

fn pending_gate_consent_run_index_prefix(run_id: &str) -> Vec<u8> {
    string_index_prefix(PENDING_GATE_CONSENT_RUN_INDEX_PREFIX, run_id)
}

fn pending_gate_consent_run_index_key(run_id: &str, claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(&pending_gate_consent_run_index_prefix(run_id), claim_id)
}

fn pending_gate_consent_group_index_prefix(group_key: &str) -> Vec<u8> {
    string_index_prefix(PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX, group_key)
}

fn pending_gate_consent_group_index_key(group_key: &str, claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(
        &pending_gate_consent_group_index_prefix(group_key),
        claim_id,
    )
}

fn pending_gate_consent_hash_index_prefix(semantic_claim_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_GATE_CONSENT_HASH_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(PENDING_GATE_CONSENT_HASH_INDEX_PREFIX);
    key.extend_from_slice(semantic_claim_hash);
    key
}

fn pending_gate_consent_hash_index_key(
    semantic_claim_hash: &[u8; 32],
    claim_id: &[u8; 16],
) -> Vec<u8> {
    index_key_with_id(
        &pending_gate_consent_hash_index_prefix(semantic_claim_hash),
        claim_id,
    )
}

fn pending_gate_consent_index_state_key(claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(PENDING_GATE_CONSENT_INDEX_STATE_PREFIX, claim_id)
}

fn sort_pending_gate_consents(records: &mut [PendingGateConsentRecord]) {
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
}

fn encode_critical_confirm_invalidation(
    record: &CriticalConfirmInvalidationRecord,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("critical confirm invalidation encode failed"))
}

fn decode_critical_confirm_invalidation(raw: &[u8]) -> Result<CriticalConfirmInvalidationRecord> {
    let record: CriticalConfirmInvalidationRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("critical confirm invalidation"))?;
    if record.version != CRITICAL_CONFIRM_INVALIDATION_VERSION || record.claim_id == [0; 16] {
        return Err(Error::CorruptedIndex("critical confirm invalidation"));
    }
    Ok(record)
}

fn encode_pending_gate_consent(record: &PendingGateConsentRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("pending gate consent encode failed"))
}

pub(super) fn decode_pending_gate_consent(raw: &[u8]) -> Result<PendingGateConsentRecord> {
    let record: PendingGateConsentRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
    vet_pending_gate_consent_record(&record)?;
    Ok(record)
}

fn encode_pending_gate_consent_index_state(
    state: &PendingGateConsentIndexState,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(state)
        .map_err(|_| Error::InvariantViolation("pending gate consent index state encode failed"))
}

fn decode_pending_gate_consent_index_state(raw: &[u8]) -> Result<PendingGateConsentIndexState> {
    let state: PendingGateConsentIndexState = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("pending gate consent index state"))?;
    if state.version != PENDING_GATE_CONSENT_INDEX_STATE_VERSION
        || state.run_id.trim().is_empty()
        || state.group_key.trim().is_empty()
    {
        return Err(Error::CorruptedIndex("pending gate consent index state"));
    }
    Ok(state)
}

fn vet_pending_gate_consent_record(record: &PendingGateConsentRecord) -> Result<()> {
    if record.version != PENDING_GATE_CONSENT_VERSION
        || record.diff_handle.is_empty()
        || record.diff_handle.len() > GATE_DIFF_HANDLE_MAX_LEN
        || record.reason_codes.is_empty()
        || !record
            .reason_codes
            .iter()
            .all(|reason| reason.starts_with("gate.pending."))
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    if let Some(dreamer_run_id) = record.dreamer_run_id.as_deref()
        && (dreamer_run_id.trim().is_empty()
            || dreamer_run_id.len() > PENDING_GATE_CONSENT_DREAMER_RUN_ID_MAX_LEN)
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    Ok(())
}
