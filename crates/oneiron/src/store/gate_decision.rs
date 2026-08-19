//! The append-only gate-decision ledger: decision rows, claim/grant-ref
//! indexes, the pending-deletion sidecar, and the attempt-run index used by
//! the claim-index backfill.

use std::str;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

use super::*;

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(crate) const GATE_DECISION_LEDGER_VERSION: u8 = 0;

/// Accepted DECODE version for an in-place-redacted row (ONE-1637/ONE-1638).
/// [`GATE_DECISION_LEDGER_VERSION`] (0) remains the only APPEND version, so the
/// ABI-pinned const above is unchanged and existing v0 bytes still round-trip.
pub(crate) const GATE_DECISION_LEDGER_VERSION_REDACTED: u8 = 1;

pub(super) const GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_decision:v0:";

/// Pre-commit crash-recovery sidecar for a deletion authority record. This is
/// not the Gate decision ledger: TXN3 consumes it with
/// `append_gate_decision_in_txn` in the active-store purge transaction.
const PENDING_DELETION_GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_delete_pending:v0:";

/// Durable proof that a locally-authored deletion tombstone requires an
/// authority sidecar before recovery may purge its target. Kept separate
/// from the sidecar so corruption/loss of the latter is detectable instead
/// of being mistaken for a legitimate sidecar-free remote tombstone.
const DELETION_GATE_REQUIRED_KEY_PREFIX: &[u8] = b"gate_delete_required:v0:";

const PENDING_DELETION_GATE_DECISION_VERSION: u8 = 0;

const GATE_DECISION_GRANT_REF_INDEX_PREFIX: &[u8] = b"gate_decision:grant_ref_index:v1:";

/// ERASE-A (ONE-1637) claim-keyed secondary index over the Gate decision
/// ledger: `prefix ‖ claim_id(16B) ‖ decision_id(16B)`, empty value.
///
/// ACCELERATION ONLY. Erase-completeness verification must never consult it —
/// an index cannot vouch for the completeness of the erase it accelerated (see
/// [`Store::verify_claim_erasure_by_scan_in_txn`]).
///
/// INVARIANT: every mutation of a `gate_decision:v0:` row MUST route through
/// `append_gate_decision_in_txn` (the sole write route) or
/// `delete_gate_decision_record_in_txn` (the sole primary-delete route, which
/// drops this index row and the grant-ref index row in the same transaction).
/// A future deleter loads/decodes the record and calls the latter; a raw
/// `vault_meta.delete` of a primary key orphans both indexes. The
/// `gate_delete_pending:v0:` recovery sidecar is a distinct keyspace and is not
/// covered by this rule.
const GATE_DECISION_CLAIM_INDEX_PREFIX: &[u8] = b"gate_decision_by_claim:v0:";

/// Durable proof that every pre-existing ledger row is claim-indexed. While
/// ABSENT, per-claim discovery falls back to a full keyspace scan; erase is
/// never refused during backfill.
pub(super) const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY: &[u8] =
    b"gate_decision_by_claim_backfill_complete";

/// Only accepted value byte for the backfill-complete flag row.
pub(super) const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE: [u8; 1] = [1];

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
const ATTEMPT_RUN_INDEX_PREFIX: &[u8] = b"job:run_index:v1:";

pub(super) const GATE_DIFF_HANDLE_MAX_LEN: usize = 128;

const GATE_RECEIPT_REASON_MAX_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GateDecisionId {
    bytes: [u8; 16],
}

impl GateDecisionId {
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.bytes
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSystemNoticeAction {
    pub label: String,
    pub target: String,
}

pub(crate) const GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN: usize = 128;

/// Bounds on a notice's setting-change affordance. Named so the writers that
/// build a notice can hold themselves to the same numbers the ledger enforces,
/// instead of discovering them at append time.
pub(crate) const GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN: usize = 128;
pub(crate) const GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN: usize = 512;

pub(crate) const GATE_SYSTEM_NOTICE_BODY_MAX_LEN: usize = 1024;

pub(crate) const GATE_SYSTEM_NOTICE_PLANE_MAX_LEN: usize = 64;
pub(crate) const GATE_SYSTEM_NOTICE_VERSION_MAX_LEN: usize = 64;
pub(crate) const GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSystemNoticeRecord {
    pub notice_type: String,
    pub channel: String,
    pub voice: String,
    pub audience: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting_change_offer: Option<GateSystemNoticeAction>,
    /// Which policy plane produced this notice — the vault owner's own policy,
    /// or a hosted service's legal policy. Absent for notices that are not
    /// policy verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_plane: Option<String>,
    /// Version of the policy the notice was decided under. A hosted legal
    /// plane always sets it; the owner plane has no versioned document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Where the reader can go to read the policy itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionRecord {
    pub version: u8,
    pub decision_id: GateDecisionId,
    pub created_at: u64,
    pub outcome: String,
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_notices: Vec<GateSystemNoticeRecord>,
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub content_kind: String,
    pub policy_manifest_version: String,
    pub claim_id: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
    /// Set when this row was redacted in place to its retention skeleton
    /// (version 1). Never set at append time; the erase coupling (ONE-1638)
    /// is the only writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_at: Option<u64>,
}

/// Outcome of one ERASE-A (ONE-1637) claim-index backfill run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateClaimIndexBackfill {
    /// Pre-existing claim-bound ledger rows written into the index by this run.
    pub rows_indexed: u64,
    /// The durable flag was already set, so the run was a no-op.
    pub already_complete: bool,
}

/// Private TXN1 recovery data for a deletion authority record. The target and
/// wire reason bind the sidecar to exactly one tombstone, so a remote update
/// cannot consume a same-request-id sidecar for a different deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
struct PendingDeletionGateDecisionRecord {
    version: u8,
    target: [u8; 16],
    tombstone_reason: u8,
    decision: GateDecisionRecord,
}

impl Store {
    /// One-time ERASE-A (ONE-1637) backfill: indexes every pre-existing
    /// claim-bound ledger row and sets the durable completeness flag in ONE
    /// write txn, so a crash leaves either nothing or everything (RCPT-1
    /// crash-safety shape). Idempotent across reruns.
    pub(crate) fn backfill_gate_decision_claim_index(&self) -> Result<GateClaimIndexBackfill> {
        let mut wtxn = self.env.write_txn()?;
        if self.gate_decision_claim_index_backfill_complete_in_txn(&wtxn)? {
            return Ok(GateClaimIndexBackfill {
                rows_indexed: 0,
                already_complete: true,
            });
        }

        // Collect before writing: LMDB forbids mutating a DB while one of its
        // iterators is live. Only the two ids each index row needs are
        // retained — the decoded record is dropped inside the walk, so an
        // unbounded ledger of claim-free (or string-heavy) rows never
        // accumulates here.
        let mut claim_rows = Vec::new();
        self.for_each_gate_decision_in_txn(&wtxn, |record| {
            if let Some(claim_id) = record.claim_id {
                claim_rows.push((claim_id, record.decision_id));
            }
            Ok(())
        })?;
        for (claim_id, decision_id) in &claim_rows {
            self.vault_meta.put(
                &mut wtxn,
                &gate_decision_claim_index_key(claim_id, *decision_id),
                b"",
            )?;
        }
        self.vault_meta.put(
            &mut wtxn,
            GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
            &GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE,
        )?;
        wtxn.commit()?;
        Ok(GateClaimIndexBackfill {
            rows_indexed: claim_rows.len() as u64,
            already_complete: false,
        })
    }

    pub(crate) fn put_attempt_run_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: Option<&str>,
        attempt_id: &[u8; 16],
    ) -> Result<()> {
        let Some(run_id) = run_id else {
            return Ok(());
        };
        self.vault_meta
            .put(wtxn, &attempt_run_index_key(run_id, attempt_id), b"1")?;
        self.refresh_pending_gate_consent_group_aliases_for_run_in_txn(wtxn, run_id)?;
        Ok(())
    }

    /// Removes the run sidecar for a test fixture's intentionally deleted
    /// primary attempt row in the same transaction. Readers remain fail-closed
    /// when a dangling sidecar is observed.
    #[cfg(test)]
    pub(crate) fn delete_attempt_run_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: Option<&str>,
        attempt_id: &[u8; 16],
    ) -> Result<()> {
        let Some(run_id) = run_id else {
            return Ok(());
        };
        self.vault_meta
            .delete(wtxn, &attempt_run_index_key(run_id, attempt_id))?;
        Ok(())
    }

    pub(crate) fn attempt_ids_for_run_in_txn(
        &self,
        txn: &RoTxn<'_>,
        run_id: &str,
    ) -> Result<Vec<[u8; 16]>> {
        let prefix = attempt_run_index_prefix(run_id);
        let mut ids = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, _) = row?;
            ids.push(index_suffix_id(&key, &prefix, "attempt run index")?);
        }
        Ok(ids)
    }

    pub(crate) fn append_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        append_gate_decision_row_in_txn(self, wtxn, record)
    }

    /// Appends a collision-checked logical UUIDv7 successor. A fixed clock can
    /// reproduce a UUIDv7 seed after reopen, so collisions advance from the
    /// durable same-timestamp tail rather than replacing UUIDv7 bits with a hash.
    pub(crate) fn append_fresh_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &mut GateDecisionRecord,
    ) -> Result<()> {
        let seed = record.decision_id;
        let mut prefix = Vec::with_capacity(GATE_DECISION_KEY_PREFIX.len() + 6);
        prefix.extend_from_slice(GATE_DECISION_KEY_PREFIX);
        prefix.extend_from_slice(&seed.as_bytes()[..6]);
        let tail = self
            .vault_meta
            .prefix_iter(&*wtxn, &prefix)?
            .last()
            .transpose()?
            .map(|(key, _)| gate_decision_id_from_key(&key))
            .transpose()?;
        let mut decision_id = match tail {
            Some(tail) if tail.as_bytes() >= seed.as_bytes() => logical_uuid_v7_successor(tail)?,
            _ => seed,
        };
        while self.gate_decision_in_txn(&*wtxn, decision_id)?.is_some() {
            decision_id = logical_uuid_v7_successor(decision_id)?;
        }
        record.decision_id = decision_id;
        self.append_gate_decision_in_txn(wtxn, record)
    }

    /// The ONLY route that removes a primary `gate_decision:v0:` row. Sidecar
    /// index rows go first and the primary second, all in the caller's
    /// transaction, so a failure at any step aborts the whole unit and no
    /// deleter can drop a primary while leaving its indexes pointing at it.
    /// Both sidecar deletes are safe no-ops for a record without a `grant_ref`
    /// or `claim_id`. Takes a decoded record because the grant-ref and claim
    /// index keys are only reconstructible from the primary's bytes.
    fn delete_gate_decision_record_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        self.delete_gate_decision_grant_ref_index_in_txn(wtxn, record)?;
        self.delete_gate_decision_claim_index_in_txn(wtxn, record)?;
        self.vault_meta
            .delete(wtxn, &gate_decision_key(record.decision_id))?;
        Ok(())
    }

    pub(crate) fn delete_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        let Some(record) = self.gate_decision_in_txn(&*wtxn, decision_id)? else {
            return Err(Error::InvariantViolation(
                "staged gate decision missing during rollback",
            ));
        };
        self.delete_gate_decision_record_in_txn(wtxn, &record)
    }

    /// Stages the required marker and deletion authority sidecar before a
    /// locally gated tombstone can be committed. The sidecar exists only so a
    /// crash before TXN3 can recover the exact evaluated actor/policy data; it
    /// is never queryable as a Gate decision and is consumed by TXN3.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn put_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<()> {
        let pending = PendingDeletionGateDecisionRecord {
            version: PENDING_DELETION_GATE_DECISION_VERSION,
            target: *target,
            tombstone_reason,
            decision: record.clone(),
        };
        vet_pending_deletion_gate_decision_record(&pending)?;
        let key = pending_deletion_gate_decision_key(record.decision_id);
        let sidecar_exists = if let Some(existing) = self.vault_meta.get(&*wtxn, &key)? {
            let existing = decode_pending_deletion_gate_decision(&existing)?;
            if existing != pending {
                return Err(Error::InvariantViolation(
                    "pending deletion gate decision id collision",
                ));
            }
            true
        } else {
            false
        };
        if !sidecar_exists {
            let value = encode_pending_deletion_gate_decision(&pending)?;
            self.vault_meta.put(wtxn, &key, &value)?;
        }
        let required_key = deletion_gate_required_key(record.decision_id);
        let required_value = encode_deletion_gate_required(target, tombstone_reason);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &required_key)? {
            if *existing != required_value {
                return Err(Error::InvariantViolation(
                    "deletion gate required marker id collision",
                ));
            }
        } else {
            self.vault_meta.put(wtxn, &required_key, &required_value)?;
        }
        Ok(())
    }

    /// Reads a staged deletion authority record by deletion request id.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn pending_deletion_gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        request_id: GateDecisionId,
    ) -> Result<Option<GateDecisionRecord>> {
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(txn, &key)? else {
            return Ok(None);
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        Ok(Some(pending.decision))
    }

    /// Appends a staged deletion authority record to the real Gate
    /// ledger and removes its recovery sidecar atomically with TXN3.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn append_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<Option<GateDecisionRecord>> {
        let required_key = deletion_gate_required_key(request_id);
        let Some(required) = self.vault_meta.get(&*wtxn, &required_key)? else {
            return Ok(None);
        };
        let (required_target, required_reason) = decode_deletion_gate_required(&required)?;
        if required_target != *target || required_reason != tombstone_reason {
            return Ok(None);
        }
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        if pending.target != *target || pending.tombstone_reason != tombstone_reason {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        self.append_gate_decision_in_txn(wtxn, &pending.decision)?;
        self.vault_meta.delete(wtxn, &key)?;
        self.vault_meta.delete(wtxn, &required_key)?;
        Ok(Some(pending.decision))
    }

    /// Discards a staged recovery sidecar when a later ownership probe proves
    /// this request did not perform a purge. No final Gate record is emitted:
    /// gate evidence must not outlive an unperformed deletion mutation.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn discard_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<bool> {
        let required_key = deletion_gate_required_key(request_id);
        let Some(required) = self.vault_meta.get(&*wtxn, &required_key)? else {
            return Ok(false);
        };
        let (required_target, required_reason) = decode_deletion_gate_required(&required)?;
        if required_target != *target || required_reason != tombstone_reason {
            return Ok(false);
        }
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        if pending.target != *target || pending.tombstone_reason != tombstone_reason {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        self.vault_meta.delete(wtxn, &key)?;
        self.vault_meta.delete(wtxn, &required_key)?;
        Ok(true)
    }

    #[cfg(all(test, feature = "sync"))]
    pub(crate) fn remove_pending_deletion_gate_sidecar_for_test(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
    ) -> Result<()> {
        self.vault_meta
            .delete(wtxn, &pending_deletion_gate_decision_key(request_id))?;
        Ok(())
    }

    /// Returns every gate decision carrying this grant reference, newest
    /// first, without scanning the global decision ledger.
    pub(crate) fn gate_decisions_for_grant_ref(
        &self,
        grant_ref: &str,
    ) -> Result<Vec<GateDecisionRecord>> {
        let rtxn = self.env.read_txn()?;
        let prefix = gate_decision_grant_ref_index_prefix(grant_ref);
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = row?;
            let decision_id = GateDecisionId::from_bytes(index_suffix_id(
                &key,
                &prefix,
                "gate decision grant ref index",
            )?);
            let Some(record) = self.gate_decision_in_txn(&rtxn, decision_id)? else {
                return Err(Error::CorruptedIndex("gate decision grant ref index"));
            };
            if record.grant_ref.as_deref() != Some(grant_ref) {
                return Err(Error::CorruptedIndex("gate decision grant ref index"));
            }
            records.push(record);
        }
        records.sort_by(|left, right| {
            right
                .decision_id
                .as_bytes()
                .cmp(&left.decision_id.as_bytes())
        });
        Ok(records)
    }

    /// Per-claim discovery for the erase coupling (ONE-1638) and any per-claim
    /// receipt read. Index-accelerated ONLY when the durable backfill flag is
    /// set; otherwise a full keyspace scan, so a vault mid-backfill can never
    /// hide rows from an erase. Both paths return records ascending by
    /// decision_id and are result-identical.
    ///
    /// Redacted (version 1) skeletons ARE returned — they retain `claim_id` by
    /// design. Completeness is decided by
    /// [`Store::verify_claim_erasure_by_scan_in_txn`], never by this reader.
    #[cfg_attr(not(test), allow(dead_code))] // seam for the ONE-1638 erase coupling
    pub(crate) fn gate_decisions_for_claim_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionRecord>> {
        if !self.gate_decision_claim_index_backfill_complete_in_txn(txn)? {
            return self.scan_gate_decisions_for_claim_in_txn(txn, claim_id);
        }
        let prefix = gate_decision_claim_index_prefix(claim_id);
        let mut records = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, _) = row?;
            let decision_id = GateDecisionId::from_bytes(index_suffix_id(
                &key,
                &prefix,
                "gate decision claim index",
            )?);
            let Some(record) = self.gate_decision_in_txn(txn, decision_id)? else {
                return Err(Error::CorruptedIndex("gate decision claim index"));
            };
            if record.claim_id != Some(*claim_id) {
                return Err(Error::CorruptedIndex("gate decision claim index"));
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Full-keyspace per-claim discovery: the fallback path taken while the
    /// backfill flag is unset, and directly callable for parity checks.
    #[cfg_attr(not(test), allow(dead_code))] // seam for the ONE-1638 erase coupling
    pub(crate) fn scan_gate_decisions_for_claim_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionRecord>> {
        let mut records = Vec::new();
        self.for_each_gate_decision_in_txn(txn, |record| {
            if record.claim_id == Some(*claim_id) {
                records.push(record);
            }
            Ok(())
        })?;
        Ok(records)
    }

    /// ERASE step-5 completeness verify: the decision ids still claim-bound AND
    /// unredacted. ALWAYS a full `gate_decision:v0:` keyspace scan and NEVER a
    /// read of the claim index, in any flag state — an index that accelerated
    /// the erase cannot also certify it complete. An empty result means erasure
    /// is complete for this claim. Deliberately uncapped: a correctness scan
    /// takes no query-budget shortcut.
    #[cfg_attr(not(test), allow(dead_code))] // seam for the ONE-1638 erase coupling
    pub(crate) fn verify_claim_erasure_by_scan_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionId>> {
        let mut remaining = Vec::new();
        self.for_each_gate_decision_in_txn(txn, |record| {
            if record.claim_id == Some(*claim_id) && record.redacted_at.is_none() {
                remaining.push(record.decision_id);
            }
            Ok(())
        })?;
        Ok(remaining)
    }

    /// Streams every primary ledger row in ascending decision_id order,
    /// checking each row against its own key and handing ownership of the
    /// decoded record to `visit`.
    ///
    /// MEMORY CONTRACT: the caller's filter runs INSIDE the cursor walk, so a
    /// filtered read retains only its matches (or a projection of them) and the
    /// ledger's size stops bounding peak memory on a long-lived vault. The
    /// `Result<()>` return — not a `Vec` — is what enforces this; do not
    /// reintroduce an intermediate collection of every record.
    pub(super) fn for_each_gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        mut visit: impl FnMut(GateDecisionRecord) -> Result<()>,
    ) -> Result<()> {
        let upper = gate_decision_upper_bound();
        for row in self.vault_meta.range(
            txn,
            &(
                std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            let decision_id = gate_decision_id_from_key(&key)?;
            let record = decode_gate_decision(&value)?;
            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            visit(record)?;
        }
        Ok(())
    }

    /// Reads the durable backfill-complete flag. A present row with any byte
    /// other than the pinned value is corruption, not a soft "incomplete".
    pub(crate) fn gate_decision_claim_index_backfill_complete_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<bool> {
        match self
            .vault_meta
            .get(txn, GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY)?
        {
            Some(value) if *value == GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE => Ok(true),
            Some(_) => Err(Error::CorruptedIndex(
                "gate decision claim index backfill flag",
            )),
            None => Ok(false),
        }
    }

    pub(crate) fn gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<Option<GateDecisionRecord>> {
        let Some(value) = self.vault_meta.get(txn, &gate_decision_key(decision_id))? else {
            return Ok(None);
        };
        let record = decode_gate_decision(&value)?;
        if record.decision_id != decision_id {
            return Err(Error::CorruptedIndex("gate decision ledger"));
        }
        Ok(Some(record))
    }

    /// Parts-based form, so a streaming backfill can write the row without
    /// holding the decoded record it came from. The append path builds the
    /// same row inline in [`append_gate_decision_row_in_txn`], which is
    /// target-parameterized and so cannot route through a `Store` method.
    pub(super) fn put_gate_decision_grant_ref_index_row_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        grant_ref: &str,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        self.vault_meta.put(
            wtxn,
            &gate_decision_grant_ref_index_key(grant_ref, decision_id),
            b"1",
        )?;
        Ok(())
    }

    fn delete_gate_decision_grant_ref_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        let Some(grant_ref) = record.grant_ref.as_deref() else {
            return Ok(());
        };
        self.vault_meta.delete(
            wtxn,
            &gate_decision_grant_ref_index_key(grant_ref, record.decision_id),
        )?;
        Ok(())
    }

    fn delete_gate_decision_claim_index_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        let Some(claim_id) = record.claim_id.as_ref() else {
            return Ok(());
        };
        self.vault_meta.delete(
            wtxn,
            &gate_decision_claim_index_key(claim_id, record.decision_id),
        )?;
        Ok(())
    }

    pub fn gate_decisions(&self, limit: usize) -> Result<Vec<GateDecisionRecord>> {
        self.gate_decisions_page(None, limit)
    }

    pub(crate) fn gate_decisions_page(
        &self,
        before: Option<GateDecisionId>,
        limit: usize,
    ) -> Result<Vec<GateDecisionRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rtxn = self.env.read_txn()?;
        let upper = before.map_or_else(gate_decision_upper_bound, gate_decision_key);
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in self.vault_meta.rev_range(
            &rtxn,
            &(
                std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(GATE_DECISION_KEY_PREFIX) {
                break;
            }
            let decision_id = gate_decision_id_from_key(&key)?;
            let record = decode_gate_decision(&value)?;
            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            records.push(record);
            if records.len() == limit {
                break;
            }
        }
        Ok(records)
    }
}

/// Appends one WRITE-PATH gate decision plus its two index rows, addressed by
/// write target (ONE-1728 K5).
///
/// TIER SEPARATION IS THE POINT. Write-path decisions are receipts ABOUT the
/// content they judged, so a decision on session content stages into the
/// overlay and evaporates with the transcript it describes. The EGRESS tier is
/// categorically different — those decisions and REDACTION_AUDIT are floor
/// survivors and keep crossing to base through
/// [`crate::off_record::FloorWrites`], never through here.
///
/// The key/encode functions and both index side writes are shared verbatim, so
/// a session decision is byte-identical to the base row it would have been —
/// which is what makes promote a replay rather than a re-derivation.
fn append_gate_decision_row_in_txn(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    record: &GateDecisionRecord,
) -> Result<()> {
    // Decode accepts the redacted skeleton (ONE-1637); APPEND never mints
    // one. Redaction is an in-place rewrite owned by the erase coupling.
    if record.version != GATE_DECISION_LEDGER_VERSION || record.redacted_at.is_some() {
        return Err(Error::InvariantViolation("gate decision born redacted"));
    }
    vet_gate_decision_record(record)?;
    let key = gate_decision_key(record.decision_id);
    if store.vault_meta().get(wtxn, &key)?.is_some() {
        return Err(Error::InvariantViolation("gate decision id collision"));
    }
    let value = encode_gate_decision(record)?;
    store.vault_meta().put(wtxn, &key, &value)?;
    if let Some(grant_ref) = record.grant_ref.as_deref() {
        store.vault_meta().put(
            wtxn,
            &gate_decision_grant_ref_index_key(grant_ref, record.decision_id),
            b"1",
        )?;
    }
    if let Some(claim_id) = record.claim_id.as_ref() {
        store.vault_meta().put(
            wtxn,
            &gate_decision_claim_index_key(claim_id, record.decision_id),
            b"",
        )?;
    }
    Ok(())
}

pub(super) fn gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

fn pending_deletion_gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_DELETION_GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(PENDING_DELETION_GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

fn deletion_gate_required_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DELETION_GATE_REQUIRED_KEY_PREFIX.len() + 16);
    key.extend_from_slice(DELETION_GATE_REQUIRED_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

fn gate_decision_id_from_key(key: &[u8]) -> Result<GateDecisionId> {
    let bytes = key
        .strip_prefix(GATE_DECISION_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("gate decision ledger"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("gate decision ledger"))?;
    Ok(GateDecisionId { bytes })
}

pub(super) fn gate_decision_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(GATE_DECISION_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("gate decision key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("gate decision key prefix upper bound must not overflow");
    key
}

/// Returns the next lexicographic UUIDv7 while retaining RFC version and
/// variant bits. Exhausting random bits carries into the logical timestamp.
fn logical_uuid_v7_successor(id: GateDecisionId) -> Result<GateDecisionId> {
    let mut bytes = id.as_bytes();
    if bytes[6] >> 4 != 0x7 || bytes[8] >> 6 != 0b10 {
        return Err(Error::InvariantViolation("gate decision id is not UUIDv7"));
    }
    for index in [15_usize, 14, 13, 12, 11, 10, 9] {
        if bytes[index] != u8::MAX {
            bytes[index] += 1;
            return Ok(GateDecisionId::from_bytes(bytes));
        }
        bytes[index] = 0;
    }
    if bytes[8] & 0x3f != 0x3f {
        bytes[8] += 1;
        return Ok(GateDecisionId::from_bytes(bytes));
    }
    bytes[8] = 0x80;
    if bytes[7] != u8::MAX {
        bytes[7] += 1;
        return Ok(GateDecisionId::from_bytes(bytes));
    }
    bytes[7] = 0;
    if bytes[6] & 0x0f != 0x0f {
        bytes[6] += 1;
        return Ok(GateDecisionId::from_bytes(bytes));
    }
    bytes[6] = 0x70;
    for index in (0..6).rev() {
        if bytes[index] != u8::MAX {
            bytes[index] += 1;
            return Ok(GateDecisionId::from_bytes(bytes));
        }
        bytes[index] = 0;
    }
    Err(Error::InvariantViolation(
        "UUIDv7 logical timestamp exhausted",
    ))
}

fn gate_decision_grant_ref_index_prefix(grant_ref: &str) -> Vec<u8> {
    string_index_prefix(GATE_DECISION_GRANT_REF_INDEX_PREFIX, grant_ref)
}

fn gate_decision_grant_ref_index_key(grant_ref: &str, decision_id: GateDecisionId) -> Vec<u8> {
    index_key_with_id(
        &gate_decision_grant_ref_index_prefix(grant_ref),
        &decision_id.as_bytes(),
    )
}

/// Both key components are fixed 16-byte ids, so the index needs no
/// `string_index_prefix` length header to stay unambiguous.
fn gate_decision_claim_index_prefix(claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(GATE_DECISION_CLAIM_INDEX_PREFIX, claim_id)
}

fn gate_decision_claim_index_key(claim_id: &[u8; 16], decision_id: GateDecisionId) -> Vec<u8> {
    index_key_with_id(
        &gate_decision_claim_index_prefix(claim_id),
        &decision_id.as_bytes(),
    )
}

fn attempt_run_index_prefix(run_id: &str) -> Vec<u8> {
    string_index_prefix(ATTEMPT_RUN_INDEX_PREFIX, run_id)
}

fn attempt_run_index_key(run_id: &str, attempt_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(&attempt_run_index_prefix(run_id), attempt_id)
}

fn encode_gate_decision(record: &GateDecisionRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("gate decision ledger encode failed"))
}

pub(super) fn decode_gate_decision(raw: &[u8]) -> Result<GateDecisionRecord> {
    let record: GateDecisionRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("gate decision ledger"))?;
    vet_gate_decision_record(&record)?;
    Ok(record)
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn encode_pending_deletion_gate_decision(
    record: &PendingDeletionGateDecisionRecord,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("pending deletion gate decision encode failed"))
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn decode_pending_deletion_gate_decision(raw: &[u8]) -> Result<PendingDeletionGateDecisionRecord> {
    let record: PendingDeletionGateDecisionRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("pending deletion gate decision"))?;
    vet_pending_deletion_gate_decision_record(&record)?;
    Ok(record)
}

fn encode_deletion_gate_required(target: &[u8; 16], tombstone_reason: u8) -> [u8; 18] {
    let mut value = [0_u8; 18];
    value[0] = PENDING_DELETION_GATE_DECISION_VERSION;
    value[1] = tombstone_reason;
    value[2..].copy_from_slice(target);
    value
}

fn decode_deletion_gate_required(raw: &[u8]) -> Result<([u8; 16], u8)> {
    let raw: [u8; 18] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("deletion gate required marker"))?;
    if raw[0] != PENDING_DELETION_GATE_DECISION_VERSION || !matches!(raw[1], 1..=4) {
        return Err(Error::CorruptedIndex("deletion gate required marker"));
    }
    let mut target = [0_u8; 16];
    target.copy_from_slice(&raw[2..]);
    Ok((target, raw[1]))
}

/// Version-dispatched ledger vet. Version 0 is the live row shape; version 1 is
/// the retention skeleton left behind by an in-place redaction (ONE-1638), whose
/// claim-bearing fields are required to be scrubbed. Only version 0 may be
/// APPENDED — decode accepts both.
///
/// ASYMMETRY, DELIBERATE: `actor_class` is required non-empty on the version-1
/// skeleton ONLY, though E-A's D1 table lists it non-empty for both columns.
/// The v0 exemption is load-bearing, not an oversight:
///
/// * On v0 the field is caller-asserted, attacker-influenced input. The
///   external-effect door records the class the caller SENT
///   (`record_external_effect_policy`), and `evaluate_gate` answers an empty
///   one with `DenyMissingActorClass` — a recorded, auditable denial. Vetting
///   it here would turn that fail-closed deny into
///   `CorruptedIndex("gate decision ledger")`, i.e. let any caller abort the
///   write txn (and, once a denial row is on disk, poison every later ledger
///   scan) with an empty string. Recording what was actually asserted is the
///   point of a decision ledger; the deny is the enforcement.
/// * On v1 the field is ours. A skeleton is minted only by the erase coupling,
///   from an already-vetted row, and `actor_class` is one of the few
///   accountability fields the retention design keeps. Empty there means the
///   redactor scrubbed something it must have retained — a real invariant
///   break, correctly fatal.
///
/// `diff_handle` on the v1 skeleton must be EMPTY. This TIGHTENS E-A's D1
/// table, which read "≤ `GATE_DIFF_HANDLE_MAX_LEN`, empty ALLOWED" and left the
/// sentinel bytes to E-B (open question 4). A length cap alone cannot tell a
/// fixed sentinel from a live handle, and the handle is a content binding — a
/// pointer at the very body the redaction exists to scrub — so "empty allowed"
/// let a redacted row keep one. Empty is the only self-evidently scrubbed
/// value. E-B may still mint a sentinel, but only by pinning its bytes in a vet
/// amendment here, which makes the sentinel checkable rather than assumed.
///
/// Pinned by `record_schema_v0_bytes_stable_and_v1_skeleton_vets` (empty-class
/// v1 rejected, empty-class v0 accepted),
/// `redacted_skeleton_must_not_retain_a_diff_handle`, and
/// `gate::tests::effect_actor_class_spoof_fails_closed` (the deny path stays a
/// deny). Tightening v0's `actor_class` is an E-B vet amendment, and needs the
/// effect door to stop recording caller-asserted classes verbatim first.
fn vet_gate_decision_record(record: &GateDecisionRecord) -> Result<()> {
    let shared_ok = !record.outcome.is_empty()
        && !record.content_kind.is_empty()
        && !record.policy_manifest_version.is_empty()
        && record.diff_handle.len() <= GATE_DIFF_HANDLE_MAX_LEN;
    let version_ok = match record.version {
        GATE_DECISION_LEDGER_VERSION => {
            record.redacted_at.is_none()
                && !record.reason_codes.is_empty()
                && record
                    .grant_ref
                    .as_deref()
                    .is_none_or(|grant_ref| !grant_ref.trim().is_empty())
                && !record.diff_handle.is_empty()
                && record
                    .reason_codes
                    .iter()
                    .all(|reason| reason.starts_with("gate."))
                && record
                    .receipt_reasons
                    .iter()
                    .all(|reason| valid_gate_receipt_reason(reason))
                && record
                    .system_notices
                    .iter()
                    .all(valid_gate_system_notice_record)
        }
        // The skeleton keeps only the accountability fields the retention
        // design retains; everything claim-bearing must already be gone.
        // `actor_class` is required here and NOT on v0 — see the asymmetry
        // note above. `diff_handle` must be EMPTY, not merely bounded — see the
        // handle note above.
        GATE_DECISION_LEDGER_VERSION_REDACTED => {
            record.redacted_at.is_some_and(|at| at > 0)
                && !record.actor_class.is_empty()
                && record.reason_codes.is_empty()
                && record.receipt_reasons.is_empty()
                && record.system_notices.is_empty()
                && record.actor_ref.is_none()
                && record.grant_ref.is_none()
                && record.diff_handle.is_empty()
        }
        _ => false,
    };
    if !shared_ok || !version_ok {
        return Err(Error::CorruptedIndex("gate decision ledger"));
    }
    Ok(())
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn vet_pending_deletion_gate_decision_record(
    record: &PendingDeletionGateDecisionRecord,
) -> Result<()> {
    if record.version != PENDING_DELETION_GATE_DECISION_VERSION
        || !matches!(record.tombstone_reason, 1..=4)
        || record.decision.content_kind != "deletion"
    {
        return Err(Error::CorruptedIndex("pending deletion gate decision"));
    }
    vet_gate_decision_record(&record.decision)
}

/// Whether a gate system notice is well-formed enough to sit in the ledger.
///
/// READ PATH TOO, not just the append path: `decode_gate_decision` runs this
/// over rows already on disk, so tightening it makes a non-conforming row
/// UNREADABLE (`CorruptedIndex`), not merely unwritable. That is the intended
/// reading — a notice attributing a verdict to a plane that does not exist is
/// corrupt whenever it is found — and it costs nothing today because no writer
/// in this crate can produce one, which is why `GATE_DECISION_LEDGER_VERSION`
/// does not move. Loosen-then-tighten here without checking the decode path
/// again and a real vault stops opening.
fn valid_gate_system_notice_record(notice: &GateSystemNoticeRecord) -> bool {
    valid_gate_notice_token(&notice.notice_type, 64)
        && !notice.channel.trim().is_empty()
        && notice.channel.len() <= 64
        && valid_gate_notice_token(&notice.voice, 32)
        && valid_gate_notice_token(&notice.audience, 32)
        && !notice.body.trim().is_empty()
        && notice.body.len() <= GATE_SYSTEM_NOTICE_BODY_MAX_LEN
        && notice.row_ref.as_deref().is_none_or(|row_ref| {
            !row_ref.trim().is_empty() && row_ref.len() <= GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN
        })
        && notice.setting_change_offer.as_ref().is_none_or(|offer| {
            !offer.label.trim().is_empty()
                && offer.label.len() <= GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN
                && !offer.target.trim().is_empty()
                && offer.target.len() <= GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN
        })
        && notice
            .policy_plane
            .as_deref()
            .is_none_or(valid_gate_notice_plane)
        // Attribution belongs to a plane. `policy_version` names the version of
        // SOMETHING and `docs_url` points at the document that SOMETHING
        // publishes; with no plane named, the record says a rule was cited
        // without saying whose. Every writer already holds this — it is written
        // down here so the ledger holds it too.
        && (notice.policy_plane.is_some()
            || (notice.policy_version.is_none() && notice.docs_url.is_none()))
        && valid_gate_notice_attribution(
            notice.policy_version.as_deref(),
            GATE_SYSTEM_NOTICE_VERSION_MAX_LEN,
        )
        && valid_gate_notice_attribution(
            notice.docs_url.as_deref(),
            GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN,
        )
}

/// The policy planes a gate system notice may be attributed to.
///
/// Spelled as literals rather than read off `PolicyPlane::as_str`: `store` sits
/// UNDER `policy_model` in the crate's layering (policy_model imports store,
/// never the reverse), so the ledger guard cannot depend on the enum it
/// mirrors. `store::tests::gate_notice_plane_tokens_mirror_the_policy_plane_enum`
/// pins the two spellings together, so a renamed variant fails a test instead of
/// silently widening the ledger.
pub(crate) const GATE_SYSTEM_NOTICE_PLANE_TOKENS: [&str; 2] = ["owner_policy", "hosted_legal"];

/// A plane must be one of the two the policy planes publish — not merely a
/// well-formed token. Any `snake_case` string passing here would let a writer
/// attribute a verdict to a plane that does not exist, and a reader has no way
/// to tell that from a real one.
fn valid_gate_notice_plane(plane: &str) -> bool {
    valid_gate_notice_token(plane, GATE_SYSTEM_NOTICE_PLANE_MAX_LEN)
        && GATE_SYSTEM_NOTICE_PLANE_TOKENS.contains(&plane)
}

fn valid_gate_notice_attribution(value: Option<&str>, max_len: usize) -> bool {
    value.is_none_or(|value| !value.trim().is_empty() && value.len() <= max_len)
}

fn valid_gate_notice_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_gate_receipt_reason(reason: &str) -> bool {
    if let Some(rest) = reason.strip_prefix("gate.allow.") {
        return !rest.is_empty()
            && rest.len() <= GATE_RECEIPT_REASON_MAX_LEN
            && rest.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
            });
    }

    // Accepted receipt-reason prefix FAMILIES (everything else is rejected):
    // counterparty_* (OF-347 contact/consent), connector_key_* and
    // effector_budget_* (OF-277 GOV-01 status wall / budget exhaustion),
    // charter_* (GOV-10 drift / never-list). The charset and length rules
    // below apply to every family.
    !reason.is_empty()
        && reason.len() <= GATE_RECEIPT_REASON_MAX_LEN
        && (reason.starts_with("counterparty_")
            || reason.starts_with("connector_key_")
            || reason.starts_with("effector_budget_")
            || reason.starts_with("charter_"))
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
