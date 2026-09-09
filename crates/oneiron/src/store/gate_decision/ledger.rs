//! Gate-decision ledger Store methods plus the row append and record codec.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::store::{ManifestDbs, RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT, Store, index_suffix_id};

use super::keys::{
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE, GATE_DECISION_KEY_PREFIX,
    attempt_run_index_key, attempt_run_index_prefix, gate_decision_claim_index_key,
    gate_decision_claim_index_prefix, gate_decision_grant_ref_index_key,
    gate_decision_grant_ref_index_prefix, gate_decision_id_from_key, gate_decision_key,
    gate_decision_upper_bound, logical_uuid_v7_successor,
};
use super::types::{
    GATE_DECISION_LEDGER_VERSION, GateClaimIndexBackfill, GateDecisionId, GateDecisionRecord,
};
use super::vet::vet_gate_decision_record;

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
    pub(in crate::store) fn scan_gate_decisions_for_claim_in_txn(
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
    pub(in crate::store) fn verify_claim_erasure_by_scan_in_txn(
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
    pub(crate) fn for_each_gate_decision_in_txn(
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
    pub(in crate::store) fn gate_decision_claim_index_backfill_complete_in_txn(
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
    pub(in crate::store) fn put_gate_decision_grant_ref_index_row_in_txn(
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

pub(in crate::store) fn encode_gate_decision(record: &GateDecisionRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("gate decision ledger encode failed"))
}

pub(in crate::store) fn decode_gate_decision(raw: &[u8]) -> Result<GateDecisionRecord> {
    let record: GateDecisionRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("gate decision ledger"))?;
    vet_gate_decision_record(&record)?;
    Ok(record)
}
