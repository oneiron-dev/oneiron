//! Gate-decision ledger Store methods plus the row append and record codec.

use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::{ManifestDbs, RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT, Store};

use super::keys::{
    ATTEMPT_RUN_INDEX_PREFIX, GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE,
    GATE_DECISION_CLAIM_INDEX_PREFIX, GATE_DECISION_GRANT_REF_INDEX_PREFIX, attempt_run_index_key,
    attempt_run_index_prefix, gate_decision_claim_index_key, gate_decision_claim_index_prefix,
    gate_decision_grant_ref_index_key, gate_decision_grant_ref_index_prefix,
    logical_uuid_v7_successor,
};
use super::orcb;
use super::types::{
    GATE_DECISION_LEDGER_VERSION, GateClaimIndexBackfill, GateDecisionId, GateDecisionRecord,
};
use super::vet::vet_gate_decision_record;

/// The stored value is plain named MessagePack or encrypted ORCB bytes;
/// the Store door decodes with its current custody root after this typed read.
pub(super) const LEDGER: SideTable<GateDecisionId, Vec<u8>, Raw> =
    SideTable::new(&side_table::GATE_DECISION_LEDGER);
const CUSTODY_ROOT: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::GATE_DECISION_CUSTODY_ROOT);

/// Presence marker literal byte `b"1"`, matching the marker already on disk
/// for the grant-ref and attempt-run secondary indexes and the unapplied
/// preflight marker.
pub(super) struct OneMarker;

impl RawValue for OneMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(b"1".to_vec())
    }

    fn from_raw(_bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self)
    }
}

const GRANT_REF_INDEX: SideTable<Vec<u8>, OneMarker, Raw> =
    SideTable::new(&side_table::GATE_DECISION_GRANT_REF_INDEX);

/// Claim-keyed secondary index; the value is an empty marker on disk.
const CLAIM_INDEX: SideTable<Vec<u8>, (), Raw> =
    SideTable::new(&side_table::GATE_DECISION_CLAIM_INDEX);

const CLAIM_INDEX_BACKFILL_COMPLETE: SideTable<(), [u8; 1], Raw> =
    SideTable::new(&side_table::GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE);

const ATTEMPT_RUN_INDEX: SideTable<Vec<u8>, OneMarker, Raw> =
    SideTable::new(&side_table::ATTEMPT_RUN_INDEX);

/// The bytes of a composite index key after its table's own declared prefix:
/// strips `base_prefix` (the module's existing hand-spelled prefix constant,
/// byte-identical to the table's declaration) from a key the module's
/// existing builder already produced in full.
fn suffix_of(full: Vec<u8>, base_prefix: &[u8]) -> Vec<u8> {
    full[base_prefix.len()..].to_vec()
}

/// The trailing 16-byte id of a composite index key, given the raw suffix
/// [`SideTable::scan_from`]/[`SideTable::iter_from`] returns for a scan
/// scoped to one string component (so the suffix still carries that
/// component's own encoding ahead of the id).
fn tail_id(bytes: &[u8], context: &'static str) -> Result<[u8; 16]> {
    bytes
        .len()
        .checked_sub(16)
        .and_then(|start| bytes.get(start..))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::CorruptedIndex(context))
}

#[cfg(test)]
thread_local! {
    static BEFORE_GATE_PAGE_DECODE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static BEFORE_GATE_GRANT_DECODE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(in crate::store) fn arm_before_gate_page_decode(callback: impl FnOnce() + 'static) {
    BEFORE_GATE_PAGE_DECODE.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

#[cfg(test)]
pub(in crate::store) fn arm_before_gate_grant_decode(callback: impl FnOnce() + 'static) {
    BEFORE_GATE_GRANT_DECODE.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

impl Store {
    /// Readers acquire this BEFORE opening an LMDB snapshot. Retirement takes
    /// the write half BEFORE the exterior marker/unlink, so no healthy live
    /// snapshot loses custody between its key check and file open.
    pub(crate) fn gate_custody_read_guard(&self) -> Result<std::sync::RwLockReadGuard<'_, ()>> {
        self.core
            .gate_retirement_lock
            .read()
            .map_err(|_| Error::InvariantViolation("gate decision custody lock poisoned"))
    }

    /// Decode one row against its key, decrypting only claim-bound ORCB values.
    pub(in crate::store) fn decode_gate_decision_value(
        &self,
        decision_id: GateDecisionId,
        raw: &[u8],
    ) -> Result<GateDecisionRecord> {
        if orcb::is_orcb(raw) {
            orcb::decode_hot(&self.core.gate_custody_root, decision_id, raw)
        } else {
            decode_gate_decision(raw)
        }
    }

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
            CLAIM_INDEX.put(
                self,
                &mut wtxn,
                &suffix_of(
                    gate_decision_claim_index_key(claim_id, *decision_id),
                    GATE_DECISION_CLAIM_INDEX_PREFIX,
                ),
                &(),
            )?;
        }
        CLAIM_INDEX_BACKFILL_COMPLETE.put(
            self,
            &mut wtxn,
            &(),
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
        ATTEMPT_RUN_INDEX.put(
            self,
            wtxn,
            &suffix_of(
                attempt_run_index_key(run_id, attempt_id),
                ATTEMPT_RUN_INDEX_PREFIX,
            ),
            &OneMarker,
        )?;
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
        ATTEMPT_RUN_INDEX.delete(
            self,
            wtxn,
            &suffix_of(
                attempt_run_index_key(run_id, attempt_id),
                ATTEMPT_RUN_INDEX_PREFIX,
            ),
        )?;
        Ok(())
    }

    pub(crate) fn attempt_ids_for_run_in_txn(
        &self,
        txn: &RoTxn<'_>,
        run_id: &str,
    ) -> Result<Vec<[u8; 16]>> {
        let scan_prefix = suffix_of(attempt_run_index_prefix(run_id), ATTEMPT_RUN_INDEX_PREFIX);
        let mut ids = Vec::new();
        for key in ATTEMPT_RUN_INDEX.scan_keys(self, txn, &scan_prefix)? {
            ids.push(tail_id(&key, "attempt run index")?);
        }
        Ok(ids)
    }

    pub(crate) fn append_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        crate::ports::recorded_at_in_txn(self, wtxn)?;
        if record.claim_id.is_some() {
            // The first claim-bound append pins a path to LIVE exterior custody
            // in the same LMDB transaction as the value. Restoring the image
            // elsewhere reuses that path, never a backed-up key copy.
            let expected = orcb::encode_custody_root(&self.core.gate_custody_root)?;
            match CUSTODY_ROOT.get(self, &*wtxn, &())? {
                Some(bound) if bound != expected => {
                    return Err(Error::CorruptedIndex("gate decision custody binding"));
                }
                Some(_) => {}
                None => CUSTODY_ROOT.put(self, wtxn, &(), &expected)?,
            }
        }
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
        let tail = LEDGER
            .scan_keys(self, &*wtxn, &seed.as_bytes()[..6])?
            .last()
            .copied();
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
    pub(in crate::store) fn delete_gate_decision_record_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        self.delete_gate_decision_grant_ref_index_in_txn(wtxn, record)?;
        self.delete_gate_decision_claim_index_in_txn(wtxn, record)?;
        self.delete_gate_retention_context_in_txn(wtxn, record.decision_id)?;
        self.delete_gate_decision_claim_refs_in_txn(wtxn, record.decision_id)?;
        LEDGER.delete(self, wtxn, &record.decision_id)?;
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

    /// Rewrites every live row for a deleted claim to its retention skeleton
    /// inside the caller's destructive transaction. The claim index is retained
    /// for discovery of skeletons; the grant-ref index is removed because its
    /// source field is scrubbed. Discovery falls back to a full scan until the
    /// durable claim-index backfill has completed. A held key partition keeps
    /// its rows, so every door that tears a held claim (facade, batch, cascade
    /// or replay) is refused here, before anything is rewritten.
    pub(crate) fn redact_gate_decisions_for_claim_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
        redacted_at: u64,
    ) -> Result<bool> {
        self.reject_held_gate_partition_in_txn(&*wtxn, claim_id)?;
        let id = crate::entity_id::EntityId::from_bytes(*claim_id)
            .map_err(|_| Error::CorruptedIndex("gate decision claim id"))?;
        let pending = self.pending_gate_consent_in_txn(&*wtxn, &id)?.is_some();
        let mut records = self.gate_decisions_for_claim_in_txn(&*wtxn, claim_id)?;
        records.extend(self.bundle_gate_decisions_for_claim_in_txn(&*wtxn, claim_id)?);
        let mut changed = pending;
        for mut record in records {
            // Batch preflight stages receipts for *future* ops in this same
            // txn. Their marker is consumed only after their op applies; a
            // delete before that op must not scrub its future receipt.
            if self.is_unapplied_preflight_decision_in_txn(&*wtxn, record.decision_id)? {
                continue;
            }
            if record.redacted_at.is_some() {
                if !self
                    .gate_decision_claim_refs_in_txn(&*wtxn, record.decision_id)?
                    .is_empty()
                {
                    return Err(Error::CorruptedIndex(
                        "redacted gate decision claim references",
                    ));
                }
                continue;
            }
            changed = true;
            self.delete_gate_decision_grant_ref_index_in_txn(wtxn, &record)?;
            self.delete_gate_decision_claim_refs_in_txn(wtxn, record.decision_id)?;
            record.version = super::types::GATE_DECISION_LEDGER_VERSION_REDACTED;
            // v0 records a caller's empty class on an auditable denial; v1
            // requires a non-empty retention label.
            if record.actor_class.is_empty() {
                record.actor_class = "unspecified".to_owned();
            }
            record.reason_codes.clear();
            record.receipt_reasons.clear();
            record.system_notices.clear();
            record.actor_ref = None;
            record.grant_ref = None;
            record.diff_handle.clear();
            // An injected clock at epoch zero must still produce a valid v1 row.
            record.redacted_at = Some(redacted_at.max(1));
            super::vet::vet_gate_decision_record(&record)?;
            LEDGER.put(
                self,
                wtxn,
                &record.decision_id,
                &encode_gate_decision(&record)?,
            )?;
        }
        // The tray carries the original content binding and can mint a fresh
        // live v0 resolution from a v1 skeleton. Remove it and every index
        // inside this same destructive transaction, before verification.
        self.delete_pending_gate_consent_in_txn(wtxn, &id)?;
        for decision_id in self.verify_claim_erasure_by_scan_in_txn(&*wtxn, claim_id)? {
            if !self.is_unapplied_preflight_decision_in_txn(&*wtxn, decision_id)? {
                return Err(Error::CorruptedIndex("gate decision claim erasure"));
            }
        }
        self.stage_erased_claim_key_retirement_in_txn(wtxn, claim_id)?;
        Ok(changed)
    }

    /// Erase destroys the claim's exterior key in the same act (ARCH-0038
    /// #erasure-completeness): a restored pre-erase image must not decrypt
    /// the rows this erase redacted. The retirement intent commits with the
    /// redaction; the caller's post-commit finisher destroys the key, as the
    /// age sweep's does. A future receipt that batch preflight staged in this
    /// transaction stays readable: it moves to the generation after the
    /// retired one before the intent lands.
    fn stage_erased_claim_key_retirement_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<()> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so no claim key can either.
            return Ok(());
        }
        let root = &self.core.gate_custody_root;
        let overflow = || Error::ArithmeticOverflow("gate decision key generation");
        let first = orcb::key_generation(root, claim_id)?;
        // An earlier erase whose key is not destroyed yet may already have
        // moved kept receipts one generation up.
        let mut through = None;
        let mut generation = first;
        while orcb::key_published(root, claim_id, generation)? {
            through = Some(generation);
            generation = generation.checked_add(1).ok_or_else(overflow)?;
        }
        let pending = super::retention::RETIRE_PENDING.get(self, &*wtxn, claim_id)?;
        let Some(through) = through.max(pending) else {
            return Ok(());
        };
        let next = through.checked_add(1).ok_or_else(overflow)?;
        for record in self.gate_decisions_for_claim_in_txn(&*wtxn, claim_id)? {
            if record.redacted_at.is_none() {
                LEDGER.put(
                    self,
                    wtxn,
                    &record.decision_id,
                    &orcb::encode_hot_at(root, &record, next)?,
                )?;
            }
        }
        super::retention::RETIRE_PENDING.put(self, wtxn, claim_id, &through)
    }

    /// Drops the rows a restore must not bring back: a checkpoint row whose
    /// key generation was retired after the image was taken, with every
    /// index row and the pending ask that named it. Runs in the restore's
    /// own transaction, before the restored ledger is first read.
    pub(crate) fn drop_erased_gate_decisions_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        erased: &[(GateDecisionId, [u8; 16])],
    ) -> Result<()> {
        if erased.is_empty() {
            return Ok(());
        }
        let ids: std::collections::HashSet<GateDecisionId> =
            erased.iter().map(|(id, _)| *id).collect();
        let grant_keys: Vec<Vec<u8>> = GRANT_REF_INDEX
            .scan_keys(self, &*wtxn, &[])?
            .into_iter()
            .filter(|key| {
                tail_id(key, "gate decision grant ref index")
                    .is_ok_and(|tail| ids.contains(&GateDecisionId::from_bytes(tail)))
            })
            .collect();
        for key in &grant_keys {
            GRANT_REF_INDEX.delete(self, wtxn, key)?;
        }
        for (decision_id, claim_id) in erased {
            CLAIM_INDEX.delete(
                self,
                wtxn,
                &suffix_of(
                    gate_decision_claim_index_key(claim_id, *decision_id),
                    GATE_DECISION_CLAIM_INDEX_PREFIX,
                ),
            )?;
            self.delete_gate_retention_context_in_txn(wtxn, *decision_id)?;
            self.delete_gate_decision_claim_refs_in_txn(wtxn, *decision_id)?;
            self.discard_unapplied_preflight_marker_in_txn(wtxn, *decision_id)?;
            LEDGER.delete(self, wtxn, decision_id)?;
            let id = crate::entity_id::EntityId::from_bytes(*claim_id)
                .map_err(|_| Error::CorruptedIndex("gate decision claim id"))?;
            if self
                .pending_gate_consent_in_txn(&*wtxn, &id)?
                .is_some_and(|pending| ids.contains(&pending.decision_id))
            {
                self.delete_pending_gate_consent_in_txn(wtxn, &id)?;
            }
        }
        Ok(())
    }

    /// Returns every gate decision carrying this grant reference, newest
    /// first, without scanning the global decision ledger.
    pub(crate) fn gate_decisions_for_grant_ref(
        &self,
        grant_ref: &str,
    ) -> Result<Vec<GateDecisionRecord>> {
        let _custody = self.gate_custody_read_guard()?;
        let rtxn = self.env.read_txn()?;
        #[cfg(test)]
        BEFORE_GATE_GRANT_DECODE.with(|slot| {
            if let Some(callback) = slot.borrow_mut().take() {
                callback();
            }
        });
        let scan_prefix = suffix_of(
            gate_decision_grant_ref_index_prefix(grant_ref),
            GATE_DECISION_GRANT_REF_INDEX_PREFIX,
        );
        let mut records = Vec::new();
        for key in GRANT_REF_INDEX.scan_keys(self, &rtxn, &scan_prefix)? {
            let decision_id =
                GateDecisionId::from_bytes(tail_id(&key, "gate decision grant ref index")?);
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

    /// Singular-claim decision discovery for erasure and per-claim receipt
    /// reads. Bundle receipts are deliberately excluded: callers selecting the
    /// latest claim verdict must never receive a multi-claim bundle instead.
    /// Index-accelerated ONLY when the durable backfill flag is
    /// set; otherwise a full keyspace scan, so a vault mid-backfill can never
    /// hide rows from an erase. Both paths return records ascending by
    /// decision_id and are result-identical.
    ///
    /// Redacted (version 1) skeletons ARE returned — they retain `claim_id` by
    /// design. Completeness is decided by
    /// [`Store::verify_claim_erasure_by_scan_in_txn`], never by this reader.
    pub(crate) fn gate_decisions_for_claim_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionRecord>> {
        if !self.gate_decision_claim_index_backfill_complete_in_txn(txn)? {
            return self.scan_gate_decisions_for_claim_in_txn(txn, claim_id);
        }
        let scan_prefix = suffix_of(
            gate_decision_claim_index_prefix(claim_id),
            GATE_DECISION_CLAIM_INDEX_PREFIX,
        );
        let mut records = Vec::new();
        for key in CLAIM_INDEX.scan_keys(self, txn, &scan_prefix)? {
            let decision_id =
                GateDecisionId::from_bytes(tail_id(&key, "gate decision claim index")?);
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
    pub(crate) fn verify_claim_erasure_by_scan_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionId>> {
        let mut remaining = Vec::new();
        self.for_each_gate_decision_in_txn(txn, |record| {
            if record.redacted_at.is_none()
                && (record.claim_id == Some(*claim_id)
                    || self
                        .gate_decision_claim_refs_in_txn(txn, record.decision_id)?
                        .contains(claim_id))
            {
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
        for row in LEDGER.iter_from(self, txn, &[])? {
            let (decision_id, raw) = row?;
            let record = self.decode_gate_decision_value(decision_id, &raw)?;

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
        match CLAIM_INDEX_BACKFILL_COMPLETE.get(self, txn, &())? {
            Some(value) if value == GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE => Ok(true),
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
        let Some(raw) = LEDGER.get(self, txn, &decision_id)? else {
            return Ok(None);
        };
        let record = self.decode_gate_decision_value(decision_id, &raw)?;
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
        GRANT_REF_INDEX.put(
            self,
            wtxn,
            &suffix_of(
                gate_decision_grant_ref_index_key(grant_ref, decision_id),
                GATE_DECISION_GRANT_REF_INDEX_PREFIX,
            ),
            &OneMarker,
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
        GRANT_REF_INDEX.delete(
            self,
            wtxn,
            &suffix_of(
                gate_decision_grant_ref_index_key(grant_ref, record.decision_id),
                GATE_DECISION_GRANT_REF_INDEX_PREFIX,
            ),
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
        CLAIM_INDEX.delete(
            self,
            wtxn,
            &suffix_of(
                gate_decision_claim_index_key(claim_id, record.decision_id),
                GATE_DECISION_CLAIM_INDEX_PREFIX,
            ),
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
        let _custody = self.gate_custody_read_guard()?;
        let rtxn = self.env.read_txn()?;
        match self.gate_decisions_page_in_txn(&rtxn, before, limit) {
            Ok(rows) => Ok(rows),
            Err(error @ Error::CorruptedIndex("gate decision ORCB")) => {
                // Collect retirement witnesses while the old read snapshot is
                // alive, then drop it BEFORE opening a fresh LMDB read slot.
                // Raw rows, so a ledger key of another shape is not a scan
                // failure here; only a row addressable by decision id can be
                // re-read below as removed.
                let mut retired_keys = Vec::new();
                for row in LEDGER.iter_raw_from(self, &rtxn, &[])? {
                    let (key, raw) = row?;
                    if orcb::raw_key_retired(&self.core.gate_custody_root, &raw)?
                        && let Some(decision_id) = GateDecisionId::decode_key(&key)
                    {
                        retired_keys.push(decision_id);
                    }
                }
                drop(rtxn);
                if retired_keys.is_empty() {
                    return Err(error);
                }
                let current = self.env.read_txn()?;
                let mut removed = false;
                for decision_id in retired_keys {
                    removed |= !LEDGER.contains(self, &current, &decision_id)?;
                }
                if removed {
                    self.gate_decisions_page_in_txn(&current, before, limit)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn gate_decisions_page_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        before: Option<GateDecisionId>,
        limit: usize,
    ) -> Result<Vec<GateDecisionRecord>> {
        #[cfg(test)]
        BEFORE_GATE_PAGE_DECODE.with(|slot| {
            if let Some(callback) = slot.borrow_mut().take() {
                callback();
            }
        });
        if limit == 0 {
            return Ok(Vec::new());
        }
        let upper = before.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in LEDGER.iter_rev_range(self, rtxn, Bound::Unbounded, upper)? {
            let (decision_id, raw) = row?;
            let record = self.decode_gate_decision_value(decision_id, &raw)?;

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
    if LEDGER.contains(store, wtxn, &record.decision_id)? {
        return Err(Error::InvariantViolation("gate decision id collision"));
    }
    let value = if let Some(claim) = record.claim_id {
        // A committed age sweep may still be retiring this partition's
        // exterior key. No new ciphertext may reuse it in that interval.
        if super::retention::RETIRE_PENDING.contains(store, &*wtxn, &claim)? {
            return Err(Error::InvalidConfig(
                "gate decision partition is retiring".into(),
            ));
        }
        orcb::encode_hot(store.gate_key_root(), record)?
    } else {
        encode_gate_decision(record)?
    };
    LEDGER.put(store, wtxn, &record.decision_id, &value)?;
    super::retention_scope::append_context_in_txn(store, wtxn, record)?;
    if let Some(grant_ref) = record.grant_ref.as_deref() {
        GRANT_REF_INDEX.put(
            store,
            wtxn,
            &suffix_of(
                gate_decision_grant_ref_index_key(grant_ref, record.decision_id),
                GATE_DECISION_GRANT_REF_INDEX_PREFIX,
            ),
            &OneMarker,
        )?;
    }
    if let Some(claim_id) = record.claim_id.as_ref() {
        CLAIM_INDEX.put(
            store,
            wtxn,
            &suffix_of(
                gate_decision_claim_index_key(claim_id, record.decision_id),
                GATE_DECISION_CLAIM_INDEX_PREFIX,
            ),
            &(),
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
