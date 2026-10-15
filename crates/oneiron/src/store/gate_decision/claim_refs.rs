//! Inbox-bundle claim references and uncommitted batch-preflight markers:
//! the two gate-decision sidecars erasure consults next to the ledger rows.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::side_table::{self, LegacyCompact, Raw, SideTable};
use crate::store::Store;

use super::ledger::OneMarker;
use super::types::{GateDecisionId, GateDecisionRecord};

/// A multi-claim inbox bundle's complete constituent claim ids, ascending and
/// distinct. Its indexed counterpart [`CLAIM_REF_INDEX`] is an acceleration
/// only; this sidecar is the source for independent scan verification. Both
/// are shredded with the bundle row. Key: decision id.
const CLAIM_REFS: SideTable<GateDecisionId, Vec<[u8; 16]>, LegacyCompact> =
    SideTable::new(&side_table::GATE_DECISION_CLAIM_REFS);

/// Per-constituent index over [`CLAIM_REFS`]; the value is an empty marker.
/// Key: claim id + decision id.
const CLAIM_REF_INDEX: SideTable<([u8; 16], GateDecisionId), (), Raw> =
    SideTable::new(&side_table::GATE_DECISION_CLAIM_REF_INDEX);

/// Uncommitted-only batch preflight protection. A batch records every future
/// write decision before applying its first op; deletion may scrub only the
/// decisions already consumed. Markers are removed as each op applies, and
/// never survive a successful batch commit. Key: decision id.
const UNAPPLIED_PREFLIGHT: SideTable<GateDecisionId, OneMarker, Raw> =
    SideTable::new(&side_table::GATE_DECISION_UNAPPLIED_PREFLIGHT);

impl Store {
    /// Appends an inbox bundle and its blind per-constituent claim references
    /// atomically. A bundle has no singular claim_id; its content digest alone
    /// cannot be reversed to find the claims it describes on deletion.
    pub(crate) fn append_gate_decision_with_claim_refs_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
        claim_refs: &[[u8; 16]],
    ) -> Result<()> {
        if record.claim_id.is_some() || claim_refs.is_empty() {
            return Err(Error::InvariantViolation("bundle claim references"));
        }
        let mut refs = claim_refs.to_vec();
        refs.sort_unstable();
        refs.dedup();
        self.append_gate_decision_in_txn(wtxn, record)?;
        CLAIM_REFS.put(self, wtxn, &record.decision_id, &refs)?;
        for claim_id in &refs {
            CLAIM_REF_INDEX.put(self, wtxn, &(*claim_id, record.decision_id), &())?;
        }
        Ok(())
    }

    /// Reads the complete association, independent of the secondary index.
    pub(super) fn gate_decision_claim_refs_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: GateDecisionId,
    ) -> Result<Vec<[u8; 16]>> {
        let Some(refs) = CLAIM_REFS.get(self, txn, &id)? else {
            return Ok(Vec::new());
        };
        if refs.is_empty() || refs.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::CorruptedIndex("gate decision claim references"));
        }
        Ok(refs)
    }

    /// Shreds all constituent refs with the primary. A redacted bundle keeps
    /// its accountability skeleton but no pointer to any member claim.
    pub(super) fn delete_gate_decision_claim_refs_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: GateDecisionId,
    ) -> Result<()> {
        let refs = self.gate_decision_claim_refs_in_txn(&*wtxn, id)?;
        for claim_id in refs {
            CLAIM_REF_INDEX.delete(self, wtxn, &(claim_id, id))?;
        }
        CLAIM_REFS.delete(self, wtxn, &id)?;
        Ok(())
    }

    /// Marks a preflight decision that belongs to an unapplied batch op.
    /// These markers exist only within the batch's write transaction: every
    /// successful op consumes its marker before commit; errors abort the txn.
    pub(crate) fn mark_unapplied_preflight_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        UNAPPLIED_PREFLIGHT.put(self, wtxn, &decision_id, &OneMarker)?;
        Ok(())
    }

    pub(crate) fn consume_unapplied_preflight_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        if !UNAPPLIED_PREFLIGHT.delete(self, wtxn, &decision_id)? {
            return Err(Error::InvariantViolation(
                "unapplied preflight marker missing",
            ));
        }
        Ok(())
    }

    /// Restore's cleanup of a dropped row: a committed image never carries
    /// a marker, so its absence is the normal case here.
    pub(super) fn discard_unapplied_preflight_marker_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        UNAPPLIED_PREFLIGHT.delete(self, wtxn, &decision_id)?;
        Ok(())
    }

    pub(super) fn is_unapplied_preflight_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<bool> {
        UNAPPLIED_PREFLIGHT.contains(self, txn, &decision_id)
    }

    /// Per-constituent discovery used ONLY by erasure; ordinary claim
    /// receipt readers must not mistake a bundle receipt for a claim verdict.
    pub(crate) fn bundle_gate_decisions_for_claim_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<GateDecisionRecord>> {
        let mut records = Vec::new();
        // Bundle refs have a separate index because a decision may describe
        // many claims. The primary's complete refs sidecar checks each hit.
        for row in CLAIM_REF_INDEX.iter_from(self, txn, claim_id.as_slice())? {
            let ((_, decision_id), ()) = row?;
            if !self
                .gate_decision_claim_refs_in_txn(txn, decision_id)?
                .contains(claim_id)
            {
                return Err(Error::CorruptedIndex("gate decision claim ref index"));
            }
            let Some(record) = self.gate_decision_in_txn(txn, decision_id)? else {
                return Err(Error::CorruptedIndex("gate decision claim ref index"));
            };
            if record.redacted_at.is_some() {
                return Err(Error::CorruptedIndex("gate decision claim ref index"));
            }
            records.push(record);
        }
        records.sort_by_key(|record| record.decision_id.as_bytes());
        Ok(records)
    }
}
