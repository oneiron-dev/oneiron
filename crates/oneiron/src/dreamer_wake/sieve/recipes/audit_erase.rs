//! Candidate refs in retained audit decisions, scrubbed with their saved copies.

use std::collections::BTreeSet;

use super::{AUDIT, SieveAuditRecord};
use crate::attempt_queue::AttemptId;
use crate::side_table::SideKey;
use crate::{EntityId, Result};

impl SieveAuditRecord {
    pub(crate) fn decision_candidate_refs(&self) -> BTreeSet<EntityId> {
        let Self::Flagged(audit) = self else {
            return BTreeSet::new();
        };
        audit
            .decisions
            .iter()
            .flat_map(|kept| {
                kept.decision.evidence.iter().copied().chain(
                    kept.decision
                        .receipt
                        .evidence_versions
                        .iter()
                        .map(|version| version.id),
                )
            })
            .collect()
    }

    pub(crate) fn forget_decision_candidate(&mut self, id: &EntityId) -> bool {
        let Self::Flagged(audit) = self else {
            return false;
        };
        let mut changed = false;
        for kept in &mut audit.decisions {
            let decision = &mut kept.decision;
            let before = decision.evidence.len() + decision.receipt.evidence_versions.len();
            decision.evidence.retain(|candidate| candidate != id);
            decision
                .receipt
                .evidence_versions
                .retain(|version| version.id != *id);
            changed |= before != decision.evidence.len() + decision.receipt.evidence_versions.len();
        }
        changed
    }
}

/// Scrubs valid canonical rows without making an unrelated malformed audit
/// refuse an otherwise working erase. Raw storage errors still abort the writer.
pub(crate) fn forget_audit_candidate_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut changed = Vec::new();
    for row in AUDIT.iter_raw_from(store, txn, &[])? {
        let (key, raw) = row?;
        let Some(attempt) = AttemptId::decode_key(&key) else {
            tracing::warn!("a sieve audit key did not decode; its candidate refs are unchanged");
            continue;
        };
        let mut audit = match AUDIT.decode_value(&raw) {
            Ok(audit) => audit,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a sieve audit did not decode; its candidate refs are unchanged"
                );
                continue;
            }
        };
        if audit.forget_decision_candidate(id) {
            changed.push((attempt, audit));
        }
    }
    for (attempt, audit) in changed {
        AUDIT.put(store, txn, &attempt, &audit)?;
    }
    Ok(())
}
