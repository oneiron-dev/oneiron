//! Moved from `crates/oneiron/src/dreamer_wake/sieve/recipes/audit_erase.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::sieve::recipes::SieveAuditRecord;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;

impl SieveAuditRecord {
    pub fn decision_candidate_refs(&self) -> BTreeSet<EntityId> {
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

    pub fn forget_decision_candidate(&mut self, id: &EntityId) -> bool {
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
