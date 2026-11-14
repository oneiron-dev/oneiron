//! The typed per-edge provenance audit (FIX 3959, ARCH-0034
//! `#provenance-claim`): every `edge.provenance` Claim of one directed edge
//! the caller may read, with its author, actor class, source revision,
//! confidence, validity and lifecycle.

use std::cell::RefCell;

use super::claim_stale::ReadFilterInput;
use super::{Memory, MemoryError, MemoryResult};
use crate::claim::{ClaimLifecycleStatus, ClaimReadStatus, ScopedReadResult};
use crate::edge::EdgeKind;
use crate::error::Error;
use crate::provenance::EdgeRef;
use crate::vault::ReadMode;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::edge_provenance::{
    EdgeProvenanceActorClass, EdgeProvenanceLifecycle, EdgeProvenanceRequest,
    EdgeProvenanceSupersession, EdgeProvenanceView,
};

/// 32 lowercase hex characters for an opaque 16-byte reference.
fn opaque_ref_hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Memory<'_> {
    /// Audits one directed edge (FIX 3959): every `edge.provenance` claim of
    /// it this caller's Recorded lane reads, superseded and retracted truth
    /// included, newest first by the claims' own precedence. One snapshot
    /// binds the read: the edge's endpoints and exact pair must pass the
    /// caller's admission, then each claim is read as an ordinary point read
    /// under the request's filter, whose shared CLAIM admission withholds
    /// whole a claim whose author or cited source revision this lane may not
    /// read (`ScopedRead::provenance_cited_readable_in`). Read suffices: the
    /// reader need not be the author. An endpoint name that resolves to no
    /// record, and a missing or withheld edge, read empty with the same
    /// receipt; only a malformed request is refused.
    pub fn edge_provenance(
        &self,
        request: &EdgeProvenanceRequest,
    ) -> MemoryResult<ScopedReadResult<Vec<EdgeProvenanceView>>> {
        let kind = EdgeKind::from_name(&request.edge_kind).ok_or_else(|| {
            MemoryError::bad_request_with(
                format!("unknown edge kind {:?}", request.edge_kind),
                &["Use a snake_case EdgeKind name such as about or claim_of."],
            )
        })?;
        let filter = request.filter.as_ref().map(ReadFilterInput::to_filter);
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let endpoint = |reference: &str| -> MemoryResult<Option<crate::EntityId>> {
            Ok(self
                .read_target(reference, ReadMode::Live)?
                .map(|(id, _)| id))
        };
        let edge = match (
            endpoint(&request.source_ref)?,
            endpoint(&request.target_ref)?,
        ) {
            (Some(source), Some(target)) => Some(EdgeRef::new(source, kind, target)),
            _ => None,
        };
        let audit: RefCell<Option<crate::provenance::EdgeProvenanceAudit>> = RefCell::new(None);
        lane.edge_claims_projected(
            edge.as_ref(),
            filter.as_ref(),
            |txn, edge| -> MemoryResult<Vec<crate::EntityId>> {
                let found = self.vault.edge_provenance_audit_in_txn(txn, edge)?;
                let ids = found.cohort.iter().map(|(claim, _)| claim.id).collect();
                *audit.borrow_mut() = Some(found);
                Ok(ids)
            },
            |txn, rows| {
                let Some(found) = audit.borrow_mut().take() else {
                    return Ok(Vec::new());
                };
                let winner = found.winner;
                let mut admitted = Vec::with_capacity(rows.len());
                for ((claim, lifecycle), (id, row)) in found.cohort.into_iter().zip(rows) {
                    if claim.id != id {
                        return Err(Error::InvariantViolation(
                            "edge provenance cohort and its reads disagree",
                        )
                        .into());
                    }
                    if let Some(row) = row {
                        admitted.push((claim, lifecycle, row));
                    }
                }
                admitted.sort_by(|(a, _, _), (b, _, _)| {
                    b.learned_at
                        .cmp(&a.learned_at)
                        .then_with(|| b.record.confidence.total_cmp(&a.record.confidence))
                        .then_with(|| b.id.as_bytes().cmp(a.id.as_bytes()))
                });
                admitted
                    .into_iter()
                    .map(|(claim, lifecycle, row)| {
                        let record = &claim.record;
                        Ok(EdgeProvenanceView {
                            claim_ref: claim.id.to_hex(),
                            short_ref: self.short_ref_of_in_txn(txn, &claim.id)?,
                            source_ref: claim.subject.source.to_hex(),
                            edge_kind: claim.subject.kind.name().to_owned(),
                            target_ref: claim.subject.target.to_hex(),
                            actor_entity_ref: record.actor_entity_ref.to_hex(),
                            actor_class: claim.actor_class.into(),
                            source_revision_ref: record
                                .source_revision_ref
                                .as_ref()
                                .map(opaque_ref_hex),
                            body_snapshot_ref: record
                                .body_snapshot_ref
                                .as_ref()
                                .map(opaque_ref_hex),
                            confidence: record.confidence,
                            supersession_status: record.supersession_status.into(),
                            valid_from: record.valid_from,
                            valid_to: record.valid_to,
                            substrate_ref: record.substrate_ref.map(|model| model.to_hex()),
                            reasoning_effort: record.reasoning_effort.clone(),
                            lifecycle: claim.wrapper.lifecycle.into(),
                            stale: claim.wrapper.lifecycle == ClaimLifecycleStatus::Active
                                && lifecycle == ClaimLifecycleStatus::Retracted,
                            learned_at: row.learned_at,
                            occurred_start: row.occurred.start,
                            occurred_end: row.occurred.end,
                            winner: winner == Some(claim.id),
                        })
                    })
                    .collect::<MemoryResult<Vec<_>>>()
            },
        )
    }
}
