//! The typed per-edge provenance audit (FIX 3959, ARCH-0034
//! `#provenance-claim`): every `edge.provenance` Claim of one directed edge
//! the caller may read, with its author, actor class, source revision,
//! confidence, validity and lifecycle.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};

use super::claim_stale::ReadFilterInput;
use super::{Memory, MemoryError, MemoryResult};
use crate::claim::{ClaimLifecycleStatus, ClaimReadStatus, ScopedRead, ScopedReadResult};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::Error;
use crate::provenance::{EdgeRef, StoredProvenanceClaim, SupersessionStatus};
use crate::vault::{ReadMode, RevisionRef};

/// `vault.edges.provenance` input: one directed edge, named by its two
/// endpoint refs and its kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeProvenanceRequest {
    /// The edge's source entity, by short ref or 32-hex id.
    pub source_ref: String,
    /// The snake_case `EdgeKind` name of the edge.
    pub edge_kind: String,
    /// The edge's target entity, by short ref or 32-hex id.
    pub target_ref: String,
    /// Caller retrieval filter on the provenance claims; met with the actor
    /// ceiling, it only narrows.
    #[serde(default)]
    pub filter: Option<ReadFilterInput>,
}

/// The write-time validated class of a provenance claim's actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeProvenanceActorClass {
    Human,
    Agent,
    System,
}

impl From<EdgeActorClass> for EdgeProvenanceActorClass {
    fn from(class: EdgeActorClass) -> Self {
        match class {
            EdgeActorClass::Human => Self::Human,
            EdgeActorClass::Agent => Self::Agent,
            EdgeActorClass::System => Self::System,
        }
    }
}

/// A provenance claim's authoritative `supersession_status`, the value the
/// edge's `confirmation_status` flag mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeProvenanceSupersession {
    Proposed,
    Confirmed,
    Disputed,
    Retracted,
}

impl From<SupersessionStatus> for EdgeProvenanceSupersession {
    fn from(status: SupersessionStatus) -> Self {
        match status {
            SupersessionStatus::Proposed => Self::Proposed,
            SupersessionStatus::Confirmed => Self::Confirmed,
            SupersessionStatus::Disputed => Self::Disputed,
            SupersessionStatus::Retracted => Self::Retracted,
        }
    }
}

/// The wrapping claim's stored lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeProvenanceLifecycle {
    Active,
    Superseded,
    Retracted,
}

impl From<ClaimLifecycleStatus> for EdgeProvenanceLifecycle {
    fn from(lifecycle: ClaimLifecycleStatus) -> Self {
        match lifecycle {
            ClaimLifecycleStatus::Active => Self::Active,
            ClaimLifecycleStatus::Superseded => Self::Superseded,
            ClaimLifecycleStatus::Retracted => Self::Retracted,
        }
    }
}

/// One readable `edge.provenance` claim of the audited edge. Every ref is
/// lowercase hex; an absent optional field was not recorded. A ref names a
/// record and grants no read of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EdgeProvenanceView {
    /// 32-hex id of the provenance claim.
    pub claim_ref: String,
    /// The claim's short ref, when assigned.
    pub short_ref: Option<String>,
    /// 32-hex id of the edge's source entity.
    pub source_ref: String,
    /// snake_case `EdgeKind` name of the edge.
    pub edge_kind: String,
    /// 32-hex id of the edge's target entity.
    pub target_ref: String,
    /// 32-hex id of the PERSON, agent or MACHINE that asserted the edge.
    pub actor_entity_ref: String,
    /// The actor's write-time validated class.
    pub actor_class: EdgeProvenanceActorClass,
    /// 32-hex ref of the source document revision the assertion was read
    /// at; absent when no source document exists.
    pub source_revision_ref: Option<String>,
    /// 32-hex citation of the exact text the actor read, when recorded.
    pub body_snapshot_ref: Option<String>,
    /// The actor's confidence, in [0, 1].
    pub confidence: f32,
    /// The authoritative supersession status.
    pub supersession_status: EdgeProvenanceSupersession,
    /// Valid-time start (Unix s), when recorded.
    pub valid_from: Option<u64>,
    /// Valid-time end (Unix s); absent while the assertion still holds.
    pub valid_to: Option<u64>,
    /// 32-hex id of the MODEL substrate that produced the write, when recorded.
    pub substrate_ref: Option<String>,
    /// The substrate's reasoning-effort setting for the write, when recorded.
    pub reasoning_effort: Option<String>,
    /// The wrapping claim's stored lifecycle.
    pub lifecycle: EdgeProvenanceLifecycle,
    /// Whether an active claim's cited source was erased: the engine then
    /// counts it as withdrawn, never as live.
    pub stale: bool,
    /// When the vault learned the claim (Unix s), the precedence key.
    pub learned_at: u64,
    /// The claim envelope's occurred start (Unix s).
    pub occurred_start: u64,
    /// The claim envelope's occurred end (Unix s).
    pub occurred_end: u64,
    /// Whether this is the claim the edge's two flags are stamped from: the
    /// winner among the live claims by learned_at, then confidence, then
    /// claim id. No readable claim is marked when that winner is withheld.
    pub winner: bool,
}

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
    /// under the request's filter, and a claim whose author or cited source
    /// revision this lane may not read is withheld whole. Read suffices: the
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
                    if let Some(row) = row
                        && cited_refs_readable_in(self.vault, &lane, txn, &claim)?
                    {
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

/// Whether `lane` may read, in `txn`, every record `claim` names beside its
/// edge: its actor, and the document its `source_revision_ref` cites, at that
/// revision. A cited revision no record retains proves no read and fails, as
/// an unreadable one does, so the claim is withheld whole.
fn cited_refs_readable_in(
    vault: &crate::Vault,
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    claim: &StoredProvenanceClaim,
) -> MemoryResult<bool> {
    if !lane
        .entities_readable_in_txn(txn, &[claim.record.actor_entity_ref])?
        .into_iter()
        .all(|readable| readable)
    {
        return Ok(false);
    }
    let Some(revision) = claim.record.source_revision_ref else {
        return Ok(true);
    };
    let revision = RevisionRef(revision);
    let Some(document) = vault.revision_record_in(txn, revision)? else {
        return Ok(false);
    };
    Ok(lane
        .get_entities_parts_with_mode_in_txn(txn, &[document], ReadMode::Pinned(revision))?
        .into_iter()
        .next()
        .flatten()
        .is_some())
}
