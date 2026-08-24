use super::*;

use heed::RwTxn;

use crate::affect::Vad;
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ppr;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;

pub(super) struct AppliedClaimCandidate {
    pub(super) had_graph_mutation: bool,
    pub(super) had_vector_mutation: bool,
    pub(super) cleared_pending_embedding: bool,
    pub(super) pending_embedding_token: Option<Vec<u8>>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "candidate writes thread existing apply_put context"
)]
pub(super) fn apply_claim_candidate(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    occurred: TimeRange,
    learned_at: u64,
    has_later_covering_text_op: bool,
    write_policy: Option<&crate::gate::PolicyManifestResolution>,
    internal_lexical_query_hint: bool,
    record_gate_decisions: bool,
    persist_gate_pending_consent: bool,
    can_resolve_pending_consent: bool,
    include_source_in_gate_input: bool,
    claim_gate_prechecked: bool,
    preflight_gate_decision_id: Option<crate::store::GateDecisionId>,
) -> Result<AppliedClaimCandidate> {
    crate::gate::validate_write_envelope(envelope)?;

    let actor = envelope.actor();
    let actor_raw = store
        .entities
        .get(wtxn, actor.entity_ref().as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let actor_header =
        EntityMetadataHeader::parse(&actor_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())?;

    let subject = candidate.subject();
    if let crate::claim::ClaimSubject::Entity(subject_id) = subject
        && store.entities.get(wtxn, subject_id.as_bytes())?.is_none()
    {
        return Err(Error::EntityNotFound);
    }

    let body = candidate.into_claim_body(envelope);
    let data = crate::claim::encode_claim_body(&body)?;
    let applied_put = apply_put(
        store,
        wtxn,
        id,
        crate::registry::ENTITY_TYPE_CLAIM,
        occurred,
        learned_at,
        &data,
        false,
        false,
        false,
        has_later_covering_text_op,
        write_policy,
        Some(envelope),
        internal_lexical_query_hint,
        record_gate_decisions,
        persist_gate_pending_consent,
        can_resolve_pending_consent,
        include_source_in_gate_input,
        claim_gate_prechecked,
        preflight_gate_decision_id,
        None,
        // A claim candidate is never part of a promotion closure: promote
        // replays the session's typed journal, which stages no candidate op.
        BaseWriteOrigin::Ordinary,
    )?;

    let subject_id = match subject {
        crate::claim::ClaimSubject::Entity(subject_id) => Some(subject_id),
        crate::claim::ClaimSubject::Edge { .. } => None,
    };
    let removed_claim_of = reconcile_claim_of_edges(store, wtxn, &id, subject_id)?;
    let mut had_graph_mutation = !removed_claim_of.is_empty();
    for removed_subject in &removed_claim_of {
        ppr::invalidate_ppr_for_edge(store, wtxn, &id, removed_subject)?;
    }

    let Some(subject_id) = subject_id else {
        return Ok(AppliedClaimCandidate {
            had_graph_mutation,
            had_vector_mutation: applied_put.had_vector_mutation,
            cleared_pending_embedding: applied_put.cleared_pending_embedding,
            pending_embedding_token: applied_put.pending_embedding_token,
        });
    };

    let weight = EdgeKind::ClaimOf
        .default_weight()
        .ok_or(Error::InvariantViolation(
            "ClaimOf edge missing default weight",
        ))?;
    apply_edge(
        store,
        wtxn,
        id,
        EdgeKind::ClaimOf,
        subject_id,
        weight,
        Vad::NEUTRAL,
    )?;
    ppr::invalidate_ppr_for_edge(store, wtxn, &id, &subject_id)?;
    had_graph_mutation = true;
    Ok(AppliedClaimCandidate {
        had_graph_mutation,
        had_vector_mutation: applied_put.had_vector_mutation,
        cleared_pending_embedding: applied_put.cleared_pending_embedding,
        pending_embedding_token: applied_put.pending_embedding_token,
    })
}

pub(super) fn reconcile_claim_of_edges(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    claim_id: &EntityId,
    new_subject: Option<EntityId>,
) -> Result<Vec<EntityId>> {
    let prefix = edge_kind_prefix(claim_id, EdgeKind::ClaimOf);
    let mut stale_subjects = Vec::new();
    for entry in store.edges_out.prefix_iter(wtxn, &prefix)? {
        let (key, value) = entry?;
        let subject = parse_strict_edge_record(&key, &value)?.target;
        if Some(subject) != new_subject {
            stale_subjects.push(subject);
        }
    }

    for subject in &stale_subjects {
        apply_delete_edge(store, wtxn, *claim_id, EdgeKind::ClaimOf, *subject)?;
    }
    Ok(stale_subjects)
}
