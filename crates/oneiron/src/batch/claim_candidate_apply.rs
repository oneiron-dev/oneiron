use super::*;

use heed::RwTxn;

use crate::affect::Vad;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ppr;
use crate::store::Store;

pub(super) struct AppliedClaimCandidate {
    pub(super) had_graph_mutation: bool,
    pub(super) had_vector_mutation: bool,
    pub(super) cleared_pending_embedding: bool,
    pub(super) pending_embedding_token: Option<Vec<u8>>,
}

pub(super) fn apply_claim_candidate(
    store: &Store,
    config: &crate::config::VaultConfig,
    birth_context: (&crate::analyzer::MultilingualAnalyzer, bool),
    wtxn: &mut RwTxn<'_>,
    request: ClaimCandidateRequest<'_>,
) -> Result<AppliedClaimCandidate> {
    let ClaimCandidateRequest {
        id,
        candidate,
        envelope,
        occurred,
        learned_at,
        decision,
        consent,
        indexing,
        write_policy,
    } = request;
    crate::gate::validate_write_envelope(envelope)?;
    let (analyzer, text_index_trusted) = birth_context;

    let actor = envelope.actor();
    let actor_raw =
        crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
    let actor_header =
        EntityMetadataHeader::parse(&actor_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())?;

    let subject = candidate.subject();
    if candidate.predicate() == crate::pipeline::PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
        && subject != crate::claim::ClaimSubject::Entity(actor.entity_ref())
    {
        return Err(Error::InvalidClaimBody(
            "world default subset must be authored by its subject agent",
        ));
    }
    if let crate::claim::ClaimSubject::Entity(subject_id) = subject
        && crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &subject_id)?.is_none()
    {
        return Err(Error::EntityNotFound);
    }

    if let Some(relationship) = candidate.relationship() {
        let found = crate::vault::live_entity_row_in_txn(store, wtxn, &relationship)?.live_type();
        if found != Some(crate::registry::ENTITY_TYPE_RELATIONSHIP) {
            return Err(crate::error::RegistryError::InvalidRelationship {
                relationship,
                found,
            }
            .into());
        }
    }
    // The default stamps a birth. A candidate re-put over a stored claim keeps
    // the facet that claim was born with.
    let default_facet = claim_candidate_birth_facet(store, wtxn, &id)?;
    let had_prior = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &id)?.is_some();
    let body = candidate.into_claim_body(envelope, default_facet)?;
    let data = crate::claim::encode_claim_body(&body)?;
    if had_prior {
        crate::claim::history_store::close_machine_history_for_successor(
            store,
            config,
            analyzer,
            wtxn,
            id,
            &body,
            actor,
            learned_at,
            text_index_trusted,
        )?;
    }
    let applied_put = apply_put(
        store,
        wtxn,
        PutRequest {
            row: PutRow {
                id,
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                occurred,
                learned_at,
                data: &data,
            },
            // A candidate opens no admit band and no hub inlet.
            options: PutOptions {
                decision,
                consent,
                indexing,
                ..PutOptions::default()
            },
            context: PutContext {
                // A claim candidate is never part of a promotion closure:
                // promote replays the session's typed journal, which stages
                // no candidate op.
                origin: BaseWriteOrigin::Ordinary,
                write_policy,
                write_envelope: Some(envelope),
                hub_admission: None,
                refinement_admission: None,
                // Carried-forward transitions bind only to exact claim Puts.
                transition: None,
                posture: config.privacy.posture,
            },
        },
    )?;

    crate::claim::history_store::stage_machine_birth_after_candidate(
        store,
        config,
        analyzer,
        wtxn,
        id,
        &body,
        envelope,
        occurred,
        learned_at,
        text_index_trusted,
        had_prior,
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

/// The exact birth facet kept by both the final materializer and signer.
pub(crate) fn claim_candidate_birth_facet(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<EntityId> {
    let stored_facet = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .filter(|raw| {
            EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        })
        .and_then(|raw| {
            crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).ok()
        })
        .map(|stored| stored.scope_facet);
    match stored_facet {
        Some(facet) => Ok(facet),
        None => crate::claim::default_facet_in(store, txn),
    }
}

pub(super) fn reconcile_claim_of_edges(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    claim_id: &EntityId,
    new_subject: Option<EntityId>,
) -> Result<Vec<EntityId>> {
    let mut stale_subjects = Vec::new();
    for entry in crate::ports::EdgeStoreRead::port_edges(
        store,
        wtxn,
        claim_id,
        crate::ports::EdgeDirection::Out,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let subject = entry?.target;
        if Some(subject) != new_subject {
            stale_subjects.push(subject);
        }
    }

    for subject in &stale_subjects {
        apply_delete_edge(store, wtxn, *claim_id, EdgeKind::ClaimOf, *subject)?;
    }
    Ok(stale_subjects)
}
