use super::*;

use std::collections::{HashMap, HashSet};

use heed::RwTxn;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::ppr_cache_invalidation as ppr;
use crate::write_envelope::ClaimCandidate;
use oneiron_contracts::affect::Vad;

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
    pre_mask: Option<ClaimCandidate>,
) -> Result<AppliedClaimCandidate> {
    let ClaimCandidateRequest {
        id,
        candidate,
        envelope,
        occurred,
        learned_at,
        mut decision,
        consent,
        indexing,
        write_policy,
        owner_authored,
        pending_prompt,
    } = request;
    crate::write_envelope::validate_write_envelope(envelope)?;
    let (analyzer, text_index_trusted) = birth_context;

    let actor = envelope.actor();
    let actor_raw =
        crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
    let actor_header =
        EntityMetadataHeader::parse(&actor_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    crate::write_envelope::provenance::actor_substrate::validate_actor_class(
        actor_header.entity_type,
        actor.actor_class(),
    )?;

    let subject = candidate.subject();
    if candidate.predicate()
        == crate::write_envelope::world_access_predicates::PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
        && subject != crate::write_envelope::claim_body::ClaimSubject::Entity(actor.entity_ref())
    {
        return Err(Error::InvalidClaimBody(
            "world default subset must be authored by its subject agent",
        ));
    }
    if let crate::write_envelope::claim_body::ClaimSubject::Entity(subject_id) = subject
        && !crate::ports::EntityStoreRead::port_entity_present(store, wtxn, &subject_id)?
    {
        return Err(Error::EntityNotFound);
    }

    for &relationship in candidate.relationship().into_iter().flatten() {
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
    let had_prior = crate::ports::EntityStoreRead::port_entity_present(store, wtxn, &id)?;
    // Only an id the mask rewrote in this transaction carries its pre-mask
    // body: its MACHINE proof is renewed over what is stored, and only after
    // the old proof verifies over the pre-mask bytes. Every other envelope
    // reaches admission byte for byte.
    let mut resigned = envelope.clone();
    let mut pre_mask_facet = None;
    if let Some(pre) = &pre_mask {
        // The mask writes handles over secrets and never moves the facet a
        // candidate names: one whose facet selector it rewrote in the opaque
        // scope is stored at the facet the selector named, the one the
        // preflight judged and its walk over the batch noted
        // (PREFLIGHT-SAME-BATCH-BIRTH-FACET).
        let pre_body = pre.clone().into_claim_body(envelope, default_facet)?;
        pre_mask_facet = Some(pre_body.scope_facet);
        crate::authority::resign_machine_claim_after_mask_in_txn(
            store,
            wtxn,
            &id,
            pre,
            &candidate,
            &mut resigned,
            pre_body.scope_facet,
        )?;
        // A receipt this candidate's preflight recorded names the body before
        // the mask wrote its handles, under the envelope it was offered with:
        // the gate reads that receipt against this body's diff
        // (CHECKER-PREVIEW-READS-UNMASKED-CANDIDATE).
        if decision.preflight.is_some() {
            let (diff, _) = crate::gate::claim_consent_binding_parts(store, wtxn, &pre_body)?;
            decision.pre_mask_diff =
                Some(<[u8; 32]>::try_from(diff.as_slice()).map_err(|_| {
                    Error::InvariantViolation("a claim diff handle is not 32 bytes")
                })?);
        }
    }
    let envelope = &resigned;
    let mut body = candidate.into_claim_body(envelope, default_facet)?;
    if let Some(facet) = pre_mask_facet {
        body.scope_facet = facet;
    }
    crate::claim::world_access::admit_world_access_write(
        store,
        wtxn,
        Some(actor.entity_ref()),
        &body,
    )?;
    // The ClaimOf weight the claim is born with: a signed initial-weight
    // entry, else the default. Both machine-history fold entry points seed
    // from this same value.
    let birth_weight = crate::store::claim_lineage::claim_initial_claim_of_weight(&body)?;
    let data = crate::write_envelope::claim_body::encode_claim_body(&body)?;
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
        &crate::secret_custody::CustodyWrite {
            store,
            config,
            analyzer,
            text_index_trusted,
        },
        wtxn,
        PutRequest {
            row: PutRow {
                id,
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                occurred,
                learned_at,
                data: &data,
                row_version: None,
                file_body: None,
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
                owner_authored,
                pending_prompt: pending_prompt.as_deref(),
                prepared_person_substrate: None,
                prepared_agent_birth: None,
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

    // FIX 7757: a candidate birth carries its canonical `FacetOf` edge in the
    // same txn as its row, at the body's facet; a re-put keeps its birth stamp.
    let birth_edge_written = if !had_prior {
        let facet = body.scope_facet;
        let owner = crate::vault::embedded_owner_actor_id()?;
        if facet == crate::claim::substrate_facet_id(owner)?
            && stored_entity_type(store, wtxn, &owner)?.is_none()
        {
            apply_ops_with_origin(
                store,
                config,
                analyzer,
                wtxn,
                vec![BatchOp::Put {
                    id: owner,
                    entity_type: crate::registry::ENTITY_TYPE_PERSON,
                    occurred,
                    learned_at,
                    row_version: None,
                    data: crate::vault::encode_embedded_owner_actor_body()?,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                text_index_trusted,
                ApplyOpsGateMode::new(false, false),
                BaseWriteOrigin::Ordinary,
            )?;
        }
        let found = stored_entity_type(store, wtxn, &facet)?;
        if found != Some(crate::registry::ENTITY_TYPE_FACET) {
            return Err(Error::Registry(crate::error::RegistryError::InvalidFacet {
                facet,
                found,
            }));
        }
        apply_edge_with_created_at(
            store,
            wtxn,
            id,
            EdgeKind::FacetOf,
            facet,
            1.0,
            learned_at,
            Vad::NEUTRAL,
            None,
        )?;
        ppr::invalidate_ppr_for_edge(store, wtxn, &id, &facet)?;
        true
    } else {
        false
    };

    let subject_id = match subject {
        crate::write_envelope::claim_body::ClaimSubject::Entity(subject_id) => Some(subject_id),
        crate::write_envelope::claim_body::ClaimSubject::Edge { .. } => None,
    };
    let removed_claim_of = reconcile_claim_of_edges(store, wtxn, &id, subject_id)?;
    let mut had_graph_mutation = birth_edge_written || !removed_claim_of.is_empty();
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

    let weight = birth_weight.ok_or(Error::InvariantViolation(
        "ClaimOf edge missing birth weight",
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
/// FIX 7757: the stored `FacetOf` birth edge is authoritative when present;
/// the body and the vault default stay as fallback for rows born without one.
pub(crate) fn claim_candidate_birth_facet(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<EntityId> {
    if let Some(facet) = crate::federation::record_scope::birth_facet(store, txn, *id)? {
        return Ok(facet);
    }
    let stored_facet = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .filter(|raw| {
            EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        })
        .and_then(|raw| {
            crate::write_envelope::claim_body::decode_claim_body(
                &raw[ENTITY_METADATA_HEADER_LEN..],
                true,
            )
            .ok()
        })
        .map(|stored| stored.scope_facet);
    match stored_facet {
        Some(facet) => Ok(facet),
        None => crate::claim::default_facet_in(store, txn),
    }
}

/// [`claim_candidate_birth_facet`] as apply reads it, for a walk over a
/// batch's ops before any of them applies (PREFLIGHT-SAME-BATCH-BIRTH-FACET).
/// Apply runs the ops in order in one transaction: a CLAIM an earlier op
/// births stamps the facet a later candidate of that id is stored at, and a
/// delete leaves the id to the vault default. The pre-batch state shows
/// neither. A write over a stored claim keeps its birth facet (apply refuses
/// one that names another, `FacetStampImmutable`).
///
/// Only an id's own CLAIM births (raw put or candidate) and deletes are
/// noted. Other writers of a birth facet are not: a birth of another entity
/// type at the id, a FacetOf edge op, a lexical-hint or delete-cascade
/// teardown, a gap-decay lapse birth. A later candidate of such an id is
/// still judged over the pre-batch answer and, held, fails closed at the
/// replay match, as before.
pub(crate) struct BatchBirthFacets {
    /// Ids two or more of the batch's ops write: only a later op on the same
    /// id reads what an earlier one noted, so no other op is decoded again.
    repeated: HashSet<EntityId>,
    /// Each id an earlier op wrote: `Some(facet)` born at it, `None` deleted.
    written: HashMap<EntityId, Option<EntityId>>,
}

/// The id `op` writes a CLAIM row at, or deletes.
fn claim_write_id(op: &BatchOp) -> Option<&EntityId> {
    match op {
        BatchOp::Put {
            id, entity_type, ..
        } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM => Some(id),
        BatchOp::ClaimCandidate { id, .. } | BatchOp::Delete { id } => Some(id),
        _ => None,
    }
}

impl BatchBirthFacets {
    /// The walk state for `ops`, before the first of them.
    pub(crate) fn new(ops: &[BatchOp]) -> Self {
        let mut once = HashSet::new();
        let mut repeated = HashSet::new();
        for id in ops.iter().filter_map(claim_write_id) {
            if !once.insert(*id) {
                repeated.insert(*id);
            }
        }
        Self {
            repeated,
            written: HashMap::new(),
        }
    }

    /// The facet a candidate for `id` is stored at once the ops noted so far
    /// have applied.
    pub(crate) fn birth_facet(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<EntityId> {
        match self.written.get(id) {
            Some(Some(facet)) => Ok(*facet),
            Some(None) => crate::claim::default_facet_in(store, txn),
            None => claim_candidate_birth_facet(store, txn, id),
        }
    }

    /// Notes what `op` does to the birth facet of the id it writes; call it
    /// after the read for `op` itself. A body apply cannot decode aborts the
    /// batch at that op, so no later op reads it and it is not noted. The op
    /// is read as offered: apply stores a candidate the mask rewrites at the
    /// facet it named before the mask.
    pub(crate) fn note(
        &mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<()> {
        if !claim_write_id(op).is_some_and(|id| self.repeated.contains(id)) {
            return Ok(());
        }
        let (id, facet) = match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                ..
            } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM => {
                let Ok(body) = crate::write_envelope::claim_body::decode_claim_body(data, true)
                else {
                    return Ok(());
                };
                (id, body.scope_facet)
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                ..
            } => {
                let facet = self.birth_facet(store, txn, id)?;
                let Ok(body) = (**candidate).clone().into_claim_body(envelope, facet) else {
                    return Ok(());
                };
                (id, body.scope_facet)
            }
            BatchOp::Delete { id } => {
                self.written.insert(*id, None);
                return Ok(());
            }
            _ => return Ok(()),
        };
        // A birth when no row is stored for `id` at this point of the batch:
        // apply then stamps the body's facet as the claim's birth edge.
        let stored = match self.written.get(id) {
            Some(written) => written.is_some(),
            None => crate::ports::EntityStoreRead::port_entity_present(store, txn, id)?,
        };
        if !stored {
            self.written.insert(*id, Some(facet));
        }
        Ok(())
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
        crate::channel_identity::note_claim_delete_for_rekey(
            store,
            wtxn,
            claim_id,
            Some(*subject),
        )?;
        apply_delete_edge(store, wtxn, *claim_id, EdgeKind::ClaimOf, *subject)?;
    }
    Ok(stale_subjects)
}
