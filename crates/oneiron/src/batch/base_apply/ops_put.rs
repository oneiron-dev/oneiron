//! Base-apply Put arm: validated puts with births and projections.

use super::validation::{birth_stamp_target, consume_preflight_decisions, validate_put_type};
use super::*;
use crate::error::RegistryError;
use crate::ppr;
use crate::temporal::TimeRange;
use zeroize::Zeroizing;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_put_arm(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    gate_mode: &ApplyOpsGateMode,
    id: EntityId,
    mut entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: Vec<u8>,
    allow_maintenance: bool,
    allow_reserved_predicate: bool,
    hub_sync_imported: bool,
    materialization: &Option<ClaimMaterialization>,
    transition: &Option<VerifiedClaimTransition>,
    mut put_options: PutOptions,
    origin: BaseWriteOrigin<'_>,
    text_index_trusted: bool,
) -> Result<()> {
    let mut data = Zeroizing::new(data);
    entity_type = validate_put_type(
        store,
        wtxn,
        &id,
        (entity_type, &mut data),
        allow_maintenance,
        allow_reserved_predicate,
        hub_sync_imported,
    )?;
    let replicated = allow_maintenance && allow_reserved_predicate;
    // FIX 3677: a long opaque local ASSET body goes to its file
    // here, and the row keeps its manifest; a replicated or
    // replayed row is written as it came.
    put_options.storage.asset_file = state.asset_files.remove(&id);
    if put_options.storage.asset_file.is_none()
        && !replicated
        && !state.replay
        && let Some((manifest, file)) =
            crate::store::file_put_body_in_txn(store, wtxn, entity_type, &data)?
    {
        data = Zeroizing::new(manifest);
        put_options.storage.asset_file = Some(file);
    }
    let sources = state.text_births.get(&id).map(Vec::as_slice);
    if let Some(facet) = birth_stamp_target(
        store,
        wtxn,
        id,
        entity_type,
        replicated,
        (state.birth_mask, sources),
    )? {
        let owner = crate::vault::embedded_owner_actor_id()?;
        if state.birth_mask.is_none()
            && facet == crate::claim::substrate_facet_id(owner)?
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
                    data: crate::vault::encode_embedded_owner_actor_body()?,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                text_index_trusted,
                ApplyOpsGateMode::new(
                    state.record_gate_decisions,
                    state.persist_gate_pending_consent,
                ),
                origin,
            )?;
        }
        let found = stored_entity_type(store, wtxn, &facet)?;
        if found != Some(crate::registry::ENTITY_TYPE_FACET) {
            return Err(Error::Registry(RegistryError::InvalidFacet {
                facet,
                found,
            }));
        }
        apply_edge_with_created_at(
            store,
            wtxn,
            id,
            crate::edge::EdgeKind::FacetOf,
            facet,
            1.0,
            learned_at,
            crate::affect::Vad::NEUTRAL,
            None,
        )?;
        ppr::invalidate_ppr_for_edge(store, wtxn, &id, &facet)?;
        state.had_graph_mutation = true;
    }
    let preflight_decision_id =
        if entity_type == crate::registry::ENTITY_TYPE_CLAIM && !allow_reserved_predicate {
            state
                .preflight_gate_decision_ids
                .get_mut(&id)
                .and_then(VecDeque::pop_front)
                .flatten()
        } else {
            None
        };
    put_options.consent.can_resolve_pending =
        state.pending_gate_consent_at_batch_start.contains(&id);
    put_options.decision.preflight = preflight_decision_id;
    // A TURN or MESSAGE written again may change its words under a
    // temporal key the sieve has passed: its turn is owed a new
    // sieve read in this commit. A new TURN is owed its first
    // read, whatever time it claims; a MESSAGE joins one through
    // the witness door's re-dirty.
    let text_row = matches!(
        entity_type,
        crate::registry::ENTITY_TYPE_TURN | crate::registry::ENTITY_TYPE_MESSAGE
    );
    let rewritten = text_row && stored_entity_type(store, wtxn, &id)?.is_some();
    let born_turn = entity_type == crate::registry::ENTITY_TYPE_TURN && !rewritten;
    let applied = apply_put(
        store,
        wtxn,
        PutRequest {
            row: PutRow {
                id,
                entity_type,
                occurred,
                learned_at,
                data: &data,
            },
            options: put_options,
            context: PutContext {
                origin,
                write_policy: state.write_policy.as_ref(),
                write_envelope: materialization
                    .as_ref()
                    .and_then(ClaimMaterialization::gate_envelope)
                    .or_else(|| gate_mode.caller_envelopes.get(&id)),
                hub_admission: state.hub_admission.as_ref(),
                refinement_admission: state.refinement_admission.as_ref(),
                transition: transition.as_ref(),
                posture: config.privacy.posture,
                owner_authored: None,
            },
        },
    )?;
    consume_preflight_decisions(store, wtxn, [preflight_decision_id])?;
    if rewritten {
        crate::dreamer_wake::mark_on_publication_in_txn(store, wtxn, &id)?;
    } else if born_turn {
        crate::dreamer_wake::owe_sieve_read_in_txn(store, wtxn, &id)?;
    } else if matches!(
        entity_type,
        crate::registry::ENTITY_TYPE_ACCESS_GRANT | crate::registry::ENTITY_TYPE_POLICY_MANIFEST
    ) {
        // A grant, or a policy manifest's read grant, may let the
        // Dreamer read words the sieve left.
        crate::dreamer_wake::sieve_grant_written_in_txn(store, wtxn)?;
    }
    let revisions = super::project_history::revision_puts(
        store,
        (applied.project_revisions.into_iter())
            .map(|(revision, bytes)| (revision, bytes, occurred, learned_at)),
    )?;
    if !revisions.is_empty() {
        apply_ops_with_origin(
            store,
            config,
            analyzer,
            wtxn,
            revisions,
            text_index_trusted,
            ApplyOpsGateMode::new(
                state.record_gate_decisions,
                state.persist_gate_pending_consent,
            ),
            origin,
        )?;
    }
    state.touched_projects.extend(applied.touched_projects);
    if let Some((source_id, source_bytes)) = applied.portable_agent_source {
        apply_ops_with_origin(
            store,
            config,
            analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: source_id,
                entity_type: crate::registry::ENTITY_TYPE_ASSET,
                occurred,
                learned_at,
                data: source_bytes,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            text_index_trusted,
            ApplyOpsGateMode::new(
                state.record_gate_decisions,
                state.persist_gate_pending_consent,
            )
            .with_birth_mask(state.birth_mask),
            origin,
        )?;
    }
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        let authored = materialization.is_some() && !allow_reserved_predicate;
        claim_materialization::record_committed_claim(store, wtxn, &id, authored)?;
    }
    state
        .evicted_shell_sources
        .extend(applied.evicted_shell_sources);
    #[cfg(feature = "sync")]
    let pending_embedding_priority = if allow_maintenance && allow_reserved_predicate {
        crate::embed::EMBED_PRIORITY_SERVER
    } else {
        crate::embed::EMBED_PRIORITY_DEVICE
    };
    if let Some(token) = applied.pending_embedding_token {
        state.pending_embedding_tokens_written.insert(id, token);
        #[cfg(feature = "sync")]
        state
            .pending_embedding_enqueue_priorities
            .entry(id)
            .and_modify(|priority| {
                *priority = (*priority).min(pending_embedding_priority);
            })
            .or_insert(pending_embedding_priority);
    }
    if applied.cleared_pending_embedding {
        state.pending_embedding_tokens_written.remove(&id);
        #[cfg(feature = "sync")]
        state.pending_embedding_enqueue_priorities.remove(&id);
    }
    state.had_vector_mutation |= applied.had_vector_mutation;
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && !(allow_maintenance && allow_reserved_predicate)
        && !applied.is_lexical_query_hint_claim
    {
        let deleted =
            delete_lexical_query_hint_claims_for_target(store, wtxn, &id, &HashSet::new())?;
        for (deleted_id, neighbors) in &deleted.deleted {
            state.pending_embedding_tokens_written.remove(deleted_id);
            #[cfg(feature = "sync")]
            state
                .pending_embedding_enqueue_priorities
                .remove(deleted_id);
            ppr::invalidate_ppr_for_delete(store, wtxn, deleted_id, neighbors)?;
        }
        state.had_graph_mutation |= deleted.had_graph_mutation;
        state.had_vector_mutation |= deleted.had_vector;
    }
    if let Some((target, query_hint)) = lexical_query_hint_for_replayed_put(
        &id,
        entity_type,
        allow_maintenance && allow_reserved_predicate,
        &data,
    )? {
        let mut text_indexing = LexicalHintTextIndexing {
            analyzer,
            manifest_checked: &mut state.text_manifest_checked,
            trusted: text_index_trusted,
        };
        let materialized = materialize_lexical_query_hint_text_if_target_ready(
            store,
            wtxn,
            &mut text_indexing,
            id,
            &target,
            query_hint,
        )?;
        state.had_graph_mutation |= materialized;
    }
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        let mut text_indexing = LexicalHintTextIndexing {
            analyzer,
            manifest_checked: &mut state.text_manifest_checked,
            trusted: text_index_trusted,
        };
        let materialized =
            materialize_lexical_query_hints_for_target(store, wtxn, &mut text_indexing, &id)?;
        state.had_graph_mutation |= materialized;
    }
    // Type-76 rows are never legal participants/actors. Their
    // dedicated ingest door reconciles after the seq join, so
    // feeding event ids into the generic participant hook would
    // enumerate the append-only family once per appended event.
    if entity_type != crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        state.materialized_entity_ids.insert(id);
    }
    if !(replicated && state.replicated_puts.contains(&id)) {
        state.local_materialized_ids.insert(id);
    }
    Ok(())
}
