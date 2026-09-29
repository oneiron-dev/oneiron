//! Body/index/edge row staging helpers shared by the put and update paths.

use heed::RwTxn;

use super::{ENTITY_METADATA_HEADER_LEN, LONG_INTERVAL_THRESHOLD_SECS};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeStoreStaging, EntityStoreStaging};
use crate::side_table::StagedRow;
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;

/// Stages an optional typed optimizer-birth or hub-origin row at the put's
/// established transaction point. `None` writes nothing.
///
/// # Errors
///
/// The `vault_meta` write's own error, propagated before the body write.
pub(super) fn stage_optional_side_row(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    row: Option<StagedRow>,
) -> Result<()> {
    if let Some(row) = row {
        row.put(store, wtxn)?;
    }
    Ok(())
}

/// Stages one entity's body row: the ARCH-0019 metadata header followed by the
/// caller's body bytes (ONE-1728 K11).
///
/// Target-parameterized, so a session witness writes the SAME header layout
/// into the overlay that base writes durably — promote replays the row without
/// re-encoding it.
pub(in crate::batch) fn stage_entity_body_row(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_NOTE && !data.is_empty() {
        crate::note::validate_registered_kind(store, wtxn, data)?;
    }
    crate::ingest::reindex_identity_hints(store, wtxn, id, Some((entity_type, data)))?;
    crate::ports::reindex_named_entities(store, wtxn, id, Some((entity_type, data)))?;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(entity_type);
    payload.extend_from_slice(&occurred.start.to_be_bytes());
    payload.extend_from_slice(&occurred.end.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(data);
    crate::vault::entity_revision::capture_entity_revision(store, wtxn, id, &payload)?;
    store.port_stage_entity_row(wtxn, id, &payload)?;
    crate::conversation_dag::pin_typed_record(store, wtxn, id, entity_type, data)?;
    Ok(())
}

/// Stages the type and temporal index rows every materialized entity carries
/// (ONE-1728 K11). Target-parameterized alongside [`stage_entity_body_row`]:
/// the session's type/temporal readers compose over these overlay rows, so an
/// in-room enumeration or time-range walk sees the turn it just witnessed.
///
/// `occurred`/`learned_at` are the WITNESSING write's own stamps — never
/// restamped here — so a promoted row lands in the month window it belongs to
/// (ARCH-0052 D4).
pub(crate) fn stage_entity_index_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let type_key = Store::encode_type_key(entity_type, id);
    store.type_index().put(wtxn, &type_key, &[])?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    store
        .temporal_occurred_start()
        .put(wtxn, &occurred_start_key, &[])?;

    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_occurred_end()
            .put(wtxn, &occurred_end_key, &[])?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned().put(wtxn, &learned_key, &[])?;

    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, id);
        let occurred_start_value = occurred.start.to_be_bytes();
        store
            .temporal_long_intervals()
            .put(wtxn, &long_interval_key, &occurred_start_value)?;
    }
    Ok(())
}

/// Removes exactly the rows [`stage_entity_index_rows`] stages, for a caller
/// holding that write's own `occurred`/`learned_at` stamps.
///
/// PAIRED with the staging writer and reading the same stamps back, so the two
/// cannot drift: every conditional key a put can own — the occurred-end and
/// long-interval siblings — is decided here by the same predicate over the same
/// range. A caller that removed an entity row and left these behind would leave
/// every time-range walk answering with a dead id, and a rebuild under a new
/// stamp would ADD a key rather than move one, letting repeated drop/rebuild
/// cycles crowd a candidate buffer with one id's stale timestamps.
pub(crate) fn delete_entity_index_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let type_key = Store::encode_type_key(entity_type, id);
    store.type_index().delete(wtxn, &type_key)?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    store
        .temporal_occurred_start()
        .delete(wtxn, &occurred_start_key)?;

    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_occurred_end()
            .delete(wtxn, &occurred_end_key)?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned().delete(wtxn, &learned_key)?;

    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_long_intervals()
            .delete(wtxn, &long_interval_key)?;
    }
    Ok(())
}

/// Stages one edge's paired `edges_out`/`edges_in` rows (ONE-1728 K11).
///
/// PAIRED-WRITE INVARIANT: both directions carry byte-identical value bytes.
/// Extracted from [`apply_edge_with_created_at`] so the session path cannot
/// drift from it — a caller that wrote only one direction would leave the
/// overlay's edge readers asymmetric and promote a half-edge.
pub(in crate::batch) fn stage_edge_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    value: &[u8],
) -> Result<()> {
    let weight = crate::edge::decode_edge_value_for_kind(kind, value)?.weight;
    crate::workspace_roster::validate_project_edge_put(store, wtxn, *src, kind, *tgt, weight)?;
    store.port_stage_edge_rows(wtxn, src, kind, tgt, value)?;
    crate::conversation_dag::pin_membership(store, wtxn, src, kind, tgt)?;
    if kind == EdgeKind::DerivedFrom {
        crate::ports::record_derived_edge_in_txn(store, wtxn, src, tgt)?;
    }
    Ok(())
}

/// Maintains content-hash and source-message indexes beside the admitted SKILL body.
pub(super) fn stage_skill_index_rows(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    previous: Option<&crate::skill::SkillRecord>,
    record: &crate::skill::SkillRecord,
) -> Result<()> {
    crate::skill_hub::maintain_skill_content_hash_index_for_put(
        store,
        wtxn,
        id,
        previous.and_then(|previous| previous.content_hash),
        record.content_hash,
    )?;
    // All put doors share this reverse index, including hub import and sync replay.
    crate::skill_convert::maintain_skill_source_index_for_put(store, wtxn, id, previous, record)
}

/// Keeps CLAIM-derived thread and Dreamer indexes on every put/replay door.
pub(super) fn stage_claim_projection_indexes(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    body: &crate::claim::ClaimBody,
    learned_at: u64,
) -> Result<()> {
    if crate::thread_passport::is_thread_claim_predicate(&body.predicate) {
        super::index_thread_claim_subject(store, wtxn, id, body, learned_at)?;
    }
    crate::dreamer_runner::index_dreamer_milestone_claim_for_put(
        store, wtxn, id, body, learned_at,
    )?;
    crate::llm::index_dreamer_step_claim_for_put(store, wtxn, id, body, learned_at)
}

/// The caller's write stamps and origin for the three carrier guards.
pub(super) struct PutCarrierContext<'a> {
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    replicated: bool,
    origin: super::BaseWriteOrigin<'a>,
    posture: crate::HostingPrivacyPosture,
}

impl<'a> PutCarrierContext<'a> {
    pub(super) fn new(
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        replicated: bool,
        origin: super::BaseWriteOrigin<'a>,
        posture: crate::HostingPrivacyPosture,
    ) -> Self {
        Self {
            entity_type,
            occurred,
            learned_at,
            replicated,
            origin,
            posture,
        }
    }
}

/// Normalize a PROJECT body and admit a project-depth policy contribution
/// before the carrier guards read either row.
pub(super) fn stage_project_put(
    store: &Store,
    txn: &RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    data: &[u8],
    replicated: bool,
    posture: crate::HostingPrivacyPosture,
) -> Result<Option<Vec<u8>>> {
    let project = if crate::workspace_roster::is_project_type(store, entity_type) {
        Some(crate::workspace_roster::normalize_project_body(
            store, txn, id, data, posture,
        )?)
    } else {
        None
    };
    let data = project.as_deref().unwrap_or(data);
    if entity_type == crate::registry::ENTITY_TYPE_POLICY_MANIFEST
        && (crate::gate::project_depth::is_project_depth_id(&id)
            || crate::gate::project_depth::is_project_depth_contribution(data))
    {
        crate::gate::project_depth::validate_contribution_put(
            store, txn, id, data, replicated, posture,
        )?;
    }
    Ok(project)
}

/// Run the existing scope, storage-owned, and domain guards in order.
pub(super) fn validate_put_carriers(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
    data: &[u8],
    context: PutCarrierContext<'_>,
) -> Result<()> {
    validate_scope_carriers(store, txn, id, data, &context)?;
    super::connector_key_guard::validate_connector_manifest_put(
        store,
        txn,
        id,
        context.entity_type,
        data,
        context.replicated,
    )?;
    super::owned_body::guard_storage_owned_body(
        store,
        txn,
        &id,
        (context.entity_type, context.occurred, context.learned_at),
        data,
        context.replicated,
    )?;
    validate_domain_carriers(
        store,
        txn,
        id,
        context.entity_type,
        (context.occurred, context.learned_at),
        data,
        context.replicated,
    )
}

/// Validate producer-owned source carriers before any body or index is
/// staged. Preserve their existing write-door order on the same snapshot.
pub(super) fn validate_source_carriers(
    store: &Store,
    txn: &RwTxn<'_>,
    row: (EntityId, u8, &[u8], TimeRange, u64),
) -> Result<()> {
    let (id, entity_type, data, occurred, learned_at) = row;
    crate::skill_hub::pack_catalog::validate_pack_source_put(store, txn, &id, entity_type, data)?;
    crate::skill_hub::validate_hub_source_carrier_put(store, txn, &id, entity_type, data)?;
    crate::skill_hub::validate_refinement_carrier_put(store, txn, &id, entity_type, data)?;
    crate::agent_def::validate_birth_source_put(store, txn, &id, entity_type, data)?;
    crate::receipt::validate_put(store, txn, (&id, entity_type, data), (occurred, learned_at))
}

/// The last put-side embedding changes, after short-id and body indexes land.
pub(super) struct PostPutEmbeddingEffects {
    pub(super) pending_embedding_token: Option<Vec<u8>>,
    pub(super) cleared_pending_embedding: bool,
    pub(super) had_vector_mutation: bool,
}

pub(super) fn stage_post_put_embeddings(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
    is_lexical_query_hint_claim: bool,
    body_changed: bool,
) -> Result<PostPutEmbeddingEffects> {
    let mut cleared_pending_embedding = false;
    let mut had_vector_mutation = false;
    if is_lexical_query_hint_claim {
        cleared_pending_embedding = store.clear_pending_embedding(wtxn, id)?;
        let had_hnsw = store.hnsw_neighbors.get(wtxn, id.as_bytes())?.is_some();
        had_vector_mutation = store.vectors.delete(wtxn, id.as_bytes())? || had_hnsw;
        crate::hnsw::hnsw_deindex(store, wtxn, id)?;
    }
    let pending_embedding_token =
        if entity_type == crate::registry::ENTITY_TYPE_CLAIM && !is_lexical_query_hint_claim {
            // Mint the new invalidation token even while idle publication is
            // pending. The worker skips these revisions; old completions must
            // still observe that their token no longer owns the current body.
            let has_current_pending = store.has_current_pending_embedding_in_txn(wtxn, id)?;
            let has_vector = store.vectors.get(wtxn, id.as_bytes())?.is_some();
            if !body_changed && has_vector && !has_current_pending {
                None
            } else {
                Some(store.mark_pending_embedding(wtxn, id, data)?)
            }
        } else {
            None
        };
    Ok(PostPutEmbeddingEffects {
        pending_embedding_token,
        cleared_pending_embedding,
        had_vector_mutation,
    })
}

/// Validate typed storage carriers before any put effect is staged.
pub(super) fn validate_domain_carriers(
    store: &Store,
    txn: &RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    timestamps: (TimeRange, u64),
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY {
        // Admission is shared by typed writes and replay, before put effects.
        crate::channel_identity::validate_channel_identity_put_carrier(data, replicated)?;
    }
    if entity_type == crate::registry::ENTITY_TYPE_TASK {
        crate::task_verb::guard_ask_fact_put(store, txn, id, timestamps.0, timestamps.1, data)?;
    }
    if entity_type == crate::registry::ENTITY_TYPE_TURN {
        crate::conversation_dag::validate_session_carrier(store, txn, id, data, replicated)?;
    }
    if entity_type == crate::registry::ENTITY_TYPE_EVENT {
        crate::calendar::origin::validate_event_write(store, txn, id, data, replicated)?;
    }
    Ok(())
}

/// Replaces claim projection keys while the previous body is still readable.
/// This must run before staging the replacement entity body, in the same txn.
pub(super) fn stage_claim_projection(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    body: Option<&crate::claim::ClaimBody>,
) -> Result<()> {
    if let Some(body) = body {
        crate::claim::maintain_claim_projection_index(store, wtxn, id, body)?;
        crate::claim::history_store::maintain_machine_history_index(store, wtxn, id, body)?;
    }
    Ok(())
}

/// Retires the prior interval and changed timestamp index entries before a put.
pub(super) fn remove_prior_temporal_index_rows(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    old_occurred: TimeRange,
    old_learned: u64,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    if old_occurred.end.saturating_sub(old_occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let old_long_interval_key = Store::encode_temporal_key(old_occurred.end, id);
        store
            .temporal_long_intervals
            .delete(wtxn, &old_long_interval_key)?;
    }

    if old_occurred.start != occurred.start {
        let old_start_key = Store::encode_temporal_key(old_occurred.start, id);
        store.temporal_occurred_start.delete(wtxn, &old_start_key)?;
    }

    let old_is_range = old_occurred.start != old_occurred.end;
    let new_is_range = occurred.start != occurred.end;
    if old_is_range && (!new_is_range || old_occurred.end != occurred.end) {
        let old_end_key = Store::encode_temporal_key(old_occurred.end, id);
        store.temporal_occurred_end.delete(wtxn, &old_end_key)?;
    }

    if old_learned != learned_at {
        let old_learned_key = Store::encode_temporal_key(old_learned, id);
        store.temporal_learned.delete(wtxn, &old_learned_key)?;
    }
    Ok(())
}

pub(super) fn validate_scope_carriers(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    data: &[u8],
    context: &PutCarrierContext<'_>,
) -> Result<()> {
    let entity_type = context.entity_type;
    if entity_type == crate::registry::ENTITY_TYPE_FACET {
        super::super::facet_identity::validate_facet_overwrite(store, wtxn, id, data)?;
    }
    if crate::workspace_roster::is_project_type(store, entity_type) {
        for referenced in crate::workspace_roster::validate_project_body(id, data)? {
            super::reject_overlay_member_base_write(store, &referenced, context.origin)?;
        }
        // Live writes prove the signed leader or board authority at the door.
        // Replay stops at structure (ARCH-0040 ONE-AUTHLOG-F2): its authority
        // is judged by the project read fold, which quarantines, never refuses.
        if !context.replicated {
            crate::workspace_roster::validate_project_transition(
                store,
                wtxn,
                id,
                entity_type,
                data,
                context.posture,
            )?;
        }
    }
    if entity_type == crate::registry::ENTITY_TYPE_CONVERSATION {
        crate::workspace_roster::validate_room_body(store, wtxn, id, data)?;
    }
    Ok(())
}

/// The local Proposed-submission observation. Replay and envelope-less puts
/// cannot attribute a proposal to an actor; retries are counted only on change.
pub(super) struct ProposedClaimObservation<'a> {
    pub(super) id: EntityId,
    pub(super) replicated: bool,
    pub(super) body: Option<&'a crate::claim::ClaimBody>,
    pub(super) envelope: Option<&'a crate::write_envelope::WriteEnvelope>,
    pub(super) policy: Option<&'a crate::gate::PolicyManifestResolution>,
    pub(super) body_changed: bool,
}

pub(super) fn stage_local_proposal_observation(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    observation: ProposedClaimObservation<'_>,
) -> Result<()> {
    let ProposedClaimObservation {
        id,
        replicated,
        body,
        envelope,
        policy,
        body_changed,
    } = observation;
    if !replicated
        && let Some(body) =
            body.filter(|body| body.approval == crate::claim::ClaimApprovalStatus::Proposed)
        && let Some(envelope) = envelope
    {
        // The stored claim's scope, never a caller-selected policy position.
        let scope = crate::gate::policy_values::PolicyEvaluationScope {
            world: Some(body.world.unwrap_or_else(crate::claim::base_world_id)),
            project: Some(body.scope_project),
            ..Default::default()
        };
        let policy_source = match policy {
            Some(policy) => policy.proposal_check_threshold_source(&scope),
            None => crate::gate::resolve_policy_manifest(store, &*wtxn)?
                .proposal_check_threshold_source(&scope),
        };
        crate::gate::proposal_observation::observe_submission_in_txn(
            store,
            wtxn,
            envelope.actor().entity_ref(),
            &format!("claim:{}", id.to_hex()),
            policy_source,
            body_changed,
        )?;
    }
    Ok(())
}

/// Maintain task ownership and turn carrier rows alongside the entity body.
pub(super) fn stage_task_and_turn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    data: &[u8],
    body_changed: bool,
) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_TASK {
        crate::task_verb::index_owner_fact(store, wtxn, &id, Some(data))?;
        if body_changed {
            crate::task_verb::note_task_write(store, wtxn, id, data)?;
        }
    }
    if entity_type == crate::registry::ENTITY_TYPE_TURN {
        crate::conversation_dag::stage_session_carrier(store, wtxn, id, data)?;
        crate::conversation_dag::invalidate_thread_meta_for_turn_put(store, wtxn, id)?;
    }
    Ok(())
}
