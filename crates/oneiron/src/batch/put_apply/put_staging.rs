//! Body/index/edge row staging helpers shared by the put and update paths.

use heed::RwTxn;

use super::{ENTITY_METADATA_HEADER_LEN, LONG_INTERVAL_THRESHOLD_SECS};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::StagedRow;
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;

/// Stages the ONE-1449 MATERIAL-6 R1 optimizer-birth marker row, if this put
/// produced one, in the caller's transaction and immediately before the body
/// row it marks. `None` writes nothing.
///
/// # Errors
///
/// The `vault_meta` write's own error, propagated before the body write.
pub(super) fn stage_optimizer_birth_marker_row(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    optimizer_birth_marker: Option<StagedRow>,
) -> Result<()> {
    if let Some(row) = optimizer_birth_marker {
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
    store.entities().put(wtxn, id.as_bytes(), &payload)?;
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
    let key_out = Store::encode_edge_key(src, kind, tgt);
    let key_in = Store::encode_edge_key(tgt, kind, src);
    store.edges_out().put(wtxn, &key_out, value)?;
    store.edges_in().put(wtxn, &key_in, value)?;
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

/// Validate typed storage carriers before any put effect is staged.
pub(super) fn validate_domain_carriers(
    store: &Store,
    txn: &RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_TASK {
        crate::task_verb::guard_ask_fact_put(store, txn, id, data)?;
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
    entity_type: u8,
    data: &[u8],
    origin: super::BaseWriteOrigin<'_>,
) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_FACET {
        super::super::facet_identity::validate_facet_overwrite(store, wtxn, id, data)?;
    }
    if crate::workspace_roster::is_project_type(store, entity_type) {
        for referenced in crate::workspace_roster::validate_project_body(id, data)? {
            super::reject_overlay_member_base_write(store, &referenced, origin)?;
        }
    }
    if entity_type == crate::registry::ENTITY_TYPE_CONVERSATION {
        crate::workspace_roster::validate_room_body(store, wtxn, id, data)?;
    }
    Ok(())
}
