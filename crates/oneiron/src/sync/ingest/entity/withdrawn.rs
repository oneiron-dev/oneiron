//! A withdrawn generation at ingest (OF-013, FIX 931).
//!
//! A body of a withdrawn generation or older that is not the content-free
//! form its cutoff names never materializes, while the sweep's `hw:` row
//! waits and after its fence replaces the row, and no such form stands over a
//! newer generation held here. A newer generation materializes as any body
//! does.
//!
//! A keyframe goes on through the ordinary ladder. A Shell, a header with no
//! body, cannot: no TURN decoder reads an empty body. Under a Shell cutoff
//! that covers it, it takes the narrow install here instead. A resident row
//! of the withdrawn generation is withdrawn as the machine that cut it off
//! withdrew it, and keeps its own header; a TURN absent here lands as the
//! carrier's header, with its index rows, marked stale. A bare header that no
//! cutoff covers stays on the ordinary ladder.

use super::{EntityStep, IngestCtx};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::deletion::{WithdrawnCutoff, WithdrawnReplacement};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EntityStoreMaintenance, EntityStoreRead};
use crate::registry::ENTITY_TYPE_TURN;

/// What the withdrawn-generation gate makes of `blob`, a carrier of `id`
/// whose header is `header`: `None` when no cutoff here covers it, or when it
/// is a keyframe the ordinary ladder lands. A failed read fails closed.
pub(super) fn withdrawn_generation_step(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
) -> Result<Option<EntityStep>> {
    let (cutoff, local) = match cutoff_and_row(&ctx.vault.store, wtxn, id) {
        Ok(Some(read)) => read,
        Ok(None) => return Ok(None),
        Err(err) => {
            tracing::warn!(
                entity = %id.to_hex(),
                error = %err,
                "sync ingest: withdrawn generation read failed, failing closed"
            );
            return Ok(Some(EntityStep::Skip));
        }
    };
    if header.learned_at > cutoff.generation {
        return Ok(None);
    }
    let data = &blob[ENTITY_METADATA_HEADER_LEN..];
    let word_free = match cutoff.replacement {
        WithdrawnReplacement::EpochKeyframe => crate::compaction::is_withdrawn_keyframe(data),
        WithdrawnReplacement::Shell => data.is_empty(),
    };
    let newer_here = local
        .as_deref()
        .and_then(EntityMetadataHeader::parse)
        .is_some_and(|local| local.learned_at > header.learned_at);
    if !word_free || newer_here {
        tracing::warn!(
            entity = %id.to_hex(),
            "sync ingest: body of a withdrawn generation, refusing materialization"
        );
        return Ok(Some(EntityStep::Skip));
    }
    match cutoff.replacement {
        WithdrawnReplacement::EpochKeyframe => Ok(None),
        WithdrawnReplacement::Shell => {
            install_shell(ctx, wtxn, id, header, blob, cutoff, local.is_some()).map(Some)
        }
    }
}

/// `id`'s withdrawn-generation cutoff here and its stored row; `None`
/// without a cutoff.
fn cutoff_and_row(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(WithdrawnCutoff, Option<Vec<u8>>)>> {
    let Some(cutoff) = crate::deletion::withdrawn_generation_cutoff_in_txn(store, txn, id)? else {
        return Ok(None);
    };
    Ok(Some((cutoff, store.port_entity_raw(txn, id)?)))
}

/// Lands Shell carrier `blob` of `id`, which `cutoff` covers. A resident row
/// that still holds the words of a generation `cutoff` withdrew is withdrawn
/// as the machine that cut it off withdrew it, its header kept; a row
/// already a Shell, or holding no such words, stays. A TURN absent here lands
/// as the carrier's header with its index rows and is marked stale; any
/// other kind absent here, or a header whose times run backward, stays out.
/// No step here is a replicated content write.
fn install_shell(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
    cutoff: WithdrawnCutoff,
    resident: bool,
) -> Result<EntityStep> {
    let store = &ctx.vault.store;
    if resident {
        if crate::deletion::withdraw_received_record_in_txn(store, wtxn, id, cutoff.generation)? {
            tracing::info!(
                entity = %id.to_hex(),
                "sync ingest: a Shell carrier withdrew the resident words of its generation"
            );
        }
        return Ok(EntityStep::Skip);
    }
    if header.entity_type != ENTITY_TYPE_TURN || header.occurred_start > header.occurred_end {
        return Ok(EntityStep::Skip);
    }
    store.port_retained_shell_restore(wtxn, id, blob)?;
    crate::batch::stage_entity_index_rows(
        store,
        wtxn,
        id,
        header.entity_type,
        crate::temporal::TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    )?;
    crate::ports::mark_received_withdrawn_in_txn(store, wtxn, id)?;
    Ok(EntityStep::Skip)
}
