//! Whether an arriving body may stand in the window it replays into: one
//! whose world or month is not the window's is not admitted by it, and a
//! BASE row the owner's discard took as a departed world's alone stays out
//! while it is still that world's and the owner keeps the world on another
//! machine (FIX 14534).

use super::{EntityStep, IngestCtx, Residence, refuse};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_NOTE;

/// A body whose world or month is not its window's is not admitted by that window, except a
/// retained world shell the window still holds.
pub(super) fn check_residence(
    ctx: &IngestCtx<'_>,
    wtxn: &heed::RwTxn<'_>,
    id: EntityId,
    blob: &[u8],
) -> Result<Option<EntityStep>> {
    let Some(residence) = ctx.residence else {
        return Ok(None);
    };
    let Some(window) = crate::sync::types::WindowKey::try_new(ctx.window_key) else {
        return Ok(None);
    };
    if crate::sync::types::entity_belongs_to_window(blob, &window) {
        return Ok(None);
    }
    let outside = || Error::InvalidConfig("entity outside window residence".into());
    match residence {
        Residence::Quarantine(doc) => {
            if window.world().is_some()
                && crate::sync::types::retained_world_shell_belongs_to_window(
                    ctx.vault,
                    wtxn,
                    doc,
                    ctx.tombstones,
                    &id,
                    blob,
                    &window,
                    false,
                )?
            {
                return Ok(None);
            }
            Ok(Some(refuse(Some(id), outside())))
        }
        Residence::Forward { doc, trusted } => {
            if crate::sync::types::retained_world_shell_belongs_to_window(
                ctx.vault,
                wtxn,
                doc,
                ctx.tombstones,
                &id,
                blob,
                &window,
                trusted,
            )? {
                // The dedicated shell restorer runs after this pass.
                return Ok(Some(EntityStep::Skip));
            }
            Err(outside())
        }
    }
}

/// Leaves out a BASE row the owner's discard took as `world`'s alone
/// (Engine 11-06 08:34 call 1 = A) while the arriving body is still that
/// world's alone and this install's fold keeps the world on one other
/// machine. The discard's mark is only the cue: a NOTE is judged by the
/// `InWorld` edges its carrier gives it, any other row by its stamp
/// (`record_world_in` over the arriving body), and a row no longer the
/// world's alone, or a world this install holds again, comes back, its mark
/// forgotten. A NOTE no document comes with waits for one.
pub(super) fn check_discarded(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
) -> Result<Option<EntityStep>> {
    let vault = ctx.vault;
    let Some(world) = crate::sync::residence::discarded_world_in(&vault.store, wtxn, id)? else {
        return Ok(None);
    };
    let placed = match crate::identity::read_machine_id_in_txn(vault, wtxn)? {
        Some(me) => {
            let fold = vault.authority_view_readonly_in_txn(wtxn)?;
            crate::sync::residence::world_placed_elsewhere_in(&fold, me, world)
        }
        None => false,
    };
    let alone = if header.entity_type == ENTITY_TYPE_NOTE {
        // The window's carrier, or the document an edge's endpoint hydration
        // reads its body from.
        match ctx.carrier_doc().or(ctx.body_refs) {
            Some(doc) => carried_worlds(doc, id) == [world],
            None => placed,
        }
    } else {
        let body = blob.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        crate::federation::record_scope::record_world_in(
            &vault.store,
            wtxn,
            id,
            header.entity_type,
            body,
        )? == Some(Some(world))
    };
    if placed && alone {
        return Ok(Some(EntityStep::Skip));
    }
    crate::sync::residence::forget_discarded_in_txn(&vault.store, wtxn, id)?;
    Ok(None)
}

/// The worlds the `InWorld` edges `doc` carries for the NOTE `id` name, in
/// order. An edge whose value is not an `InWorld` edge value's bytes in that
/// kind's layout is one the edge pass refuses (`decode_edge_value_for_kind`),
/// and names no world.
fn carried_worlds(doc: &loro::LoroDoc, id: EntityId) -> Vec<EntityId> {
    let mut worlds = std::collections::BTreeSet::new();
    crate::sync::loro_support::map_for_each_value_bytes(&doc.get_map("edges"), |key, value| {
        if let Some((source, EdgeKind::InWorld, target)) = crate::sync::bridge::parse_edge_key(key)
            && source == id
            && value.is_some_and(|value| {
                crate::edge::decode_edge_value_for_kind(EdgeKind::InWorld, value).is_ok()
            })
        {
            worlds.insert(target);
        }
    });
    worlds.into_iter().collect()
}
