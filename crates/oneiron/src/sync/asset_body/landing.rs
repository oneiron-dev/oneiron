//! A received by-reference body lands (FIX 5489): its carrier takes the
//! window's own ingest ladder again, with the body staged, in one writer.
//!
//! The body is staged from its spool in the writer that commits it, with
//! the values custody holds as that writer reads them, as the staged blob
//! door stages; no writer waits on the network. The writer first reads the
//! window's live document again: a carrier a later write replaced, or a
//! reference it no longer binds, is not landed. The ladder then judges the
//! carrier as it judges any (tombstones, delete markers, residence, a
//! release fence, the echo), and lands the row through the replicated
//! door, at the tier the transfer's lane lands it at (FIX 12118). The rows it
//! writes are the window's own: the live mirror never rewrites the carrier
//! with them. A landed row wakes what waits on it and notifies the live
//! queries as Observer B's ingest does (FIX 5489).

use super::references::{AssetBodyRef, bound_in};
use super::session::AssetBodyPeer;
use crate::conversation_dag::topology::Dependency;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{AssetBodySpool, StagedAssetBody};
use crate::sync::bridge::{
    MaterializedDiffSummary, Materializer, OriginMark, RevisionEvent, wake_parent_retry_in_txn,
};
use crate::sync::ingest::{
    EntityStep, IngestCtx, Residence, ingest_rows_in_savepoint, note_born, note_delivered_in_txn,
    watches,
};
use crate::sync::loro_support::{TombstoneIndex, map_get_bytes};
use crate::sync::types::WindowKey;
use crate::vault::entity_revision::revision_for_mode_in_txn;
use crate::vault::{EntityRevisionChange, ReadMode};

/// Lands `spool`, every byte of the body `body` names, as the row of its
/// carrier in `window`. `false` when the carrier was not landed: the window
/// no longer binds this exact pair, or the ladder left it unwritten.
///
/// # Errors
///
/// A body whose measured facts are not the reference's, and the ladder's
/// local failures.
pub(super) fn land(
    peer: &AssetBodyPeer<'_>,
    window: &WindowKey,
    body: &AssetBodyRef,
    spool: AssetBodySpool,
) -> Result<bool> {
    let Some(doc) = (peer.window)(window) else {
        return Ok(false);
    };
    let vault = peer.vault;
    let key = body.key();
    let _import = crate::sync::manager::import_scope();
    let mut unborn = false;
    // The staged body outlives the commit: its pin keeps a published file
    // from the collector until the row naming it is durable.
    let (landed, carrier, _staged, change) = vault.with_write_txn_grouped(|wtxn| {
        let Some(carrier) = map_get_bytes(&doc.get_map("entities"), &key) else {
            return Ok((false, Vec::new(), None::<StagedAssetBody>, None));
        };
        if bound_in(&doc, &body.id, &carrier).as_ref() != Some(body) {
            return Ok((false, carrier, None, None));
        }
        unborn = watches(vault, &body.id)
            && !crate::ports::EntityStoreRead::port_entity_present(&vault.store, wtxn, &body.id)?;
        let previous_revision =
            revision_for_mode_in_txn(&vault.store, wtxn, &body.id, ReadMode::Live)?;
        let known = vault.asset_stream_known_in_txn(wtxn)?;
        let staged = spool.stage(vault, body.mime.as_deref(), known)?;
        let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
        let steps = {
            let lease_vault_id = peer.materializer.lease_vault_id();
            let ingest = IngestCtx::new(vault, window.as_str(), lease_vault_id, &tombstones)
                .with_residence(Residence::Quarantine(&doc))
                .with_asset_body(body.id, &staged, peer.lane.landing_tier());
            ingest_rows_in_savepoint(&ingest, wtxn, &[(key.as_str(), Some(&carrier[..]))])?
        };
        let landed = steps.first().and_then(EntityStep::written) == Some(body.id);
        let mut change = None;
        if landed {
            note_delivered_in_txn(vault, wtxn, body.id, &carrier)?;
            let revision = revision_for_mode_in_txn(&vault.store, wtxn, &body.id, ReadMode::Live)?;
            if previous_revision != revision {
                change = Some(EntityRevisionChange {
                    entity: body.id,
                    previous_revision,
                    revision,
                    indexed_revision: revision_for_mode_in_txn(
                        &vault.store,
                        wtxn,
                        &body.id,
                        ReadMode::Indexed,
                    )?,
                });
            }
            // A child, anchor or Parent deferred on this row wakes now.
            wake_parent_retry_in_txn(vault, wtxn, &[Dependency::Entity(body.id)])?;
        }
        Ok((landed, carrier, Some(staged), change))
    })?;
    if landed && unborn {
        note_born(vault, body.id, &carrier);
    }
    if landed {
        notify_landed(peer.materializer, window, body.id, &key, &carrier, change);
    }
    Ok(landed)
}

/// Tells the live queries the row `key` of `window`'s entities landed as
/// `carrier`, with its revision `change`, as Observer B tells them of a row
/// its import lands: committed, from no connection's import.
fn notify_landed(
    materializer: &Materializer,
    window: &WindowKey,
    id: EntityId,
    key: &str,
    carrier: &[u8],
    change: Option<EntityRevisionChange>,
) {
    let path = format!("w:{}/entities", window.as_str());
    let diff = MaterializedDiffSummary {
        containers: vec![format!("e:{}", id.to_hex()), format!("{path}/{key}")],
        bytes: key.len().saturating_add(carrier.len()),
        revision_events: change.into_iter().map(RevisionEvent::Original).collect(),
    };
    materializer.notify_live_queries(&path, &diff, &OriginMark::default());
}
