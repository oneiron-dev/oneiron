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
//! door. The rows it writes are the window's own: the live mirror never
//! rewrites the carrier with them.

use super::references::{AssetBodyRef, bound_in};
use super::session::AssetBodyPeer;
use crate::error::Result;
use crate::store::{AssetBodySpool, StagedAssetBody};
use crate::sync::ingest::{
    EntityStep, IngestCtx, Residence, ingest_rows_in_savepoint, note_born, note_delivered_in_txn,
    watches,
};
use crate::sync::loro_support::{TombstoneIndex, map_get_bytes};
use crate::sync::types::WindowKey;

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
    let (landed, carrier, _staged) = vault.with_write_txn_grouped(|wtxn| {
        let Some(carrier) = map_get_bytes(&doc.get_map("entities"), &key) else {
            return Ok((false, Vec::new(), None::<StagedAssetBody>));
        };
        if bound_in(&doc, &body.id, &carrier).as_ref() != Some(body) {
            return Ok((false, carrier, None));
        }
        unborn = watches(vault, &body.id)
            && !crate::ports::EntityStoreRead::port_entity_present(&vault.store, wtxn, &body.id)?;
        let known = vault.asset_stream_known_in_txn(wtxn)?;
        let staged = spool.stage(vault, body.mime.as_deref(), known)?;
        let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
        let steps = {
            let ingest = IngestCtx::new(vault, window.as_str(), peer.lease_vault_id, &tombstones)
                .with_residence(Residence::Quarantine(&doc))
                .with_asset_body(body.id, &staged);
            ingest_rows_in_savepoint(&ingest, wtxn, &[(key.as_str(), Some(&carrier[..]))])?
        };
        let landed = steps.first().and_then(EntityStep::written) == Some(body.id);
        if landed {
            note_delivered_in_txn(vault, wtxn, body.id, &carrier)?;
        }
        Ok((landed, carrier, Some(staged)))
    })?;
    if landed && unborn {
        note_born(vault, body.id, &carrier);
    }
    Ok(landed)
}
