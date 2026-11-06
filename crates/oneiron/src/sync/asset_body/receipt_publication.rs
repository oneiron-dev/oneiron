//! Commit-bound canonical receipt carriers for native body landings.

use loro::{CommitOptions, LoroDoc};

use super::references::{AssetBodyRef, bound_in};
use super::session::AssetBodyPeer;
use crate::error::Result;
use crate::store::StagedAssetBody;
use crate::sync::bridge::BRIDGE_ORIGIN;
use crate::sync::loro_support::{export_updates_from, map_delete, map_insert_bytes};
use crate::sync::schema::ASSET_BODY_REFS_MAP;
use crate::sync::types::WindowKey;

/// A detached update already journaled with the row it represents. Only the
/// successful landing writer constructs one; publishing never opens a writer.
pub(super) struct ReceiptPublication {
    doc: LoroDoc,
    window: WindowKey,
    update: Vec<u8>,
}

impl ReceiptPublication {
    pub(super) fn prepare_in_txn(
        peer: &AssetBodyPeer<'_>,
        txn: &mut heed::RwTxn<'_>,
        doc: &LoroDoc,
        candidate: &LoroDoc,
        window: &WindowKey,
        body: &AssetBodyRef,
        carrier: &[u8],
        staged: &StagedAssetBody,
    ) -> Result<Option<Self>> {
        let Some(raw) =
            crate::receipt::receipt_archive_mirror_row_from_staged(&body.id, carrier, staged)?
        else {
            return Ok(None);
        };
        let key = body.key();
        if crate::sync::loro_support::map_get_bytes(&candidate.get_map("entities"), &key).as_deref()
            != Some(carrier)
            || bound_in(&candidate, &body.id, carrier).as_ref() != Some(body)
        {
            return Ok(None);
        }
        // Passive native oplog read: no live barrier or implicit commit.
        // Concurrent unrelated edits merge normally; no whole-VV equality gate.
        let before = doc.oplog_vv();
        map_insert_bytes(&candidate.get_map("entities"), &key, &raw)?;
        map_delete(&candidate.get_map(ASSET_BODY_REFS_MAP), &key)?;
        candidate.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
        let update = export_updates_from(candidate, &before)?;
        crate::sync::bridge::persist_window_update_in_txn(
            peer.vault,
            txn,
            window.as_str(),
            &update,
        )?;
        crate::sync::queue::push_update_in_txn(peer.vault, txn, window.as_str(), &update)?;
        Ok(Some(Self {
            doc: doc.clone(),
            window: window.clone(),
            update,
        }))
    }

    /// Called after commit and the socket's ORIGINAL LocalBodyLand handling.
    /// Import failures leave the native durable journal and queue available
    /// for replay; they never turn a committed body into a negative Receipt.
    pub(super) fn publish(self, peer: &AssetBodyPeer<'_>) {
        match self.doc.import_with(&self.update, BRIDGE_ORIGIN) {
            Ok(status) if status.pending.is_none() => {
                if let Some((_, _, manager)) = peer.vault.live_window(&self.window) {
                    manager
                        .outbound()
                        .route_live(self.window.as_str(), &self.update);
                }
            }
            Ok(_) => tracing::warn!(window = %self.window.as_str(),
                "journaled receipt carrier awaits native window dependencies"),
            Err(error) => tracing::warn!(window = %self.window.as_str(), %error,
                "journaled receipt carrier did not enter the live window"),
        }
    }
}
