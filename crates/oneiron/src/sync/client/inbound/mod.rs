//! Inbound wire dispatch, window-update import, and bulk history transfer.

use loro::VersionVector;

use super::base::{SyncClient, load_root_doc};
use super::types::SyncResidenceMode;
use crate::sync::SyncEvent;
use crate::sync::transport;
use crate::sync::transport::{
    LEASE_STATUS_GRANTED, MAX_DECODED_PAYLOAD_BYTES, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE,
    TAG_EPHEMERAL, TAG_LEASE_GRANTED, TAG_SYNC_UPDATE, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC,
    TransportError,
};
use crate::sync::types::WindowKey;

mod bulk;
mod window_sync;

impl SyncClient {
    /// Handles an incoming wire message from the server.
    pub fn handle_server_message(
        &mut self,
        data: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        if data.is_empty() {
            return Err(TransportError::InvalidPayload("empty message"));
        }

        let tag = data[0];
        if self.config.federation_peer.is_some()
            && matches!(tag, TAG_BULK_TRANSFER | TAG_BULK_TRANSFER_DONE)
        {
            return Err(TransportError::InvalidPayload(
                "full-window bulk transfer on federation lane",
            ));
        }
        let payload = &data[1..];
        let mut responses = Vec::new();

        match tag {
            transport::TAG_LFS_CHUNK_SYNC => {
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                responses.extend(self.handle_lfs_chunk_reply(payload)?);
            }
            transport::TAG_RPC if self.config.note_session.is_some() => {
                super::note_session::accept_bind_reply(payload)?;
                self.note_session_bound = true;
            }
            transport::TAG_ASSET_BODY_WANT..=transport::TAG_ASSET_BODY_RECEIPT => {
                responses.extend(self.handle_asset_body_frame(tag, payload)?);
            }
            transport::TAG_LEAF_KEY_REQUEST..=transport::TAG_LEAF_KEY_FAILURE => {
                responses.extend(self.handle_leaf_key_frame(tag, payload)?);
            }
            transport::TAG_DOCUMENT => {
                responses.extend(self.handle_document_frame(transport::decode_document(payload)?)?);
            }
            transport::TAG_BATCH => {
                for frame in transport::decode_document_batch(payload)? {
                    responses.extend(self.handle_document_frame(frame)?);
                }
            }
            TAG_SYNC_UPDATE => {
                // Root doc update/snapshot from server — cap before import so a
                // hostile/buggy server cannot force an unbounded allocation.
                // Reuses the bulk-transfer 8 MB cap (ONE-1127).
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                // Import, then persist so the imported state survives
                // restart (d:root).
                let frontiers_before = self.root_doc.state_frontiers();
                self.root_doc
                    .import(payload)
                    .map_err(|_| TransportError::InvalidPayload("root doc import failed"))?;
                // A federation peer's root names its windows for this lane to
                // follow; it is not this vault's root, so none of it reaches
                // the owner's d:root or lease mirror (OF-149).
                let persisted = if self.config.federation_peer.is_some() {
                    Ok(())
                } else {
                    self.persist_root_state()
                };
                if let Err(err) = persisted {
                    if let Err(revert_err) = self.root_doc.revert_to(&frontiers_before) {
                        return Err(TransportError::Storage(format!(
                            "persist root doc: {err}; root revert after import persist failure: {revert_err}"
                        )));
                    }
                    let restored = load_root_doc(&self.vault).map_err(|reload_err| {
                        TransportError::Storage(format!(
                            "persist root doc: {err}; reload root doc after persist failure: {reload_err}"
                        ))
                    })?;
                    restored.set_peer_id(self.client_id).map_err(|peer_err| {
                        TransportError::Storage(format!(
                            "persist root doc: {err}; restore root peer id after persist failure: {peer_err}"
                        ))
                    })?;
                    self.root_doc = restored;
                    return Err(TransportError::Storage(format!("persist root doc: {err}")));
                }
                responses.extend(self.newly_followed_window_requests()?);
            }
            TAG_EPHEMERAL => {
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                self.ephemeral_store
                    .apply(payload)
                    .map_err(|_| TransportError::InvalidPayload("ephemeral import failed"))?;
            }
            TAG_LEASE_GRANTED => {
                // ONE-1140 (OD-5): the server's ack for this connect's lease
                // request. Exhaustive frame validation; a frame echoing a
                // DIFFERENT client id is a protocol violation (the server
                // direct-replies to the requester), fail closed.
                let (status, client_id, expires_at) = transport::decode_lease_granted(payload)?;
                if client_id != self.client_id {
                    return Err(TransportError::InvalidPayload(
                        "LeaseGranted echoes a foreign client id",
                    ));
                }
                if status == LEASE_STATUS_GRANTED {
                    tracing::debug!(
                        client_id = format!("{client_id:016x}"),
                        expires_at,
                        "sync: lease granted/renewed"
                    );
                } else {
                    // Rejection is surfaced as a typed event and sync
                    // PROCEEDS: fail-closed lives at the replay doors
                    // (peers quarantine this device's NEW receipts), not
                    // the pipe.
                    tracing::warn!(
                        client_id = format!("{client_id:016x}"),
                        "sync: lease request REJECTED (binding conflict or revoked)"
                    );
                    let _ = self.event_tx.send(SyncEvent::LeaseDenied { client_id });
                }
            }
            TAG_VERSION_VECTOR => {
                // Server's root VV. Root is server-authoritative, so there is
                // nothing to send back — but the payload must still be valid
                // Loro binary VV bytes. Malformed VV → typed error, fail-closed.
                VersionVector::decode(payload).map_err(|_| TransportError::VersionVectorDecode)?;
            }
            TAG_WINDOW_SYNC => {
                let (window_key, sub_tag, inner) = transport::decode_window_sync(payload)?;
                responses.extend(self.handle_window_sync(window_key, sub_tag, inner)?);
            }
            TAG_BULK_TRANSFER => {
                if self.config.residence_mode == SyncResidenceMode::Opened {
                    return Err(TransportError::InvalidPayload(
                        "full-window bulk transfer on opened-item lane",
                    ));
                }
                let (window_key, compressed) = transport::decode_bulk_transfer(payload)?;
                let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
                if !Self::follows_window(&key, &self.effective_worlds()?) {
                    return Err(TransportError::InvalidPayload("unfollowed world window"));
                }
                self.handle_bulk_transfer(window_key, compressed)?;
            }
            TAG_BULK_TRANSFER_DONE => {
                if self.config.residence_mode == SyncResidenceMode::Opened {
                    return Err(TransportError::InvalidPayload(
                        "full-window bulk transfer on opened-item lane",
                    ));
                }
                let (window_key, doc_state) = transport::decode_bulk_transfer_done(payload)?;
                let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
                if !Self::follows_window(&key, &self.effective_worlds()?) {
                    return Err(TransportError::InvalidPayload("unfollowed world window"));
                }
                self.handle_bulk_transfer_done(window_key, doc_state)?;
            }
            _ => return Err(TransportError::UnknownTag(tag)),
        }

        // A successfully decoded control/root frame can advance one retained
        // update. Malformed/oversized messages never trigger replay side effects.
        // Window updates leave newly deferred bytes for the next timer tick.
        if tag != TAG_WINDOW_SYNC {
            self.replay_deferred_federation_update()?;
        } else {
            responses.extend(self.owner_note_requests()?);
        }
        Ok(responses)
    }

    /// Whether `window_key`'s local doc is VV-identical to the most recent
    /// server VV observed for that window (ONE-1128).
    ///
    /// `None` means there is no local doc or no server VV witness yet —
    /// callers MUST treat `None` as NOT converged (fail-closed). A window
    /// without a server witness can never vouch for queued updates.
    pub fn window_converged(&self, window_key: &str) -> Option<bool> {
        let window = self.window(window_key)?;
        let server_vv = self.server_vvs.get(window_key)?;
        Some(window.doc.oplog_vv() == *server_vv)
    }

    /// Imports a queued offline update into the LOCAL window doc before it is
    /// replayed to the server (ONE-1128).
    ///
    /// Convergence is confirmed by VV equality with the server, and equality
    /// only vouches for ops the local doc contains. Skipping this import
    /// would let a server that never received the queued ops compare
    /// VV-equal against a fresh local doc — and the queue would be cleared
    /// with the ops lost in flight (for a delete-bearing update, a vanished
    /// GDPR tombstone).
    ///
    /// An opened-item machine mirrors queued bytes only into a window it
    /// still holds promoted, judged again once the handle is held: a copy
    /// that outlived its queue row does not reopen a window a demotion
    /// emptied. An ungranted window's rows stay queued, unsent.
    pub fn import_queued_update(
        &mut self,
        window_key: &str,
        update: &[u8],
    ) -> std::result::Result<(), TransportError> {
        if !self.full_window_exchange_allowed(window_key)? {
            return Ok(());
        }
        let window = self.ensure_window(window_key)?;
        if !self.full_window_exchange_allowed(window_key)? {
            return Ok(());
        }
        window
            .doc
            .import(update)
            .map_err(|_| TransportError::InvalidPayload("queued update import failed"))?;
        Ok(())
    }
}

/// Maps a delta-export error onto the transport taxonomy.
///
/// Malformed inbound VV bytes (`CrdtDecodeError`) get the dedicated
/// fail-closed variant; anything else is an export-side failure.
fn map_delta_export_err(e: crate::error::Error) -> TransportError {
    match e {
        crate::error::Error::Sync(crate::error::SyncError::CrdtDecodeError { .. }) => {
            TransportError::VersionVectorDecode
        }
        _ => TransportError::InvalidPayload("delta export failed"),
    }
}
