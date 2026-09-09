//! Inbound wire dispatch, window-update import, and bulk history transfer.

use std::cmp::Ordering::{Equal, Less};

use loro::VersionVector;

use super::base::{SyncClient, load_root_doc};
use crate::error::Error;
use crate::sync::SyncEvent;
use crate::sync::bridge::persist_window_update;
use crate::sync::loro_support::{doc_version_vector, export_updates_since};
use crate::sync::quarantine;
use crate::sync::schema::create_window_doc;
use crate::sync::transport;
use crate::sync::transport::{
    LEASE_STATUS_GRANTED, MAX_DECODED_PAYLOAD_BYTES, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE,
    TAG_EPHEMERAL, TAG_LEASE_GRANTED, TAG_SYNC_UPDATE, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC,
    TransportError, window_sub_tags,
};
use crate::sync::types::WindowKey;
use crate::sync::window::{LoadedWindow, apply_pending_window_updates, load_window_from_state};

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
        let payload = &data[1..];
        let mut responses = Vec::new();

        match tag {
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
                if let Err(err) = self.persist_root_state() {
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
                let (window_key, compressed) = transport::decode_bulk_transfer(payload)?;
                self.handle_bulk_transfer(window_key, compressed)?;
            }
            TAG_BULK_TRANSFER_DONE => {
                let (window_key, doc_state) = transport::decode_bulk_transfer_done(payload)?;
                self.handle_bulk_transfer_done(window_key, doc_state)?;
            }
            _ => return Err(TransportError::UnknownTag(tag)),
        }

        Ok(responses)
    }

    fn handle_window_sync(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        match sub_tag {
            window_sub_tags::VV_REQUEST => {
                // Peer sent its binary VV (SyncStep1) — reply with the delta it
                // is missing (SyncStep2), then our own VV so it can push its
                // local diff back (the reverse SyncStep1). Malformed VV →
                // typed error, fail-closed: NEVER fall back to a full export.
                let server_vv = VersionVector::decode(payload)
                    .map_err(|_| TransportError::VersionVectorDecode)?;
                let window = self.ensure_window(window_key)?;
                let doc = &window.doc;
                let delta = crate::sync::window::export_window_updates_since(
                    &self.vault,
                    &window.key,
                    doc,
                    payload,
                )
                .map_err(map_delta_export_err)?;
                let responses = vec![
                    transport::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                        .into_result()?,
                    transport::encode_window_sync(
                        window_key,
                        window_sub_tags::VV_RESPONSE,
                        &doc_version_vector(doc),
                    )
                    .into_result()?,
                ];
                // Record the server VV only after a fully valid exchange — it
                // becomes the convergence witness for this window (ONE-1128).
                self.server_vvs.insert(window_key.to_string(), server_vv);
                Ok(responses)
            }
            window_sub_tags::UPDATE => {
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                let window = self.ensure_window(window_key)?;
                self.import_accepted_window_update(window_key, &window, payload)?;
                Ok(Vec::new())
            }
            window_sub_tags::VV_RESPONSE => {
                // Peer's VV answering our VV_REQUEST — export and send only our
                // local diff. Same fail-closed VV decoding as VV_REQUEST.
                let server_vv = VersionVector::decode(payload)
                    .map_err(|_| TransportError::VersionVectorDecode)?;
                let window = self.ensure_window(window_key)?;
                let doc = &window.doc;
                let delta = crate::sync::window::export_window_updates_since(
                    &self.vault,
                    &window.key,
                    doc,
                    payload,
                )
                .map_err(map_delta_export_err)?;
                let responses = vec![
                    transport::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                        .into_result()?,
                ];
                self.server_vvs.insert(window_key.to_string(), server_vv);
                Ok(responses)
            }
            _ => Ok(Vec::new()),
        }
    }

    pub(super) fn import_accepted_window_update(
        &mut self,
        window_key: &str,
        window: &LoadedWindow,
        payload: &[u8],
    ) -> std::result::Result<(), TransportError> {
        // Server sending Loro update bytes — import into the manager-owned
        // live doc. Observer B materializes the change to LMDB synchronously
        // (entities/edges/tombstones).
        //
        // Import-then-persist is deliberate: persisting BEFORE the import
        // would durably append an unvalidated frame as a `u:w:` row, and
        // window load is fail-closed on pending updates — one malformed frame
        // would brick every future open of this window.
        let vv_before = window.doc.oplog_vv();
        window
            .doc
            .import(payload)
            .map_err(|_| TransportError::InvalidPayload("window import failed"))?;
        let key = WindowKey::new(window_key);
        // A no-op import can still reveal a same-process durability gap:
        // compare the live doc with exactly what restart would load from
        // `d:w:` + surviving `u:w:` rows, then heal only the missing live-doc
        // delta.
        if window.doc.oplog_vv() == vv_before {
            let durable_doc = match load_window_from_state(&self.vault, "local", &key) {
                Ok(doc) => doc,
                Err(Error::WindowNotFound { .. }) => {
                    let doc = create_window_doc("local", &key);
                    if let Err(e) = apply_pending_window_updates(&self.vault, &doc, &key) {
                        self.manager.discard_window(&key);
                        return Err(TransportError::Storage(format!(
                            "load durable window updates: {e}"
                        )));
                    }
                    doc
                }
                Err(e) => {
                    self.manager.discard_window(&key);
                    return Err(TransportError::Storage(format!(
                        "load durable window state: {e}"
                    )));
                }
            };
            let live_vv = window.doc.oplog_vv();
            let durable_vv = durable_doc.oplog_vv();
            if matches!(live_vv.partial_cmp(&durable_vv), Some(Less | Equal)) {
                return Ok(());
            }
            let fr_key = format!("fr:w:{window_key}");
            match self.vault.sync_state_get(&fr_key) {
                Ok(Some(_)) => {
                    self.manager.discard_window(&key);
                    return Err(TransportError::Storage(
                        "post-scrub echo deferred to full resync".to_string(),
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    self.manager.discard_window(&key);
                    return Err(TransportError::Storage(format!(
                        "read full-resync marker: {e}"
                    )));
                }
            }
            let missing = match export_updates_since(&window.doc, &doc_version_vector(&durable_doc))
            {
                Ok(missing) => missing,
                Err(e) => {
                    self.manager.discard_window(&key);
                    return Err(map_delta_export_err(e));
                }
            };
            if let Err(e) = persist_window_update(&self.vault, window_key, &missing) {
                self.manager.discard_window(&key);
                return Err(TransportError::Storage(format!(
                    "persist live durable delta: {e}"
                )));
            }
            return Ok(());
        }
        // Remote imports never fire Observer A (local-only), so persist the
        // accepted update bytes ourselves: without a u:w: row, remote state —
        // including tombstones, whose LMDB purge already ran — would vanish
        // from the doc on restart.
        if let Err(e) = persist_window_update(&self.vault, window_key, payload) {
            // Never leave RAM ahead of durable state on a FAILED persist
            // (client analog of the ONE-1129 server evict-on-persist-failure):
            // the import advanced this doc's version vector, so keeping the
            // doc registered would tell the server — on the next VV exchange —
            // that we already hold bytes that never became durable; they would
            // never be re-sent and would vanish from the doc on restart
            // (tombstones included). Discard the live window WITHOUT
            // persisting (a persist would durably commit the unconfirmed
            // import); the next open reloads from durable state and the
            // ONE-1127/1128 VV exchange re-delivers the update.
            self.manager.discard_window(&WindowKey::new(window_key));
            return Err(TransportError::Storage(format!(
                "persist remote update: {e}"
            )));
        }
        let _ = self.event_tx.send(SyncEvent::WindowUpdated {
            window_key: window_key.to_string(),
        });
        Ok(())
    }

    fn handle_bulk_transfer(
        &mut self,
        window_key: &str,
        compressed: &[u8],
    ) -> std::result::Result<(), TransportError> {
        // Streaming decompression with size limit to prevent decompression bombs.
        let mut decoder = zstd::Decoder::new(compressed)
            .map_err(|_| TransportError::InvalidPayload("zstd decoder init failed"))?;
        let mut buf = Vec::with_capacity(std::cmp::min(
            compressed.len().saturating_mul(2),
            MAX_DECODED_PAYLOAD_BYTES,
        ));
        let mut chunk = [0u8; 8192];
        loop {
            let n = std::io::Read::read(&mut decoder, &mut chunk)
                .map_err(|_| TransportError::InvalidPayload("zstd decompress failed"))?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_DECODED_PAYLOAD_BYTES {
                return Err(TransportError::FrameTooLarge {
                    size: buf.len() + n,
                    max: MAX_DECODED_PAYLOAD_BYTES,
                });
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        // Persist the in-progress marker (ARCH-0023b key table:
        // `bulk:w:{key}`, device only) so a crash between BulkTransfer and
        // BulkTransferDone is observable on restart.
        let marker_key = format!("bulk:w:{window_key}");
        self.vault
            .with_write_txn(|wtxn| {
                self.vault.store.sync_state.put(wtxn, &marker_key, &[1u8])?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(format!("persist bulk marker: {e}")))?;

        // The decompressed MessagePack payload (LMDB row application) is
        // deliberately NOT applied here: the Phase-3 server-side sender does
        // not exist yet, and building a speculative applier against an
        // unexercised wire peer is riskier than deferring. Re-ticketed for
        // the M5/M6 Phase-3 work (see ONE-1126 PR body).
        let _ = buf;
        Ok(())
    }

    fn handle_bulk_transfer_done(
        &mut self,
        window_key: &str,
        doc_state: &[u8],
    ) -> std::result::Result<(), TransportError> {
        let marker_key = format!("bulk:w:{window_key}");

        if !doc_state.is_empty() {
            if let Some(window) = self.window(window_key) {
                // Window is live: import through the observed doc so
                // Observer B materializes, then persist the merged state.
                window
                    .doc
                    .import(doc_state)
                    .map_err(|_| TransportError::InvalidPayload("bulk doc state import failed"))?;
                if let Err(e) = window.persist_state(&self.vault) {
                    // Never leave RAM ahead of durable state on a FAILED
                    // persist (same discipline as the WindowSync UPDATE
                    // arm above): the bulk import advanced this doc's
                    // version vector, so keeping the doc registered would
                    // tell the server — on the next VV exchange — that we
                    // already hold bytes that never became durable; they
                    // would never be re-sent and would vanish from the doc
                    // on restart. Discard the live window WITHOUT
                    // persisting (a persist would durably commit the
                    // unconfirmed import); the next open reloads from
                    // durable state and the ONE-1127/1128 VV exchange
                    // re-delivers the missing ops. The `bulk:w:`
                    // in-progress marker stays set for retry (fail-closed:
                    // the clear below only runs after a successful
                    // persist).
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::Storage(format!("persist bulk window: {e}")));
                }
            } else {
                // Window is ON-DISK (cold): route the snapshot through the
                // SAME gated machinery as every other remote import
                // (ONE-1156(a), WAVE-C OD-12). The previous arm parsed the
                // snapshot structure-only (`doc_from_snapshot`) and then
                // wrote raw `d:w:`/`sv:w:`/`svf:w:` rows — remote bytes
                // becoming the next open's doc state WITHOUT Observer B
                // ever seeing them: no tombstone never-downgrade, no `dt:`
                // gate, no receipt immutability, no quarantine. Fail-closed
                // replacement:
                //
                //   1. full pinned open (pt → pm → reverse → forward remat,
                //      observers attached LAST) — `ensure_window`;
                //   2. OBSERVED import — Observer B fires synchronously, so
                //      EVERY entity/edge/tombstone door runs on the remote
                //      ops;
                //   3. inline `ra:` drain scoped to this window — doc-side
                //      tombstone re-assertion at a safe commit point
                //      (handler context, OUTSIDE observer callbacks),
                //      BEFORE the persist so the persisted `d:w:` is
                //      already re-asserted (ONE-1156(c));
                //   4. `persist_state` — anti-clobber merge + the pinned
                //      `d:`/`sv:`/`svf:` triple (which subsumes the old
                //      arm's bespoke svf freshness logic);
                //   5. unload — bulk targets cold historical windows; the
                //      memory budget is restored after the persist.
                //
                // Every failure path leaves `bulk:w:{key}` set for retry
                // (the clear below only runs after success) and DISCARDS
                // the just-opened window so RAM never runs ahead of
                // durable state (same discipline as the live arm and the
                // WindowSync UPDATE arm).
                let window = self.ensure_window(window_key)?;
                if window.doc.import(doc_state).is_err() {
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::InvalidPayload(
                        "bulk doc state import failed",
                    ));
                }
                // "local" mirrors the vault's own transient window-doc user
                // id (`Vault::write_crdt_tombstone`); `create_window_doc`
                // ignores it. A `false` return (malformed `ra:` rows kept,
                // fail closed) is NOT a bulk failure: the well-formed
                // markers drained, and the kept rows stay doctor-visible
                // via `pending_reassert_windows` — failing the transfer
                // could never clear them.
                if let Err(e) = quarantine::drain_reassert_markers_for_window(
                    &self.vault,
                    "local",
                    &self.manager,
                    &WindowKey::new(window_key),
                ) {
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::Storage(format!(
                        "bulk ra: re-assertion drain: {e}"
                    )));
                }
                if let Err(e) = window.persist_state(&self.vault) {
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::Storage(format!("persist bulk window: {e}")));
                }
                // Drop our handle BEFORE the unload: the manager refuses /
                // warns on outstanding external holders (ONE-1150).
                drop(window);
                self.manager
                    .unload_window(&WindowKey::new(window_key))
                    .map_err(|e| TransportError::Storage(format!("unload bulk window: {e}")))?;
            }
        }

        // Clear the in-progress marker only after persistence succeeded
        // (fail-closed: a failed persist leaves the marker set for retry).
        self.vault
            .with_write_txn(|wtxn| {
                self.vault.store.sync_state.delete(wtxn, &marker_key)?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(format!("clear bulk marker: {e}")))?;

        let _ = self.event_tx.send(SyncEvent::BulkTransferComplete {
            window_key: window_key.to_string(),
        });
        Ok(())
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
    pub fn import_queued_update(
        &mut self,
        window_key: &str,
        update: &[u8],
    ) -> std::result::Result<(), TransportError> {
        let window = self.ensure_window(window_key)?;
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
        crate::error::Error::CrdtDecodeError { .. } => TransportError::VersionVectorDecode,
        _ => TransportError::InvalidPayload("delta export failed"),
    }
}
