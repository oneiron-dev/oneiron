//! The bulk-transfer message family.
//! The entry point is `SyncClient::handle_bulk_transfer`.
//! Dispatched by `super`.

use super::super::base::SyncClient;
use crate::error::{Error, SyncError};
use crate::sync::SyncEvent;
use crate::sync::quarantine;
use crate::sync::schema::create_window_doc;
use crate::sync::transport::{MAX_DECODED_PAYLOAD_BYTES, TransportError};
use crate::sync::types::WindowKey;
use crate::sync::window::{apply_pending_window_updates, load_window_from_state};
use crate::sync::window_rows::BULK_TRANSFER_MARKER;

impl SyncClient {
    pub(super) fn handle_bulk_transfer(
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
        let marker_key = window_key.to_owned();
        self.vault
            .with_write_txn_grouped(|wtxn| {
                BULK_TRANSFER_MARKER.put(&self.vault.store, wtxn, &marker_key, &[1u8])?;
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

    pub(super) fn handle_bulk_transfer_done(
        &mut self,
        window_key: &str,
        doc_state: &[u8],
    ) -> std::result::Result<(), TransportError> {
        let marker_key = window_key.to_owned();

        if !doc_state.is_empty() {
            // The state comes in its envelope, its pads installed here first (FIX 7107).
            let state = self.bulk_window_state(&WindowKey::new(window_key), doc_state)?;
            let doc_state = state.as_slice();
            // FIX 11709: the home this connection proved, if it proved one, sent
            // the state: its MESSAGE rows take the own-device lane as it lands.
            let own_device = self.own_device_import(self.home_peer);
            if let Some(window) = self.window(window_key) {
                // Window is live: import through the observed doc so
                // Observer B materializes, then persist the merged state.
                crate::sync::window::validate_window_update_residence_with_vault(
                    &self.vault,
                    &window.doc,
                    doc_state,
                    &window.key,
                )
                .map_err(|error| {
                    TransportError::from_window_admission(&error, "bulk window residence denied")
                })?;
                crate::sync::ingest::with_own_device_import(
                    &self.vault,
                    own_device.as_ref(),
                    (&window.key, &window.doc),
                    doc_state,
                    || window.doc.import(doc_state),
                )
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
                let key = WindowKey::new(window_key);
                let candidate = match load_window_from_state(&self.vault, "local", &key) {
                    Ok(doc) => doc,
                    Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
                        let doc = create_window_doc("local", &key);
                        apply_pending_window_updates(&self.vault, &doc, &key)
                            .map_err(|e| TransportError::Storage(e.to_string()))?;
                        doc
                    }
                    Err(e) => return Err(TransportError::Storage(e.to_string())),
                };
                crate::sync::window::validate_window_update_residence_with_vault(
                    &self.vault,
                    &candidate,
                    doc_state,
                    &key,
                )
                .map_err(|error| {
                    TransportError::from_window_admission(&error, "bulk window residence denied")
                })?;
                let window = self.ensure_window(window_key)?;
                crate::sync::window::validate_window_update_residence_with_vault(
                    &self.vault,
                    &window.doc,
                    doc_state,
                    &key,
                )
                .map_err(|error| {
                    TransportError::from_window_admission(&error, "bulk window residence denied")
                })?;
                let imported = crate::sync::ingest::with_own_device_import(
                    &self.vault,
                    own_device.as_ref(),
                    (&key, &window.doc),
                    doc_state,
                    || window.doc.import(doc_state),
                );
                if imported.is_err() {
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
            .with_write_txn_grouped(|wtxn| {
                BULK_TRANSFER_MARKER.delete(&self.vault.store, wtxn, &marker_key)?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(format!("clear bulk marker: {e}")))?;

        let _ = self.event_tx.send(SyncEvent::BulkTransferComplete {
            window_key: window_key.to_string(),
        });
        Ok(())
    }
}
