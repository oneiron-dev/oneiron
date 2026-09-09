//! Initial-connect and re-bootstrap sync frame builders.

use loro::{LoroDoc, VersionVector};

use super::base::SyncClient;
use super::types::{SVF_FRESH, SyncEvent};
use crate::error::Result;
use crate::sync::loro_support::doc_version_vector;
use crate::sync::transport;
use crate::sync::transport::{TAG_VERSION_VECTOR, TransportError, window_sub_tags};
use crate::sync::types::WindowKey;

impl SyncClient {
    /// Drops all in-memory CRDT state for a forced re-bootstrap (ARCH-0023b
    /// Fig. 2: "drop Docs + queue").
    ///
    /// Manager-owned window docs are discarded WITHOUT persisting (the next
    /// open reloads from durable state), recorded server VVs are cleared,
    /// and the root doc is replaced with a fresh one so Phase 1 re-runs from
    /// an empty VV. Clearing the PERSISTENT queue is the connection
    /// manager's half (`SyncQueue::clear_all`, which preserves the `h:`/`m:`
    /// metadata, the `x:` quarantine family, and delete-bearing `q:` rows +
    /// their `d:` markers).
    pub fn reset_for_re_bootstrap(&mut self) {
        for key in self.manager.loaded_keys() {
            self.manager.discard_window(&key);
        }
        self.server_vvs.clear();
        let root_doc = LoroDoc::new();
        let _meta = root_doc.get_map("meta");
        // Same peer-id pinning as `new`: the client never authors root ops,
        // and a fresh doc has no ops, so this cannot fail.
        let _ = root_doc.set_peer_id(self.client_id);
        self.root_doc = root_doc;
    }

    /// Re-bootstrap sync frames: drop all in-memory docs, then produce the
    /// Phase 1-2 frames (root VV + default-window VV requests) WITHOUT the
    /// protocol hello — the hello is a once-per-connection preamble
    /// (ONE-1127) and the re-bootstrap reuses the live connection.
    pub fn generate_re_bootstrap_sync(&mut self) -> Vec<Vec<u8>> {
        self.generate_re_bootstrap_sync_for_windows(std::iter::empty::<String>())
            .expect("re-bootstrap sync frame encode failed")
    }

    /// Re-bootstrap sync frames with explicit windows that must be requested
    /// even if they are outside the default current/previous window set.
    pub(in crate::sync) fn generate_re_bootstrap_sync_for_windows<I>(
        &mut self,
        extra_windows: I,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError>
    where
        I: IntoIterator<Item = String>,
    {
        self.reset_for_re_bootstrap();
        self.generate_phase_frames_with_extra_windows(extra_windows)
    }

    /// Generates initial sync messages for the connection flow.
    ///
    /// Returns messages to send to the server, in wire order (the ONE-1140
    /// OD-5 connect-sequence literal `[hello][lease_request][…existing]`):
    /// 1. Protocol-version hello (MUST be the first frame — server checks it)
    /// 2. Lease request (proof-of-possession over this device's identity;
    ///    sent on EVERY connect — registration and renewal are one frame)
    /// 3. Root doc VV (so server knows what we have)
    /// 4. Default window VV requests (current + previous month), plus any
    ///    additional already-loaded windows
    ///
    /// All version vectors are Loro binary `VersionVector::encode()` bytes —
    /// the JSON VV encoding is dead (wire break pinned in ONE-1127).
    ///
    /// Fast reconnect (the `sv:`/`svf:` reader): for a window that is not
    /// loaded and whose `svf:w:{key}` flag is fresh, the VV is decoded from
    /// the persisted `sv:w:{key}` StateVector without loading the doc.
    /// Stale or absent state vectors fall back to a full manager open.
    pub fn generate_initial_sync(&self) -> Vec<Vec<u8>> {
        self.try_generate_initial_sync()
            .expect("initial sync frame encode failed")
    }

    /// Fallible initial-sync frame builder for the connection flow.
    ///
    /// Production connection code uses this path so an encoder failure aborts
    /// the connect attempt instead of silently skipping a window request.
    pub(in crate::sync) fn try_generate_initial_sync(
        &self,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        // Phase 0: full-window hello — this client path still uses the
        // pre-FED-002 full-window VV_REQUEST flow.
        // Frame #2: lease request (ONE-1140, OD-5).
        let mut messages = vec![
            transport::encode_legacy_full_window_protocol_hello(),
            self.lease_request_frame(),
        ];
        messages.extend(self.generate_phase_frames()?);
        Ok(messages)
    }

    /// Phase 1-2 sync frames: root VV + default-window VV requests.
    ///
    /// Shared by the initial connection flow (which prepends the protocol
    /// hello) and the forced re-bootstrap (which does not).
    fn generate_phase_frames(&self) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        self.generate_phase_frames_with_extra_windows(std::iter::empty::<String>())
    }

    fn generate_phase_frames_with_extra_windows<I>(
        &self,
        extra_windows: I,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut messages = Vec::new();

        // Phase 1: Send our root VV (empty for new client — server will send snapshot)
        let mut vv_msg = vec![TAG_VERSION_VECTOR];
        vv_msg.extend_from_slice(&doc_version_vector(&self.root_doc));
        messages.push(vv_msg);

        // Phase 2: Default windows for the wall clock now (current +
        // previous), then any other windows already loaded in the manager.
        // Saturate to 0 on pre-epoch wall clock (NTP regression, suspended
        // VM, embedded device with reset RTC). Matches sync/queue.rs
        // push_embed_job.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let mut keys: Vec<WindowKey> = Vec::new();
        let mut next = Some(WindowKey::from_timestamp(now_secs));
        for _ in 0..self.config.default_window_count {
            let Some(key) = next else { break };
            next = key.previous_month();
            keys.push(key);
        }
        for key in self.manager.loaded_keys() {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        for key in extra_windows {
            let Some(window_key) = WindowKey::try_new(key.as_str()) else {
                let _ = self.event_tx.send(SyncEvent::Error(format!(
                    "Re-bootstrap skipped invalid forced window key: {key}"
                )));
                continue;
            };
            if !keys.contains(&window_key) {
                keys.push(window_key);
            }
        }

        for key in keys {
            match self.window_vv_for_initial_sync(&key) {
                Ok(vv) => {
                    let frame = transport::encode_window_sync(
                        key.as_str(),
                        window_sub_tags::VV_REQUEST,
                        &vv,
                    )
                    .into_result()
                    .inspect_err(|e| {
                        let _ = self.event_tx.send(SyncEvent::Error(format!(
                            "Initial sync frame encode for window {key} failed: {e}"
                        )));
                    })?;
                    messages.push(frame);
                }
                Err(e) => {
                    let _ = self.event_tx.send(SyncEvent::Error(format!(
                        "Initial sync VV for window {key} failed: {e}"
                    )));
                }
            }
        }

        Ok(messages)
    }

    /// Resolves the wire VV (Loro binary `VersionVector::encode()` bytes)
    /// for one window during initial sync: live doc when loaded; persisted
    /// `sv:w:` when `svf:w:` is fresh (no doc load — the fast-reconnect
    /// path); full manager open otherwise.
    fn window_vv_for_initial_sync(&self, key: &WindowKey) -> Result<Vec<u8>> {
        if let Some(window) = self.manager.window(key) {
            return Ok(doc_version_vector(&window.doc));
        }

        {
            let rtxn = self.vault.store.env.read_txn()?;
            let svf_key = format!("svf:w:{key}");
            let fresh = matches!(
                self.vault.store.sync_state.get(&rtxn, &svf_key)?,
                Some(raw) if *raw == [SVF_FRESH]
            );
            if fresh {
                let sv_key = format!("sv:w:{key}");
                if let Some(sv_raw) = self.vault.store.sync_state.get(&rtxn, &sv_key)? {
                    // Persisted StateVector V1 — decode validates structure
                    // before anything reaches the wire (fail-closed: a
                    // corrupt row falls through to a full doc load instead
                    // of shipping garbage).
                    match VersionVector::decode(&sv_raw) {
                        Ok(vv) => return Ok(vv.encode()),
                        Err(e) => {
                            tracing::warn!(
                                window = %key,
                                error = %e,
                                "initial-sync: corrupt persisted state vector — falling back to doc load"
                            );
                        }
                    }
                }
            }
        }

        let window = self.manager.open_window(key)?;
        Ok(doc_version_vector(&window.doc))
    }
}

/// Computes the next backoff delay with exponential growth capped at max.
pub fn next_backoff(current_ms: u32, max_ms: u32) -> u32 {
    std::cmp::min(current_ms.saturating_mul(2), max_ms)
}
