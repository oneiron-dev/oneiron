//! Initial-connect and re-bootstrap sync frame builders.

use loro::{LoroDoc, VersionVector};

use super::base::{FollowedWorlds, SyncClient};
use super::types::{SVF_FRESH, SyncClientConfig, SyncEvent, SyncResidenceMode};
use crate::error::Result;
use crate::sync::loro_support::doc_version_vector;
use crate::sync::transport;
use crate::sync::transport::{TAG_VERSION_VECTOR, TransportError, window_sub_tags};
use crate::sync::types::WindowKey;
use crate::sync::window_rows::{WINDOW_SHALLOW_FENCE, WINDOW_STATE_VECTOR};

impl SyncClient {
    /// Every socket has its own subscribed-key set. A reconnect retains its
    /// local Docs and root, but must negotiate every world VV again after
    /// the server's root response (and after all shared base VVs). The
    /// worlds it follows are read here, before its first frame, and every
    /// frame of this negotiation selects from them
    /// (`negotiated_worlds_or_live`): a change after this point
    /// renegotiates once the steady loop starts.
    pub(crate) fn begin_connection_sync(&mut self) {
        self.negotiated_worlds = self.effective_worlds().ok();
        self.requested_windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.pending_world_windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.root_bootstrapped = false;
        self.leaf_key_sends = Default::default();
        self.sealed_updates.restart();
        // A grant or a replacement on an earlier socket proves nothing on this one (FIX 20202).
        self.promotions_granted.clear();
        self.follow_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.follows_refused.clear();
        self.replacements_installed.clear();
    }

    /// The worlds this negotiation's frames select from: the set read as
    /// its connection began, which the steady loop compares
    /// ([`Self::follow_set_changed`]), so a change during the negotiation
    /// renegotiates. Before any connection began, or when that read failed,
    /// the set read now.
    fn negotiated_worlds_or_live(&self) -> std::result::Result<FollowedWorlds, TransportError> {
        match &self.negotiated_worlds {
            Some(worlds) => Ok(worlds.clone()),
            None => self.effective_worlds(),
        }
    }

    /// Drops all in-memory CRDT state for a forced re-bootstrap (ARCH-0023b
    /// Fig. 2: "drop Docs + queue").
    ///
    /// Manager-owned window docs are discarded WITHOUT persisting (the next
    /// open reloads from durable state), recorded server VVs are cleared,
    /// and the root doc is replaced with a fresh one so Phase 1 re-runs from
    /// an empty VV. Clearing the PERSISTENT queue is the connection
    /// manager's half (`SyncQueue::clear_all`, which preserves the `h:`/`m:`
    /// metadata, the `e:` embedding jobs, the `x:` quarantine family, and
    /// delete-bearing `q:` rows + their `d:` markers).
    pub fn reset_for_re_bootstrap(&mut self) {
        self.cancel_lfs_download();
        for key in self.manager.loaded_keys() {
            self.manager.discard_window(&key);
        }
        self.server_vvs.clear();
        self.requested_windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.pending_world_windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.root_bootstrapped = false;
        self.residence_acks.clear();
        self.reset_window_pads();
        self.reset_root_parts();
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
    /// Returns protocol hello, root VV and requested window VVs. Device
    /// lease requests are retired; authentication uses a paired capability.
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
        // v13 carries own-device windows and grant-backed entity documents
        // on the same connection, and window replacements (v14 adds both to
        // residence); authentication uses a paired capability.
        // Device lease requests are retired (C07); the NOTE session bind
        // (HEAD) still rides along when configured.
        let mut messages = vec![Self::session_hello(&self.config)];
        // A peer session binds the socket's actor too, so the peer admits its
        // promotion and document requests as the home does; only the NOTE
        // authority side of the bind stays the home's (FIX 4748,
        // `note_session_bound`).
        if let Some(session) = &self.config.note_session {
            messages.push(super::note_session::bind_frame(session)?);
        }
        messages
            .extend(self.generate_phase_frames_with_extra_windows(std::iter::empty::<String>())?);
        Ok(messages)
    }

    /// The protocol hello a sync session over `config` opens with: the
    /// federation lane's, or its residence mode's lane with window
    /// replacement. A peer session's probe of the home opens with it too
    /// (FIX 4748).
    pub(in crate::sync) fn session_hello(config: &SyncClientConfig) -> Vec<u8> {
        if config.federation_peer.is_some() {
            return transport::encode_protocol_hello();
        }
        match config.residence_mode {
            SyncResidenceMode::Opened => transport::encode_replacement_residence_protocol_hello(),
            SyncResidenceMode::All => transport::encode_replacement_full_window_protocol_hello(),
        }
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

        let effective_worlds = self.negotiated_worlds_or_live()?;
        let mut keys: Vec<WindowKey> = Vec::new();
        if self.config.residence_mode == SyncResidenceMode::All {
            let mut next = Some(WindowKey::from_timestamp(now_secs));
            for _ in 0..self.config.default_window_count {
                let Some(key) = next else { break };
                next = key.previous_month();
                if let FollowedWorlds::Only(worlds) = &effective_worlds {
                    for world in worlds {
                        let scoped = WindowKey::for_month_world(&key, *world);
                        if !keys.contains(&scoped) {
                            keys.push(scoped);
                        }
                    }
                }
                keys.push(key);
            }
            for key in self.manager.loaded_keys() {
                if Self::follows_window(&key, &effective_worlds) && !keys.contains(&key) {
                    keys.push(key);
                }
            }
            // The home/sync-all replica requests every root and local partition,
            // including historical base months and world claims not yet indexed
            // by a fresh server. A followed world also needs its base month.
            let mut discovered = crate::sync::schema::read_window_list(&self.root_doc);
            if effective_worlds.follows_any() {
                discovered.extend(
                    crate::sync::discover_local_window_keys(&self.vault)
                        .map_err(|error| TransportError::Storage(error.to_string()))?,
                );
            }
            for key in Self::selected_discovered_windows(discovered, &effective_worlds) {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
            // This vault's embedding setup rows (OF-370) live in one fixed window, which a
            // fresh device has no row of its own to discover.
            let setup =
                WindowKey::from_timestamp(crate::store::embedding::EMBEDDING_SETUP_LEARNED_AT);
            if !keys.contains(&setup) {
                keys.push(setup);
            }
        } else {
            for marker in self
                .vault
                .sync_state_keys_with_prefix("rp:w:")
                .map_err(|e| TransportError::Storage(e.to_string()))?
            {
                let key = marker
                    .strip_prefix("rp:w:")
                    .and_then(WindowKey::try_new)
                    .ok_or(TransportError::InvalidWindowKey)?;
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
            // A followed world's windows sync in full with no promotion marker:
            // the home grants each one on this socket (`follows_full_window`),
            // or refuses it (`FOLLOW_REFUSED`). Only the windows the home's
            // root lists are asked.
            if self.config.residence_selector.is_some() {
                for key in crate::sync::schema::read_window_list(&self.root_doc) {
                    if key.world().is_some()
                        && self.follows_full_window_in(key.as_str(), &effective_worlds)
                        && !keys.contains(&key)
                    {
                        keys.push(key);
                    }
                }
            }
            // This vault's embedding setup rows (OF-370) reach an opened-item device whatever
            // it opened: it asks the home to grant their window (`setup_catch_up`).
            let setup =
                WindowKey::from_timestamp(crate::store::embedding::EMBEDDING_SETUP_LEARNED_AT);
            if self.config.residence_selector.is_some()
                && self.setup_catch_up(setup.as_str())
                && !keys.contains(&setup)
            {
                keys.push(setup);
            }
        }
        for key in extra_windows {
            let Some(window_key) = WindowKey::try_new(key.as_str()) else {
                let _ = self.event_tx.send(SyncEvent::Error(format!(
                    "Re-bootstrap skipped invalid forced window key: {key}"
                )));
                continue;
            };
            if Self::follows_window(&window_key, &effective_worlds) && !keys.contains(&window_key) {
                keys.push(window_key);
            }
        }

        keys.sort_by(|left, right| {
            left.world()
                .is_some()
                .cmp(&right.world().is_some())
                .then_with(|| left.as_str().cmp(right.as_str()))
        });
        for key in keys {
            if self.config.residence_mode == SyncResidenceMode::Opened
                && self.config.federation_peer.is_none()
            {
                // A home that may not read the window's world is not asked to
                // promote it, nor for its vector (FIX 922 item 11).
                if !self.home_may_promote(&key) {
                    continue;
                }
                // A followed world's window this device never promoted is
                // asked as a follow, and its vector waits for the home's
                // grant: a home that does not grant the whole window answers
                // FOLLOW_REFUSED, and nothing of it goes on this socket.
                if self.follow_only_window_in(&key, &effective_worlds)? {
                    messages.push(self.follow_request_frame(&key)?);
                    self.requested_windows
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(key);
                    continue;
                }
                messages.push(self.promotion_request_frame(&key)?);
                // The setup window's vector waits for the home's grant.
                if self.setup_catch_up(key.as_str()) {
                    continue;
                }
            }
            // No vector request names a world window to a home that may not
            // read the world (FIX 922 item 11).
            if !self.home_may_request(&key) {
                continue;
            }
            if key.world().is_some() {
                // The server sends root first, but initial frames are already
                // queued on this socket. Wait for that root response, request
                // every shared base month, THEN this world's VV.
                self.pending_world_windows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(key);
                continue;
            }
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
                    self.requested_windows
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(key);
                    messages.push(frame);
                }
                Err(e) => {
                    let _ = self.event_tx.send(SyncEvent::Error(format!(
                        "Initial sync VV for window {key} failed: {e}"
                    )));
                }
            }
        }

        self.owner_note_requests()?;
        // A peer session asks for no NOTE: the NOTE lane is its authority's,
        // the home's (FIX 4748).
        let requests = self
            .manager
            .documents()
            .request_frames()
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        messages.extend(
            requests
                .into_iter()
                .filter(|frame| self.peer_session.is_none() || !self.note_document_frame(frame)),
        );
        Ok(messages)
    }

    /// The `PROMOTION_REQUEST` frame for `key`: this lane's residence
    /// selector, as the home grant-checks it.
    fn promotion_request_frame(
        &self,
        key: &WindowKey,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        self.selector_request_frame(key, window_sub_tags::PROMOTION_REQUEST)
    }

    /// The `FOLLOW_REQUEST` frame for followed window `key`: the same
    /// selector, which the home grant-checks as a promotion's, but answers a
    /// refusal with `FOLLOW_REFUSED` and keeps the socket open. Records the
    /// request for [`Self::unanswered_follow_requests`].
    fn follow_request_frame(
        &self,
        key: &WindowKey,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        let frame = self.selector_request_frame(key, window_sub_tags::FOLLOW_REQUEST)?;
        self.follow_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.clone());
        Ok(frame)
    }

    /// The `sub_tag` frame for `key` carrying this lane's residence selector.
    fn selector_request_frame(
        &self,
        key: &WindowKey,
        sub_tag: u8,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        let selector =
            self.config
                .residence_selector
                .as_ref()
                .ok_or(TransportError::InvalidPayload(
                    "promoted window has no selector",
                ))?;
        let bytes = crate::sync::encode_sync_selector(selector)
            .map_err(|_| TransportError::InvalidPayload("invalid promotion selector"))?;
        transport::encode_window_sync(key.as_str(), sub_tag, &bytes).into_result()
    }

    fn selected_discovered_windows(
        discovered: Vec<WindowKey>,
        effective_worlds: &FollowedWorlds,
    ) -> Vec<WindowKey> {
        let mut selected = Vec::new();
        for key in discovered {
            if key.world().is_some() && Self::follows_window(&key, effective_worlds) {
                let base =
                    WindowKey::from_timestamp(key.start_timestamp().expect("validated window"));
                if !selected.contains(&base) {
                    selected.push(base);
                }
                if !selected.contains(&key) {
                    selected.push(key);
                }
            } else if key.world().is_none()
                && effective_worlds.follows_any()
                && !selected.contains(&key)
            {
                // A selected-world edge can name a shared base endpoint
                // learned in any older month. The first-touch item index in
                // ONE-2662 may narrow these shared base fetches later; this
                // carrier must not strand valid graph dependencies today.
                selected.push(key);
            }
        }
        selected
    }

    /// The root document may arrive after initial frames on a new device.
    /// Request newly advertised, followed world windows only after the root
    /// import is durable. A repeat root update never requests the same key.
    pub(super) fn newly_followed_window_requests(
        &mut self,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        let effective_worlds = self.negotiated_worlds_or_live()?;
        // Opened residence exchanges full VVs only for promoted windows and
        // followed worlds' windows; the deferred set holds the ones this
        // connection's first frames asked to promote.
        let opened = self.config.residence_mode == SyncResidenceMode::Opened
            && self.config.federation_peer.is_none();
        let mut discovered = if opened {
            Vec::new()
        } else {
            let mut listed = crate::sync::schema::read_window_list(&self.root_doc);
            listed.extend(self.manager.loaded_keys());
            listed
        };
        discovered.extend(
            self.pending_world_windows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .cloned(),
        );
        // A followed world's window the root lists now and this connection's
        // first frames did not ask for: it is asked as a follow, and its
        // vector waits for the home's grant.
        let mut late_follows = std::collections::HashSet::new();
        if opened && self.config.residence_selector.is_some() {
            for key in crate::sync::schema::read_window_list(&self.root_doc) {
                let requested = self
                    .requested_windows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&key);
                if key.world().is_some()
                    && !requested
                    && !discovered.contains(&key)
                    && self.follow_only_window_in(&key, &effective_worlds)?
                    && self.home_may_promote(&key)
                {
                    late_follows.insert(key.clone());
                    discovered.push(key);
                }
            }
        }
        if !opened && !self.root_bootstrapped && effective_worlds.follows_any() {
            discovered.extend(
                crate::sync::discover_local_window_keys(&self.vault)
                    .map_err(|error| TransportError::Storage(error.to_string()))?,
            );
        }
        // A promoted world window is requested alone: the device opened it,
        // whether or not its world is followed, and its base month is not
        // promoted, so the home would refuse that month's full exchange.
        let mut keys = if opened {
            discovered
        } else {
            Self::selected_discovered_windows(discovered, &effective_worlds)
        };
        keys.sort_by(|left, right| {
            left.world()
                .is_some()
                .cmp(&right.world().is_some())
                .then_with(|| left.as_str().cmp(right.as_str()))
        });
        let mut frames = Vec::new();
        for key in keys {
            if self
                .requested_windows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&key)
            {
                continue;
            }
            // Judged again as the deferred keys drain: the home may no longer
            // read the world (FIX 922 item 11).
            if !self.home_may_request(&key) {
                continue;
            }
            if late_follows.contains(&key) {
                frames.push(self.follow_request_frame(&key)?);
                self.requested_windows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(key);
                continue;
            }
            let vv = self
                .window_vv_for_initial_sync(&key)
                .map_err(|e| TransportError::Storage(e.to_string()))?;
            let frame =
                transport::encode_window_sync(key.as_str(), window_sub_tags::VV_REQUEST, &vv)
                    .into_own_frame()?;
            self.requested_windows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key.clone());
            self.pending_world_windows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
            frames.push(frame);
            // The keys whose pad is not here, asked off this loop (FIX 6706).
            self.schedule_world_pad_repair(&key);
        }
        self.root_bootstrapped = true;
        Ok(frames)
    }

    /// The version requests this connection owes the home for the windows a
    /// policy wake readied here (fix list row 19634): up to `budget` windows
    /// whose ready generation `progress` has not asked for, from the one after
    /// where its last pass ended, each with the generation read and its
    /// `VV_REQUEST`. Only a window this connection exchanged already goes, on
    /// the gates the home's answers meet as they come in: this lane follows or
    /// promoted it, may exchange its whole window, and the home may read its
    /// world; and this vault still stores it. No federation lane asks. Nothing
    /// is stamped here: the caller stamps a window once its request is on the
    /// socket. A window whose vector cannot be read now stays owed.
    pub(in crate::sync) fn ready_window_requests(
        &self,
        progress: &mut crate::sync::manager::ReadyProgress,
        budget: usize,
    ) -> std::result::Result<Vec<(WindowKey, u64, Vec<u8>)>, TransportError> {
        if self.config.federation_peer.is_some() {
            return Ok(Vec::new());
        }
        // Read once a window is owed; worlds that cannot be read keep every
        // owed window for a later pass.
        let mut worlds = None;
        let due = progress
            .due(&self.manager, budget, |key| {
                worlds
                    .get_or_insert_with(|| self.effective_worlds().ok())
                    .as_ref()
                    .is_some_and(|effective| self.ready_window_requestable(key, effective))
            })
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let mut requests = Vec::with_capacity(due.len());
        for (key, generation) in due {
            let vv = match self.window_vv_for_initial_sync(&key) {
                Ok(vv) => vv,
                Err(error) => {
                    tracing::warn!(window = %key, %error, "ready window vector not read");
                    continue;
                }
            };
            let frame =
                transport::encode_window_sync(key.as_str(), window_sub_tags::VV_REQUEST, &vv)
                    .into_result()?;
            requests.push((key, generation, frame));
        }
        Ok(requests)
    }

    /// Whether ready window `key` may be asked of the home on this
    /// connection now ([`Self::ready_window_requests`]).
    fn ready_window_requestable(&self, key: &WindowKey, effective_worlds: &FollowedWorlds) -> bool {
        let exchanged = self
            .requested_windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(key);
        exchanged
            && !self.setup_catch_up(key.as_str())
            && (Self::follows_window(key, effective_worlds)
                || self.opened_window_promoted(key).unwrap_or(false))
            && self
                .full_window_exchange_allowed(key.as_str())
                .unwrap_or(false)
            && self.home_may_request(key)
            && self.manager.window_stored(key).unwrap_or(false)
    }

    /// Resolves the wire VV (Loro binary `VersionVector::encode()` bytes)
    /// for one window during initial sync: live doc when loaded; persisted
    /// `sv:w:` when `svf:w:` is fresh (no doc load — the fast-reconnect
    /// path); full manager open otherwise.
    pub(super) fn window_vv_for_initial_sync(&self, key: &WindowKey) -> Result<Vec<u8>> {
        if let Some(window) = self.manager.window(key) {
            return Ok(doc_version_vector(&window.doc));
        }

        {
            let rtxn = self.vault.store.env.read_txn()?;
            let window_key = key.as_str().to_owned();
            let fresh = matches!(
                WINDOW_SHALLOW_FENCE.get(&self.vault.store, &rtxn, &window_key)?,
                Some(raw) if raw == [SVF_FRESH]
            );
            if fresh
                && let Some(sv_raw) =
                    WINDOW_STATE_VECTOR.get(&self.vault.store, &rtxn, &window_key)?
            {
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

        let window = self.manager.open_window(key)?;
        Ok(doc_version_vector(&window.doc))
    }
}

/// Computes the next backoff delay with exponential growth capped at max.
pub fn next_backoff(current_ms: u32, max_ms: u32) -> u32 {
    std::cmp::min(current_ms.saturating_mul(2), max_ms)
}
