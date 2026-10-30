//! The window-sync message family.
//! The entry point is `SyncClient::handle_window_sync`.
//! Dispatched by `super::handle_server_message`.

use std::cmp::Ordering::{Equal, Less};

use loro::VersionVector;

use super::super::OwnDeviceImport;
use super::super::base::SyncClient;
use super::super::types::SyncResidenceMode;
use crate::error::{Error, SyncError, SyncProtocolValidation};
use crate::sync::SyncEvent;
use crate::sync::bridge::persist_window_update;
use crate::sync::loro_support::{doc_version_vector, export_updates_since};
use crate::sync::schema::create_window_doc;
use crate::sync::transport;
use crate::sync::transport::{MAX_DECODED_PAYLOAD_BYTES, TransportError, window_sub_tags};
use crate::sync::types::WindowKey;
use crate::sync::window::{
    LoadedWindow, WindowExport, apply_pending_window_updates, load_window_from_state,
    persisted_window_pads,
};

impl SyncClient {
    pub(super) fn handle_window_sync(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
        // A window the server stopped pushing to this socket changed. An owner-lane device that
        // follows it asks for it again, and the request subscribes it again; anything else reads
        // the notice as nothing, since the server may not know what this device follows. A world
        // window is never asked of a home that may not read the world (FIX 922 item 11).
        if sub_tag == window_sub_tags::WINDOW_INVALIDATE {
            if !payload.is_empty() {
                return Err(TransportError::InvalidPayload(
                    "invalid window invalidation",
                ));
            }
            if self.config.federation_peer.is_some()
                || self.config.residence_mode == SyncResidenceMode::Opened
                || !Self::follows_window(&key, &self.effective_worlds()?)
                || !self.home_may_request(&key)
            {
                return Ok(Vec::new());
            }
            let vv = self
                .window_vv_for_initial_sync(&key)
                .map_err(|e| TransportError::Storage(e.to_string()))?;
            return Ok(vec![
                transport::encode_window_sync(window_key, window_sub_tags::VV_REQUEST, &vv)
                    .into_result()?,
            ]);
        }
        // A device syncs what it opened (ARCH-0023b): a window this device
        // promoted is resident whether or not its world is followed.
        if self.config.federation_peer.is_none()
            && !Self::follows_window(&key, &self.effective_worlds()?)
            && !self.opened_window_promoted(&key)?
        {
            return Err(TransportError::InvalidPayload("unfollowed world window"));
        }
        if matches!(
            sub_tag,
            window_sub_tags::UPDATE
                | window_sub_tags::VV_REQUEST
                | window_sub_tags::VV_RESPONSE
                | window_sub_tags::REPLACEMENT
        ) && !self.full_window_exchange_allowed(window_key)?
        {
            return Err(TransportError::InvalidPayload(
                "full-window exchange requires causal promotion",
            ));
        }
        if self.config.federation_peer.is_some()
            && matches!(
                sub_tag,
                window_sub_tags::VV_REQUEST
                    | window_sub_tags::VV_RESPONSE
                    | window_sub_tags::REPLACEMENT
            )
        {
            return Err(TransportError::InvalidPayload(
                "full-window vector exchange on federation lane",
            ));
        }
        // A window's bytes come in their envelope, its pads installed here first (FIX 7107).
        let (sub_tag, payload) = match self.accept_window_pad_frame(&key, sub_tag, payload)? {
            std::ops::ControlFlow::Continue(frame) => frame,
            std::ops::ControlFlow::Break(answer) => return Ok(answer),
        };
        let payload: &[u8] = &payload;
        match sub_tag {
            window_sub_tags::PROMOTION_GRANTED | window_sub_tags::PROMOTED_INVALIDATE
                if self.config.residence_mode == SyncResidenceMode::Opened =>
            {
                let catch_up = self.setup_catch_up(window_key);
                if !payload.is_empty()
                    || (!catch_up
                        && self
                            .vault
                            .sync_state_get(&format!("rp:w:{window_key}"))
                            .map_err(|e| TransportError::Storage(e.to_string()))?
                            .is_none())
                {
                    return Err(TransportError::InvalidPayload("unpromoted window control"));
                }
                // The setup window's catch-up asks for the window only once the home granted it.
                if sub_tag == window_sub_tags::PROMOTION_GRANTED && !catch_up {
                    return Ok(Vec::new());
                }
                // Nor is the vector asked of a home that may not read the
                // window's world (FIX 922 item 11).
                if !self.home_may_request(&key) {
                    return Ok(Vec::new());
                }
                let window = self.ensure_window(window_key)?;
                Ok(vec![
                    transport::encode_window_sync(
                        window_key,
                        window_sub_tags::VV_REQUEST,
                        &doc_version_vector(&window.doc),
                    )
                    .into_result()?,
                ])
            }
            window_sub_tags::RESIDENCE_ACK
                if self.config.residence_mode == SyncResidenceMode::Opened =>
            {
                // The receipt binds what was sent for the row (FIX 7107).
                self.accept_window_pad_receipt(window_key, sub_tag, payload)
            }
            window_sub_tags::SELECTOR_DEFERRED => {
                // The retry resumes a federated selector exchange: the same
                // door as the selector request builder, with the same refusal.
                self.require_federation_peer()?;
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES || payload.len() <= 32 {
                    return Err(TransportError::InvalidPayload(
                        "invalid selector defer response",
                    ));
                }
                let request =
                    crate::sync::decode_selector_vv_request(&payload[32..]).map_err(|_| {
                        TransportError::InvalidPayload("invalid deferred selector request")
                    })?;
                let vv = VersionVector::decode(&request.remote_vv)
                    .map_err(|_| TransportError::VersionVectorDecode)?;
                if !vv.is_empty() {
                    return Err(TransportError::InvalidPayload(
                        "nonempty deferred selector vector",
                    ));
                }
                Ok(vec![
                    transport::encode_window_sync(
                        window_key,
                        window_sub_tags::SELECTOR_RETRY,
                        payload,
                    )
                    .into_result()?,
                ])
            }
            window_sub_tags::VV_REQUEST => {
                // Peer sent its binary VV (SyncStep1) — reply with the delta it
                // is missing (SyncStep2), then our own VV so it can push its
                // local diff back (the reverse SyncStep1). Malformed VV →
                // typed error, fail-closed: NEVER fall back to a full export.
                let server_vv = VersionVector::decode(payload)
                    .map_err(|_| TransportError::VersionVectorDecode)?;
                let window = self.ensure_window(window_key)?;
                let doc = &window.doc;
                // The setup window's catch-up sends nothing up: its vector alone
                // asks the home for what this device lacks.
                if self.setup_catch_up(window_key) {
                    return Ok(vec![
                        transport::encode_window_sync(
                            window_key,
                            window_sub_tags::VV_RESPONSE,
                            &doc_version_vector(doc),
                        )
                        .into_result()?,
                    ]);
                }
                let Some(delta) = self.export_to_server(&window, payload, &server_vv)? else {
                    return Ok(vec![replacement_request(window_key)?]);
                };
                let mut responses = self.window_pad_frames(
                    window_key,
                    window_sub_tags::UPDATE,
                    None,
                    &delta,
                    Some(doc),
                )?;
                responses.push(
                    transport::encode_window_sync(
                        window_key,
                        window_sub_tags::VV_RESPONSE,
                        &doc_version_vector(doc),
                    )
                    .into_result()?,
                );
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
                if self.config.federation_peer.is_some() {
                    self.import_federated_window_update(
                        window_key,
                        payload,
                        self.config.federation_admission_role,
                    )?;
                    return Ok(Vec::new());
                }
                // The home this connection proved, if it proved one, sent these bytes.
                match self.import_own_device_window_update(window_key, payload, self.home_peer) {
                    Ok(()) => Ok(Vec::new()),
                    // The update builds on history this window's own shallow root cut away: no
                    // update can bring it level, the server's replacement can.
                    Err(_) if self.update_reaches_below_root(&key, payload) => {
                        self.staged_world_updates
                            .retain(|(staged, bytes, _)| staged != &key || bytes != payload);
                        Ok(vec![replacement_request(window_key)?])
                    }
                    Err(error) => Err(error),
                }
            }
            window_sub_tags::REPLACEMENT => {
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                let evidence = self.staged_entity_evidence()?;
                // Judged again once no demotion holds the window closed.
                let (window, conflicts) = self
                    .manager
                    .replace_window_admitted(&key, payload, &evidence, || {
                        self.full_window_exchange_allowed(window_key)
                            .unwrap_or(false)
                    })
                    .map_err(|error| match error {
                        Error::Sync(SyncError::SyncProtocolError {
                            context: SyncProtocolValidation::ReplacementBusy,
                        }) => TransportError::Storage(
                            "window replacement waits on a held window".to_string(),
                        ),
                        Error::Sync(SyncError::SyncProtocolError {
                            context: SyncProtocolValidation::ReplacementRejected,
                        }) => TransportError::InvalidPayload("window replacement rejected"),
                        error => TransportError::Storage(error.to_string()),
                    })?;
                if !conflicts.is_empty() {
                    let _ = self.event_tx.send(SyncEvent::ReplacementConflicts {
                        window_key: window_key.to_string(),
                        conflicts,
                    });
                }
                // The replaced window starts a fresh exchange: what the server held of the old
                // one witnesses nothing about the new one.
                self.server_vvs.remove(window_key);
                let vv = doc_version_vector(&window.doc);
                drop(window);
                Ok(vec![
                    transport::encode_window_sync(window_key, window_sub_tags::VV_REQUEST, &vv)
                        .into_result()?,
                ])
            }
            window_sub_tags::VV_RESPONSE => {
                // Peer's VV answering our VV_REQUEST — export and send only our
                // local diff. Same fail-closed VV decoding as VV_REQUEST.
                let server_vv = VersionVector::decode(payload)
                    .map_err(|_| TransportError::VersionVectorDecode)?;
                if self.setup_catch_up(window_key) {
                    return Ok(Vec::new());
                }
                let window = self.ensure_window(window_key)?;
                let Some(delta) = self.export_to_server(&window, payload, &server_vv)? else {
                    return Ok(vec![replacement_request(window_key)?]);
                };
                let responses = self.window_pad_frames(
                    window_key,
                    window_sub_tags::UPDATE,
                    None,
                    &delta,
                    Some(&window.doc),
                )?;
                self.server_vvs.insert(window_key.to_string(), server_vv);
                Ok(responses)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn staged_entity_evidence(
        &self,
    ) -> std::result::Result<
        std::collections::HashMap<crate::EntityId, (WindowKey, Vec<u8>)>,
        TransportError,
    > {
        let mut evidence = std::collections::HashMap::new();
        for (key, bytes, _) in &self.staged_world_updates {
            let live = self.ensure_window(key.as_str())?;
            let candidate = live.doc.fork();
            let imported = candidate
                .import(bytes)
                .map_err(|_| TransportError::InvalidPayload("staged world update decode failed"))?;
            if imported.pending.is_some() {
                return Err(TransportError::InvalidPayload(
                    "staged world update has missing causal history",
                ));
            }
            let tombstones =
                crate::sync::loro_support::TombstoneIndex::build(&candidate.get_map("tombstones"));
            let mut entities = Vec::new();
            crate::sync::loro_support::map_for_each_value_bytes(
                &candidate.get_map("entities"),
                |raw, blob| {
                    if let Some(blob) = blob {
                        entities.push((raw.to_owned(), blob.to_vec()));
                    }
                },
            );
            for (raw, blob) in entities {
                let id = crate::EntityId::from_hex(&raw)
                    .map_err(|_| TransportError::InvalidPayload("invalid staged entity id"))?;
                if id.to_hex() != raw {
                    return Err(TransportError::InvalidPayload(
                        "invalid staged entity alias",
                    ));
                }
                if !crate::sync::types::entity_belongs_to_window(&blob, key) {
                    let txn = self
                        .vault
                        .store
                        .env
                        .read_txn()
                        .map_err(|e| TransportError::Storage(e.to_string()))?;
                    let shell = crate::sync::types::retained_world_shell_belongs_to_window(
                        &self.vault,
                        &txn,
                        &candidate,
                        &tombstones,
                        &id,
                        &blob,
                        key,
                        false,
                    )
                    .map_err(|e| TransportError::Storage(e.to_string()))?;
                    if !shell {
                        return Err(TransportError::InvalidPayload(
                            "staged entity outside world",
                        ));
                    }
                    // A witnessed shell is valid local content, but it has no
                    // claim body to prove another window's edge endpoint.
                    continue;
                }
                if evidence.insert(id, (key.clone(), blob)).is_some() {
                    return Err(TransportError::InvalidPayload("duplicate staged entity"));
                }
            }
        }
        Ok(evidence)
    }

    pub(in crate::sync::client) fn drain_staged_world_updates(&mut self) -> std::result::Result<(), TransportError> {
        let mut healed = Vec::new();
        loop {
            if self.staged_world_updates.is_empty() {
                break;
            }
            let evidence = self.staged_entity_evidence()?;
            let mut progressed = false;
            let mut index = 0;
            while index < self.staged_world_updates.len() {
                let key = self.staged_world_updates[index].0.clone();
                let live = self.ensure_window(key.as_str())?;
                // A window demoted since its frame was staged stays closed.
                if !self.full_window_exchange_allowed(key.as_str())? {
                    self.staged_world_updates.remove(index);
                    continue;
                }
                match crate::sync::window::validate_window_update_with_staged_worlds(
                    &self.vault,
                    &live.doc,
                    &self.staged_world_updates[index].1,
                    &key,
                    &evidence,
                ) {
                    Ok(()) => {}
                    Err(crate::Error::InvalidConfig(reason))
                        if reason == "edge endpoint unresolved" =>
                    {
                        index += 1;
                        continue;
                    }
                    Err(error) => {
                        return Err(TransportError::from_window_admission(
                            &error,
                            "staged world residence denied",
                        ));
                    }
                }
                let (key, bytes, from) = self.staged_world_updates[index].clone();
                // A staged update keeps the machine that sent it (FIX 11709).
                let own_device = self.own_device_import(from);
                self.import_accepted_window_update_with_evidence(
                    key.as_str(),
                    &live,
                    &bytes,
                    &evidence,
                    own_device.as_ref(),
                )?;
                self.staged_world_updates.remove(index);
                healed.push(key);
                progressed = true;
                break;
            }
            if !progressed {
                break;
            }
        }
        for key in healed {
            let live = self.ensure_window(key.as_str())?;
            crate::sync::window::forward_rematerialize(
                &self.vault,
                &live.doc,
                self.manager.materializer(),
                &key,
            )
            .map_err(|error| TransportError::Storage(format!("heal staged world edge: {error}")))?;
        }
        Ok(())
    }

    pub(in crate::sync::client) fn import_accepted_window_update(
        &mut self,
        window_key: &str,
        window: &LoadedWindow,
        payload: &[u8],
    ) -> std::result::Result<(), TransportError> {
        self.import_accepted_window_update_with_evidence(
            window_key,
            window,
            payload,
            &std::collections::HashMap::new(),
            None,
        )
    }

    /// [`Self::import_accepted_window_update`] with `evidence`, staged world
    /// rows, and under `own_device`, the proof an own machine sent `payload`
    /// (FIX 11709).
    pub(in crate::sync::client) fn import_accepted_window_update_with_evidence(
        &mut self,
        window_key: &str,
        window: &LoadedWindow,
        payload: &[u8],
        evidence: &std::collections::HashMap<crate::EntityId, (WindowKey, Vec<u8>)>,
        own_device: Option<&OwnDeviceImport>,
    ) -> std::result::Result<(), TransportError> {
        // Server sending Loro update bytes — import into the manager-owned
        // live doc. Observer B materializes the change to LMDB synchronously
        // (entities/edges/tombstones).
        //
        // Import-then-persist is deliberate: persisting BEFORE the import
        // would durably append an unvalidated frame as a `u:w:` row, and
        // window load is fail-closed on pending updates — one malformed frame
        // would brick every future open of this window.
        crate::sync::window::validate_window_update_with_staged_worlds(
            &self.vault,
            &window.doc,
            payload,
            &window.key,
            evidence,
        )
        .map_err(|error| {
            TransportError::from_window_admission(&error, "entity outside window residence")
        })?;
        // A retained world shell has no body to tell Observer B its address.
        // The isolated pre-import validator proved its witness; persist that
        // address BEFORE the observed import fires the tombstone and edge
        // observers. This is not a new grant: it is exact peer-window state
        // admitted by the same payload check above.
        if window.key.world().is_some() {
            let candidate = window.doc.fork();
            candidate
                .import(payload)
                .map_err(|_| TransportError::InvalidPayload("window import failed"))?;
            let witnesses = candidate.get_map("retained_claim_worlds");
            let mut ids = Vec::new();
            witnesses.for_each(|raw, _| ids.push(raw.to_owned()));
            let tombstones =
                crate::sync::loro_support::TombstoneIndex::build(&candidate.get_map("tombstones"));
            self.vault
                .with_write_txn_grouped(|txn| {
                    for raw in &ids {
                        let id = crate::EntityId::from_hex(raw)?;
                        if let Some(blob) = crate::sync::loro_support::map_get_bytes(
                            &candidate.get_map("entities"),
                            raw,
                        ) && crate::sync::types::retained_world_shell_belongs_to_window(
                            &self.vault,
                            txn,
                            &candidate,
                            &tombstones,
                            &id,
                            &blob,
                            &window.key,
                            false,
                        )? {
                            self.vault.store.sync_state.put(
                                txn,
                                &format!("m:dw:{raw}"),
                                window.key.as_str().as_bytes(),
                            )?;
                        }
                    }
                    Ok(())
                })
                .map_err(|error| TransportError::Storage(error.to_string()))?;
        }
        let vv_before = window.doc.oplog_vv();
        let key = WindowKey::new(window_key);
        // FIX 11709: the MESSAGE rows an own machine's proven connection sent
        // take the own-device lane in the doors this import and its retained
        // world pass run, and no others.
        crate::sync::ingest::with_own_device_import(
            &self.vault,
            own_device,
            (&key, &window.doc),
            payload,
            || self.land_window_update(window, &key, payload),
        )?;
        // A no-op import can still reveal a same-process durability gap:
        // compare the live doc with exactly what restart would load from
        // `d:w:` + surviving `u:w:` rows, then heal only the missing live-doc
        // delta.
        if window.doc.oplog_vv() == vv_before {
            let durable_doc = match load_window_from_state(&self.vault, "local", &key) {
                Ok(doc) => doc,
                Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
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
                    return Err(super::map_delta_export_err(e));
                }
            };
            // Its pads persist by reference where custody here holds them
            // (FIX 7107).
            let missing = persisted_window_pads(&self.vault, &key, &missing, Some(&window.doc));
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
        // from the doc on restart. Its pads persist by reference where
        // custody here holds them (FIX 7107).
        let persisted = persisted_window_pads(&self.vault, &key, payload, Some(&window.doc));
        if let Err(e) = persist_window_update(&self.vault, window_key, &persisted) {
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

    /// Imports `payload` into `window`'s live document, `key`'s, where Observer
    /// B materializes it, then lands a retained world shell it holds.
    fn land_window_update(
        &self,
        window: &LoadedWindow,
        key: &WindowKey,
        payload: &[u8],
    ) -> std::result::Result<(), TransportError> {
        window
            .doc
            .import(payload)
            .map_err(|_| TransportError::InvalidPayload("window import failed"))?;
        if key.world().is_some() && !window.doc.get_map("retained_claim_worlds").is_empty() {
            // Observer B cannot materialize a bodyless CLAIM on an entity-map
            // callback: its paired witness/tombstone may arrive later in the
            // same Loro import. The complete, validated document is now live;
            // replay it through the ordinary forward recovery door before
            // persisting or acknowledging the version vector.
            if let Err(error) = crate::sync::window::forward_rematerialize(
                &self.vault,
                &window.doc,
                self.manager.materializer(),
                key,
            ) {
                self.manager.discard_window(key);
                return Err(TransportError::Storage(format!(
                    "restore retained world shell: {error}"
                )));
            }
        }
        Ok(())
    }

    /// What this device sends the server for `window` past the server's vector: the update
    /// bytes, or `None` when only a replacement could bring the server level. A device never
    /// pushes a replacement on the hub; it asks for the hub's and writes its own state on top
    /// (`REPLACEMENT_REQUEST`). A server holding nothing of the window takes the snapshot as
    /// its first update, as before replacements existed.
    fn export_to_server(
        &self,
        window: &LoadedWindow,
        payload: &[u8],
        server_vv: &VersionVector,
    ) -> std::result::Result<Option<Vec<u8>>, TransportError> {
        let export = crate::sync::window::export_window_since_for(
            &self.vault,
            &window.key,
            &window.doc,
            payload,
            None,
            crate::sync::window::Withhold::Peer(self.home_peer),
        )
        .map_err(super::map_delta_export_err)?;
        Ok(match export {
            WindowExport::Update(delta) => Some(delta),
            WindowExport::Replacement(snapshot) if server_vv.is_empty() => Some(snapshot),
            WindowExport::Replacement(_) => None,
        })
    }

    /// `REPLACEMENT_REQUEST` frames asking the server for each of `windows` whole.
    pub(in crate::sync) fn replacement_requests(
        &self,
        windows: &std::collections::BTreeSet<String>,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        windows.iter().map(|key| replacement_request(key)).collect()
    }

    /// Whether `update` failed on this device because it builds on history below the live
    /// window's own shallow root.
    fn update_reaches_below_root(&self, key: &WindowKey, update: &[u8]) -> bool {
        self.manager.window(key).is_some_and(|window| {
            crate::sync::window::update_reaches_below_root(&window.doc, update)
        })
    }
}

/// A device's request for the server's replacement of `window_key`.
fn replacement_request(window_key: &str) -> std::result::Result<Vec<u8>, TransportError> {
    transport::encode_window_sync(window_key, window_sub_tags::REPLACEMENT_REQUEST, &[])
        .into_result()
}
