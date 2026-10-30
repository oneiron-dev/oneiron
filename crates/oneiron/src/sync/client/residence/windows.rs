//! Window promote, retain, and demote lifecycle.
//! The entry point is `SyncClient::retain_window`.
//! Vocabulary owned by `super`.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::super::OwnDeviceImport;
use super::super::base::{ITEM11_UNREADABLE_HOME_PROMOTION, SyncClient, home_reads_window};
use super::super::types::{SyncClientConfig, SyncResidenceMode};
use crate::EntityId;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;

use super::rpc::{ResidenceRpc, refused, residence_budgets};

#[derive(Deserialize)]
pub(super) struct PromotionReply {
    pub(super) window: String,
    snapshot: String,
    /// Every pad of the window's world the home holds (FIX 3789).
    pub(super) pads: Vec<super::promoted_pads::PromotedPad>,
}

/// The home's version vector for one window (OF-534 demotion).
#[derive(Deserialize)]
struct WindowVvReply {
    window: String,
    vv: String,
}

/// [`super::import_promotion_snapshot`] with this vault to judge the custody
/// transitions an own machine's promotion carries by (OF-422): without one,
/// admission refuses every custody insert. Under `own_device`, the proof the
/// home this promotion's socket proved sent `snapshot`, each MESSAGE row it
/// holds takes the own-device lane as it lands in `window` (FIX 12111).
fn import_promotion_snapshot_with(
    vault: &crate::Vault,
    (window, doc): (&WindowKey, &loro::LoroDoc),
    snapshot: &[u8],
    own_device: Option<&OwnDeviceImport>,
) -> bool {
    crate::sync::window::validate_promotion_snapshot(vault, doc, snapshot).is_ok()
        && crate::sync::ingest::with_own_device_import(
            vault,
            own_device,
            (window, doc),
            snapshot,
            || crate::sync::ingest::with_promotion(vault, || doc.import(snapshot)),
        )
        .is_ok()
}

/// Sync-state prefix of a window this machine holds in full whose retain the
/// home refused ([`SyncClient::retain_window`]). The residence upkeep asks
/// again, so a grant that changed since lets the window sync without waiting
/// for a first edit to promote it.
const RETAIN_REFUSED_PREFIX: &str = "rr:w:";

/// Asks the home again to retain each window it refused, on an opened
/// machine; returns how many it retains now. Off the live sync loop, on the
/// window manager and a client config alone, like [`relay_sealed_bundle`].
pub(crate) async fn retry_refused_retains(
    manager: &std::sync::Arc<crate::sync::manager::WindowManager>,
    config: &SyncClientConfig,
) -> Result<usize, TransportError> {
    if config.residence_mode != SyncResidenceMode::Opened || config.federation_peer.is_some() {
        return Ok(0);
    }
    let refused = manager
        .vault()
        .sync_state_keys_with_prefix(RETAIN_REFUSED_PREFIX)
        .map_err(|e| TransportError::Storage(e.to_string()))?;
    if refused.is_empty() {
        return Ok(0);
    }
    let (mut client, _events) = SyncClient::new(std::sync::Arc::clone(manager), config.clone())
        .map_err(|e| TransportError::Storage(e.to_string()))?;
    let mut retained = 0;
    for marker in refused {
        let Some(window) = marker
            .strip_prefix(RETAIN_REFUSED_PREFIX)
            .and_then(WindowKey::try_new)
        else {
            continue;
        };
        if client.retain_window(&window).await? {
            retained += 1;
        }
    }
    Ok(retained)
}

impl SyncClient {
    /// Promote a thin item's whole canonical window before the first edit.
    /// A denied or oversized full-window grant leaves the thin cache read-only.
    pub async fn promote_window(
        &mut self,
        window: &WindowKey,
        item: EntityId,
    ) -> Result<(), TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let budgets = residence_budgets(&self.vault)?;
        let cache = self.thin_item(item)?.ok_or_else(refused)?;
        if &cache.window != window {
            return Err(refused());
        }
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector = base64::engine::general_purpose::STANDARD
            .encode(encode_sync_selector(selector).map_err(|_| refused())?);
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        // A home that may not read the window's world is not told its name
        // (FIX 922 item 11): the thin cache stays read-only, as with no home.
        if ITEM11_UNREADABLE_HOME_PROMOTION && !home_reads_window(&self.vault, rpc.home, window) {
            return Err(TransportError::Storage(
                "home may not read this world".into(),
            ));
        }
        let reply: PromotionReply = serde_json::from_value(
            rpc.request(
                "residence.promote",
                json!({
                    "window": window.as_str(), "selector": selector, "entityId": item.to_hex()
                }),
            )
            .await?,
        )
        .map_err(|_| refused())?;
        if reply.window != window.as_str() {
            return Err(refused());
        }
        let pads = super::promoted_pads::checked_pads(window, &reply.pads)?;
        // Its envelope's pads reach custody first (FIX 7107).
        let snapshot = self.promotion_snapshot(window, &reply.snapshot)?;
        if snapshot.len() > crate::sync::residence::MAX_PROMOTION_SNAPSHOT_BYTES {
            return Err(refused());
        }
        // The world's pads reach custody here before the snapshot (FIX 6706).
        self.hydrate_promoted_pads(&mut rpc, window, &selector, item)
            .await;
        // Do not merge a canonical frontier into an independently authored
        // sparse window. Its prior ops would not be a causal continuation.
        // A key pad held here is not mirrored into it: the snapshot carries
        // the window's pads (FIX 3789).
        let loaded = crate::sync::ingest::with_first_promotion_open(&self.vault, || {
            self.ensure_window(window.as_str())
        })?;
        if !loaded.doc.oplog_vv().is_empty() {
            return Err(TransportError::InvalidPayload(
                "unpromoted window has local CRDT history",
            ));
        }
        let own_device = self.own_device_import(rpc.home);
        if !import_promotion_snapshot_with(
            &self.vault,
            (window, &loaded.doc),
            &snapshot,
            own_device.as_ref(),
        ) {
            self.manager.discard_window(window);
            return Err(refused());
        }
        if let Err(error) = loaded.persist_state(&self.vault) {
            self.manager.discard_window(window);
            return Err(TransportError::Storage(error.to_string()));
        }
        // Publish the writable marker only AFTER the canonical doc is
        // durable. Cached thin bodies in this window can no longer shadow it.
        self.vault
            .with_write_txn_grouped(|txn| {
                let stale: Vec<_> = self
                    .vault
                    .store
                    .sync_state
                    .prefix_iter(txn, "ro:e:")?
                    .map(|row| row.map(|(key, value)| (key.to_string(), value.to_vec())))
                    .collect::<std::result::Result<_, _>>()?;
                for (key, value) in stale {
                    if value == window.as_str().as_bytes() {
                        let id = key.strip_prefix("ro:e:").ok_or(crate::Error::InvalidKey)?;
                        self.vault.store.sync_state.delete(txn, &key)?;
                        self.vault
                            .store
                            .sync_state
                            .delete(txn, &format!("ri:b:{id}"))?;
                        self.vault
                            .store
                            .sync_state
                            .delete(txn, &format!("ri:d:{id}"))?;
                        self.vault
                            .store
                            .sync_state
                            .delete(txn, &format!("rt:e:{id}"))?;
                    }
                }
                self.vault
                    .store
                    .sync_state
                    .put(txn, &format!("rp:w:{window}"), &[1])?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        super::promoted_pads::land_pads(&self.vault, window, &pads);
        self.materialize_sealed_mirror(window);
        crate::store::turn_missing::reconcile_after_promotion(&self.vault);
        self.manager.notify_promotion(window);
        Ok(())
    }

    /// The bundle sections this machine took in while `window` stood
    /// unpromoted wait in its mirror: the promoted window holds their rows
    /// now. A failure leaves them there for the next take.
    fn materialize_sealed_mirror(&self, window: &WindowKey) {
        let Some(world) = window.world() else {
            return;
        };
        if let Err(error) = crate::sync::ingest::with_promotion(&self.vault, || {
            self.manager.materialize_sealed_mirror(world, window)
        }) {
            tracing::warn!(%error, %window, "sealed mirror not materialized on promotion");
        }
    }

    /// Keep a window this machine already holds in full (it synced all) as
    /// a promoted opened window. The home grant-checks the whole window
    /// first, exactly as for a first-edit promotion, and only then is the
    /// window marked promoted. Its snapshot merges into the held copy: the
    /// two are the same canonical CRDT, never an independently authored one.
    /// A refused window stays on disk but no longer syncs, and is marked so the
    /// residence upkeep asks again ([`retry_refused_retains`]).
    pub async fn retain_window(&mut self, window: &WindowKey) -> Result<bool, TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        if self
            .vault
            .sync_state_get(&format!("rp:w:{window}"))
            .map_err(|e| TransportError::Storage(e.to_string()))?
            .is_some()
        {
            self.catch_up_promoted_pads(window, None).await;
            return Ok(true);
        }
        let budgets = residence_budgets(&self.vault)?;
        let loaded = self.ensure_window(window.as_str())?;
        // The home admits a promotion through one live row it selects.
        let mut item = None;
        crate::sync::loro_support::map_for_each_value_bytes(
            &loaded.doc.get_map("entities"),
            |key, value| {
                if item.is_none() && value.is_some() {
                    item = EntityId::from_hex(key).ok();
                }
            },
        );
        let Some(item) = item else {
            return Ok(false);
        };
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector = base64::engine::general_purpose::STANDARD
            .encode(encode_sync_selector(selector).map_err(|_| refused())?);
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        // A home that may not read the window's world is not told its name or
        // the selector (FIX 3872): the window stays on disk, marked for the
        // residence upkeep to ask again, as when the home refuses it.
        if ITEM11_UNREADABLE_HOME_PROMOTION && !home_reads_window(&self.vault, rpc.home, window) {
            self.mark_retain_refused(window)?;
            return Ok(false);
        }
        let reply = match rpc
            .request(
                "residence.promote",
                json!({
                    "window": window.as_str(), "selector": selector, "entityId": item.to_hex()
                }),
            )
            .await
        {
            Ok(reply) => reply,
            Err(TransportError::InvalidPayload(_)) => {
                self.mark_retain_refused(window)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let reply: PromotionReply = serde_json::from_value(reply).map_err(|_| refused())?;
        if reply.window != window.as_str() {
            return Err(refused());
        }
        let pads = super::promoted_pads::checked_pads(window, &reply.pads)?;
        // Its envelope's pads reach custody first (FIX 7107).
        let snapshot = self.promotion_snapshot(window, &reply.snapshot)?;
        // The world's pads reach custody here before the snapshot (FIX 6706).
        self.hydrate_promoted_pads(&mut rpc, window, &selector, item)
            .await;
        let own_device = self.own_device_import(rpc.home);
        if snapshot.len() > crate::sync::residence::MAX_PROMOTION_SNAPSHOT_BYTES
            || !import_promotion_snapshot_with(
                &self.vault,
                (window, &loaded.doc),
                &snapshot,
                own_device.as_ref(),
            )
        {
            self.mark_retain_refused(window)?;
            return Ok(false);
        }
        loaded
            .persist_state(&self.vault)
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        self.vault
            .with_write_txn_grouped(|txn| {
                self.vault
                    .store
                    .sync_state
                    .delete(txn, &format!("{RETAIN_REFUSED_PREFIX}{window}"))?;
                self.vault
                    .store
                    .sync_state
                    .put(txn, &format!("rp:w:{window}"), &[1])
            })
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        super::promoted_pads::land_pads(&self.vault, window, &pads);
        self.materialize_sealed_mirror(window);
        crate::store::turn_missing::reconcile_after_promotion(&self.vault);
        self.manager.notify_promotion(window);
        Ok(true)
    }

    /// Marks `window` as one whose retain the home refused, for
    /// [`retry_refused_retains`].
    fn mark_retain_refused(&self, window: &WindowKey) -> Result<(), TransportError> {
        self.vault
            .with_write_txn_grouped(|txn| {
                self.vault.store.sync_state.put(
                    txn,
                    &format!("{RETAIN_REFUSED_PREFIX}{window}"),
                    &[1],
                )
            })
            .map_err(|e| TransportError::Storage(e.to_string()))
    }

    /// Demote a promoted window back to thin (OF-534). The home's version
    /// vector for the window must cover every op this device holds; then the
    /// local replica goes, in bounded steps with the window closed, and its
    /// items read through the thin cache again. The home keeps the window,
    /// and a later first edit promotes it again. Controls, tombstoned and
    /// pending rows stay. Not `complete` while the home lacks an op, a queued
    /// write for the window waits, or a handle keeps the window open: call
    /// again.
    pub async fn demote_window(
        &mut self,
        window: &WindowKey,
    ) -> Result<crate::sync::residence::WindowDemotion, TransportError> {
        let storage = |e: crate::Error| TransportError::Storage(e.to_string());
        if self.config.residence_mode != SyncResidenceMode::Opened
            || self
                .vault
                .sync_state_get(&format!("rp:w:{window}"))
                .map_err(storage)?
                .is_none()
        {
            return Err(refused());
        }
        let budgets = residence_budgets(&self.vault)?;
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector = base64::engine::general_purpose::STANDARD
            .encode(encode_sync_selector(selector).map_err(|_| refused())?);
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        // A home that may not read the window's world is not told its name or
        // the selector (FIX 3872): the window stays promoted here.
        if ITEM11_UNREADABLE_HOME_PROMOTION && !home_reads_window(&self.vault, rpc.home, window) {
            return Err(TransportError::Storage(
                "home may not read this world".into(),
            ));
        }
        let reply: WindowVvReply = serde_json::from_value(
            rpc.request(
                "residence.window.vv",
                json!({ "window": window.as_str(), "selector": selector }),
            )
            .await?,
        )
        .map_err(|_| refused())?;
        if reply.window != window.as_str() {
            return Err(refused());
        }
        let home = base64::engine::general_purpose::STANDARD
            .decode(reply.vv)
            .ok()
            .and_then(|bytes| loro::VersionVector::decode(&bytes).ok())
            .ok_or_else(refused)?;
        // A loaded window persists before it closes; one a handle still
        // holds stays, and the demotion waits.
        match self.manager.unload_window(window) {
            Ok(_) => {}
            Err(crate::Error::Sync(crate::error::SyncError::WindowBusy { .. })) => {
                return Ok(crate::sync::residence::WindowDemotion::default());
            }
            Err(error) => return Err(storage(error)),
        }
        Ok(
            crate::sync::residence::demote_resident_window(&self.vault, window, &home)
                .map_err(storage)?
                .unwrap_or_default(),
        )
    }
}
