//! Thin-item fetch and open reads.
//! The entry point is `SyncClient::fetch_item`.
//! Vocabulary owned by `super`.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::super::base::{SyncClient, home_reads_window};
use super::super::types::SyncResidenceMode;
use super::{OpenedItem, ThinItem};
use crate::EntityId;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::{self, TransportError};
use crate::sync::types::WindowKey;

use super::rpc::{ResidenceRpc, refused, residence_budgets};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TouchReply {
    window: String,
    entity_id: String,
    blob: String,
    document: String,
}

impl SyncClient {
    /// Resolve and import one grant-selected ledger item on first touch.
    pub async fn fetch_item(
        &mut self,
        window: &WindowKey,
        item: EntityId,
    ) -> Result<(), TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let budgets = residence_budgets(&self.vault)?;
        // A promoted window is a canonical equal CRDT copy. Reopening its
        // resident row must never recreate a thin cache or ask for another
        // promotion. A newly born row waits for the promoted VV exchange.
        if self
            .vault
            .sync_state_get(&format!("rp:w:{window}"))
            .map_err(|e| TransportError::Storage(e.to_string()))?
            .is_some()
        {
            return if self
                .vault
                .get_raw(&item)
                .map_err(|e| TransportError::Storage(e.to_string()))?
                .is_some()
            {
                self.catch_up_promoted_pads(window, Some(item)).await;
                Ok(())
            } else {
                Err(TransportError::InvalidPayload(
                    "promoted item needs window resync",
                ))
            };
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
        // A home that may not read the window's world is not told its name,
        // the selector or the item (FIX 922 item 11): the touch fails as
        // with no home.
        if !home_reads_window(&self.vault, rpc.home, window) {
            return Err(TransportError::Storage(
                "home may not read this world".into(),
            ));
        }
        let reply: TouchReply = serde_json::from_value(
            rpc.request(
                "residence.touch",
                json!({
                    "window": window.as_str(), "selector": selector, "entityId": item.to_hex()
                }),
            )
            .await?,
        )
        .map_err(|_| refused())?;
        if reply.entity_id != item.to_hex() || reply.window != window.as_str() {
            return Err(refused());
        }
        let blob = base64::engine::general_purpose::STANDARD
            .decode(reply.blob)
            .map_err(|_| refused())?;
        let header = crate::batch::EntityMetadataHeader::parse(&blob).ok_or_else(refused)?;
        // A row past one frame, such as an authority entry, is taken whole:
        // the RPC reply's own bound holds it (FIX 8246).
        if window
            .start_timestamp()
            .is_none_or(|start| header.learned_at < start)
            || window
                .end_timestamp()
                .is_some_and(|end| header.learned_at >= end)
        {
            return Err(refused());
        }
        let document = base64::engine::general_purpose::STANDARD
            .decode(reply.document)
            .map_err(|_| refused())?;
        if document.len() > transport::MAX_DECODED_PAYLOAD_BYTES
            || document.first() != Some(&transport::TAG_DOCUMENT)
        {
            return Err(refused());
        }
        let document_frame = transport::decode_document(&document[1..])?;
        if document_frame.entity != item
            || !matches!(
                document_frame.kind,
                transport::document_sub_tags::STATE | transport::document_sub_tags::UPDATE
            )
        {
            return Err(refused());
        }
        // The grant-checked body and text are one atomic READ-ONLY cache
        // entry. Neither reaches the observed Loro window or LMDB entity
        // tables until the canonical window is promoted before a write.
        let now = self.vault.store.clock.wall_now();
        self.vault
            .with_write_txn_grouped(|txn| {
                if self
                    .vault
                    .store
                    .sync_state
                    .get(txn, &format!("rp:w:{window}"))?
                    .is_some()
                {
                    if !crate::ports::EntityStoreRead::port_entity_present(
                        &self.vault.store,
                        txn,
                        &item,
                    )? {
                        return Err(crate::Error::InvalidKey);
                    }
                    return Ok(());
                }
                self.vault
                    .store
                    .sync_state
                    .put(txn, &format!("ri:b:{}", item.to_hex()), &blob)?;
                self.vault.store.sync_state.put(
                    txn,
                    &format!("ri:d:{}", item.to_hex()),
                    &document,
                )?;
                self.vault.store.sync_state.put(
                    txn,
                    &format!("ro:e:{}", item.to_hex()),
                    window.as_str().as_bytes(),
                )?;
                crate::sync::residence::record_item_touch_in_txn(&self.vault, txn, item, now)?;
                // FIX 4385: a machine history the cached row needs is owed.
                crate::sync::machine_history::owe_touched_in_txn(
                    &self.vault,
                    txn,
                    window.as_str(),
                    item,
                    &blob,
                )?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Read a previously fetched thin item. This cache has no writable Loro
    /// handle; callers must promote its window before any edit.
    pub fn thin_item(&self, item: EntityId) -> Result<Option<ThinItem>, TransportError> {
        read_thin_item(&self.vault, item)
    }

    /// Open one item: its read cache when this machine opened it before,
    /// else its local canonical row, else a first touch at the home. Each
    /// open of a cached item stamps its last touch, which ages the cache.
    pub async fn open_item(
        &mut self,
        window: &WindowKey,
        item: EntityId,
    ) -> Result<OpenedItem, TransportError> {
        let storage = |e: crate::Error| TransportError::Storage(e.to_string());
        if let Some(cached) = self.thin_item(item)?
            && &cached.window == window
        {
            crate::sync::residence::record_item_touch(&self.vault, item).map_err(storage)?;
            return Ok(OpenedItem::Thin(cached));
        }
        if let Some(raw) = self.vault.get_raw(&item).map_err(storage)? {
            return Ok(OpenedItem::Resident {
                entity_id: item,
                window: window.clone(),
                raw,
            });
        }
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(TransportError::InvalidPayload("item not yet synced"));
        }
        self.fetch_item(window, item).await?;
        self.thin_item(item)?
            .map(OpenedItem::Thin)
            .ok_or_else(refused)
    }
}

/// Read a previously fetched thin item on the vault alone.
pub(super) fn read_thin_item(
    vault: &crate::Vault,
    item: EntityId,
) -> Result<Option<ThinItem>, TransportError> {
    let txn = vault
        .store
        .env
        .read_txn()
        .map_err(|e| TransportError::Storage(e.to_string()))?;
    let id = item.to_hex();
    let Some(raw_window) = vault
        .store
        .sync_state
        .get(&txn, &format!("ro:e:{id}"))
        .map_err(|e| TransportError::Storage(e.to_string()))?
    else {
        return Ok(None);
    };
    let window = std::str::from_utf8(&raw_window)
        .ok()
        .and_then(WindowKey::try_new)
        .ok_or_else(refused)?;
    if vault
        .store
        .sync_state
        .get(&txn, &format!("rp:w:{window}"))
        .map_err(|e| TransportError::Storage(e.to_string()))?
        .is_some()
    {
        return Ok(None);
    }
    let raw = vault
        .store
        .sync_state
        .get(&txn, &format!("ri:b:{id}"))
        .map_err(|e| TransportError::Storage(e.to_string()))?
        .ok_or_else(refused)?;
    let document = vault
        .store
        .sync_state
        .get(&txn, &format!("ri:d:{id}"))
        .map_err(|e| TransportError::Storage(e.to_string()))?
        .ok_or_else(refused)?;
    Ok(Some(ThinItem {
        entity_id: item,
        window,
        raw: raw.to_vec(),
        document: document.to_vec(),
    }))
}
