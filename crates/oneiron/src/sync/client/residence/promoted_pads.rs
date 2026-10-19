//! The pads of a promoted window's world (FIX 3789). A pad rides its world's
//! window of the month its row was learned, and a machine that syncs what it
//! opened follows only the windows it promoted, so a key of the world would
//! not open here. A promotion therefore also brings every pad of the window's
//! world the home holds, each with the window it rides, once the home has
//! admitted the whole window (`residence.promote`). Each row lands through the
//! explicit replay door under this machine's own tier, whose put door checks a
//! pad as window ingest would; nothing the home asserts is trusted beyond the
//! row. A window promoted here before asks again, on a reopen or a retain,
//! while a key of its world this vault's authority names has no pad here; its
//! promoted copy stays as it is.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use super::super::base::{ITEM11_UNREADABLE_HOME_PROMOTION, home_reads_window};
use super::{PromotionReply, ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::sync::client::ImportTier;
use crate::sync::replay::{ReplicatedEntity, replay_entity};
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;
use crate::{EntityId, TimeRange, Vault};

/// One pad row a promotion reply carries.
#[derive(Deserialize)]
pub(super) struct PromotedPad {
    id: String,
    window: String,
    raw: String,
}

/// One pad row of a promotion reply, checked.
pub(super) struct PadRow {
    id: EntityId,
    header: EntityMetadataHeader,
    raw: Zeroizing<Vec<u8>>,
}

/// The pad rows of a promotion reply for `window`, each checked before any
/// lands: a pad of `window`'s world, riding the window the home named for it,
/// which is its world's window of the month its row was learned. Any other
/// row refuses the reply.
pub(super) fn checked_pads(
    window: &WindowKey,
    pads: &[PromotedPad],
) -> Result<Vec<PadRow>, TransportError> {
    let world = window.world();
    pads.iter()
        .map(|pad| {
            let id = EntityId::from_hex(&pad.id).map_err(|_| refused())?;
            let raw = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(&pad.raw)
                    .map_err(|_| refused())?,
            );
            let header = EntityMetadataHeader::parse(&raw).ok_or_else(refused)?;
            let rides =
                crate::sync::residence::residence_window_for_blob(&raw).map_err(|_| refused())?;
            if world.is_none()
                || !matches!(
                    crate::world_keys::pad_body_world(&raw),
                    Some(Ok(of)) if Some(of) == world
                )
                || WindowKey::try_new(pad.window.as_str()) != Some(rides)
            {
                return Err(refused());
            }
            Ok(PadRow { id, header, raw })
        })
        .collect()
}

/// Lands each of `pads` this machine lacks, after a promotion of `window`. A
/// row the replay door refuses, or one a storage failure stops, is passed
/// over and logged: its key stays without its pad until a later reopen or
/// retain brings it.
pub(super) fn land_pads(vault: &Vault, window: &WindowKey, pads: &[PadRow]) {
    for pad in pads {
        if let Err(error) = land_pad(vault, pad) {
            tracing::warn!(%error, %window, row = %pad.id.to_hex(), "promoted pad not landed");
        }
    }
}

/// Lands one pad row unless this machine holds a row at its id.
fn land_pad(vault: &Vault, pad: &PadRow) -> crate::Result<()> {
    let held = {
        let rtxn = vault.store.env.read_txn()?;
        crate::ports::EntityStoreRead::port_entity_present(&vault.store, &rtxn, &pad.id)?
    };
    if held {
        return Ok(());
    }
    replay_entity(
        vault,
        ReplicatedEntity {
            id: pad.id,
            entity_type: pad.header.entity_type,
            occurred: TimeRange {
                start: pad.header.occurred_start,
                end: pad.header.occurred_end,
            },
            learned_at: pad.header.learned_at,
            body: &pad.raw[ENTITY_METADATA_HEADER_LEN..],
        },
        ImportTier::OwnDevice,
    )
}

impl SyncClient {
    /// Asks the home again for the pads of `window`'s world, a window promoted
    /// here before, while a key of the world this vault's authority names has
    /// no pad here (FIX 3789). The home admits the ask as a promotion, through
    /// `item` or else the first live row the window holds, and its snapshot is
    /// not imported. A failure is logged and waits for the next reopen or
    /// retain.
    pub(super) async fn catch_up_promoted_pads(
        &mut self,
        window: &WindowKey,
        item: Option<EntityId>,
    ) {
        if let Err(error) = self.ask_promoted_pads(window, item).await {
            tracing::warn!(%error, %window, "promoted window's pads not caught up");
        }
    }

    async fn ask_promoted_pads(
        &mut self,
        window: &WindowKey,
        item: Option<EntityId>,
    ) -> Result<(), TransportError> {
        let storage = |e: crate::Error| TransportError::Storage(e.to_string());
        let Some(world) = window.world() else {
            return Ok(());
        };
        if !self.vault.world_pads_missing(world).map_err(storage)? {
            return Ok(());
        }
        let item = match item {
            Some(item) => item,
            None => {
                let loaded = self.ensure_window(window.as_str())?;
                let mut first = None;
                crate::sync::loro_support::map_for_each_value_bytes(
                    &loaded.doc.get_map("entities"),
                    |key, value| {
                        if first.is_none() && value.is_some() {
                            first = EntityId::from_hex(key).ok();
                        }
                    },
                );
                let Some(first) = first else {
                    return Ok(());
                };
                first
            }
        };
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
        // A home that may not read the window's world is not told its name
        // (FIX 922 item 11).
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
        land_pads(&self.vault, window, &checked_pads(window, &reply.pads)?);
        Ok(())
    }
}
