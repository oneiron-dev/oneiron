//! Discover locally held world/month partitions without loading their Docs.
//!
//! A fresh root can have LMDB claims but no persisted window snapshot yet.
//! Listing only root or `d:w:` misses those claims forever in sync-all mode.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::{
    DeletionMarker, EntityStoreRead, TimelineQuery, TombstoneStoreRead, WindowDeletionRows,
};

use crate::sync::types::WindowKey;

/// Enumerates locally addressable partitions, including cfg-off delete intent.
/// Streaming reads keep working memory proportional to distinct keys, not rows.
pub fn discover_local_window_keys(vault: &Vault) -> Result<Vec<WindowKey>> {
    let default_manifest = crate::gate::default_policy_manifest_id()?;
    let txn = vault.store.env.read_txn()?;
    let mut keys = BTreeSet::new();
    for row in vault
        .store
        .port_entity_timeline(&txn, TimelineQuery::default())?
    {
        let row = row?;
        // The row is read in place: its header and, for a claim that carries
        // its body, a key pad or a key wrap entry, the body's world.
        let Some((header, body_world)) = vault
            .store
            .port_entity_with_raw(&txn, &row.id, |raw| {
                let header = EntityMetadataHeader::parse(raw)
                    .ok_or(Error::CorruptedIndex("entity metadata"))?;
                if row.id == default_manifest
                    || header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC
                {
                    return Ok(None);
                }
                let body_world = if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && raw.len() > ENTITY_METADATA_HEADER_LEN
                {
                    let body =
                        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                    Some(body.world)
                } else if let Ok(Some(world)) = crate::sync::types::entity_world(raw) {
                    // A live pad or key wrap rides its world's windows.
                    Some(Some(world))
                } else {
                    None
                };
                Ok(Some((header, body_world)))
            })?
            .ok_or(Error::CorruptedIndex("temporal learned dangling entity"))?
        else {
            continue;
        };
        let base = WindowKey::from_timestamp(header.learned_at);
        keys.insert(base.to_string());
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            let scoped = if let Some(world) = body_world {
                world
            } else {
                vault
                    .store
                    .port_deletion_marker(&txn, DeletionMarker::WindowAddress, &row.id)?
                    .and_then(|raw| std::str::from_utf8(&raw).ok().and_then(WindowKey::try_new))
                    .and_then(|key| key.world())
            };
            if let Some(world) = scoped {
                keys.insert(WindowKey::for_month_world(&base, world).to_string());
            }
        } else if let Some(Some(world)) = body_world {
            // A pad- or wrap-only month of a world is a partition too.
            keys.insert(WindowKey::for_month_world(&base, world).to_string());
        }
    }
    // A snapshot's whole label names its window; an update or pending tombstone names it by
    // the first segment of its key.
    for row in vault
        .store
        .port_window_doc_rows_raw(&txn, |window, _| WindowKey::try_new(window.as_str()))?
    {
        if let Some(key) = row? {
            keys.insert(key.to_string());
        }
    }
    for row in vault
        .store
        .port_window_update_keys(&txn, None, |name| first_segment(name, "u:w:"))?
    {
        if let Some(key) = row? {
            keys.insert(key.to_string());
        }
    }
    keys.extend(pending_tombstone_windows_in_txn(vault, &txn)?);
    keys.into_iter()
        .map(WindowKey::try_new)
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::InvalidKey)
}

/// The window an update or pending tombstone key names by its first segment.
fn first_segment(name: &str, prefix: &str) -> Option<WindowKey> {
    WindowKey::try_new(name[prefix.len()..].split(':').next().unwrap_or(""))
}

/// The windows whose committed `pt:` tombstones wait here, once each.
fn pending_tombstone_windows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<String>> {
    let mut windows = BTreeSet::new();
    for row in vault
        .store
        .port_pending_tombstone_rows_raw(txn, |name, _| first_segment(name, "pt:"))?
    {
        if let Some(key) = row? {
            windows.insert(key.to_string());
        }
    }
    Ok(windows)
}

/// Publishes every window's committed `pt:` tombstones now rather than at
/// its next load (FIX 3849): a raw transaction that staged them, outside
/// `BatchBuilder::commit` and `write_txn_door`, installs no postcommit
/// publication. A live lane's residence upkeep tick runs it. A window that
/// fails keeps its markers for the next tick or its load, and is logged.
pub(crate) fn retry_pending_tombstones(vault: &Vault) -> Result<u32> {
    let windows = pending_tombstone_windows_in_txn(vault, &vault.store.env.read_txn()?)?;
    let mut published = 0;
    for window in windows {
        let Some(key) = WindowKey::try_new(window.as_str()) else {
            continue;
        };
        match crate::sync::window::publish_pending_tombstones(vault, &key) {
            Ok(count) => published += count,
            Err(error) => tracing::warn!(
                %error,
                window = %window,
                "pending tombstones left to the next upkeep tick or the window's load"
            ),
        }
    }
    Ok(published)
}
