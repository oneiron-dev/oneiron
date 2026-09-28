//! Discover locally held world/month partitions without loading their Docs.
//!
//! A fresh root can have LMDB claims but no persisted window snapshot yet.
//! Listing only root or `d:w:` misses those claims forever in sync-all mode.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, TimelineQuery};

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
        let raw = vault
            .store
            .entities
            .get(&txn, row.id.as_bytes())?
            .ok_or(Error::CorruptedIndex("temporal learned dangling entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity metadata"))?;
        if row.id == default_manifest
            || header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC
        {
            continue;
        }
        let base = WindowKey::from_timestamp(header.learned_at);
        keys.insert(base.to_string());
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            let scoped = if raw.len() > ENTITY_METADATA_HEADER_LEN {
                crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?.world
            } else {
                let mapping = format!("m:dw:{}", row.id.to_hex());
                vault
                    .store
                    .sync_state
                    .get(&txn, &mapping)?
                    .and_then(|raw| std::str::from_utf8(&raw).ok().and_then(WindowKey::try_new))
                    .and_then(|key| key.world())
            };
            if let Some(world) = scoped {
                keys.insert(WindowKey::for_month_world(&base, world).to_string());
            }
        }
    }
    for prefix in ["d:w:", "u:w:", "pt:"] {
        for row in vault.store.sync_state.prefix_iter(&txn, prefix)? {
            let (name, _) = row?;
            let suffix = &name[prefix.len()..];
            let key = if prefix == "d:w:" {
                suffix
            } else {
                suffix.split(':').next().unwrap_or("")
            };
            if let Some(key) = WindowKey::try_new(key) {
                keys.insert(key.to_string());
            }
        }
    }
    keys.into_iter()
        .map(WindowKey::try_new)
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::InvalidKey)
}
