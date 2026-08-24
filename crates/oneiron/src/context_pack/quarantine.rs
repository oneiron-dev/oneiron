//! Sync-quarantine rows read during pack assembly, and the index that excludes
//! quarantined entities from a pack.

use std::collections::HashSet;

use heed::RoTxn;
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

pub(super) const PACK_QUARANTINE_ROW: &str = "sync quarantine row";
const PACK_REMAT_MARKER_PREFIX: &str = "rm:w:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PackQuarantineContainer {
    Entities,
    Edges,
    Tombstones,
    Leases,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct PackQuarantineRecord {
    pub(super) window_key: String,
    pub(super) container: PackQuarantineContainer,
    pub(super) crdt_key_hash: u64,
    pub(super) crdt_key_len: u32,
}

#[derive(Debug, Default)]
pub(super) struct PackQuarantineIndex {
    active_entity_keys: HashSet<(u64, u32)>,
}

impl PackQuarantineIndex {
    pub(super) fn contains_entity(&self, id: &EntityId) -> bool {
        self.active_entity_keys
            .contains(&pack_entity_crdt_key_metadata(id))
    }
}

pub(super) fn load_pack_quarantine_index(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<PackQuarantineIndex> {
    let active_remat_markers = load_active_pack_entity_remat_markers(store, rtxn)?;
    let mut active_entity_keys: HashSet<(u64, u32)> = active_remat_markers
        .iter()
        .map(|(_window, entity_key)| *entity_key)
        .collect();
    let iter = store.sync_queue.prefix_iter(rtxn, b"x:")?;
    for entry in iter {
        let (key, value) = entry?;
        if !is_quarantine_key(&key) {
            continue;
        }
        let record = rmp_serde::from_slice::<PackQuarantineRecord>(&value)
            .map_err(|_| Error::CorruptedIndex(PACK_QUARANTINE_ROW))?;
        if record.container != PackQuarantineContainer::Entities {
            continue;
        }
        // `x:` rows are retained diagnostics; the pending `rm:w:` marker is
        // the live retry signal that keeps the referenced entity blocked.
        let entity_key = (record.crdt_key_hash, record.crdt_key_len);
        if active_remat_markers.contains(&(record.window_key, entity_key)) {
            active_entity_keys.insert(entity_key);
        }
    }
    Ok(PackQuarantineIndex { active_entity_keys })
}

fn load_active_pack_entity_remat_markers(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<HashSet<(String, (u64, u32))>> {
    let mut markers = HashSet::new();
    let iter = store
        .sync_state
        .prefix_iter(rtxn, PACK_REMAT_MARKER_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        let rest = &key[PACK_REMAT_MARKER_PREFIX.len()..];
        let Some((window_key, entity_hex)) = rest.split_once(':') else {
            continue;
        };
        if EntityId::from_hex(entity_hex).is_err() {
            continue;
        }
        markers.insert((window_key.to_string(), pack_crdt_key_metadata(entity_hex)));
    }
    Ok(markers)
}

pub(super) fn pack_entity_crdt_key_metadata(id: &EntityId) -> (u64, u32) {
    pack_crdt_key_metadata(&id.to_hex())
}

fn pack_crdt_key_metadata(key: &str) -> (u64, u32) {
    (
        xxh3_64(key.as_bytes()),
        u32::try_from(key.len()).unwrap_or(u32::MAX),
    )
}

fn is_quarantine_key(key: &[u8]) -> bool {
    key.len() == 10 && key.starts_with(b"x:")
}
