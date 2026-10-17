//! Which rows of a window a federation peer's import brought (Docs Q04).
//! Window admission judges a peer's rows in a read transaction before the
//! import; a door that must judge one again in its own writer transaction,
//! after a local change that committed in between, asks here. The import
//! records each such row with the exact bytes the peer brought before it
//! lands any of them, so the door tells the peer's row from this vault's own
//! by id and bytes, as the birth watch does, and forward rematerialization
//! after a crash still finds it.

use loro::LoroMap;

use crate::batch::EntityMetadataHeader;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_EMBEDDING_SETUP};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::{EntityId, Vault};

/// The kinds whose door judges a peer's row apart from this vault's own.
const PEER_JUDGED_KINDS: [u8; 2] = [ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_EMBEDDING_SETUP];

/// The blake3 digest of the bytes a peer's import brought for one row of a
/// window. Key: hex32 (entity id) ":" window key.
const PEER_ORIGIN: SideTable<String, [u8; 32], Raw> = SideTable::new(&side_table::SYNC_PEER_ORIGIN);

fn origin_key(window_key: &str, id: &EntityId) -> String {
    format!("{}:{window_key}", id.to_hex())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn judged(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob)
        .is_some_and(|header| PEER_JUDGED_KINDS.contains(&header.entity_type))
}

/// The rows of a peer's admitted entities map whose door judges them by
/// origin, each with the digest of the bytes the peer brought.
pub(in crate::sync) fn peer_rows(entities: &LoroMap) -> Vec<(EntityId, [u8; 32])> {
    let mut rows = Vec::new();
    map_for_each_value_bytes(entities, |key, value| {
        if let (Ok(id), Some(blob)) = (EntityId::from_hex(key), value)
            && judged(blob)
        {
            rows.push((id, digest(blob)));
        }
    });
    rows
}

/// Records the rows a peer's import brings into `window_key`, committed
/// before the import lands any of them. A later import of the same row
/// supersedes its record.
pub(in crate::sync) fn record_peer_rows(
    vault: &Vault,
    window_key: &str,
    rows: &[(EntityId, [u8; 32])],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for (id, sent) in rows {
            PEER_ORIGIN.put(&vault.store, wtxn, &origin_key(window_key, id), sent)?;
        }
        Ok(())
    })
}

/// Whether `blob` at `id` in `window_key` holds the exact bytes a peer's
/// import brought. A record whose row now holds other bytes is dropped: its
/// carrier was replaced.
pub(in crate::sync) fn peer_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &EntityId,
    blob: &[u8],
) -> Result<bool> {
    let key = origin_key(window_key, id);
    let Some(held) = PEER_ORIGIN.get(&vault.store, wtxn, &key)? else {
        return Ok(false);
    };
    if held == digest(blob) {
        return Ok(true);
    }
    PEER_ORIGIN.delete(&vault.store, wtxn, &key)?;
    Ok(false)
}

/// Drops the record of each carrier a local path removes, in any window,
/// when it holds those exact bytes.
pub(in crate::sync) fn forget_peer_rows(
    vault: &Vault,
    carriers: &[(EntityId, Vec<u8>)],
) -> Result<()> {
    if !carriers.iter().any(|(_, carrier)| judged(carrier)) {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for (id, carrier) in carriers.iter().filter(|(_, carrier)| judged(carrier)) {
            let removed = digest(carrier);
            let prefix = format!("{}:", id.to_hex());
            for (key, held) in PEER_ORIGIN.scan_from(&vault.store, wtxn, prefix.as_bytes())? {
                if held == removed {
                    PEER_ORIGIN.delete(&vault.store, wtxn, &key)?;
                }
            }
        }
        Ok(())
    })
}
