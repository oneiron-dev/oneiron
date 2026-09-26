//! The tombstone classification every replicated tombstone takes before replay.

use loro::LoroMap;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::deletion::decode_tombstone_value;
use crate::entity_id::EntityId;
use crate::error::{Error, RegistryError};
use crate::sync::loro_support::map_get_bytes;
use crate::vault::Vault;

/// Where one tombstone goes.
#[derive(Debug)]
pub(in crate::sync) enum TombstoneStep {
    /// Refused before replay; the caller records it in `x:`. `id` is `None` when the key names
    /// no entity.
    Refuse { id: Option<EntityId>, err: Error },
    /// Replay the value through the reason-aware primitive (ONE-1133). `hard` when the value
    /// decodes as a hard delete: a non-binary value replays as the empty slice, which decodes
    /// HARD (fail closed: over-purge, never under-delete).
    Replay { id: EntityId, hard: bool },
}

/// Classifies one tombstones-map value. `value` is empty for a non-binary value.
///
/// A key that names no entity is refused. A tombstone over a delete-protected engine record
/// whose envelope sits in the window's entities map but has not reached LMDB yet is refused
/// too: protection must not depend on pass or observer callback order, and the headerless
/// replay path would otherwise mint a permanent `dt:` marker over the record. A protected row
/// already in LMDB is refused by the replay primitive itself.
pub(in crate::sync) fn classify_tombstone(
    vault: &Vault,
    entities_map: &LoroMap,
    key: &str,
    value: &[u8],
) -> TombstoneStep {
    let Ok(id) = EntityId::from_hex(key) else {
        return TombstoneStep::Refuse {
            id: None,
            err: Error::InvalidKey,
        };
    };
    if matches!(vault.read_entity_header(&id), Ok(None))
        && let Some(entity_blob) = map_get_bytes(entities_map, &id.to_hex())
        && let Some(header) = admitted_concurrent_delete_protected_header(&entity_blob)
    {
        return TombstoneStep::Refuse {
            id: Some(id),
            err: Error::Registry(RegistryError::MaintenanceKindNotWritable(
                header.entity_type,
            )),
        };
    }
    TombstoneStep::Replay {
        id,
        hard: decode_tombstone_value(value).is_hard(),
    }
}

/// Classifies a concurrent peer envelope for tombstone protection only after running the same
/// deterministic body predicate as replicated type-76 ingestion. Other established protected
/// kinds keep their header classification; type-76 never gains protection from its header
/// alone.
fn admitted_concurrent_delete_protected_header(blob: &[u8]) -> Option<EntityMetadataHeader> {
    let header = EntityMetadataHeader::parse(blob)?;
    if !crate::registry::is_delete_protected_engine_record(header.entity_type) {
        return None;
    }
    if header.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        let data = &blob[ENTITY_METADATA_HEADER_LEN..];
        crate::identity_topology::decode_replicated_identity_topology_event_body(data).ok()?;
    }
    Some(header)
}
