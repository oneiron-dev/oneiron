//! Sync-specific types for the CRDT sync layer.
//!
//! NOTE (ONE-1130): `SyncConfig` stays — the window manager (ONE-1125)
//! reads `default_window_count` — but its former compaction fields (512 KB
//! threshold + 30 s throttle) and the vector-sync flag were removed: the
//! compaction feature they configured is not implemented and nothing read
//! them. The contract values live in ARCH-0023b; re-introduce that config
//! together with the compaction implementation, not before it.

/// Configuration for the sync layer.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Number of windows loaded by default (current + previous month). Default: 2.
    pub default_window_count: u8,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            default_window_count: 2,
        }
    }
}

/// A local CRDT update routed to the connection's outbound path.
///
/// Produced by Observer A ([`crate::sync::bridge::OutboundSink`]) for every
/// persisted local commit and consumed by the connection's debounce → wire
/// loop. `update_bytes` are raw Loro update bytes (not wire-encoded yet).
#[derive(Debug)]
pub struct LocalUpdate {
    /// Window key (`YYYY-MM` or `YYYY-MM@<world hex>`).
    pub window_key: String,
    /// Raw Loro update bytes (not wire-encoded yet).
    pub update_bytes: Vec<u8>,
}

pub use crate::memory::message_presence::{MessagePresenceScope, ScopedPresenceFrame};

pub use crate::window_key::WindowKey;
pub(crate) use crate::window_key::parse_window_key_str;

/// The ledger-plane partition axis: only CLAIM and WORLD_KEY_PAD bodies and a
/// world's side entries (its key wraps and the joins over its side leaves)
/// name a world. Other entity families, a world's settings entries included,
/// remain in the shared base window.
pub(crate) fn entity_world(raw: &[u8]) -> crate::error::Result<Option<crate::EntityId>> {
    use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
    // ITEM11_LIVE_PAD_CARRIER: a live pad rides its world's month windows. A
    // pad that does not decode stays in the base window's quarantine.
    if let Some(Ok(world)) = crate::world_keys::pad_body_world(raw) {
        return Ok(Some(world));
    }
    let header =
        EntityMetadataHeader::parse(raw).ok_or(crate::Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        // A world's side entries ride its month windows, to its readers only
        // (FIX 3871). An entry that does not decode stays in the base window.
        return Ok(authority_side_entry_world(raw));
    }
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?.world)
}

/// The world of the AUTHORITY_LOG row `raw` when the row is one of that
/// world's side entries (`authority::side_world`), which places the row in
/// the world's month windows, to its readers only. It covers both kinds of
/// side entry: the world's key wraps (FIX 3871), and the joins a carrier
/// stages over the world's side leaves (FIX 11868). `None` for any other
/// row, a world's settings entry included, and for an entry that does not
/// decode.
pub(crate) fn authority_side_entry_world(raw: &[u8]) -> Option<crate::EntityId> {
    use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
    if EntityMetadataHeader::parse(raw)?.entity_type != crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        return None;
    }
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..)?;
    let entry = crate::authority::decode_authority_log_entry_body(body).ok()?;
    crate::authority::side_world(&entry.op)
}

/// Validate residence before replay/export. A malformed CLAIM cannot be
/// assigned to any partition and therefore must not cross the wire.
pub(crate) fn entity_belongs_to_window(raw: &[u8], key: &WindowKey) -> bool {
    match entity_world(raw) {
        Ok(world) => {
            world == key.world()
                && (world.is_none()
                    || crate::batch::EntityMetadataHeader::parse(raw).is_some_and(|header| {
                        WindowKey::from_timestamp(header.learned_at).0 == key.0[..7]
                    }))
        }
        // Retain existing base-mode quarantine for malformed opaque carriers.
        // A world window never admits a row with no proven world assignment.
        Err(_) => key.world().is_none(),
    }
}

/// Exact retained CLAIM shells carry no body/world field. Only a paired
/// canonical soft tombstone plus trusted recovery, or this vault's durable
/// deletion address, can bind the shell to a world window.
#[expect(
    clippy::too_many_arguments,
    reason = "the pass's tombstone index rides beside the window's existing inputs"
)]
pub(crate) fn retained_world_shell_belongs_to_window(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    doc: &loro::LoroDoc,
    tombstones: &crate::sync::loro_support::TombstoneIndex,
    id: &crate::EntityId,
    blob: &[u8],
    key: &WindowKey,
    trusted: bool,
) -> crate::error::Result<bool> {
    if key.world().is_none() || blob.len() != crate::batch::ENTITY_METADATA_HEADER_LEN {
        return Ok(false);
    }
    let Some(header) = crate::batch::EntityMetadataHeader::parse(blob) else {
        return Ok(false);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || WindowKey::from_timestamp(header.learned_at).0 != key.0[..7]
    {
        return Ok(false);
    }
    let Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(value))) =
        tombstones.map().get(&id.to_hex())
    else {
        return Ok(false);
    };
    if crate::deletion::decode_tombstone_value(&value).reason
        != Some(crate::deletion::TombstoneReason::UserDelete)
        || tombstones.values_for(id).len() != 1
    {
        return Ok(false);
    }
    if doc.get_map("entities").get(&id.to_hex()).is_some()
        && crate::recovery::retained_soft_shell(doc, tombstones, id).is_none()
    {
        return Ok(false);
    }
    if trusted {
        return Ok(true);
    }
    let mapped = tombstone_residence_in(vault, txn, id, key)?;
    if mapped == TombstoneResidence::Wrong {
        return Ok(false);
    }
    if mapped == TombstoneResidence::Match {
        return Ok(true);
    }
    Ok(key.world().is_some_and(|world| {
        crate::sync::loro_support::map_get_bytes(
            &doc.get_map("retained_claim_worlds"),
            &id.to_hex(),
        )
        .as_deref()
            == Some(world.as_bytes().as_slice())
    }))
}

/// An edge with a world endpoint lives in that world, alongside the shared
/// base endpoint. Edges joining two different worlds are not replicated.
pub(crate) fn edge_worlds_match(
    source: Option<crate::EntityId>,
    target: Option<crate::EntityId>,
    key: &WindowKey,
) -> bool {
    match key.world() {
        None => source.is_none() && target.is_none(),
        Some(world) => {
            (source == Some(world) || target == Some(world))
                && [source, target]
                    .iter()
                    .all(|axis| axis.is_none_or(|id| id == world))
        }
    }
}

pub(crate) fn edge_belongs_to_window(
    vault: &crate::Vault,
    source: &crate::EntityId,
    target: &crate::EntityId,
    key: &WindowKey,
) -> crate::error::Result<bool> {
    let src = vault.get_raw_unsealed(source)?;
    let tgt = vault.get_raw_unsealed(target)?;
    let (Some(src), Some(tgt)) = (src, tgt) else {
        // Preserve the existing base-mode deferred-endpoint handling; a
        // world edge with no proof of its second endpoint cannot travel.
        return Ok(key.world().is_none());
    };
    let resident_world = |id: &crate::EntityId,
                          raw: &[u8]|
     -> crate::error::Result<Option<Option<crate::EntityId>>> {
        match entity_world(raw) {
            Ok(world) => Ok(Some(world)),
            Err(error) => {
                let shell = crate::batch::EntityMetadataHeader::parse(raw).is_some_and(|header| {
                    header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                        && raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
                });
                if !shell || key.world().is_none() {
                    return Err(error);
                }
                let txn = vault.store.env.read_txn()?;
                if tombstone_residence_in(vault, &txn, id, key)? == TombstoneResidence::Match {
                    Ok(Some(key.world()))
                } else {
                    Ok(None) // A shell assigned to another world cannot travel here.
                }
            }
        }
    };
    let Some(src_world) = resident_world(source, &src)? else {
        return Ok(false);
    };
    let Some(tgt_world) = resident_world(target, &tgt)? else {
        return Ok(false);
    };
    if !edge_worlds_match(src_world, tgt_world, key) {
        return Ok(false);
    }
    if key.world().is_some() {
        // Base→world edges reside with the world TARGET's birth month.
        // All other world edges reside with their source's birth month.
        let carrier = if src_world.is_none() { &tgt } else { &src };
        let header = crate::batch::EntityMetadataHeader::parse(carrier)
            .ok_or(crate::Error::CorruptedIndex("entity metadata"))?;
        return Ok(WindowKey::from_timestamp(header.learned_at).0 == key.0[..7]);
    }
    Ok(true)
}

/// Validate a received edge against both CRDT carriers and LMDB rows.
/// World edges require proven endpoints; base edges retain the existing
/// deferred-unknown-endpoint behavior but cannot name a known world claim.
pub(crate) fn edge_belongs_to_window_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    doc: &loro::LoroDoc,
    tombstones: &crate::sync::loro_support::TombstoneIndex,
    source: &crate::EntityId,
    target: &crate::EntityId,
    key: &WindowKey,
) -> crate::error::Result<bool> {
    let entities = doc.get_map("entities");
    let mut worlds = [None, None];
    let mut learned_at = [None, None];
    for (index, id) in [source, target].iter().enumerate() {
        let in_doc = crate::sync::loro_support::map_get_bytes(&entities, &id.to_hex());
        let stored = crate::ports::EntityStoreRead::port_entity_raw_wiped(&vault.store, txn, id)?;
        // A malformed peer carrier in a base doc is quarantined by the
        // entity pass. Keep the old deferred-edge behavior instead of
        // converting that remote rejection into local index corruption.
        let doc_world = match in_doc.as_ref().map(|raw| entity_world(raw)) {
            Some(Ok(world)) => Some(world),
            Some(Err(_)) if key.world().is_none() => None,
            Some(Err(_))
                if retained_world_shell_belongs_to_window(
                    vault,
                    txn,
                    doc,
                    tombstones,
                    id,
                    in_doc.as_deref().expect("matched"),
                    key,
                    false,
                )? =>
            {
                Some(key.world())
            }
            Some(Err(_)) => return Ok(false),
            None => None,
        };
        let stored_world = match stored.as_ref().map(|raw| entity_world(raw)) {
            Some(Ok(world)) => Some(world),
            Some(Err(_))
                if retained_world_shell_belongs_to_window(
                    vault,
                    txn,
                    doc,
                    tombstones,
                    id,
                    stored.as_deref().expect("matched"),
                    key,
                    false,
                )? =>
            {
                Some(key.world())
            }
            Some(Err(error)) => return Err(error),
            None => None,
        };
        if let (Some(doc_world), Some(stored_world)) = (doc_world, stored_world)
            && doc_world != stored_world
        {
            return Ok(false);
        }
        worlds[index] = doc_world.or(stored_world);
        let carrier = in_doc.as_deref().or(stored.as_deref().map(Vec::as_slice));
        learned_at[index] = carrier
            .and_then(crate::batch::EntityMetadataHeader::parse)
            .map(|header| header.learned_at);
    }
    if key.world().is_some()
        && (worlds.iter().any(Option::is_none) || learned_at.iter().any(Option::is_none))
    {
        return Ok(false);
    }
    if !edge_worlds_match(worlds[0].flatten(), worlds[1].flatten(), key) {
        return Ok(false);
    }
    if key.world().is_some() {
        let carrier_at = if worlds[0].flatten().is_none() {
            learned_at[1]
        } else {
            learned_at[0]
        };
        return Ok(carrier_at.is_some_and(|at| WindowKey::from_timestamp(at).0 == key.0[..7]));
    }
    Ok(true)
}

/// Proof of residence for a delete which has no body of its own. An unknown
/// world target must not create a process-wide hard-delete marker: the same
/// entity ID might later be admitted under another world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TombstoneResidence {
    Match,
    Wrong,
    Unknown,
}

pub(crate) fn tombstone_residence_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &crate::EntityId,
    key: &WindowKey,
) -> crate::error::Result<TombstoneResidence> {
    use crate::ports::{DeletionMarker, TombstoneStoreRead};
    let mapped = vault
        .store
        .port_deletion_marker(txn, DeletionMarker::WindowAddress, id)?
        .map(|raw| {
            std::str::from_utf8(&raw)
                .ok()
                .and_then(WindowKey::try_new)
                .ok_or(crate::Error::InvalidKey)
        })
        .transpose()?;
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(&vault.store, txn, id)?
    {
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(crate::Error::CorruptedIndex("entity metadata"))?;
        // The existing protected-record gate owns this refusal. Residence
        // must not replace its typed MaintenanceKindNotWritable reason.
        if crate::registry::is_delete_protected_engine_record(header.entity_type) {
            return Ok(TombstoneResidence::Match);
        }
        // A CLAIM or key pad shell has lost the body that named its world: its
        // deletion address answers below.
        if !matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_CLAIM | crate::registry::ENTITY_TYPE_WORLD_KEY_PAD
        ) || raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            let actual_world = entity_world(&raw)?;
            let matches = actual_world == key.world()
                && (key.world().is_none()
                    || WindowKey::from_timestamp(header.learned_at).0 == key.0[..7])
                && mapped.as_ref().is_none_or(|mapped| mapped == key);
            return Ok(if matches {
                TombstoneResidence::Match
            } else {
                TombstoneResidence::Wrong
            });
        }
    }
    Ok(match mapped {
        Some(mapped) if mapped == *key => TombstoneResidence::Match,
        Some(_) => TombstoneResidence::Wrong,
        None => TombstoneResidence::Unknown,
    })
}

/// Generates the Doc GUID for a window.
pub fn window_doc_guid(user_id: &str, key: &WindowKey) -> String {
    format!("vault:{user_id}:w:{key}")
}

/// Generates the Doc GUID for a root doc.
pub fn root_doc_guid(user_id: &str) -> String {
    format!("vault:{user_id}")
}

#[cfg(test)]
use crate::window_key::date_to_unix;

#[cfg(test)]
mod tests {
    use super::*;

    /// `from_timestamp` must stay total, bounded, and inside the ARCH-0023b
    /// `YYYY-MM` key format for ANY u64 input. The pre-fix code (a) cast `ts
    /// as i64`, so ts > i64::MAX wrapped negative and silently produced
    /// "1970-01", (b) walked one year per loop iteration toward the target
    /// (hundreds of billions of iterations for ts near i64::MAX), and (c)
    /// emitted >4-digit years ("10000-01") that `parse_window_key_str`
    /// rejects, stranding any sync_state rows written under them.
    #[test]
    fn window_key_from_timestamp_clamps_far_future_to_last_representable_window() {
        // Last second of year 9999 still maps inside the format.
        let last_valid = date_to_unix(9999, 12, 31).unwrap() + 86_399;
        assert_eq!(WindowKey::from_timestamp(last_valid).as_str(), "9999-12");

        // First second of year 10000 clamps (would otherwise be "10000-01").
        let year_10000 = date_to_unix(10_000, 1, 1).unwrap();
        assert_eq!(WindowKey::from_timestamp(year_10000).as_str(), "9999-12");

        // Extreme values: must terminate promptly and not sign-wrap.
        for ts in [i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
            let key = WindowKey::from_timestamp(ts);
            assert_eq!(key.as_str(), "9999-12", "ts={ts}");
            assert!(
                parse_window_key_str(key.as_str()).is_some(),
                "clamped key must satisfy the pinned YYYY-MM format"
            );
        }
    }
}
