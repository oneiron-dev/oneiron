//! Companion-register admission/scrub, identity topology ingest, and edge key/value helpers.

use std::collections::HashSet;

use loro::{CommitOptions, LoroDoc, LoroMap};

use super::BRIDGE_ORIGIN;
use super::entities::materialize_entity_blob_in_txn;

use crate::affect::Vad;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::companion::{
    CompanionExportClassification, ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::edge::{
    DecodedEdgeValue, EdgeKind, EdgeProvenanceFlags, decode_edge_value, encode_edge_value,
};
use crate::entity_id::EntityId;
use crate::error::SyncError;
use crate::sync::loro_support::{
    map_delete, map_for_each_bytes, map_get_bytes, tombstone_map_contains_id,
};
use crate::sync::quota;
use crate::{Error, Result, Vault};

/// Shared fail-closed ingest door for replicated type-76 identity-topology
/// event records (ARCH-0023b single-writer stream class, AUTHORITY_LOG
/// shape). Observer B's entity pass and forward rematerialization BOTH
/// route here, so every sync entry point enforces the same trust model:
///
/// * byte-identical replay → idempotent short-circuit after validation and
///   seq-clock join, before quota or full-family reconciliation; derived
///   shell healing rides the bounded edge echo/materialization paths rather
///   than making unchanged startup replay quadratic;
/// * divergent bytes for an existing id → typed
///   [`SyncError::IdentityTopologyEventDivergence`](crate::error::SyncError::IdentityTopologyEventDivergence) (equivocation on an
///   immutable single-writer record: local bytes win; callers quarantine
///   via `remote_rejection_reason`, never abort, never silent-LWW);
/// * a fresh id → fail-closed D18 body validation, per-stream ingest
///   quota, the replicated put, then `seq = max(local, incoming)` and
///   shell-edge reconciliation from the ledger fold — the sync twin of the
///   local door's atomic record+edges commit (the ruled invariant:
///   `merged_into` / `split_into` edges only move as a door side-effect of
///   a validated type-76 event).
pub(crate) fn ingest_replicated_identity_topology_event_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
    data: &[u8],
    lease_vault_id: u64,
) -> Result<bool> {
    let byte_identical_replay = vault
        .store
        .entities
        .get(&*wtxn, id.as_bytes())?
        .map(|existing| *existing == *blob);
    match byte_identical_replay {
        Some(true) => {
            // The stored bytes equal the replayed bytes, so a decode
            // failure here is on-disk corruption — LOCAL, fail-closed —
            // never a rejectable remote input.
            let record =
                crate::identity_topology::decode_replicated_identity_topology_event_body(data)
                    .map_err(|_| crate::Error::CorruptedIndex("identity topology event body"))?;
            validate_replicated_identity_topology_record_before_mutation(vault, &*wtxn, &record)?;
            vault.advance_identity_topology_seq_in_txn(wtxn, record.seq)?;
            vault.neutralize_delete_protected_marker_in_txn(
                wtxn,
                id,
                crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            )?;
            return Ok(false);
        }
        Some(false) => {
            return Err(crate::Error::Sync(
                crate::error::SyncError::IdentityTopologyEventDivergence { id: *id },
            ));
        }
        None => {}
    }
    let record = crate::identity_topology::decode_replicated_identity_topology_event_body(data)?;
    validate_replicated_identity_topology_record_before_mutation(vault, &*wtxn, &record)?;
    let quota_debit = quota::try_accept_maintenance_ingest_peer_in_txn(
        vault,
        wtxn,
        quota::peer_key_from_identity_topology_stream(lease_vault_id),
        crate::unix_seconds_now(),
    )?;
    let apply_result = vault
        .batch_in()
        .put_replicated(
            id,
            header.entity_type,
            crate::temporal::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(wtxn);
    if let Err(err) = apply_result {
        if let Some(quota_debit) = quota_debit {
            quota::rollback_maintenance_ingest_debit_in_txn(vault, wtxn, quota_debit)?;
        }
        return Err(err);
    }
    vault.advance_identity_topology_seq_in_txn(wtxn, record.seq)?;
    vault.reconcile_identity_topology_edges_in_txn(wtxn)?;
    vault.neutralize_delete_protected_marker_in_txn(
        wtxn,
        id,
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
    )?;
    Ok(true)
}

/// Maps the shared local-door participant rejection into the existing
/// type-76 remote-input class. This runs before quota, put, seq join, or
/// reconciliation, so quarantine-and-continue can never commit a rejected
/// event row as a side effect of handling the rejection.
fn validate_replicated_identity_topology_record_before_mutation(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> Result<()> {
    vault
        .validate_replicated_identity_topology_event_in_txn(rtxn, record)
        .map_err(|err| match err {
            Error::Sync(SyncError::IdentityTopologyRejected(
                crate::identity_topology::IdentityTopologyRejection::NotStructural { .. }
                | crate::identity_topology::IdentityTopologyRejection::FacetMerge { .. },
            )) => Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
                "identity topology event participant is not merge-eligible structural state",
            )),
            Error::ActorClassMismatch { .. } => {
                Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
                    "identity topology event actor class does not match the available actor",
                ))
            }
            other => other,
        })
}

pub(super) fn ensure_companion_register_kind_for_entity_delta(
    vault: &Vault,
    delta: &loro::event::MapDelta<'_>,
) -> Result<()> {
    for new_val in delta.updated.values() {
        let Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) = new_val else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(blob) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            continue;
        }
        let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
            &blob[ENTITY_METADATA_HEADER_LEN..]
        } else {
            &[]
        };
        if companion_register_sync_admitted(data).unwrap_or(false) {
            vault.ensure_companion_register_kind()?;
            return Ok(());
        }
    }
    Ok(())
}

pub(super) fn companion_register_sync_admitted(data: &[u8]) -> Result<bool> {
    let record = decode_companion_record_body(data)?;
    Ok(record.export_classification != CompanionExportClassification::LocalOnly)
}

pub(super) fn companion_register_blob_is_local_only(blob: &[u8]) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return Err(Error::CorruptedIndex("entity metadata"));
    };
    if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
        return Ok(false);
    }
    let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
        &blob[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };
    Ok(!companion_register_sync_admitted(data)?)
}

pub(super) struct CompanionCrdtScrub {
    entity_key: String,
    id: EntityId,
}

impl CompanionCrdtScrub {
    pub(super) fn new(entity_key: impl Into<String>, id: EntityId) -> Self {
        Self {
            entity_key: entity_key.into(),
            id,
        }
    }
}

pub(super) fn scrub_local_only_companions_from_crdt(
    doc: &LoroDoc,
    scrubs: &[CompanionCrdtScrub],
) -> Result<()> {
    if scrubs.is_empty() {
        return Ok(());
    }

    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let mut changed = false;
    let mut ids = HashSet::new();

    for scrub in scrubs {
        ids.insert(scrub.id);
        if entities_map.get(scrub.entity_key.as_str()).is_some() {
            map_delete(&entities_map, scrub.entity_key.as_str())?;
            changed = true;
        }
    }

    let mut edge_keys = Vec::new();
    map_for_each_bytes(&edges_map, |edge_key, _| {
        if let Some((src, _, tgt)) = parse_edge_key(edge_key)
            && (ids.contains(&src) || ids.contains(&tgt))
        {
            edge_keys.push(edge_key.to_owned());
        }
    });
    for edge_key in &edge_keys {
        map_delete(&edges_map, edge_key)?;
        changed = true;
    }

    if changed {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(())
}

/// Endpoint hydration outcome for Observer B edge materialization.
pub(super) enum EndpointHydration {
    /// Endpoint already present in LMDB — NO write was performed, so a batch
    /// rollback loses nothing for this endpoint (never flagged for remat).
    Ready,
    /// Endpoint body was just hydrated into LMDB from the CRDT entities map —
    /// an ACTUAL write. Carries the written blob so the edge-batch swallow
    /// site can flag a durable `rm:` marker for this endpoint if the whole
    /// txn rolls back (ONE-1147 fix-wave): the rolled-back hydration write
    /// would otherwise vanish silently — unmarked, and with no edge
    /// necessarily tracked to carry it. The caller treats it identically to
    /// `Ready` for the edge's own fate (the edge proceeds).
    Hydrated(Vec<u8>),
    /// Endpoint absent or tombstoned — defer the edge (it stays in the CRDT
    /// and re-materializes when its endpoint does).
    Deferred,
    /// Endpoint is a local-only companion register row. Edges touching it
    /// must not materialize or remain in a shared CRDT window.
    LocalOnly,
    /// The endpoint's CRDT entities-map blob is structurally undecodable —
    /// REMOTE garbage by construction (the blob came from the remote doc),
    /// so the edge op is rejected with it (quarantined by the caller). Never
    /// conflated with the engine's own LOCAL `CorruptedIndex`, which stays a
    /// fail-closed typed error.
    RejectedBlob,
}

// Test-only LOCAL endpoint-hydration failure injection for the fail-closed
// split tests: when set to an entity id, the next hydration of that id
// returns a non-remote-classifiable error (the engine's own read failing).
// One-shot, thread-local (Loro observer callbacks fire synchronously on the
// committing thread).

#[cfg(test)]
thread_local! {
    pub(in crate::sync) static INJECT_LOCAL_ENDPOINT_FAILURE: std::cell::Cell<Option<EntityId>> =
        const { std::cell::Cell::new(None) };
}

pub(super) fn ensure_entity_materialized_from_crdt(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entities_map: &LoroMap,
    tombstones_map: &LoroMap,
    window_key: &str,
    id: &EntityId,
    lease_vault_id: u64,
) -> Result<EndpointHydration> {
    #[cfg(test)]
    {
        let inject = INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| {
            if cell.get() == Some(*id) {
                cell.set(None);
                true
            } else {
                false
            }
        });
        if inject {
            return Err(Error::Io(std::io::Error::other(
                "injected local endpoint read failure (test hook)",
            )));
        }
    }

    // Tombstone gate FIRST: a tombstoned OR locally hard-deleted (`dt:`
    // marker) endpoint must never count as "ready", even while a stale LMDB
    // row survives (crash window between the tombstone CRDT commit and the
    // purge txn, or a failed purge). Checking row existence first would
    // materialize an edge onto the stale row — re-adding an active carrier
    // ARCH-0038 requires purged. Presence is ANY-value (fail closed):
    // non-binary tombstones gate too. Without the dt: leg, a crafted
    // tombstone removal would make the silent gate-skip read as "ready" and
    // push an edge op against a missing endpoint;
    // `materialize_entity_blob_in_txn` re-checks both as the structural
    // fail-closed gate before its put.
    //
    // Value-agnostic, entity-canonical tombstone presence (a non-binary
    // tombstone decodes HARD downstream; a case-shifted hex key still
    // names this id) OR the permanent local `dt:` marker: an edge whose
    // endpoint was hard-deleted must not hydrate the endpoint body back
    // into LMDB even after hostile tombstone-map manipulation.
    if tombstone_map_contains_id(tombstones_map, id)
        || vault.local_hard_delete_marker_exists_in_txn(wtxn, id)?
    {
        return Ok(EndpointHydration::Deferred);
    }

    if let Some(raw) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
        if companion_register_blob_is_local_only(&raw)? {
            return Ok(EndpointHydration::LocalOnly);
        }
        return Ok(EndpointHydration::Ready);
    }

    let hex_id = id.to_hex();
    let Some(blob) = map_get_bytes(entities_map, &hex_id) else {
        return Ok(EndpointHydration::Deferred);
    };
    // Structural pre-validation of the REMOTE blob (mirrors the entity
    // delta path's decode-before-local-read ordering): an unparsable
    // endpoint blob is remote garbage, distinguished from the LOCAL
    // `CorruptedIndex` that `materialize_entity_blob_in_txn` would conflate
    // it with at the caller's classification.
    if EntityMetadataHeader::parse(&blob).is_none() {
        return Ok(EndpointHydration::RejectedBlob);
    }
    if companion_register_blob_is_local_only(&blob)? {
        return Ok(EndpointHydration::LocalOnly);
    }
    if !materialize_entity_blob_in_txn(
        vault,
        wtxn,
        tombstones_map,
        window_key,
        &hex_id,
        &blob,
        lease_vault_id,
    )? {
        return Ok(EndpointHydration::Deferred);
    }
    // ONE-1147 fix-wave: distinguish an ACTUAL hydration write from the
    // already-present `Ready` above, carrying the written bytes so the
    // edge-batch swallow site can flag a durable rm: marker (parity guard +
    // heal-on-write discharge) if this write is later rolled back. `blob` is
    // moved into the variant after `materialize_entity_blob_in_txn` borrowed
    // it.
    Ok(EndpointHydration::Hydrated(blob))
}

/// Parses an edge key: `{src_hex}:{kind_u8:02}:{tgt_hex}` → (src, kind, tgt).
///
/// Uses `:` delimiter splitting instead of byte-index slicing for panic safety.
pub fn parse_edge_key(key: &str) -> Option<(EntityId, EdgeKind, EntityId)> {
    let mut parts = key.splitn(3, ':');
    let src_hex = parts.next()?;
    let kind_str = parts.next()?;
    let tgt_hex = parts.next()?;

    // Validate expected segment lengths (32-char hex IDs, 2-char kind)
    if src_hex.len() != 32 || kind_str.len() != 2 || tgt_hex.len() != 32 {
        return None;
    }

    let src = EntityId::from_hex(src_hex).ok()?;
    let kind_u8: u8 = kind_str.parse().ok()?;
    let kind = EdgeKind::try_from_u8(kind_u8)?;
    let tgt = EntityId::from_hex(tgt_hex).ok()?;
    Some((src, kind, tgt))
}

/// Parses a 12/24/26-byte edge value.
pub fn parse_edge_value(buf: &[u8]) -> Option<DecodedEdgeValue> {
    decode_edge_value(buf).ok()
}

/// Encodes an edge value for CRDT map storage using the ARCH-0034 layout class.
pub fn encode_edge_value_for_crdt(
    kind: EdgeKind,
    weight: f32,
    created_at: u64,
    vad: Option<Vad>,
    provenance: Option<EdgeProvenanceFlags>,
) -> Result<Vec<u8>> {
    encode_edge_value(
        kind,
        weight,
        created_at,
        vad.unwrap_or(Vad::NEUTRAL),
        provenance,
    )
}

/// Formats an edge key for CRDT map: `{src_hex}:{kind:02}:{tgt_hex}`.
pub fn format_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> String {
    format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex())
}
