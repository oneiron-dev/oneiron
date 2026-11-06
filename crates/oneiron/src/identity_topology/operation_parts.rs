//! One merge, split or facet decision too large for one record, carried
//! across bounded records of the same family (FIX 10188).
//!
//! A decision whose inline record would pass the body bound, or name more
//! participants or masks than one record may, is stored as an
//! [`StoredIdentityOpAction::OperationManifest`] under the decision's own id
//! plus `parts` [`StoredIdentityOpAction::OperationPart`] records under ids
//! derived from (manifest id, index). The parts carry the decision's own
//! inline record body, byte for byte; the manifest names its length and
//! digest, and the decision's signed admission binds the manifest, so no
//! part can be forged, dropped or reordered without the decision reading as
//! absent.
//!
//! Every reader that reasons about a decision's participants, heads, masks
//! or map reads the ASSEMBLED record
//! ([`logical_identity_topology_event_for_store_in_txn`]). Seals,
//! attribution and core digests keep reading the stored manifest, which is
//! the record the admission signed. A manifest whose parts are not all here,
//! or do not add up to its digest, is pending: it folds, receipts and undoes
//! as nothing, and the arrival of its last part completes it. Nothing ever
//! reads a prefix as a smaller decision.

use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::IDENTITY_TOPOLOGY_OPERATION_PART;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::store::Store;
use crate::vault::Vault;

use super::event_body_codec::{
    decode_identity_topology_event_body, decode_identity_topology_operation_payload,
    encode_identity_topology_event_body,
};
use super::store_entity_helpers::identity_topology_event_for_store_in_txn;
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::wire_keys::{
    IDENTITY_TOPOLOGY_OPERATION_PART_BYTES, MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES,
    MAX_IDENTITY_TOPOLOGY_EVENT_FACETS, MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS,
};
use crate::error::SyncError;

/// The id of part `index` of the manifest `root`.
pub(crate) fn operation_part_id(root: &EntityId, index: u32) -> Result<EntityId> {
    EntityId::derive(
        IDENTITY_TOPOLOGY_OPERATION_PART,
        &[root.as_bytes(), &index.to_be_bytes()],
    )
}

/// The digest a manifest names: its payload, bound to the manifest's own id
/// so one payload cannot stand for another decision.
fn operation_payload_digest(root: &EntityId, payload: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("oneiron identity-topology operation payload v1");
    hasher.update(root.as_bytes());
    hasher.update(&(payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Whether `decision`, whose inline body is `body_len` bytes, fits one
/// record: within the body bound and the per-record participant and mask
/// bounds.
fn fits_one_record(decision: &StoredIdentityOpEvent, body_len: usize) -> bool {
    if body_len > MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES {
        return false;
    }
    // Participants count the survivor of a merge and the original of a split.
    match &decision.action {
        StoredIdentityOpAction::Merge { sources, .. } => {
            sources.len() < MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS
        }
        StoredIdentityOpAction::Split { heads, .. } => {
            heads.len() < MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS
        }
        StoredIdentityOpAction::Facet { facets, .. } => {
            facets.len() <= MAX_IDENTITY_TOPOLOGY_EVENT_FACETS
        }
        _ => true,
    }
}

/// The stored records of one decision.
pub(super) struct OperationRecords {
    /// The record stored under the decision's id: the decision itself, or
    /// its manifest.
    pub(super) root: StoredIdentityOpEvent,
    /// The part records with their derived ids, in payload order; empty for
    /// an inline decision.
    pub(super) parts: Vec<(EntityId, StoredIdentityOpEvent)>,
}

/// Lays out `decision`, stored under `id`, as bounded records. A decision
/// that fits one record is stored as itself, byte for byte as before FIX
/// 10188. A merge, split or facet that does not becomes a manifest plus
/// parts whose payload is the decision's inline body, so its assembled read
/// is exactly `decision`. Any other kind past the body bound stays one
/// record, and the write chokepoint's body check refuses it as before.
pub(super) fn operation_records(
    id: &EntityId,
    decision: StoredIdentityOpEvent,
) -> Result<OperationRecords> {
    let payload = encode_identity_topology_event_body(&decision)?;
    let carries_parts = matches!(
        decision.action,
        StoredIdentityOpAction::Merge { .. }
            | StoredIdentityOpAction::Split { .. }
            | StoredIdentityOpAction::Facet { .. }
    );
    if !carries_parts || fits_one_record(&decision, payload.len()) {
        return Ok(OperationRecords {
            root: decision,
            parts: Vec::new(),
        });
    }
    let mut parts = Vec::new();
    for (index, slice) in payload
        .chunks(IDENTITY_TOPOLOGY_OPERATION_PART_BYTES)
        .enumerate()
    {
        let index = u32::try_from(index).map_err(|_| {
            Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
                "identity topology operation payload exceeds the part index",
            ))
        })?;
        // A part is inert storage: it shares its decision's seq and time so
        // it claims no place of its own in the family's order.
        parts.push((
            operation_part_id(id, index)?,
            StoredIdentityOpEvent {
                seq: decision.seq,
                validated_at_write: false,
                invalidated: false,
                at: decision.at,
                actor: None,
                source: decision.source,
                approval: ClaimApprovalStatus::Auto,
                confidence: 1.0,
                evidence: None,
                action: StoredIdentityOpAction::OperationPart {
                    root: *id,
                    index,
                    payload: slice.to_vec(),
                },
            },
        ));
    }
    let part_count = u32::try_from(parts.len()).map_err(|_| {
        Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            "identity topology operation payload exceeds the part index",
        ))
    })?;
    let root = StoredIdentityOpEvent {
        seq: decision.seq,
        validated_at_write: decision.validated_at_write,
        invalidated: decision.invalidated,
        at: decision.at,
        actor: None,
        source: decision.source,
        approval: decision.approval,
        confidence: decision.confidence,
        evidence: None,
        action: StoredIdentityOpAction::OperationManifest {
            kind: decision.action.kind_str(),
            parts: part_count,
            length: payload.len() as u64,
            digest: operation_payload_digest(id, &payload),
        },
    };
    Ok(OperationRecords { root, parts })
}

/// The decision `raw`, stored under `id`, read whole: `raw` itself when it is
/// an inline record; the assembled payload when it is a manifest whose parts
/// are all here and add up to its length and digest; `None` for a part, and
/// for a manifest still waiting on a part, so no reader takes a prefix for a
/// smaller decision. A part that does not decode, or does not belong where
/// its id puts it, leaves its manifest pending rather than failing every
/// reader of the family.
///
/// The assembled record keeps the manifest's mutable historical flags; its
/// payload must agree with the manifest on every other envelope field.
pub(crate) fn logical_identity_topology_event_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: StoredIdentityOpEvent,
) -> Result<Option<StoredIdentityOpEvent>> {
    let manifest = match &raw.action {
        StoredIdentityOpAction::OperationPart { .. } => return Ok(None),
        StoredIdentityOpAction::OperationManifest {
            kind,
            parts,
            length,
            digest,
        } => Some((*kind, *parts, *length, *digest)),
        _ => None,
    };
    let Some((kind, parts, length, digest)) = manifest else {
        return Ok(Some(raw));
    };
    let mut payload = Vec::new();
    for index in 0..parts {
        let Some(row) = store.port_entity_record(rtxn, &operation_part_id(id, index)?)? else {
            return Ok(None);
        };
        if row.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
            return Ok(None);
        }
        let Ok(part) = decode_identity_topology_event_body(&row.body) else {
            return Ok(None);
        };
        let StoredIdentityOpAction::OperationPart {
            root,
            index: part_index,
            payload: slice,
        } = part.action
        else {
            return Ok(None);
        };
        if root != *id || part_index != index {
            return Ok(None);
        }
        payload.extend_from_slice(&slice);
        if payload.len() as u64 > length {
            return Ok(None);
        }
    }
    if payload.len() as u64 != length || operation_payload_digest(id, &payload) != digest {
        return Ok(None);
    }
    let Ok(decision) = decode_identity_topology_operation_payload(&payload) else {
        return Ok(None);
    };
    if decision.action.kind_str() != kind
        || decision.seq != raw.seq
        || decision.at != raw.at
        || decision.source != raw.source
        || decision.approval != raw.approval
        || decision.confidence.to_bits() != raw.confidence.to_bits()
        || decision.actor.is_some()
    {
        return Ok(None);
    }
    Ok(Some(StoredIdentityOpEvent {
        validated_at_write: raw.validated_at_write,
        invalidated: raw.invalidated,
        ..decision
    }))
}

/// The decision stored under `id`, read whole
/// ([`logical_identity_topology_event_for_store_in_txn`]); `Ok(None)` when
/// the id is absent too.
pub(crate) fn identity_topology_decision_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StoredIdentityOpEvent>> {
    let Some(raw) = identity_topology_event_for_store_in_txn(store, rtxn, id)? else {
        return Ok(None);
    };
    logical_identity_topology_event_for_store_in_txn(store, rtxn, id, raw)
}

/// Refuses an operation part stored under any id but the one its manifest
/// and index derive, so a part can neither squat another record's id nor be
/// read twice.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn validate_operation_part_id(
    id: &EntityId,
    record: &StoredIdentityOpEvent,
) -> Result<()> {
    if let StoredIdentityOpAction::OperationPart { root, index, .. } = &record.action
        && *id != operation_part_id(root, *index)?
    {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            "identity topology operation part is stored under another id",
        )));
    }
    Ok(())
}

impl Vault {
    /// The decision stored under `id`, read whole (FIX 10188): what a reader
    /// of its participants, heads, masks or map takes. `Ok(None)` for an
    /// absent id, an operation part, and a manifest still waiting on a part.
    /// A seal or core digest reads the stored record instead
    /// ([`Vault::identity_topology_event_in_txn`]).
    pub(crate) fn identity_topology_decision_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<StoredIdentityOpEvent>> {
        let Some(raw) = self.identity_topology_event_in_txn(rtxn, id)? else {
            return Ok(None);
        };
        logical_identity_topology_event_for_store_in_txn(&self.store, rtxn, id, raw)
    }
}
