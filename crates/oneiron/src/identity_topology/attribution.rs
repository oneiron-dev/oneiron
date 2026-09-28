//! Erasable authorship for immutable type-76 decisions.
//!
//! A decision's body is never rewritten for erasure. Its author lives in a
//! separate type-76 carrier, and a permanent actorless redaction fact defeats
//! every attribution for the same decision/digest, regardless of arrival order.

use std::collections::{BTreeMap, BTreeSet};

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::{
    StoredIdentityOpAction, StoredIdentityOpEvent, decode_identity_topology_event_body,
    encode_identity_topology_event_body,
};

/// A target is bound to the exact immutable body, not just an ID that a peer
/// could fill with a different decision. This is also the redaction join key.
pub(crate) type AttributionKey = (EntityId, [u8; 32]);

#[derive(Default)]
struct AttributionState {
    carriers: BTreeMap<AttributionKey, Vec<(EntityId, WriteActor)>>,
    redacted: BTreeSet<AttributionKey>,
}

fn scan_in_txn(store: &Store, rtxn: &heed::RoTxn<'_>) -> Result<AttributionState> {
    let mut state = AttributionState::default();
    for entry in store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
    {
        let (key, _) = entry?;
        let id = crate::vault::entity_id_from_type_index_key(&key)?;
        let raw = store
            .entities
            .get(rtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("identity attribution index"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("identity attribution header"))?;
        if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
            return Err(Error::CorruptedIndex("identity attribution type"));
        }
        let record = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("identity attribution body"))?;
        match record.action {
            StoredIdentityOpAction::AuthorAttribution {
                target,
                core_digest,
                actor,
            } => state
                .carriers
                .entry((target, core_digest))
                .or_default()
                .push((id, actor)),
            StoredIdentityOpAction::AuthorRedaction {
                target,
                core_digest,
            } => {
                state.redacted.insert((target, core_digest));
            }
            _ => {}
        }
    }
    Ok(state)
}

/// The permanent redaction wins even when its attribution is received later.
/// A receiver must call this after admitting each redaction AND attribution;
/// the export door also calls it before returning any window bytes.
#[cfg(feature = "sync")]
pub(crate) fn scrub_redacted_attributions_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<Vec<EntityId>> {
    let state = scan_in_txn(&vault.store, wtxn)?;
    let ids = state
        .redacted
        .iter()
        .filter_map(|key| state.carriers.get(key))
        .flatten()
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    scrub_carriers_in_txn(vault, wtxn, &ids)?;
    Ok(ids)
}

fn scrub_carriers_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ids: &[EntityId],
) -> Result<()> {
    for id in ids {
        // Deindex removes the current body, type-index entry, and every
        // revision (including pre-erasure versions). No core row is touched.
        crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, id)?;
        crate::batch::deindex_entity(&vault.store, wtxn, id)?;
    }
    Ok(())
}

/// Read-only author hydration. A decision with multiple distinct unredacted
/// stamps is corrupt, not arbitrarily selected by index iteration order.
pub(crate) fn effective_author_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<WriteActor>> {
    let Some(raw) = store.entities.get(rtxn, target.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("identity topology core header"))?;
    if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    let core = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("identity topology core body"))?;
    let key = (target, super::admission_disposition::core_digest(&core)?);
    let state = scan_in_txn(store, rtxn)?;
    if state.redacted.contains(&key) {
        return Ok(None);
    }
    let Some(carriers) = state.carriers.get(&key) else {
        return Ok(None);
    };
    let actor = carriers[0].1;
    if carriers.iter().any(|(_, other)| *other != actor) {
        return Err(Error::CorruptedIndex("conflicting identity attribution"));
    }
    Ok(Some(actor))
}

/// Sidecars are not decisions: bypass the decision writer's recursive signed
/// admission disposition and mint exactly one engine-authored type-76 row.
fn write_sidecar_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    action: StoredIdentityOpAction,
    source: ClaimSource,
    now: u64,
) -> Result<EntityId> {
    let id = vault.store.clock.entity_id()?;
    let record = StoredIdentityOpEvent {
        seq: vault.next_identity_topology_seq_in_txn(wtxn)?,
        validated_at_write: true,
        invalidated: false,
        at: now,
        actor: None,
        source,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action,
    };
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: encode_identity_topology_event_body(&record)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(id)
}
/// Called by the local decision writer in the SAME transaction as the core.
/// Does not put personal author bytes in the immutable decision body.
pub(crate) fn record_author_attribution_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    core_digest: [u8; 32],
    actor: WriteActor,
    source: ClaimSource,
    now: u64,
) -> Result<Option<EntityId>> {
    let state = scan_in_txn(&vault.store, wtxn)?;
    let key = (target, core_digest);
    if state.redacted.contains(&key) {
        return Ok(None);
    }
    if state.carriers.contains_key(&key) {
        return Err(Error::CorruptedIndex("duplicate identity attribution"));
    }
    let core =
        vault
            .identity_topology_event_in_txn(wtxn, &target)?
            .ok_or(Error::CorruptedIndex(
                "identity topology attribution target",
            ))?;
    if super::admission_disposition::core_digest(&core)? != core_digest {
        return Err(Error::CorruptedIndex(
            "identity topology attribution digest",
        ));
    }
    let id = write_sidecar_in_txn(
        vault,
        wtxn,
        StoredIdentityOpAction::AuthorAttribution {
            target,
            core_digest,
            actor,
        },
        source,
        now,
    )?;
    Ok(Some(id))
}

/// Append the actorless, permanent redaction fact before destroying personal
/// carriers. This also records a fact when the attribution has not arrived.
pub(crate) fn redact_author_attribution_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    now: u64,
) -> Result<Vec<EntityId>> {
    let core = vault
        .identity_topology_event_in_txn(wtxn, &target)?
        .ok_or(Error::CorruptedIndex("identity topology redaction target"))?;
    let core_digest = super::admission_disposition::core_digest(&core)?;
    let key = (target, core_digest);
    let state = scan_in_txn(&vault.store, wtxn)?;
    if !state.redacted.contains(&key) {
        if let Some(carriers) = state.carriers.get(&key) {
            for (_, actor) in carriers {
                vault.record_actor_disposition_before_redaction_in_txn(wtxn, target, *actor)?;
            }
        }
        write_sidecar_in_txn(
            vault,
            wtxn,
            StoredIdentityOpAction::AuthorRedaction {
                target,
                core_digest,
            },
            core.source,
            now,
        )?;
    }
    let ids = state
        .carriers
        .get(&key)
        .into_iter()
        .flatten()
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    scrub_carriers_in_txn(vault, wtxn, &ids)?;
    Ok(ids)
}

/// Actor erasure is independent of the decision's participant set. One
/// redaction per affected core defeats a delayed replica's old stamp.
pub(crate) fn redact_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
) -> Result<Vec<EntityId>> {
    let state = scan_in_txn(&vault.store, wtxn)?;
    let targets: BTreeSet<_> = state
        .carriers
        .iter()
        .filter(|(_, carriers)| carriers.iter().any(|(_, a)| a.entity_ref() == actor))
        .map(|(key, _)| key.0)
        .collect();
    let mut scrubbed = Vec::new();
    for target in targets {
        scrubbed.extend(redact_author_attribution_in_txn(vault, wtxn, target, now)?);
    }
    Ok(scrubbed)
}

/// Export/forward can inspect candidate sidecars without mutating a vault.
#[cfg(feature = "sync")]
pub(crate) fn attribution_carrier_key(blob: &[u8]) -> Option<AttributionKey> {
    let header = EntityMetadataHeader::parse(blob)?;
    if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return None;
    }
    let record = decode_identity_topology_event_body(&blob[ENTITY_METADATA_HEADER_LEN..]).ok()?;
    match record.action {
        StoredIdentityOpAction::AuthorAttribution {
            target,
            core_digest,
            ..
        } => Some((target, core_digest)),
        _ => None,
    }
}

#[cfg(feature = "sync")]
pub(crate) fn redaction_carrier_key(blob: &[u8]) -> Option<AttributionKey> {
    let header = EntityMetadataHeader::parse(blob)?;
    if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return None;
    }
    let record = decode_identity_topology_event_body(&blob[ENTITY_METADATA_HEADER_LEN..]).ok()?;
    match record.action {
        StoredIdentityOpAction::AuthorRedaction {
            target,
            core_digest,
        } => Some((target, core_digest)),
        _ => None,
    }
}

#[cfg(feature = "sync")]
pub(crate) fn redacted_keys_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<AttributionKey>> {
    Ok(scan_in_txn(store, rtxn)?.redacted)
}

/// A late personal carrier is never admitted after the actorless redaction
/// fact. The CRDT egress door independently removes the remote carrier.
#[cfg(feature = "sync")]
pub(crate) fn author_attribution_redacted_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    record: &StoredIdentityOpEvent,
) -> Result<bool> {
    let StoredIdentityOpAction::AuthorAttribution {
        target,
        core_digest,
        ..
    } = record.action
    else {
        return Ok(false);
    };
    Ok(scan_in_txn(store, rtxn)?
        .redacted
        .contains(&(target, core_digest)))
}

/// Bridge hook: call after accepting either type of sidecar record, including
/// byte-identical recovery, while still holding its write transaction.
#[cfg(feature = "sync")]
pub(crate) fn reconcile_author_attribution_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    _target: EntityId,
) -> Result<Vec<EntityId>> {
    scrub_redacted_attributions_in_txn(vault, wtxn)
}
