//! Erasable authorship for immutable type-76 decisions.
//!
//! A decision's body is never rewritten for erasure. Its author lives in a
//! separate type-76 carrier, and a permanent actorless redaction fact defeats
//! every attribution for the same decision/digest, regardless of arrival order.
//!
//! Carriers are unsigned, so a peer's carrier is display and erasure input
//! only. Admission reads only the carriers this vault wrote itself.

use std::collections::{BTreeMap, BTreeSet};

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::side_table::{self, HexId, Raw, SideTable};
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

/// The author carriers this vault wrote itself, by carrier row: a digest of
/// the row's body. Local truth that never replicates, so no peer can make its
/// own carrier read as this vault's. A restore keeping this vault's authority
/// takes it from this vault, never from the image (`restore_class`), and keeps
/// only the marks whose carrier the restored vault holds.
const AUTHORED_HERE: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::IDENTITY_TOPOLOGY_AUTHORED_HERE);

struct Carrier {
    id: EntityId,
    actor: WriteActor,
    source: ClaimSource,
    /// Whether this vault wrote the carrier itself.
    here: bool,
}

#[derive(Default)]
struct AttributionState {
    carriers: BTreeMap<AttributionKey, Vec<Carrier>>,
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
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let record = decode_identity_topology_event_body(body)
            .map_err(|_| Error::CorruptedIndex("identity attribution body"))?;
        match record.action {
            StoredIdentityOpAction::AuthorAttribution {
                target,
                core_digest,
                actor,
            } => {
                let here = AUTHORED_HERE.get(store, rtxn, &HexId(id))?
                    == Some(*blake3::hash(body).as_bytes());
                state
                    .carriers
                    .entry((target, core_digest))
                    .or_default()
                    .push(Carrier {
                        id,
                        actor,
                        source: record.source,
                        here,
                    });
            }
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
        .map(|carrier| carrier.id)
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
        // The marker goes too: its digest of the body could confirm a guess.
        crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, id)?;
        crate::batch::deindex_entity(&vault.store, wtxn, id)?;
        AUTHORED_HERE.delete(&vault.store, wtxn, &HexId(*id))?;
    }
    Ok(())
}

/// Drops every written-here mark whose carrier this vault does not hold as a
/// type-76 row with the exact body the mark binds, the row `scan_in_txn`
/// reads. A restore runs it once its rows are in: a mark carried from the
/// live vault for a carrier the image predates (or holds as another kind)
/// would be a digest of an author's carrier that no erasure could reach.
pub(crate) fn drop_unheld_author_marks_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let mut unheld = Vec::new();
    for row in AUTHORED_HERE.iter_from(store, wtxn, &[])? {
        let (HexId(id), digest) = row?;
        let held = store.entities.get(wtxn, id.as_bytes())?.is_some_and(|raw| {
            EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
                && *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes() == digest
        });
        if !held {
            unheld.push(id);
        }
    }
    for id in unheld {
        AUTHORED_HERE.delete(store, wtxn, &HexId(id))?;
    }
    Ok(())
}

/// Read-only author hydration for display and erasure: every carrier counts.
/// Distinct unredacted stamps are never selected by index iteration order:
/// with a peer's carrier among them the author reads as unknown, and only
/// this vault's own carriers disagreeing is corruption.
pub(crate) fn effective_author_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<WriteActor>> {
    author_in_txn(store, rtxn, target, false)
}

/// The author admission reads (the fold's actor check, refusal mints, the
/// batch hooks): only a carrier this vault wrote itself names one. A peer's
/// unsigned carrier can neither veto a decision nor fail the fold.
pub(crate) fn admitted_author_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<WriteActor>> {
    author_in_txn(store, rtxn, target, true)
}

fn author_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    target: EntityId,
    own_only: bool,
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
    let carriers: Vec<&Carrier> = state
        .carriers
        .get(&key)
        .into_iter()
        .flatten()
        .filter(|carrier| carrier.here || !own_only)
        .collect();
    let Some(actor) = carriers.first().map(|carrier| carrier.actor) else {
        return Ok(None);
    };
    if carriers.iter().any(|carrier| carrier.actor != actor) {
        if carriers.iter().all(|carrier| carrier.here) {
            return Err(Error::CorruptedIndex("conflicting identity attribution"));
        }
        return Ok(None);
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
    let attribution = matches!(action, StoredIdentityOpAction::AuthorAttribution { .. });
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
    let data = encode_identity_topology_event_body(&record)?;
    if attribution {
        AUTHORED_HERE.put(
            &vault.store,
            wtxn,
            &HexId(id),
            blake3::hash(&data).as_bytes(),
        )?;
    }
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
            data,
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
    redact_attribution_key_in_txn(vault, wtxn, (target, core_digest), core.source, now)
}

/// Redacts one exact `(target, digest)` key and scrubs every carrier bound to
/// it, this vault's and peers' alike.
fn redact_attribution_key_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: AttributionKey,
    source: ClaimSource,
    now: u64,
) -> Result<Vec<EntityId>> {
    let (target, core_digest) = key;
    let state = scan_in_txn(&vault.store, wtxn)?;
    if !state.redacted.contains(&key) {
        // A refusal is admission: only an author this vault stamped itself
        // can earn one. A peer's carrier is erased below all the same.
        for carrier in state.carriers.get(&key).into_iter().flatten() {
            if carrier.here {
                vault.record_actor_disposition_before_redaction_in_txn(
                    wtxn,
                    target,
                    carrier.actor,
                )?;
            }
        }
        write_sidecar_in_txn(
            vault,
            wtxn,
            StoredIdentityOpAction::AuthorRedaction {
                target,
                core_digest,
            },
            source,
            now,
        )?;
    }
    let ids = state
        .carriers
        .get(&key)
        .into_iter()
        .flatten()
        .map(|carrier| carrier.id)
        .collect::<Vec<_>>();
    scrub_carriers_in_txn(vault, wtxn, &ids)?;
    Ok(ids)
}

/// Actor erasure is independent of the decision's participant set. One
/// redaction per affected core defeats a delayed replica's old stamp. Every
/// carrier naming the actor goes by its own key: a peer's carrier for a
/// decision this vault lacks, or for another body, is erased too, and never
/// fails the erasure.
pub(crate) fn redact_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
) -> Result<Vec<EntityId>> {
    let state = scan_in_txn(&vault.store, wtxn)?;
    let keys: BTreeMap<AttributionKey, ClaimSource> = state
        .carriers
        .iter()
        .filter_map(|(key, carriers)| {
            carriers
                .iter()
                .find(|carrier| carrier.actor.entity_ref() == actor)
                .map(|carrier| (*key, carrier.source))
        })
        .collect();
    let mut scrubbed = Vec::new();
    for (key, source) in keys {
        scrubbed.extend(
            if held_decision_digest_in_txn(vault, wtxn, key.0)? == Some(key.1) {
                redact_author_attribution_in_txn(vault, wtxn, key.0, now)?
            } else {
                redact_attribution_key_in_txn(vault, wtxn, key, source, now)?
            },
        );
    }
    Ok(scrubbed)
}

/// The core digest of `target` when it is a decision this vault holds.
fn held_decision_digest_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<[u8; 32]>> {
    if vault.get_entity_type_in_txn(rtxn, &target)? != Some(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT) {
        return Ok(None);
    }
    let Some(core) = vault.identity_topology_event_in_txn(rtxn, &target)? else {
        return Ok(None);
    };
    if matches!(
        core.action,
        StoredIdentityOpAction::AdmissionDisposition(_)
            | StoredIdentityOpAction::AuthorAttribution { .. }
            | StoredIdentityOpAction::AuthorRedaction { .. }
    ) {
        return Ok(None);
    }
    super::admission_disposition::core_digest(&core).map(Some)
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
