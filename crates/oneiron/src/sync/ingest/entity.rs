//! The entity-ingest ladder: one admission for every replicated entities-map value.

use loro::LoroMap;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, RegistryError, Result, SyncError};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_FACET,
    ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_NOTE, ENTITY_TYPE_REDACTION_AUDIT,
};
use crate::sync::bridge::{
    companion_register_sync_admitted, ingest_replicated_identity_topology_event_in_txn,
};
use crate::sync::loro_support::{tombstone_map_contains_id, tombstone_values_for_id};
use crate::sync::pack_sync;
use crate::sync::quarantine::{
    self, QuarantineContainer, quarantine_rejected_op_in_txn, remote_rejection_reason,
};
use crate::sync::quota;
use crate::vault::Vault;

/// What one ingest reads besides the value: the vault, the window the value replays into, the
/// lease vault its receipts verify against, and that window's tombstones map.
pub(in crate::sync) struct IngestCtx<'a> {
    vault: &'a Vault,
    window_key: &'a str,
    lease_vault_id: u64,
    tombstones_map: &'a LoroMap,
}

impl<'a> IngestCtx<'a> {
    pub(in crate::sync) fn new(
        vault: &'a Vault,
        window_key: &'a str,
        lease_vault_id: u64,
        tombstones_map: &'a LoroMap,
    ) -> Self {
        Self {
            vault,
            window_key,
            lease_vault_id,
            tombstones_map,
        }
    }
}

/// The ladder's verdict on one entities-map value.
#[derive(Debug)]
pub(in crate::sync) enum EntityStep {
    /// The remote value is refused. Whatever the door staged must be rolled back and the op
    /// recorded in `x:` (ONE-1124); [`ingest_entity_in_savepoint`] does both.
    Quarantine(EntityRefusal),
    /// Nothing to write: a delete gate holds, the local bytes already match, or the kind never
    /// replicates.
    Skip,
    /// A restricted companion register row. It stays local, and its carrier and every edge
    /// touching it must leave the shared document.
    LocalOnlyCompanion(EntityId),
    /// The replicated row was written.
    Materialized(EntityId),
    /// A delete-protected engine row passed its door (and was written when `wrote`). Its `dt:`
    /// poison is neutralized and every tombstone naming it is refused into `x:` in the same
    /// transaction.
    Protected { id: EntityId, wrote: bool },
}

impl EntityStep {
    /// The entity whose row this step wrote, if any.
    pub(in crate::sync) fn written(&self) -> Option<EntityId> {
        match self {
            Self::Materialized(id) | Self::Protected { id, wrote: true } => Some(*id),
            _ => None,
        }
    }
}

/// One refused entities-map value.
#[derive(Debug)]
pub(in crate::sync) struct EntityRefusal {
    /// The entity the key names; `None` when the key is not an entity id.
    pub(in crate::sync) id: Option<EntityId>,
    /// The typed rejection the `x:` row records.
    pub(in crate::sync) err: Error,
    /// What the refusal leaves pending.
    pub(in crate::sync) retry: RefusalRetry,
}

/// What a refused value leaves pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::sync) enum RefusalRetry {
    /// No later local change admits these bytes.
    Terminal,
    /// A later pass may admit them: the quota window rolls over, or the pack kind is installed
    /// (`pack_sync::pack_rejection_keeps_retry_marker`).
    Retry,
    /// Admission waits on another replicated row this vault has not seen yet.
    DependencyPending,
}

impl RefusalRetry {
    fn of(err: &Error) -> Self {
        if crate::subject_model::subject_model_dependency_pending(err)
            || err.kind() == ErrorKind::ProjectDependencyPending
        {
            Self::DependencyPending
        } else if matches!(
            err,
            Error::Sync(SyncError::MaintenanceIngestQuotaExceeded { .. })
        ) || pack_sync::pack_rejection_keeps_retry_marker(err)
        {
            Self::Retry
        } else {
            Self::Terminal
        }
    }
}

fn refuse(id: Option<EntityId>, err: Error) -> EntityStep {
    EntityStep::Quarantine(EntityRefusal {
        id,
        err,
        retry: RefusalRetry::Terminal,
    })
}

/// [`ingest_entity_in_txn`] inside a savepoint of `parent`: a refusal rolls back whatever the
/// door staged (project ancestry and room reconciliation can reject after staging a row) and
/// records the op in `x:` on the parent; every other step commits into the parent.
pub(in crate::sync) fn ingest_entity_in_savepoint(
    ctx: &IngestCtx<'_>,
    parent: &mut heed::RwTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
) -> Result<EntityStep> {
    let mut savepoint = ctx.vault.store.env.nested_write_txn(parent)?;
    let step = ingest_entity_in_txn(ctx, &mut savepoint, key, value)?;
    if let EntityStep::Quarantine(refusal) = &step {
        drop(savepoint);
        quarantine_rejected_op_in_txn(
            ctx.vault,
            parent,
            ctx.window_key,
            QuarantineContainer::Entities,
            key,
            &refusal.err,
            value.unwrap_or_default(),
        )?;
    } else {
        savepoint.commit()?;
    }
    Ok(step)
}

/// Runs the whole admission ladder for one entities-map value inside `wtxn`. `value` is `None`
/// when the map holds something other than bytes under `key`.
///
/// A REMOTE refusal comes back as [`EntityStep::Quarantine`] and may leave staged writes in
/// `wtxn`; the caller rolls them back. `Err` is a LOCAL failure (the engine's own storage or
/// on-disk corruption) and fails closed: it is never quarantined.
pub(in crate::sync) fn ingest_entity_in_txn(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
) -> Result<EntityStep> {
    // ONE-1157: a non-bytes value where an entity blob belongs is an undecodable remote op
    // (it carries no bytes, so its payload is empty), never an invisible skip.
    let Some(blob) = value else {
        return Ok(refuse(EntityId::from_hex(key).ok(), Error::InvalidKey));
    };
    // Decode the REMOTE envelope first, before the key and before any local read, so a later
    // `CorruptedIndex` from the engine's own rows is never conflated with a bad remote blob,
    // and so a concurrent protected engine record (notably type-76) cannot hide behind a
    // hostile tombstone or a pre-fix `dt:` poison marker.
    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return Ok(refuse(
            EntityId::from_hex(key).ok(),
            Error::CorruptedIndex("entity metadata"),
        ));
    };
    let Ok(id) = EntityId::from_hex(key) else {
        return Ok(refuse(None, Error::InvalidKey));
    };
    // ONE-1158: a non-canonical (case-shifted) hex alias key is a protocol violation; no engine
    // version emits one (`to_hex()` is lowercase). Materializing it would leave the alias key
    // live in the entities map while tombstone-commit removal deletes only the canonical key.
    if key != id.to_hex() {
        return Ok(refuse(Some(id), Error::InvalidKey));
    }
    match admit(ctx, wtxn, id, &header, blob) {
        Err(err) if remote_rejection_reason(&err).is_some() => {
            Ok(EntityStep::Quarantine(EntityRefusal {
                id: Some(id),
                retry: RefusalRetry::of(&err),
                err,
            }))
        }
        admitted => admitted,
    }
}

fn admit(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
) -> Result<EntityStep> {
    let vault = ctx.vault;
    // Internal chunk bytes never materialize from Loro, including after GC retired the row but
    // kept its reservation.
    if crate::origin::lfs::is_lfs_chunk_asset_in_txn(&vault.store, wtxn, &id)?
        || crate::origin::lfs::is_lfs_chunk_blob(&id, blob)
    {
        return Ok(EntityStep::Skip);
    }
    let delete_protected = crate::registry::is_delete_protected_engine_record(header.entity_type);
    if !delete_protected && deleted_here(ctx, wtxn, &id) {
        return Ok(EntityStep::Skip);
    }
    // NOTE replay may not discharge or outlive an unproven purge retry (the old native NOTE
    // lane's pending-delete fence).
    if header.entity_type == ENTITY_TYPE_NOTE
        && quarantine::unproven_remat_marker_exists_in_txn(vault, wtxn, ctx.window_key, &id)?
    {
        return Ok(EntityStep::Skip);
    }
    let data = &blob[ENTITY_METADATA_HEADER_LEN..];
    if header.entity_type == ENTITY_TYPE_FACET && crate::companion::is_identity_facet_body(data) {
        if !companion_register_sync_admitted(data)? {
            tracing::warn!(
                entity = %id.to_hex(),
                "sync ingest: refused local-only companion register materialization"
            );
            return Ok(EntityStep::LocalOnlyCompanion(id));
        }
        vault.ensure_companion_register_kind()?;
    }
    if header.entity_type == ENTITY_TYPE_DIAGNOSTIC {
        // T1 observations and eligibility receipts are local to their account: replay may not
        // revive a remote detector's local observations.
        return Ok(EntityStep::Skip);
    }
    // Byte-identical replay is an idempotent skip. The immutable kinds decide it inside their
    // own door instead: a REDACTION_AUDIT receipt beside its lease verification, a type-76
    // event beside its divergence and seq-clock checks, and an AUTHORITY_LOG row (ONE-1604-D5)
    // because an exact match must still reach its `dt:` neutralization.
    if !matches!(
        header.entity_type,
        ENTITY_TYPE_REDACTION_AUDIT
            | ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
            | ENTITY_TYPE_AUTHORITY_LOG
    ) && let Some(local) = vault.store.entities.get(&*wtxn, id.as_bytes())?
    {
        // Pack echo: the local row holds receiver-local bytes (local handle/generation) while
        // the carrier holds canonical origin bytes, so byte equality never holds after a
        // name-based remap; the canonical/local mapping decides.
        if *local == *blob || pack_sync::pack_echo_equal(&local, blob) {
            return Ok(EntityStep::Skip);
        }
        // SoftErase shell guard: `user_delete` truncates the local record to the 25 B header
        // shell and writes NO CRDT record (contracts.ts deleteReasons user_delete; cross-device
        // propagation is deferred to ONE-1090), so the carrier still holds the pre-delete body.
        // Replaying it over the shell would resurrect deleted content: delete wins. Interim
        // guard until reason-aware tombstones land in M4-06.
        if local.len() == ENTITY_METADATA_HEADER_LEN && blob.len() > ENTITY_METADATA_HEADER_LEN {
            tracing::warn!(
                entity = %id.to_hex(),
                "sync ingest: kept local SoftErase shell over longer CRDT body (reason-aware tombstones land in M4-06)"
            );
            return Ok(EntityStep::Skip);
        }
    }
    // Pack remote preflight: a malformed REMOTE envelope is refused here, before the name-based
    // remap reads the local map. `InvalidPackByteMap` stays unclassified, so a later one from
    // the remap is LOCAL corruption and fails closed.
    if pack_sync::is_pack_handle(header.entity_type)
        && let Some(remote_err) = pack_sync::remote_pack_envelope_error(data)
    {
        return Ok(refuse(Some(id), remote_err));
    }
    let quota_debit = match header.entity_type {
        ENTITY_TYPE_REDACTION_AUDIT => match admit_receipt(ctx, wtxn, &id, blob, data)? {
            ReceiptAdmission::LocalEcho => return Ok(EntityStep::Skip),
            ReceiptAdmission::New(debit) => debit,
        },
        ENTITY_TYPE_AUTHORITY_LOG => {
            if vault
                .store
                .entities
                .get(&*wtxn, id.as_bytes())?
                .is_some_and(|local| *local == *blob)
            {
                refuse_protected_tombstones(ctx, wtxn, &id, header.entity_type)?;
                return Ok(EntityStep::Protected { id, wrote: false });
            }
            crate::batch::validate_replicated_authority_log_for_local_vault(
                &vault.store,
                wtxn,
                &id,
                data,
            )?;
            None
        }
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT => {
            // ARCH-0055: type-76 ledger events take the ONE fail-closed single-writer door
            // (validation, per-stream quota, seq-clock join, shell-edge reconciliation), never
            // the generic LWW put, which would overwrite an accepted local event.
            let wrote = ingest_replicated_identity_topology_event_in_txn(
                vault,
                wtxn,
                &id,
                header,
                blob,
                data,
                ctx.lease_vault_id,
            )?;
            refuse_protected_tombstones(ctx, wtxn, &id, header.entity_type)?;
            return Ok(EntityStep::Protected { id, wrote });
        }
        _ => None,
    };
    // Replicated put: the CRDT mirror is unfiltered, so the maintenance band (REDACTION_AUDIT)
    // and reserved-predicate `edge.provenance` truth-Claims reach here on the way back into
    // LMDB. The public gate would drop them; `put_replicated` admits both engine-authored bands
    // while still validating structure: unknown type bytes, ungrammatical predicates, malformed
    // CLAIM bodies and ONE-1159 provenance records fail typed, and come back as refusals.
    let applied = vault
        .batch_in()
        .put_replicated(
            &id,
            header.entity_type,
            crate::temporal::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(wtxn);
    if let Err(err) = applied {
        if let Some(quota_debit) = quota_debit {
            quota::rollback_maintenance_ingest_debit_in_txn(vault, wtxn, quota_debit)?;
        }
        return Err(err);
    }
    if delete_protected {
        refuse_protected_tombstones(ctx, wtxn, &id, header.entity_type)?;
        return Ok(EntityStep::Protected { id, wrote: true });
    }
    Ok(EntityStep::Materialized(id))
}

/// Delete wins over a lingering entities-map body.
///
/// A tombstone always wins over concurrent entities-map state (ONE-1133, ARCH-0038: "If
/// tombstoned in CRDT, never resurrect"): hard delete purges LMDB but leaves the stale blob in
/// the live map, and tombstone deltas fire only when the tombstones map changes. Presence is
/// value-agnostic (a non-binary tombstone decodes HARD downstream) and entity-canonical (a
/// case-shifted hex key still names this id).
///
/// The local `dt:` marker (ONE-1122) is read second: the tombstones map is mutable remote
/// input, and a crafted update that REMOVES the tombstone and re-puts the key must not
/// resurrect a hard-deleted body. A failed marker read fails closed.
fn deleted_here(ctx: &IngestCtx<'_>, txn: &heed::RoTxn<'_>, id: &EntityId) -> bool {
    if tombstone_map_contains_id(ctx.tombstones_map, id) {
        tracing::debug!(entity = %id.to_hex(), "sync ingest: entity tombstoned in CRDT (delete wins)");
        return true;
    }
    match ctx.vault.local_hard_delete_marker_exists_in_txn(txn, id) {
        Ok(false) => false,
        Ok(true) => {
            tracing::warn!(
                entity = %id.to_hex(),
                "sync ingest: entity locally hard-deleted (dt: marker), refusing materialization"
            );
            true
        }
        Err(err) => {
            tracing::warn!(
                entity = %id.to_hex(),
                error = %err,
                "sync ingest: dt: marker read failed, failing closed"
            );
            true
        }
    }
}

/// The REDACTION_AUDIT door (ONE-1134, ONE-1140). Receipts are immutable audit records
/// (contracts.ts `redactionAuditReceipt`; ARCH-0023b audit/guardrail class: quarantine
/// divergence, never silent LWW). In pinned order, before any byte is staged:
///
/// 1. the body must satisfy the pinned receipt field set, including the ONE-1140 v2 att_
///    verification grammar;
/// 2. immutability, before any crypto (accepted local bytes always win): a byte-identical
///    local receipt, or the ONE-1087 stale pre-finalization echo of the sweep's LOCAL-only
///    finalization, is an idempotent skip (`None`); any other local receipt at this id is a
///    divergence, and the local bytes are kept;
/// 3. a NEW receipt verifies its Ed25519 transcript against the embedded att_pk (OD-6) and
///    reads its `ls:` lease binding in this same transaction (OD-3/OD-7), then debits the
///    maintenance-ingest quota.
///
/// A refused receipt's bytes stay in the CRDT map, so a later forward rematerialization re-runs
/// this door once the lease mirror catches up (OD-10 lazy re-admission).
fn admit_receipt(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
    data: &[u8],
) -> Result<ReceiptAdmission> {
    let vault = ctx.vault;
    crate::deletion::validate_redaction_receipt_body(data)?;
    if let Some(local) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
        if *local == *blob
            || crate::deletion::redaction_receipt_is_stale_finalization_echo(&local, blob)
        {
            return Ok(ReceiptAdmission::LocalEcho);
        }
        return Err(Error::Sync(SyncError::RedactionReceiptDivergence {
            id: *id,
        }));
    }
    let pubkey = crate::sync::lease::verify_new_receipt_origin_for_vault_in_txn(
        vault,
        wtxn,
        ctx.lease_vault_id,
        id,
        blob,
    )?;
    let recorded_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let debit = quota::try_accept_maintenance_ingest_peer_in_txn(
        vault,
        wtxn,
        quota::peer_key_from_redaction_pubkey(&pubkey),
        recorded_at,
    )?;
    Ok(ReceiptAdmission::New(debit))
}

/// The receipt door's verdict when it admits the bytes at all.
enum ReceiptAdmission {
    /// The local receipt already holds these bytes, or their stale pre-finalization echo.
    LocalEcho,
    /// A new receipt passed its origin predicate; the put rolls back the debit if it fails.
    New(Option<quota::MaintenanceIngestQuotaDebit>),
}

/// A delete-protected engine row never takes delete authority from a tombstone (ONE-1604-D1).
/// Every tombstone naming it is recorded as refused, and any `dt:` marker a headerless
/// tombstone replay minted before the row arrived is removed: it never represented valid
/// delete authority, and left in place the hard-erase sweep would scrub append-only evidence.
fn refuse_protected_tombstones(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    let rejection = Error::Registry(RegistryError::MaintenanceKindNotWritable(entity_type));
    let crdt_key = id.to_hex();
    for tombstone in tombstone_values_for_id(ctx.tombstones_map, id) {
        quarantine_rejected_op_in_txn(
            ctx.vault,
            wtxn,
            ctx.window_key,
            QuarantineContainer::Tombstones,
            &crdt_key,
            &rejection,
            &tombstone,
        )?;
    }
    ctx.vault
        .neutralize_delete_protected_marker_in_txn(wtxn, id, entity_type)?;
    Ok(())
}
