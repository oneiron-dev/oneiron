//! The entity-ingest ladder: one admission for every replicated entities-map value.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, RegistryError, Result, SyncError};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_EMBEDDING_SETUP;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_DIAGNOSTIC,
    ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_NOTE, ENTITY_TYPE_RECEIPT_RECORD,
    ENTITY_TYPE_REDACTION_AUDIT,
};
use crate::sync::bridge::ingest_replicated_identity_topology_event_in_txn;
use crate::sync::ingest::promotion::{owe_landed_turn_in_txn, promoted_landing_in_txn};
use crate::sync::loro_support::TombstoneIndex;
use crate::sync::origin_claims::{CarriedClaim, carried_claim_in_txn};
use crate::sync::pack_sync;
use crate::sync::quarantine::{
    self, QuarantineContainer, quarantine_rejected_op_in_txn, remote_rejection_reason,
};
use crate::sync::quota;
use crate::vault::Vault;

mod asset_ref;
mod withdrawn;

/// What one ingest reads besides the value: the vault, the window the value replays into, the
/// lease vault its receipts verify against, and that window's tombstones, indexed once per pass.
pub(in crate::sync) struct IngestCtx<'a> {
    pub(super) vault: &'a Vault,
    pub(super) window_key: &'a str,
    lease_vault_id: u64,
    tombstones: &'a TombstoneIndex,
    pub(super) residence: Option<Residence<'a>>,
    /// The window's AUTHORITY_LOG rows, gathered from its carrier before the walk, which each
    /// arriving one is judged beside (FIX 11764); `None` without a carrier.
    pub(super) authority_beside: Option<crate::sync::selector::authority_beside::AuthorityBeside>,
    pub(super) staged: super::task_pairs::Staging,
    /// A by-reference body a transfer received, for its carrier (FIX 5489).
    asset_body: Option<(EntityId, &'a crate::store::StagedAssetBody)>,
    /// The window whose body references a residence-free caller reads.
    body_refs: Option<&'a loro::LoroDoc>,
}

/// How an entry holds a body that does not belong to its window's residence.
#[derive(Clone, Copy)]
pub(in crate::sync) enum Residence<'a> {
    /// Observer-B refuses it into quarantine, unless it is a retained world shell of the window.
    Quarantine(&'a loro::LoroDoc),
    /// Forward rematerialization leaves a retained world shell to the shell restorer and fails
    /// the pass on any other outside body.
    Forward {
        doc: &'a loro::LoroDoc,
        trusted: bool,
    },
}

impl<'a> IngestCtx<'a> {
    pub(in crate::sync) fn new(
        vault: &'a Vault,
        window_key: &'a str,
        lease_vault_id: u64,
        tombstones: &'a TombstoneIndex,
    ) -> Self {
        Self {
            vault,
            window_key,
            lease_vault_id,
            tombstones,
            residence: None,
            authority_beside: None,
            staged: Default::default(),
            asset_body: None,
            body_refs: None,
        }
    }

    /// Checks every body against the window's residence before admission, and gathers the
    /// window's AUTHORITY_LOG rows from its carrier, before the walk reads it, for each
    /// arriving one to be judged beside (FIX 11764).
    pub(in crate::sync) fn with_residence(mut self, residence: Residence<'a>) -> Self {
        self.residence = Some(residence);
        self.authority_beside = self.carrier_doc().map(|doc| {
            crate::sync::selector::authority_beside::AuthorityBeside::gather(
                &doc.get_map("entities"),
                |_| true,
            )
        });
        self
    }

    /// The window document the entries come from, whose birth map carries
    /// each row's Rule A envelope.
    fn carrier_doc(&self) -> Option<&'a loro::LoroDoc> {
        match self.residence? {
            Residence::Quarantine(doc) | Residence::Forward { doc, .. } => Some(doc),
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
    /// The replicated row was written.
    Materialized(EntityId),
    /// A carrier whose body moves by reference and is not here yet (FIX 5489): nothing is
    /// written, and nothing its landing discharges is discharged, until the body comes.
    Pending,
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
    /// A later pass may admit them: the quota window rolls over, the pack kind is installed
    /// (`pack_sync::pack_rejection_keeps_retry_marker`), or the owner raises the authority log's
    /// signer bound (H72, rule 5).
    Retry,
    /// Admission waits on another replicated row this vault has not seen yet.
    DependencyPending,
}

impl RefusalRetry {
    fn of(err: &Error) -> Self {
        if crate::subject_model::subject_model_dependency_pending(err)
            || matches!(
                err.kind(),
                ErrorKind::ProjectDependencyPending
                    | ErrorKind::ResidentOwnerDependencyPending
                    | ErrorKind::RemoteMachineHistoryPending
                    | ErrorKind::AskDependencyPending
                    | ErrorKind::AuthorityLogSignerPending
                    | ErrorKind::EmbeddingSetupDependencyPending
            )
        {
            Self::DependencyPending
        } else if matches!(
            err,
            Error::Sync(SyncError::MaintenanceIngestQuotaExceeded { .. })
        ) || err.kind() == ErrorKind::AuthorityLogFull
            || pack_sync::pack_rejection_keeps_retry_marker(err)
        {
            Self::Retry
        } else {
            Self::Terminal
        }
    }
}

/// A row checked against a sibling row of the same entities map: an ask word or
/// receipt against its group, a project's derived home room against its project,
/// an artifact's version bytes against the version claim that holds them.
/// Forward remat and observer B visit these after every other row of a pass or
/// delta, so a sibling carried in the same map is visited first. It lands first
/// only when its own dependencies are already met.
pub(in crate::sync) fn waits_for_sibling_row(blob: &[u8]) -> bool {
    crate::task_verb::waits_for_ask_group(blob)
        || EntityMetadataHeader::parse(blob).is_some_and(|header| {
            header.entity_type == ENTITY_TYPE_ASSET
                || (header.entity_type == ENTITY_TYPE_EMBEDDING_SETUP
                    && crate::embed::embedding_setup_rests_on_sibling(
                        &blob[ENTITY_METADATA_HEADER_LEN..],
                    ))
                || (header.entity_type == crate::registry::ENTITY_TYPE_CONVERSATION
                    && crate::workspace_roster::project_room_dependency(
                        &blob[ENTITY_METADATA_HEADER_LEN..],
                    )
                    .is_some())
        })
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
    // A row a promotion lands where none is stored, in its span or later (OF-534, FIX 3873).
    let landed = match EntityId::from_hex(key) {
        Ok(id) if promoted_landing_in_txn(ctx.vault, &savepoint, ctx.window_key)? => {
            !EntityStoreRead::port_entity_present(&ctx.vault.store, &savepoint, &id)?
        }
        _ => false,
    };
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
        // FIX 3820: a row refused for a machine history not here owes its
        // target a fetch.
        crate::sync::machine_history::owe_refused_in_txn(
            ctx.vault,
            parent,
            ctx.window_key,
            refusal.id,
            &refusal.err,
            value.unwrap_or_default(),
        )?;
    } else {
        // Rule A: the row's carried birth lands in the savepoint that
        // admitted the row, or not at all.
        if let Some(doc) = ctx.carrier_doc()
            && !matches!(step, EntityStep::Pending)
            && let Some(id) = EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key)
            && crate::vault::live_entity_row_in_txn(&ctx.vault.store, &savepoint, &id)?.is_live()
        {
            crate::sync::row_birth::stamp_carried_birth_in_txn(
                ctx.vault,
                &mut savepoint,
                doc,
                &id,
            )?;
        }
        // What the promotion owes a TURN it brings back lands with the row.
        if landed && let (Some(id), Some(blob)) = (step.written(), value) {
            owe_landed_turn_in_txn(ctx.vault, &mut savepoint, id, blob)?;
        }
        // FIX 3821: a landed machine-history row may advance its target's pin.
        if let Some(id) = step.written() {
            let outcome = ctx
                .vault
                .receive_own_machine_history_row_in_txn(&mut savepoint, &id)?;
            // FIX 3820: what the landing means for the history owed here.
            crate::sync::machine_history::note_landed_in_txn(
                ctx.vault,
                &mut savepoint,
                ctx.window_key,
                outcome,
                value.unwrap_or_default(),
            )?;
        }
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
    if let Some(step) = check_residence(ctx, wtxn, id, blob)? {
        return Ok(step);
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

/// A body whose world or month is not its window's is not admitted by that window, except a
/// retained world shell the window still holds.
fn check_residence(
    ctx: &IngestCtx<'_>,
    wtxn: &heed::RwTxn<'_>,
    id: EntityId,
    blob: &[u8],
) -> Result<Option<EntityStep>> {
    let Some(residence) = ctx.residence else {
        return Ok(None);
    };
    let Some(window) = crate::sync::types::WindowKey::try_new(ctx.window_key) else {
        return Ok(None);
    };
    if crate::sync::types::entity_belongs_to_window(blob, &window) {
        return Ok(None);
    }
    let outside = || Error::InvalidConfig("entity outside window residence".into());
    match residence {
        Residence::Quarantine(doc) => {
            if window.world().is_some()
                && crate::sync::types::retained_world_shell_belongs_to_window(
                    ctx.vault,
                    wtxn,
                    doc,
                    ctx.tombstones,
                    &id,
                    blob,
                    &window,
                    false,
                )?
            {
                return Ok(None);
            }
            Ok(Some(refuse(Some(id), outside())))
        }
        Residence::Forward { doc, trusted } => {
            if crate::sync::types::retained_world_shell_belongs_to_window(
                ctx.vault,
                wtxn,
                doc,
                ctx.tombstones,
                &id,
                blob,
                &window,
                trusted,
            )? {
                // The dedicated shell restorer runs after this pass.
                return Ok(Some(EntityStep::Skip));
            }
            Err(outside())
        }
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
    // ONE-1881: a terminal receipt takes its own writer-locked door BEFORE the generic
    // delete-wins and exact-byte shortcuts; the door refuses every tombstone naming it and
    // neutralizes its `dt:` poison in this transaction.
    if header.entity_type == ENTITY_TYPE_RECEIPT_RECORD {
        let wrote = crate::sync::receipt_ingest::ingest_in_txn(
            vault,
            wtxn,
            ctx.tombstones,
            ctx.window_key,
            &id,
            blob,
        )?;
        return Ok(EntityStep::Protected { id, wrote });
    }
    let delete_protected = crate::dreamer_runner::authority::is_base_agent_actor(&id)?
        || crate::registry::is_delete_protected_engine_record(header.entity_type)
        || crate::workspace_roster::is_project_revision_type(&vault.store, header.entity_type);
    // H125: artifact version bytes fenced here when their last artifact went come back once an
    // artifact live here holds them again. A tombstone naming them still wins.
    // A carrier a reference binds is the body it names, not its manifest bytes (FIX 5489).
    let by_ref = asset_ref::bound(ctx, &id, blob);
    if header.entity_type == ENTITY_TYPE_ASSET && !ctx.tombstones.contains(&id) {
        match &by_ref {
            Some(body) => asset_ref::readmit_staged(ctx, wtxn, &id, body)?,
            None => crate::blob_artifact::readmit_held_asset_in_txn(
                &vault.store,
                wtxn,
                &id,
                &blob[ENTITY_METADATA_HEADER_LEN..],
            )?,
        }
    }
    if !delete_protected && deleted_here(ctx, wtxn, &id) {
        crate::task_authority::note_suppressed_fact_in_txn(
            &vault.store,
            wtxn,
            &id,
            header.entity_type,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?;
        return Ok(EntityStep::Skip);
    }
    if let Some(step) = withdrawn::withdrawn_generation_step(ctx, wtxn, &id, header, blob)? {
        return Ok(step);
    }
    // NOTE replay may not discharge or outlive an unproven purge retry (the old native NOTE
    // lane's pending-delete fence).
    if header.entity_type == ENTITY_TYPE_NOTE
        && quarantine::unproven_remat_marker_exists_in_txn(vault, wtxn, ctx.window_key, &id)?
    {
        return Ok(EntityStep::Skip);
    }
    let data = &blob[ENTITY_METADATA_HEADER_LEN..];
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
    ) && let Some(local) = vault.store.port_entity_raw(wtxn, &id)?
    {
        // Pack echo: the local row holds receiver-local bytes (local handle/generation) while
        // the carrier holds canonical origin bytes, so byte equality never holds after a
        // name-based remap; the canonical/local mapping decides. A file-plane ASSET echoes its
        // body inline (FIX 5393).
        if *local == *blob
            || pack_sync::pack_echo_equal(&local, blob)
            || crate::sync::asset_body::file_echo_equal(&vault.store, wtxn, &id, &local, blob)?
            || asset_ref::echo(ctx, wtxn, &id, by_ref.as_ref(), &local, blob)?
            // A pad row rests as a reference to custody, its pad beside it (KS-5).
            || crate::world_keys::pad_echo_equal(&vault.store, &local, blob)
        {
            // FIX 5500: the replay stays a skip, but a row already here with these bytes still
            // records the origin its window carries for them, as the write below does.
            if let Some(doc) = ctx.carrier_doc() {
                super::carried_origin_in_txn(vault, wtxn, doc, ctx.window_key, &id, blob)?;
            }
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
    // KS-5: a pad reference whose pad is not here waits, pending, for its carrier.
    if let Some(err) = crate::world_keys::pad_reference_waits_in_txn(&vault.store, wtxn, &id, blob)?
    {
        let retry = RefusalRetry::DependencyPending;
        return Ok(EntityStep::Quarantine(EntityRefusal {
            id: Some(id),
            err,
            retry,
        }));
    }
    // FIX 2902: the origin the window carries for these exact bytes lands in this txn first, so
    // a peer's row another own machine or a staged import brings is judged as the peer's below.
    if let Some(doc) = ctx.carrier_doc() {
        crate::sync::ingest::carried_origin_in_txn(vault, wtxn, doc, ctx.window_key, &id, blob)?;
    }
    // A federation peer may not turn an agent definition back on (Docs Q04). Window admission
    // judged the row in a read txn; a local revocation may have committed since, so the writer
    // txn judges it again when it holds the exact bytes a peer's import brought.
    if header.entity_type == ENTITY_TYPE_AGENT_DEF
        && crate::sync::ingest::peer_row_in_txn(vault, wtxn, ctx.window_key, &id, blob)?
        && crate::agent_def::agent_definition_put_widens_in_txn(&vault.store, wtxn, &id, data)?
    {
        return Ok(refuse(
            Some(id),
            Error::Artifact(crate::error::ArtifactError::InvalidAgentDefBody(
                "a federation peer cannot turn an agent definition back on or change its models",
            )),
        ));
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
            ReceiptAdmission::LocalEcho | ReceiptAdmission::Retained => {
                return Ok(EntityStep::Skip);
            }
            ReceiptAdmission::New(debit) => debit,
        },
        ENTITY_TYPE_AUTHORITY_LOG => {
            if vault
                .store
                .port_entity_raw(wtxn, &id)?
                .is_some_and(|local| *local == *blob)
            {
                refuse_protected_tombstones(ctx, wtxn, &id, header.entity_type)?;
                return Ok(EntityStep::Protected { id, wrote: false });
            }
            // History the window carries in two or more rows lands together: the row is
            // judged beside the window's other authority rows, as its selector door judged it
            // (FIX 11764).
            let beside = || match &ctx.authority_beside {
                Some(authority) => authority.rows(),
                None => Ok(std::collections::BTreeMap::new()),
            };
            crate::batch::validate_replicated_authority_log_beside_for_local_vault(
                &vault.store,
                wtxn,
                &id,
                data,
                vault.privacy_posture(),
                &beside,
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
                (blob, ctx.window_key),
                data,
                ctx.lease_vault_id,
            )?;
            refuse_protected_tombstones(ctx, wtxn, &id, header.entity_type)?;
            return Ok(EntityStep::Protected { id, wrote });
        }
        ENTITY_TYPE_EMBEDDING_SETUP => {
            // OF-370: this vault's embedding setup reaches only its own devices. A row lives at
            // its one fixed time, so in one window, and lands in the side tables it mirrors
            // under the checks its local writer makes, in the transaction that writes it.
            let setup_refused = |reason: &str| {
                refuse(
                    Some(id),
                    Error::Artifact(crate::error::ArtifactError::InvalidEmbeddingSetupBody(
                        reason.to_owned(),
                    )),
                )
            };
            if crate::sync::ingest::peer_row_in_txn(vault, wtxn, ctx.window_key, &id, blob)? {
                return Ok(setup_refused(
                    "a peer vault's embedding setup stays in that vault",
                ));
            }
            let fixed = crate::embed::EMBEDDING_SETUP_LEARNED_AT;
            if (
                header.learned_at,
                header.occurred_start,
                header.occurred_end,
            ) != (fixed, fixed, fixed)
            {
                return Ok(setup_refused(
                    "an embedding setup row is not at its fixed time",
                ));
            }
            crate::embed::install_replicated_embedding_setup_in_txn(&vault.store, wtxn, &id, data)?;
            None
        }
        _ => None,
    };
    // FIX 3877: an origin claim lands in this vault's erased form, and a copy its held erased
    // form stands for is skipped.
    let data = match carried_claim_in_txn(vault, wtxn, &id, blob, data)? {
        CarriedClaim::Put(data) => data,
        CarriedClaim::Held => return Ok(EntityStep::Skip),
        CarriedClaim::Redacted => return Ok(EntityStep::Materialized(id)),
    };
    let data = crate::workspace_roster::carried_audience_edit_in_txn(vault, wtxn, &id, blob, data)?;
    // FIX 3554: a Switch's moved MESSAGE pointer lands with its document's head.
    if crate::entity_doc::moved_pointer_row_in_txn(vault, wtxn, &id, blob)? {
        return Ok(EntityStep::Skip);
    }
    // Replicated put: the CRDT mirror is unfiltered, so the maintenance band (REDACTION_AUDIT)
    // and reserved-predicate `edge.provenance` truth-Claims reach here on the way back into
    // LMDB. The public gate would drop them; `put_replicated` admits both engine-authored bands
    // while still validating structure: unknown type bytes, ungrammatical predicates, malformed
    // CLAIM bodies and ONE-1159 provenance records fail typed, and come back as refusals.
    // A TASK row its component stages lands in the component's batch (FIX 5998). A MESSAGE row
    // an own machine's proven connection sent takes its own-device lane to the put (FIX 9600).
    if let Some(body) = &by_ref {
        return asset_ref::land(ctx, wtxn, id, header, body);
    }
    let applied = super::task_pairs::put_or_stage(ctx, wtxn, id, header, blob, &data);
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
/// The local `dt:` marker (ONE-1122) and the row deletion fence are read second: the
/// tombstones map is mutable remote input, and a crafted update that REMOVES the tombstone and
/// re-puts the key must not resurrect a body deleted here, hard or soft. A failed marker read
/// fails closed.
fn deleted_here(ctx: &IngestCtx<'_>, txn: &heed::RoTxn<'_>, id: &EntityId) -> bool {
    if ctx.tombstones.contains(id) {
        tracing::debug!(entity = %id.to_hex(), "sync ingest: entity tombstoned in CRDT (delete wins)");
        return true;
    }
    let marked = ctx
        .vault
        .local_hard_delete_marker_exists_in_txn(txn, id)
        .and_then(|hard| {
            Ok(hard
                || ctx
                    .vault
                    .store
                    .port_deletion_marked(txn, DeletionMarker::RowFence, id)?)
        });
    match marked {
        Ok(false) => false,
        Ok(true) => {
            tracing::warn!(
                entity = %id.to_hex(),
                "sync ingest: entity deleted here (dt: marker or row fence), refusing materialization"
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
///    local receipt is an idempotent skip; any other local receipt at this id is a divergence,
///    and the local bytes are kept;
/// 3. a NEW receipt verifies its Ed25519 transcript against the embedded att_pk (OD-6) and
///    reads its `ls:` lease binding in this same transaction (OD-3/OD-7), then takes its turn
///    in maintenance admission: debited now, or kept with its context as retained work.
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
    if let Some(local) = vault.store.port_entity_raw(wtxn, id)? {
        if *local == *blob {
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
    let op = quota::MaintenanceOp::new(ctx.window_key, ctx.lease_vault_id, id, blob);
    let signer = quota::peer_key_from_redaction_pubkey(&pubkey);
    let admission = quota::admit_maintenance_in_txn(vault, wtxn, signer, op)?;
    Ok(match admission {
        quota::MaintenanceAdmission::Now(debit) => ReceiptAdmission::New(Some(debit)),
        quota::MaintenanceAdmission::Retained => ReceiptAdmission::Retained,
    })
}

/// The receipt door's verdict when it admits the bytes at all.
enum ReceiptAdmission {
    /// The local receipt already holds these exact bytes.
    LocalEcho,
    /// A new receipt passed its origin predicate; the put rolls back the debit if it fails.
    New(Option<quota::MaintenanceIngestQuotaDebit>),
    /// A new receipt waits its turn as retained work, Pending, never quarantined (FIX 8858).
    Retained,
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
    for tombstone in ctx.tombstones.values_for(id) {
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
