use super::*;

use std::collections::BTreeSet;

use heed::RwTxn;

use crate::claim::ClaimLifecycleStatus;
use crate::companion::CompanionLifecycleEventKind;
use crate::companion::{
    CompanionExportClassification, ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ppr;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::store::Store;

pub(crate) struct ReplicatedAuthorityLogValidation {
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) signer_key: crate::authority::AuthorityKey,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) signer_known: bool,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) local_vault_id: crate::authority::AuthorityVaultId,
}

/// What currently occupies a validated AUTHORITY_LOG row's content-derived store
/// key. `CrossTypeSquatter` is NOT a rejection — see
/// [`check_authority_log_store_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthorityLogKeyOccupant {
    /// The key is free, or already holds this exact authority row.
    Admissible,
    /// A non-authority row occupies the key and must be evicted before the
    /// authority row is written.
    CrossTypeSquatter,
}

/// ONE-1604-D1 store-key checks shared by every AUTHORITY_LOG write door:
/// the row's id must equal the key derived from its canonical signed body
/// hash (store-key bind: replacement-at-key cannot edit fold history), and
/// an existing AUTHORITY_LOG row's BODY is immutable at that key (append-only
/// guard). Byte-identical body re-puts stay admitted — idempotent replay with
/// metadata-only occurred/learned updates — so no legitimate convergence path
/// is narrowed. A NON-authority occupant is reported, not rejected: see the
/// cross-type squat reasoning inline.
pub(super) fn check_authority_log_store_key(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entry_hash: &crate::authority::AuthorityEntryHash,
    data: &[u8],
) -> Result<AuthorityLogKeyOccupant> {
    if crate::authority::authority_log_entity_id_from_hash(entry_hash)? != *id {
        return Err(Error::AuthorityLogStoreKeyMismatch { id: *id });
    }
    let Some(existing) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(AuthorityLogKeyOccupant::Admissible);
    };
    let existing_type = EntityMetadataHeader::parse(&existing)
        .ok_or(Error::CorruptedIndex("entity header"))?
        .entity_type;
    // ONE-1604-D1 cross-type squat: the derived id lives in the SAME global
    // entity namespace every other kind is keyed in, and signing is
    // deterministic over predictable RevokeDevice/Dissolve bodies — so a
    // hostile peer (including the very device a pending RevokeDevice names)
    // can precompute the revocation's derived id and pre-occupy it with an
    // ordinary row. If that squatter won, the append-only guard below would
    // quarantine the REVOCATION and the revoked key would stay active: the
    // guard meant to protect authority history would suppress it instead.
    //
    // A AUTHORITY_LOG write that reaches this check has already cleared FULL
    // validation at its door — canonical encoding, origin signature, and (at
    // the replicated door) the local vault-id fold — and its id is a pure
    // function of exactly those verified bytes. That is what licenses
    // dominance, and it is why a FORGED authority row cannot use it: such a
    // row fails validation and never gets here, so any occupant a real entry
    // displaces is by construction a squatter at a key it could not have
    // derived. Same-type occupants keep the append-only rule unchanged.
    if existing_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        if existing[ENTITY_METADATA_HEADER_LEN..] != *data {
            return Err(Error::AuthorityLogAppendOnlyViolation { id: *id });
        }
        return Ok(AuthorityLogKeyOccupant::Admissible);
    }
    Ok(AuthorityLogKeyOccupant::CrossTypeSquatter)
}

/// Evicts a non-authority occupant of a validated AUTHORITY_LOG row's store key so
/// the authority row can be written (ONE-1604-D1 dominance). Index rows and
/// incident edges go with it — a squatter must leave no stale carrier — and
/// the eviction is confined to the single write chokepoint so the replicated
/// validator stays side-effect-free.
///
/// The edge half is [`deindex_entity`] → `delete_related_edges`, which drops
/// BOTH directions (`edges_out` and `edges_in`) of every incident edge. That
/// is load-bearing, not incidental: a surviving edge row keeps a revoked
/// squatter traversable through the graph after its entity row is gone, so
/// any future narrowing of the eviction must keep the edge sweep. Pinned by
/// `authority_log_put_evicts_cross_type_squatter_incident_edges`; the CRDT
/// mirror of this rule lives on the reverse-remat door in `sync/window.rs`.
///
/// Call ONLY from `apply_put`'s pre-write site, never from
/// `check_authority_log_store_key`: the check runs while remotely-rejectable
/// preflight is still outstanding, and a remote rejection COMMITS
/// (quarantine-and-continue), so an eviction taken at check time would
/// outlive a rejected row.
///
/// DOMINANCE OUTRANKS DELETE PROTECTION — deliberately, and this is the one
/// place in the engine where it does. The eviction does NOT exempt kinds in
/// [`registry::is_delete_protected_engine_record`] (POLICY_MANIFEST,
/// AUTHORITY_LOG, SKILL_CONTENT_ANCHOR, IDENTITY_TOPOLOGY_EVENT), because:
/// (a) the key is a pure function of FULLY VALIDATED authority bytes, so any
/// non-122 occupant sits at an address its own kind could never derive and is
/// adversarial by construction; (b) the eviction UNWINDS the squatter's
/// induced shell effects rather than orphaning them — a type-76 squatter that
/// arrived by replicated ingest was enumerated by the ARCH-0055 reconciler
/// like any ledger event, so it may have installed real `merged_into` /
/// `split_into` edges on live participants, and both those participants and
/// every surviving merge/split source are reconciled against the fold that
/// remains after the eviction; for a copied row this is curative (the fold
/// would otherwise see one event twice); (c) an
/// exemption would hand attackers a protected band to squat from, letting a
/// planted row suppress a pending `RevokeDevice` — exactly the ONE-1604-D1
/// attack this dominance exists to close. Pinned by
/// `authority_log_put_evicts_delete_protected_squatter`; narrowing the
/// eviction to spare protected kinds is a design decision, not an edit.
///
/// Returns the shell-edge sources the evicted row induced (empty unless the
/// occupant was a type-76 event). A non-empty return means a row LEFT the
/// ledger, and the caller MUST hand it to
/// [`identity_topology::reconcile_shell_edges_after_eviction_in_txn`], which
/// reconciles it together with the surviving family. Both halves are needed:
/// `deindex_entity` drops only edges incident to the EVENT id while the
/// redirect edges sit on the merge/split PARTICIPANTS, and the removed event
/// stops being enumerable (so the surviving-set derivation misses them);
/// meanwhile the removal replays the whole fold, so later events can flip
/// effective/rejected and strand THEIR sources' edges (so the explicit
/// capture alone misses those). Left unreconciled either way they are shell
/// edges with no ledger writer: the ARCH-0055 wedge (participant undo →
/// [`Error::EntityNotFound`]) reached through authority dominance, which is
/// the state type-76 delete protection exists to prevent.
///
/// [`registry::is_delete_protected_engine_record`]: crate::registry::is_delete_protected_engine_record
/// [`identity_topology::reconcile_shell_edges_after_eviction_in_txn`]: crate::identity_topology::reconcile_shell_edges_after_eviction_in_txn
pub(super) fn evict_authority_log_store_key_squatter(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<BTreeSet<EntityId>> {
    tracing::warn!(
        entity = %id.to_hex(),
        "authority log admission displaced a non-authority row squatting its content-derived store key"
    );
    // Captured BEFORE the deindex: afterwards the action bytes are gone and
    // the induced sources are unrecoverable.
    let induced_shell_sources =
        crate::identity_topology::identity_topology_shell_sources_for_store_in_txn(
            store, wtxn, id,
        )?
        .unwrap_or_default();
    let (_existed, had_vector, had_graph_mutation, neighbors) = deindex_entity(store, wtxn, id)?;
    ppr::invalidate_ppr_for_delete(store, wtxn, id, &neighbors)?;
    if had_graph_mutation {
        ppr::increment_graph_version(store, wtxn)?;
    }
    if had_vector {
        crate::hnsw::increment_vector_version(store, wtxn)?;
    }
    Ok(induced_shell_sources)
}

pub(crate) fn validate_replicated_authority_log_for_local_vault(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<ReplicatedAuthorityLogValidation> {
    crate::authority::validate_authority_log_entry_body_bytes(data)?;
    let entry = crate::authority::decode_authority_log_entry_body(data)?;
    let entry_hash = crate::authority::authority_entry_hash(&entry)?;
    // ONE-1604-D1 mirror at the replicated door: content-address + append-only
    // are STORE checks, not ancestry checks — the door stays structural +
    // origin-sig + vault_id (ONE-1604-D2). Rejecting here (before the quota
    // debit) quarantines hostile rows without consuming ingest quota. A
    // cross-type squatter is not a rejection — this row dominates it — and
    // the eviction itself belongs to the `apply_put` chokepoint that writes
    // the row, so this validator stays a pure check.
    let _ = check_authority_log_store_key(store, wtxn, id, &entry_hash, data)?;
    let entry_vault_id = match &entry.op {
        crate::authority::AuthorityOp::Genesis { .. } => {
            crate::authority::genesis_vault_id(&entry)?
        }
        _ => entry
            .vault_id
            .ok_or(Error::InvalidAuthorityLogBody("missing authority vault id"))?,
    };
    let local_fold =
        crate::authority::fold_authority_log(&stored_authority_log_entries(store, wtxn)?);
    let local_vault_id = local_fold.vault_id.ok_or(Error::InvalidAuthorityLogBody(
        "missing local authority root",
    ))?;
    if entry_vault_id != local_vault_id {
        return Err(Error::InvalidAuthorityLogBody(
            "foreign authority log vault id",
        ));
    }
    Ok(ReplicatedAuthorityLogValidation {
        signer_known: local_fold.roster.contains_key(&entry.signer.public_key),
        signer_key: entry.signer.public_key,
        local_vault_id,
    })
}

pub(super) fn stored_authority_log_entries(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
) -> Result<Vec<crate::authority::AuthorityLogEntry>> {
    let mut entries = Vec::new();
    for entry in store
        .type_index
        .prefix_iter(wtxn, &[ENTITY_TYPE_AUTHORITY_LOG])?
    {
        let (key, _) = entry?;
        let id = authority_type_index_entity_id(&key)?;
        let raw = store
            .entities
            .get(wtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("type index row without entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        entries.push(crate::authority::decode_authority_log_entry_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?);
    }
    Ok(entries)
}

pub(super) fn authority_type_index_entity_id(key: &[u8]) -> Result<EntityId> {
    if key.len() != 1 + ENTITY_ID_LEN || key[0] != ENTITY_TYPE_AUTHORITY_LOG {
        return Err(Error::CorruptedIndex("type index key shape"));
    }
    let raw: [u8; ENTITY_ID_LEN] = key[1..]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("type index entity id"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::CorruptedIndex("type index entity id"))
}

pub(super) fn validate_companion_register_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
    companion_retired_histories: Option<&CompanionRetiredHistoryOverlay>,
) -> Result<()> {
    let record = decode_companion_record_body(data)?;
    record.validate_current_schema_lifecycle_events()?;
    let key = record.key();

    if let Some(existing_raw) = store.entities.get(&*wtxn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&existing_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER {
            let existing =
                decode_companion_record_body(&existing_raw[ENTITY_METADATA_HEADER_LEN..])?;
            if existing.key() != key {
                return Err(Error::InvalidClaimBody(
                    "companion record key cannot change",
                ));
            }
            if existing.lifecycle != ClaimLifecycleStatus::Active
                && &existing_raw[ENTITY_METADATA_HEADER_LEN..] != data
                && !is_retired_relationship_end_rescrub(&existing, &record)
            {
                return Err(Error::InvalidClaimBody("companion record is retired"));
            }
            if existing.lifecycle == ClaimLifecycleStatus::Active {
                if record.lifecycle == ClaimLifecycleStatus::Active {
                    if !existing.lifecycle_events.is_empty()
                        && record.lifecycle_events != existing.lifecycle_events
                    {
                        return Err(Error::InvalidClaimBody(
                            "companion lifecycle events cannot change through update",
                        ));
                    }
                } else if !existing.lifecycle_events.is_empty()
                    && !record
                        .lifecycle_events
                        .as_slice()
                        .starts_with(existing.lifecycle_events.as_slice())
                {
                    return Err(Error::InvalidClaimBody(
                        "companion lifecycle events must preserve history",
                    ));
                }
            }
            if existing.export_classification != CompanionExportClassification::LocalOnly
                && record.export_classification == CompanionExportClassification::LocalOnly
            {
                return Err(Error::InvalidClaimBody(
                    "companion record export cannot be downgraded to local_only",
                ));
            }
        }
    }

    if record.lifecycle == ClaimLifecycleStatus::Active {
        let terminal_lifecycle_event_kind = record.terminal_lifecycle_event_kind();
        let prior_lifecycle_events =
            if terminal_lifecycle_event_kind == Some(CompanionLifecycleEventKind::Revived) {
                Some(&record.lifecycle_events[..record.lifecycle_events.len() - 1])
            } else {
                None
            };
        let lookup = crate::companion::companion_record_key_lookup_in_txn(
            store,
            &*wtxn,
            &key,
            prior_lifecycle_events,
        )?;
        if let Some(existing_id) = lookup.active_id
            && existing_id != *id
        {
            return Err(Error::CompanionRecordAlreadyExists);
        }
        if let Some(prior_lifecycle_events) = prior_lifecycle_events {
            let persisted_retired = lookup.retired_history_id.is_some();
            let same_batch_retired = companion_retired_histories.is_some_and(|histories| {
                histories.contains(&(key.clone(), prior_lifecycle_events.to_vec()))
            });
            if !(persisted_retired || same_batch_retired) {
                return Err(Error::InvalidClaimBody(
                    "companion record revive requires retired history",
                ));
            }
        } else {
            if terminal_lifecycle_event_kind != Some(CompanionLifecycleEventKind::Created)
                || record.lifecycle_events.len() != 1
            {
                return Err(Error::InvalidClaimBody(
                    "companion create lifecycle history must be canonical",
                ));
            }
            if let Some(existing_id) = lookup.any_id
                && existing_id != *id
            {
                return Err(Error::CompanionRecordAlreadyExists);
            }
        }
    }

    Ok(())
}
