//! The checkpoint getter of blob artifact versions (KS7-2): each artifact's
//! head record and version records under the artifact's own entity tree.
//! These are metadata only: the bytes a version names sit in an ASSET, and
//! KS-2 seals every ASSET's bytes, inline or file (the entity getter hands
//! each ASSET row to it), so nothing here seals them twice. The version
//! highwater, claim and reference rows hold no payload and stay structure.
//! It also places the artifact's hosting rows (pointer, publish admission,
//! serving descriptor) under the artifact (FIX 10436).
//!
//! A version's MadeBy names its process's actor: the compartment keeps the
//! record with the artifact in that place, and the actor is an actor part.
//! The erased-producer form stays in the record with no actor part (FIX 9619).
//! A retired actor can be recovered only from its version's fully bound native
//! claim during authenticated restore, then scrubbed with that claim before
//! commit; otherwise the version stays out (FIX 6259).
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::erase::erased_producer;
use super::versions::{BlobArtifactVersion, HEAD, VERSIONS};
use crate::artifact_hosting::checkpoint as hosting;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, Join, PlacedTable, Restore,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, Restored, RowLocator, TypedRow,
};

/// Every head and version record by artifact, its process's actor split
/// out, then the artifact's hosting rows.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &PlacedTable {
            table: HEAD,
            place: place_head,
        },
        &PlacedTable {
            table: VERSIONS,
            place: place_version,
        },
        hosting::POINTERS,
        hosting::ADMISSIONS,
        hosting::SERVING,
    ],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::Row(join),
    restore: Restore::Parts,
};

/// The field the MadeBy process's actor fills.
const PROCESS: &str = "made_by.process.actor";

/// Moves the process's actor out, leaving `artifact` in its place.
fn take_process(
    version: &mut BlobArtifactVersion,
    artifact: EntityId,
    erased: EntityId,
) -> Vec<(String, EntityId)> {
    if version.made_by.process.actor == erased {
        return Vec::new();
    }
    let actor = std::mem::replace(&mut version.made_by.process.actor, artifact);
    vec![(PROCESS.to_owned(), actor)]
}

fn put_process(version: &mut BlobArtifactVersion, field: &str, actor: EntityId) -> Result<()> {
    if field != PROCESS {
        return Err(rows::bad_part());
    }
    version.made_by.process.actor = actor;
    Ok(())
}

/// A head record under its artifact, its process's actor split out.
fn place_head(out: &mut Captured, row: TypedRow<EntityId, BlobArtifactVersion>) -> Result<()> {
    let erased = erased_producer()?;
    let artifact = row.key;
    rows::split_actors(out, OwnerRef::entity(&artifact), HEAD, row, |version| {
        take_process(version, artifact, erased)
    })
}

/// A version record under its artifact, its process's actor split out.
fn place_version(
    out: &mut Captured,
    row: TypedRow<(EntityId, u64), BlobArtifactVersion>,
) -> Result<()> {
    let erased = erased_producer()?;
    let artifact = row.key.0;
    rows::split_actors(out, OwnerRef::entity(&artifact), VERSIONS, row, |version| {
        take_process(version, artifact, erased)
    })
}

/// A record with its actor back; `None` when the actor did not open.
fn join(
    _: &Store,
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    let erased = erased_producer()?;
    if at.in_table(HEAD.decl()) {
        if parts.is_empty() {
            let head = HEAD.decode_value(value)?;
            return if head.made_by.process.actor == erased {
                HEAD.encode_value(&head).map(Some)
            } else {
                Ok(None)
            };
        }
        let head = rows::join_actors(HEAD, value, parts, put_process)?;
        return HEAD.encode_value(&head).map(Some);
    }
    if at.in_table(VERSIONS.decl()) {
        if parts.is_empty() {
            let version = VERSIONS.decode_value(value)?;
            return if version.made_by.process.actor == erased {
                VERSIONS.encode_value(&version).map(Some)
            } else {
                Ok(None)
            };
        }
        let version = rows::join_actors(VERSIONS, value, parts, put_process)?;
        return VERSIONS.encode_value(&version).map(Some);
    }
    hosting::join(at, value, parts)
}

/// Leaves only absent-actor version joins for the authenticated continuation.
/// All other version, head and hosting rows land in their original order.
pub(crate) fn restore_or_defer_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    mut opened: OpenedOwnerRows,
) -> Result<Option<OpenedOwnerRows>> {
    let actor_parts = &opened.actor_parts;
    let deferred: Vec<_> = opened
        .rows
        .extract_if(.., |part| {
            let rows::RowPart::NoActor { at, value } = part else {
                return false;
            };
            (at.in_table(HEAD.decl()) || at.in_table(VERSIONS.decl()))
                && !actor_parts.iter().any(|part| part.content_locator == *at)
                // Failed and already-complete joins keep their original restore path.
                && join(store, txn, at, value, &[]).is_ok_and(|joined| joined.is_none())
        })
        .collect();
    ADAPTER.restore_parts(store, txn, &opened)?;
    if deferred.is_empty() {
        return Ok(None);
    }
    opened.rows = deferred;
    Ok(Some(opened))
}

/// Lands an authenticated restore's blob bundles after all native claim
/// dependencies are readable. A recovered original remains private to this
/// transaction; the existing restore actor scrub runs before its commit.
pub(crate) fn restore_missing_process_in_txn(
    restore: &mut crate::recovery::checkpoint::RestoreActorScrubWriter<'_, '_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    let (vault, txn, erased) = restore.parts();
    rows::restore_parts(
        &vault.store,
        txn,
        &opened,
        |at, value| ADAPTER.check(at, value),
        |txn, at, value, parts| {
            if let Some(joined) = join(&vault.store, txn, at, value, parts)? {
                return Ok(Some(joined));
            }
            recover_retired_process(vault, txn, at, value, erased, &opened)
        },
    )
}

/// Only the exact native claim can supply the actor omitted from a version
/// whose actor compartment retired after capture. No attribution is guessed.
fn recover_retired_process(
    vault: &crate::Vault,
    txn: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    erased: &std::collections::BTreeSet<EntityId>,
    opened: &OpenedOwnerRows,
) -> Result<Option<Vec<u8>>> {
    use crate::side_table::SideKey;
    use crate::write_envelope::claim_body::ClaimSubject;

    use super::made_by::{made_by_from_text, made_by_text};
    use super::provenance::{BLOB_VERSION_CLAIM_PREDICATE, blob_version_claim_value};
    use super::versions::KEY_MADE_BY;

    let (artifact, mut record, head) = if at.in_table(HEAD.decl()) {
        let Some(artifact) = at
            .key
            .strip_prefix(HEAD.decl().prefix)
            .and_then(EntityId::decode_key)
        else {
            return Ok(None);
        };
        (artifact, HEAD.decode_value(value)?, true)
    } else if at.in_table(VERSIONS.decl()) {
        let Some((artifact, version)) = at
            .key
            .strip_prefix(VERSIONS.decl().prefix)
            .and_then(<(EntityId, u64)>::decode_key)
        else {
            return Ok(None);
        };
        let record = VERSIONS.decode_value(value)?;
        if record.version != version {
            return Ok(None);
        }
        (artifact, record, false)
    } else {
        return Ok(None);
    };
    let owner = OwnerRef::entity(&artifact);
    if opened.subtype != owner.subtype
        || opened.owner32 != owner.owner32
        || record.made_by.process.actor != artifact
    {
        return Ok(None);
    }
    let claim = match vault.get_claim_in_txn(txn, &record.claim_id) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Ok(None),
        Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => return Err(error),
        // An unproved claim cannot repair a row the old join omitted.
        Err(_) => return Ok(None),
    };
    if claim.predicate != BLOB_VERSION_CLAIM_PREDICATE
        || claim.subject != ClaimSubject::Entity(artifact)
    {
        return Ok(None);
    }
    let Some(text) = claim.value.as_map().and_then(|entries| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(KEY_MADE_BY))
            .and_then(|(_, value)| value.as_str())
    }) else {
        return Ok(None);
    };
    let Ok(original) = made_by_from_text(text) else {
        return Ok(None);
    };
    let actor = original.process.actor;
    if !erased.contains(&actor)
        || !opened.unavailable.contains(&OwnerRef::entity(&actor))
        || crate::deletion::names_no_actor(vault, txn, &actor)?
    {
        return Ok(None);
    }
    record.made_by.process.actor = actor;
    if record.made_by != original
        || claim.value
            != blob_version_claim_value(
                record.version,
                &record.content_hash,
                &record.provenance,
                record.parent_version,
                record.fork_of_version,
                record.calc_engine.as_ref(),
                &made_by_text(&record.made_by)?,
            )
    {
        return Ok(None);
    }
    if head {
        HEAD.encode_value(&record).map(Some)
    } else {
        VERSIONS.encode_value(&record).map(Some)
    }
}
