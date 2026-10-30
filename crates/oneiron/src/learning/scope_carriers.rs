//! The carriers a project's scope rides beside its learning cells (FIX
//! 6038): the terminal attempt receipt's frozen project, a team receipt's
//! project and a critic review's calibration cells. Erasing the project
//! rewrites each to a fresh opaque scope, never blanked to the vault and
//! never the old id, and moves every row whose key derives from the project
//! (a scoped review and its artifacts) to a fresh opaque key, its review-id
//! pointer with it. A row that names the project but no longer decodes is
//! deleted.

use std::collections::BTreeMap;

use crate::Vault;
use crate::critic::{CRITIQUE_ARTIFACT, CritiqueArtifact, CritiqueArtifactKey};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ReceiptRecord;
use crate::side_table::{self, Named, Raw, SideTable};

use super::scope_erase::contains;

/// Terminal attempt receipts, by their raw key.
const PACK_RECEIPT: SideTable<Vec<u8>, ReceiptRecord, Named> =
    SideTable::new(&side_table::ATTEMPT_PACK_RECEIPT);

/// Team receipts as stored values (`{receipt: {project, ..}, ..}`), by raw key.
const TEAM_RECEIPT: SideTable<Vec<u8>, rmpv::Value, Named> =
    SideTable::new(&side_table::TEAM_RECEIPT);

/// Critique artifacts, by their raw key.
const ARTIFACT: SideTable<Vec<u8>, CritiqueArtifact, Named> =
    SideTable::new(&side_table::CRITIC_ARTIFACT);

/// Cached reviews as stored values (`{verdict, artifacts, ..}`), by identity
/// hash.
const REVIEW: SideTable<[u8; 32], rmpv::Value, Named> =
    SideTable::new(&side_table::CRITIC_REVIEW_RESULT);

/// A review's verdict claim to its row's full key.
const REVIEW_ID: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::CRITIC_REVIEW_RESULT_ID);

/// The same pointers by their raw key.
const REVIEW_POINTER: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::CRITIC_REVIEW_RESULT_ID);

/// Re-keys every terminal attempt receipt's frozen project stamp naming
/// erased `entity` to one fresh opaque scope.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_receipt_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let named = entity.to_hex();
    let rows = PACK_RECEIPT
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut scope = None;
    for (key, value) in rows {
        if !contains(&value, named.as_bytes()) {
            continue;
        }
        match PACK_RECEIPT.decode_value(&value) {
            Ok(mut receipt) => {
                if receipt.rescope_task_project(*entity, minted(vault, &mut scope)?) {
                    PACK_RECEIPT.put(&vault.store, wtxn, &key, &receipt)?;
                }
            }
            Err(error) => {
                tracing::warn!(%error, "an attempt receipt that no longer decodes is deleted");
                PACK_RECEIPT.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    Ok(())
}

/// Re-keys every team receipt's project naming erased `entity` to one fresh
/// opaque scope: its payoff rows stay apart from the vault's.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_team_receipt_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let named = entity.to_hex();
    let rows = TEAM_RECEIPT
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut scope = None;
    for (key, value) in rows {
        if !contains(&value, named.as_bytes()) {
            continue;
        }
        match TEAM_RECEIPT.decode_value(&value) {
            Ok(mut stored) => {
                let project =
                    field_mut(&mut stored, "receipt").and_then(|r| field_mut(r, "project"));
                if let Some(project) =
                    project.filter(|project| project.as_str() == Some(named.as_str()))
                {
                    *project = rmpv::Value::from(minted(vault, &mut scope)?.to_hex());
                    TEAM_RECEIPT.put(&vault.store, wtxn, &key, &stored)?;
                }
            }
            Err(error) => {
                tracing::warn!(%error, "a team receipt that no longer decodes is deleted");
                TEAM_RECEIPT.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    Ok(())
}

/// Re-keys every critique artifact and cached review whose calibration cell
/// is scoped to erased `entity`: the cell to one fresh opaque scope, each
/// artifact id (derived from the scope) to a fresh opaque id wherever the
/// review names it, and the review's row to a fresh opaque key with its
/// verdict's pointer. A critic's erase forgets it on the artifacts it wrote,
/// in place (FIX 5221). Registered on both stores; the first call does both.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_review_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let named = entity.to_hex();
    let mut fresh = None;
    let mut renamed = BTreeMap::new();
    let mut dropped = Vec::new();
    let rows = ARTIFACT
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        if !contains(&value, named.as_bytes()) {
            continue;
        }
        match ARTIFACT.decode_value(&value) {
            Ok(mut artifact) if artifact.calibration.project == Some(*entity) => {
                let (scope, salt) = minted_pair(vault, &mut fresh)?;
                artifact.calibration.project = Some(scope);
                artifact.artifact_id = rename(&mut renamed, &artifact.artifact_id, salt);
                let moved = CritiqueArtifactKey {
                    branch_attempt: artifact.branch_attempt,
                    artifact_id: artifact.artifact_id.clone(),
                };
                ARTIFACT.delete(&vault.store, wtxn, &key)?;
                let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
                match CRITIQUE_ARTIFACT.put(&vault.store, &mut savepoint, &moved, &artifact) {
                    Ok(()) => savepoint.commit()?,
                    Err(error) => tracing::warn!(
                        %error,
                        "a scoped critique artifact the side-row wall no longer admits is dropped by its project's erase"
                    ),
                }
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "a critique artifact that no longer decodes is deleted");
                ARTIFACT.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    // A critic's erase forgets it on every artifact it wrote (FIX 5221): its
    // ref and the person executor that copied it, in place — the key holds
    // no critic, so no row moves.
    let rows = ARTIFACT
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        if !contains(&value, named.as_bytes()) {
            continue;
        }
        let mut artifact = match ARTIFACT.decode_value(&value) {
            Ok(artifact) => artifact,
            Err(_) => continue,
        };
        if artifact.provenance.critic_ref != named {
            continue;
        }
        let opaque = crate::critic::erased_critic_ref(vault.store.clock.entity_id()?);
        artifact.forget_critic(&opaque);
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        match ARTIFACT.put(&vault.store, &mut savepoint, &key, &artifact) {
            Ok(()) => savepoint.commit()?,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "a critique artifact the side-row wall no longer admits is dropped by its critic's erase"
                );
                drop(savepoint);
                ARTIFACT.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    let rows = REVIEW
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        let Ok(hash) = <[u8; 32]>::try_from(key.as_slice()) else {
            continue;
        };
        if !contains(&value, named.as_bytes()) {
            continue;
        }
        let mut review = match REVIEW.decode_value(&value) {
            Ok(review) => review,
            Err(error) => {
                tracing::warn!(%error, "a cached review that no longer decodes is deleted");
                REVIEW.delete(&vault.store, wtxn, &hash)?;
                dropped.push(REVIEW.key_bytes(&hash));
                continue;
            }
        };
        let mut scoped = false;
        if let Some(rmpv::Value::Array(artifacts)) = field_mut(&mut review, "artifacts") {
            for artifact in artifacts {
                let project =
                    field_mut(artifact, "calibration").and_then(|c| field_mut(c, "project"));
                let Some(project) =
                    project.filter(|project| project.as_str() == Some(named.as_str()))
                else {
                    continue;
                };
                let (scope, salt) = minted_pair(vault, &mut fresh)?;
                *project = rmpv::Value::from(scope.to_hex());
                if let Some(id) =
                    field_mut(artifact, "artifact_id").and_then(|id| id.as_str().map(str::to_owned))
                {
                    rename(&mut renamed, &id, salt);
                }
                scoped = true;
            }
        }
        if !scoped {
            continue;
        }
        rename_strings(&mut review, &renamed);
        let (_, salt) = minted_pair(vault, &mut fresh)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(salt.as_bytes());
        hasher.update(&hash);
        let moved = *hasher.finalize().as_bytes();
        REVIEW.delete(&vault.store, wtxn, &hash)?;
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        if let Err(error) = REVIEW.put(&vault.store, &mut savepoint, &moved, &review) {
            tracing::warn!(
                %error,
                "a scoped review the side-row wall no longer admits is dropped by its project's erase"
            );
            drop(savepoint);
            dropped.push(REVIEW.key_bytes(&hash));
            continue;
        }
        savepoint.commit()?;
        let verdict = field_mut(&mut review, "verdict").and_then(|verdict| {
            verdict
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
        });
        match verdict {
            Some(verdict) => {
                REVIEW_ID.put(&vault.store, wtxn, &verdict, &REVIEW.key_bytes(&moved))?;
            }
            None => dropped.push(REVIEW.key_bytes(&hash)),
        }
    }
    drop_review_pointers_in_txn(vault, wtxn, &dropped)
}

/// Deletes every review-id pointer to a row in `dropped`, the full keys of
/// reviews this erase removed or moved without re-pointing, so no pointer
/// keeps a key derived from the erased project.
fn drop_review_pointers_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    dropped: &[Vec<u8>],
) -> Result<()> {
    if dropped.is_empty() {
        return Ok(());
    }
    let rows = REVIEW_POINTER
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, pointer) in rows {
        if dropped.contains(&pointer) {
            REVIEW_POINTER.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}

/// The erase's one opaque scope, minted on first need.
fn minted(vault: &Vault, scope: &mut Option<EntityId>) -> Result<EntityId> {
    match scope {
        Some(scope) => Ok(*scope),
        None => {
            let id = vault.store.clock.entity_id()?;
            *scope = Some(id);
            Ok(id)
        }
    }
}

/// The erase's opaque scope and the salt its re-keyed ids hash under, the
/// salt never stored, both minted on first need.
fn minted_pair(
    vault: &Vault,
    fresh: &mut Option<(EntityId, EntityId)>,
) -> Result<(EntityId, EntityId)> {
    match fresh {
        Some(pair) => Ok(*pair),
        None => {
            let pair = (
                vault.store.clock.entity_id()?,
                vault.store.clock.entity_id()?,
            );
            *fresh = Some(pair);
            Ok(pair)
        }
    }
}

/// `old`'s opaque replacement id under `salt`, the same for every row of
/// one erase.
fn rename(renamed: &mut BTreeMap<String, String>, old: &str, salt: EntityId) -> String {
    renamed
        .entry(old.to_owned())
        .or_insert_with(|| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(salt.as_bytes());
            hasher.update(old.as_bytes());
            format!("review_{}", hasher.finalize().to_hex())
        })
        .clone()
}

/// Replaces every string in `value`, map keys included, that `renamed` maps.
fn rename_strings(value: &mut rmpv::Value, renamed: &BTreeMap<String, String>) {
    match value {
        rmpv::Value::String(text) => {
            if let Some(new) = text.as_str().and_then(|text| renamed.get(text)) {
                *value = rmpv::Value::from(new.as_str());
            }
        }
        rmpv::Value::Array(items) => {
            for item in items {
                rename_strings(item, renamed);
            }
        }
        rmpv::Value::Map(entries) => {
            for (key, item) in entries {
                rename_strings(key, renamed);
                rename_strings(item, renamed);
            }
        }
        _ => {}
    }
}

/// The value at `name` in a MessagePack map.
fn field_mut<'a>(value: &'a mut rmpv::Value, name: &str) -> Option<&'a mut rmpv::Value> {
    match value {
        rmpv::Value::Map(entries) => entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, item)| item),
        _ => None,
    }
}
