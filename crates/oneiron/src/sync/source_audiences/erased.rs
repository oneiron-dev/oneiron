//! An erased actor's policy revisions leave the window carriers (SYNC-3 §5).
//!
//! A window's `source_audiences` map carries each policy revision a carried
//! row's closure reaches, and a revision names its readers, its shares and
//! its creator. When this vault erases an actor, the audience erase writes
//! each policy it changes as its next revision; in that same transaction
//! this drops, from every window this vault stores, each revision naming an
//! actor this vault erased, and writes the redacted successor under its own
//! revision key beside the policy's other cells: an earlier revision is never
//! rewritten under its own number, which a replica would take for a
//! conflict.
//!
//! It never touches a loaded window. It rebuilds each stored window in a
//! document no observer watches, from the erase's own transaction, and
//! stores the change as one more pending update of that window, which it
//! pins history-free and marks for a full resync; its queued sends go but
//! the delete-bearing, and the erase owes the sweep the window's compaction,
//! whose shallow cut drops the old revisions from its history. Every export,
//! persist and compaction scrubs again ([`super::refresh_and_scrub`]), so a
//! loaded copy that has not merged the removal, or a peer's copy that brings
//! a revision back, never ships one. A stored window that does not rebuild
//! fails the erase: nothing would show its carriers gone.

use std::collections::BTreeSet;

use loro::json::{JsonOpContent, MapOp};
use loro::{CommitOptions, ContainerID, ContainerType, LoroDoc, LoroValue, VersionVector};

use super::{
    Carrier, SOURCE_AUDIENCES_MAP, carried_heads, carrier, carriers, encode_policy, holds_map,
    policy_key,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::source_audience::{self, SourceAudienceKind, SourceAudiencePolicy};
use crate::sync::bridge::{BRIDGE_ORIGIN, persist_window_update_in_txn};
use crate::sync::loro_support::{
    doc_from_snapshot, export_updates_from, import_doc, map_delete, map_get_bytes, map_insert_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window_rows::{HISTORY_FREE_WINDOW, WINDOW_FULL_RESYNC_MARKER};

/// Drops, in the erase's own transaction `wtxn`, every stored window's
/// policy revision naming `actor` or another actor this vault erased, and
/// writes each such policy's current revision beside the others.
///
/// # Errors
///
/// Storage and codec failures; a stored window that does not rebuild.
pub(crate) fn erase_carriers_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for key in stored_windows_in_txn(vault, wtxn)? {
        let doc = match stored_window_in_txn(vault, wtxn, &key)? {
            Some(Ok(doc)) => doc,
            Some(Err(error)) => {
                return Err(Error::InvalidConfig(format!(
                    "an erased actor's source audience carriers: window {key} does not rebuild: {error}"
                )));
            }
            None => continue,
        };
        if !holds_map(&doc) {
            continue;
        }
        let map = doc.get_map(SOURCE_AUDIENCES_MAP);
        let mut doomed = Vec::new();
        let mut redacted = BTreeSet::new();
        for (map_key, carried) in carriers(&map) {
            if let Carrier::Policy { id, policy } = carried
                && (names(&policy, actor)
                    || source_audience::names_erased_actor_in(vault, wtxn, &policy)?)
            {
                doomed.push(map_key);
                redacted.insert(id);
            }
        }
        // A revision the live map dropped can still ride the window's
        // history, or its shallow root: the same pin, scrub and compaction
        // are owed for it.
        let in_history = doc.is_shallow() || history_names(&doc, actor);
        if doomed.is_empty() && !in_history {
            continue;
        }
        // Each redacted policy's successor: the highest revision carried,
        // redacted under its own next revision, merged into this vault's
        // (the erase's own redaction of a held head stands beside it), then
        // published as this vault now holds it.
        let heads = carried_heads(&map);
        let mut successors = Vec::new();
        for id in &redacted {
            if let Some(Some(head)) = heads.get(id) {
                let candidate = if names(head, actor) {
                    without_actor(head, actor)?
                } else {
                    head.clone()
                };
                // A conflict leaves the held policy standing.
                source_audience::merge_policy_in_txn(vault, wtxn, id, &candidate)?;
            }
            if let Some(current) = source_audience::policy_in(vault, wtxn, id)?
                && !names(&current, actor)
                && !source_audience::names_erased_actor_in(vault, wtxn, &current)?
            {
                successors.push((*id, current));
            }
        }
        rewrite_stored_window_in_txn(vault, wtxn, &key, &doc, &doomed, &successors)?;
    }
    Ok(())
}

/// `policy` without `actor`, as its own next revision.
fn without_actor(policy: &SourceAudiencePolicy, actor: &EntityId) -> Result<SourceAudiencePolicy> {
    let mut redacted = policy.clone();
    if redacted.created_by == Some(*actor) {
        redacted.created_by = None;
    }
    match &mut redacted.kind {
        SourceAudienceKind::Source { readers, .. } => {
            readers.remove(actor);
        }
        SourceAudienceKind::Thread { shared_with, .. } => {
            shared_with.remove(actor);
        }
    }
    redacted.revision = policy
        .revision
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("source audience policy revision"))?;
    Ok(redacted)
}

/// Whether a policy revision naming `actor` was ever inserted in `doc`'s
/// map, by the history it holds.
fn history_names(doc: &LoroDoc, actor: &EntityId) -> bool {
    let container = ContainerID::new_root(SOURCE_AUDIENCES_MAP, ContainerType::Map);
    let history = doc.export_json_updates(&VersionVector::default(), &doc.oplog_vv());
    history
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .any(|op| {
            op.container == container
                && matches!(
                    &op.content,
                    JsonOpContent::Map(MapOp::Insert {
                        key,
                        value: LoroValue::Binary(bytes),
                    }) if matches!(
                        carrier(key, bytes),
                        Ok(Carrier::Policy { policy, .. }) if names(&policy, actor)
                    )
                )
        })
}

/// Whether `policy` names `actor`: a reader, a share or its creator.
fn names(policy: &SourceAudiencePolicy, actor: &EntityId) -> bool {
    policy.created_by == Some(*actor)
        || match &policy.kind {
            SourceAudienceKind::Source { readers, .. } => readers.contains(actor),
            SourceAudienceKind::Thread { shared_with, .. } => shared_with.contains(actor),
        }
}

/// Writes each of `successors` under its own revision into `doc`, the
/// stored window `key` rebuilt, deletes the revisions under `doomed`, and
/// stores the change in `wtxn` as one more pending update of the window. It
/// pins the window history-free and marks it for a full resync, every queued
/// send of it going but the delete-bearing, whether or not the live map
/// changed: a revision its history keeps goes when the erasure sweep
/// compacts the window, which this owes it.
fn rewrite_stored_window_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WindowKey,
    doc: &LoroDoc,
    doomed: &[String],
    successors: &[(EntityId, SourceAudiencePolicy)],
) -> Result<()> {
    let before = doc.oplog_vv();
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let mut changed = false;
    // The successors first: a revision goes only once its redaction rides.
    for (id, head) in successors {
        let map_key = policy_key(id, head.revision);
        if map_get_bytes(&map, &map_key).is_none() {
            map_insert_bytes(&map, &map_key, &encode_policy(head)?)?;
            changed = true;
        }
    }
    for map_key in doomed {
        map_delete(&map, map_key)?;
        changed = true;
    }
    let label = key.as_str().to_owned();
    HISTORY_FREE_WINDOW.put(&vault.store, wtxn, &label, &[1u8])?;
    crate::sync::queue::scrub_window_updates_in_txn(vault, wtxn, &label)?;
    WINDOW_FULL_RESYNC_MARKER.put(&vault.store, wtxn, &label, &[1u8])?;
    crate::sweep::owed::owe_window_compaction_in_txn(vault, wtxn, key)?;
    if !changed {
        return Ok(());
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    let change = export_updates_from(doc, &before)?;
    // Last: the pending update marks the stored state vector stale too.
    persist_window_update_in_txn(vault, wtxn, &label, &change)
}

/// Every window this vault stores state for, read in `txn`: each snapshot's
/// label and each pending update's window (as the birth erase reads them).
fn stored_windows_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<WindowKey>> {
    let mut labels: BTreeSet<String> = vault
        .store
        .port_window_doc_rows_raw(txn, |window, _| window.as_str().to_owned())?
        .collect::<Result<_>>()?;
    for label in vault
        .store
        .port_window_update_keys(txn, None, update_window)?
    {
        labels.extend(label?);
    }
    Ok(labels.into_iter().filter_map(WindowKey::try_new).collect())
}

/// The window a pending update's full key (`u:w:{window}:{seq}`) names.
fn update_window(key: &str) -> Option<String> {
    let (window, _) = key.strip_prefix("u:w:")?.rsplit_once(':')?;
    Some(window.to_owned())
}

/// The window `key` as `txn` stores it, rebuilt in a document no observer
/// watches: its snapshot with each pending update on top. `None` when it
/// stores nothing; the inner error when its bytes do not rebuild.
fn stored_window_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WindowKey,
) -> Result<Option<Result<LoroDoc>>> {
    let address = WindowAddress::new(key.as_str());
    let snapshot = vault
        .store
        .port_window_doc_with_raw(txn, address, |raw| Ok(doc_from_snapshot(raw)))?;
    let mut stored = snapshot.is_some();
    let doc = match snapshot {
        Some(Ok(doc)) => doc,
        Some(Err(error)) => return Ok(Some(Err(error))),
        None => create_window_doc("local", key),
    };
    for imported in vault
        .store
        .port_window_updates(txn, address, |_, update| import_doc(&doc, update))?
    {
        if let Err(error) = imported? {
            return Ok(Some(Err(error)));
        }
        stored = true;
    }
    Ok(stored.then_some(Ok(doc)))
}
