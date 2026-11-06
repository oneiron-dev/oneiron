//! A source's erase reaches every drafter version trained on it (FIX 12569,
//! DRAFTER-DATA = A: "erasing a source drops every drafter trained on it,
//! and the stock drafter serves until the next nightly retrain").
//!
//! [`erase_drafters_for_source_in_txn`] runs at both delete doors
//! (`deletion::derived_rows`) and, through the version table's scrub
//! ([`erase_drafter_actor_in_txn`]), at an actor's erase, in the erase's own
//! transaction. In that transaction it:
//! - finds every version whose whole training ancestry names the source,
//!   whose dependency set is not precise, or whose parent is erased or
//!   unknown;
//! - moves each to `Erased` and bumps its generation, which fences its
//!   pending job: a late completion's publication rechecks the generation
//!   and is refused;
//! - returns to stock every binding that served one, even where an older
//!   private head looks clean;
//! - stages the retirement of every key of each version's sealed artifact
//!   and of both sides of its corpus (FIX 14973), so no restored image and
//!   no late receipt opens them again; the corpus sweep removes the sealed
//!   files after;
//! - drops every evaluation that names one of them (FIX 14975).
//!
//! The training examples an erased record reaches go in the same
//! transaction, by their own eraser (FIX 15128,
//! [`super::erase_drafter_examples_for_source_in_txn`]), registered beside
//! this one at both delete doors and run at an actor's erase.
//!
//! Only content-free evidence stays: the erase event names the versions and
//! the jobs it fenced, never the source.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::evaluation::erase_evaluations_in_txn;
use super::traffic::erase_drafter_examples_for_source_in_txn;
use super::{
    BINDINGS, BindingMove, DrafterActor, DrafterBinding, DrafterDependencies, DrafterEventKind,
    DrafterServing, DrafterVersion, DrafterVersionState, EVENTS, POLICY, VERSIONS,
    move_binding_in_txn, record_event_in_txn,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SideKey, SideTableDbs};
use crate::store::Store;
use crate::store::drafter_custody::retire_drafter_artifact_keys_in_txn;

/// Deletes the row stored under `prefix` + `key`, whatever its shape.
fn delete_raw(store: &Store, wtxn: &mut RwTxn<'_>, prefix: &[u8], key: &[u8]) -> Result<()> {
    store
        .side_vault_meta()
        .delete(wtxn, &[prefix, key].concat())?;
    Ok(())
}

/// The versions in `txn` that decode, and the raw key of each row that
/// does not.
fn version_rows(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<(Vec<(EntityId, DrafterVersion)>, Vec<Vec<u8>>)> {
    let mut rows = Vec::new();
    let mut damaged = Vec::new();
    for row in VERSIONS.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        match (
            <EntityId as SideKey>::decode_key(&key),
            VERSIONS.decode_value(&value),
        ) {
            (Some(id), Ok(version)) => rows.push((id, version)),
            _ => damaged.push(key),
        }
    }
    Ok((rows, damaged))
}

/// The bindings in `txn` that decode, and the raw key of each row that
/// does not.
fn binding_rows(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<(Vec<([u8; 32], DrafterBinding)>, Vec<Vec<u8>>)> {
    let mut rows = Vec::new();
    let mut damaged = Vec::new();
    for row in BINDINGS.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        match (
            <[u8; 32] as SideKey>::decode_key(&key),
            BINDINGS.decode_value(&value),
        ) {
            (Some(target), Ok(binding)) => rows.push((target, binding)),
            _ => damaged.push(key),
        }
    }
    Ok((rows, damaged))
}

/// The versions an erase of `id` reaches: each one not yet erased whose own
/// dependency set names `id` or is not precise, then, to a fixed point,
/// each one whose parent is reached, erased, or no longer held.
fn reached(versions: &[(EntityId, DrafterVersion)], id: &EntityId) -> BTreeSet<EntityId> {
    fn live(version: &DrafterVersion) -> bool {
        version.state != DrafterVersionState::Erased
    }
    let known: BTreeMap<EntityId, &DrafterVersion> = versions
        .iter()
        .map(|(key, version)| (*key, version))
        .collect();
    let mut reached: BTreeSet<EntityId> = versions
        .iter()
        .filter(|(_, version)| {
            live(version) && (!version.dependencies.precise || version.dependencies.names(id))
        })
        .map(|(key, _)| *key)
        .collect();
    loop {
        let before = reached.len();
        for (key, version) in versions {
            if !live(version) || reached.contains(key) {
                continue;
            }
            let Some(parent) = version.parent.version() else {
                continue;
            };
            let inherits =
                reached.contains(&parent) || known.get(&parent).is_none_or(|found| !live(found));
            if inherits {
                reached.insert(*key);
            }
        }
        if reached.len() == before {
            break reached;
        }
    }
}

/// The erase of `id` drops every drafter version trained on it, in the
/// erase's own transaction at both delete doors, and returns each target
/// that served one to stock. A version row or binding row that does not
/// decode goes too: it cannot show what it trained on. An id no version
/// reaches changes nothing.
///
/// # Errors
///
/// Storage and custody faults.
pub(crate) fn erase_drafters_for_source_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let (versions, damaged) = version_rows(store, wtxn)?;
    for key in &damaged {
        delete_raw(store, wtxn, VERSIONS.decl().prefix, key)?;
        if let Some(version) = <EntityId as SideKey>::decode_key(key) {
            retire_drafter_artifact_keys_in_txn(store, wtxn, &version)?;
        }
    }
    let (bindings, damaged) = binding_rows(store, wtxn)?;
    for key in &damaged {
        delete_raw(store, wtxn, BINDINGS.decl().prefix, key)?;
    }
    let reach = reached(&versions, id);
    // FIX 14975: an evaluation naming a reached version goes, its per-case
    // digests with it, and so does one that does not decode.
    erase_evaluations_in_txn(store, wtxn, &reach)?;
    if reach.is_empty() {
        return Ok(());
    }
    let at = store.clock.now_recorded_at();
    let mut erased = Vec::new();
    let mut jobs = Vec::new();
    for (key, mut version) in versions {
        if !reach.contains(&key) {
            continue;
        }
        retire_drafter_artifact_keys_in_txn(store, wtxn, &key)?;
        if matches!(
            version.state,
            DrafterVersionState::Prepared | DrafterVersionState::Training
        ) {
            jobs.extend(version.job);
        }
        version.state = DrafterVersionState::Erased;
        version.generation += 1;
        version.artifact = None;
        // FIX 14973: its corpus keys retire above; its digests go too.
        version.corpus = None;
        version.dependencies = DrafterDependencies {
            precise: true,
            ..DrafterDependencies::default()
        };
        version.updated_at = at;
        VERSIONS.put(store, wtxn, &key, &version)?;
        erased.push(key);
    }
    let kind = DrafterEventKind::Erase {
        versions: erased,
        jobs,
    };
    let gone = |serving: DrafterServing| serving.version().is_some_and(|v| reach.contains(&v));
    let mut moved = false;
    for (key, mut binding) in bindings {
        if gone(binding.serving) {
            move_binding_in_txn(
                store,
                wtxn,
                &key,
                binding,
                BindingMove {
                    to: DrafterServing::Stock,
                    previous: DrafterServing::Stock,
                    by: DrafterActor::Erase,
                    kind: kind.clone(),
                    at,
                },
            )?;
            moved = true;
        } else if gone(binding.previous) {
            binding.previous = DrafterServing::Stock;
            BINDINGS.put(store, wtxn, &key, &binding)?;
        }
    }
    if !moved {
        record_event_in_txn(store, wtxn, DrafterActor::Erase, kind, None, at)?;
    }
    Ok(())
}

/// The version table's declared scrub, for every drafter family: an erased
/// id's versions go as [`erase_drafters_for_source_in_txn`] takes them, the
/// training examples that name it go (FIX 15128), and an erased actor is
/// forgotten in the policy and the events that name it.
/// An event row that does not decode goes. One-way, in the erase's own
/// transaction.
///
/// # Errors
///
/// Storage and custody faults.
pub(crate) fn erase_drafter_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let store = &vault.store;
    erase_drafter_examples_for_source_in_txn(
        &crate::secret_record::CustodyWrite::of(vault),
        wtxn,
        id,
    )?;
    erase_drafters_for_source_in_txn(store, wtxn, id)?;
    if let Some(mut policy) = POLICY.get_lenient(store, wtxn, &())?
        && policy.set_by.as_mut().is_some_and(|by| by.forget(id))
    {
        POLICY.put(store, wtxn, &(), &policy)?;
    }
    let mut rows = Vec::new();
    for row in EVENTS.iter_raw_from(store, &*wtxn, &[])? {
        rows.push(row?);
    }
    for (key, value) in rows {
        match (
            <EntityId as SideKey>::decode_key(&key),
            EVENTS.decode_value(&value),
        ) {
            (Some(event_id), Ok(mut event)) => {
                if event.by.forget(id) {
                    EVENTS.put(store, wtxn, &event_id, &event)?;
                }
            }
            _ => delete_raw(store, wtxn, EVENTS.decl().prefix, &key)?,
        }
    }
    Ok(())
}
