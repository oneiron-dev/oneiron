//! What a probe's query is written from, and what erasing it takes (FIX 9829).
//!
//! A probe keeps its query's sources on its own row
//! ([`super::SpaceProbe::source_refs`]): the rows its document's words or bytes are read from,
//! and every record those derive from. Erasing any of them, its document or its media query
//! erases the probe and its evaluation copy in the erase's own writer. Erasing a record it only
//! finds takes that record from its targets, and a probe left with none goes.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::super::media::PendingMedia;
use super::{EMBEDDING_PROBE, repo_projection};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::provenance::made_by::MadeByInputRole;
use crate::registry::ENTITY_TYPE_TURN;

/// The stored rows a query written from `document` is written from: the rows its words or
/// bytes are read from, and every record those derive from, walked to the end through
/// `DerivedFrom` edges, registered source versions, the inputs of row births and later text
/// commits, and a TURN's messages, each row once.
///
/// # Errors
/// A store failure.
pub(super) fn probe_source_refs_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    document: &PendingMedia,
) -> Result<BTreeSet<EntityId>> {
    let mut seen = BTreeSet::new();
    let mut frontier = vec![document.id];
    frontier.extend(document.source_rows.iter().flatten().copied());
    let mut sources = BTreeSet::new();
    while let Some(row) = frontier.pop() {
        if !seen.insert(row) {
            continue;
        }
        let Some(record) = vault.store.port_entity_record(txn, &row)? else {
            continue;
        };
        sources.insert(row);
        if record.entity_type == ENTITY_TYPE_TURN
            && let Some(members) =
                crate::tagging::turn_members_in_txn(vault, &vault.store, txn, &row, false)?
        {
            frontier.extend(members.into_iter().map(|(message, ..)| message));
        }
        for origin in vault.store.port_edge_peers(
            txn,
            &row,
            EdgeDirection::Out,
            crate::EdgeKind::DerivedFrom,
        )? {
            frontier.push(origin?);
        }
        frontier.extend(crate::ports::dependency_sources_in(
            &vault.store,
            txn,
            &row,
        )?);
        if let Some(birth) = crate::provenance::birth::row_birth_in_txn(&vault.store, txn, &row)? {
            frontier.extend(
                birth
                    .made_by
                    .inputs
                    .iter()
                    .filter(|input| input.role == MadeByInputRole::Input)
                    .map(|input| input.row),
            );
        }
        frontier.extend(crate::entity_doc::commit_input_rows_in_txn(
            vault, txn, &row,
        )?);
    }
    Ok(sources)
}

/// Whether every row of `rows` is still a stored record as `txn` reads it: the author's writer
/// asks it of a query's sources, so a row erased while the model ran never has its words
/// stored again.
///
/// # Errors
/// A store failure.
pub(super) fn all_stored_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    rows: &BTreeSet<EntityId>,
) -> Result<bool> {
    for row in rows {
        if vault.store.port_entity_record(txn, row)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// In the writer that erases `id`, before its edges and provenance are torn down: every probe
/// whose query was written from it ([`super::SpaceProbe::query_sources`]) goes with its
/// evaluation copy, and every probe it answers loses it from its targets, going too when it
/// answers nothing more (FIX 9829). A probe that keeps its query keeps its id and its copy,
/// whose proof reads only its query's sources.
///
/// # Errors
/// A store failure.
pub(crate) fn erase_probe_sources_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    for (key, mut probe) in EMBEDDING_PROBE.scan(&vault.store, wtxn)? {
        if probe.query_sources().contains(id) {
            drop_probe_in_txn(vault, wtxn, &key)?;
        } else if probe.targets.remove(id) {
            if probe.targets.is_empty() {
                drop_probe_in_txn(vault, wtxn, &key)?;
            } else {
                EMBEDDING_PROBE.put(&vault.store, wtxn, &key, &probe)?;
            }
        }
    }
    Ok(())
}

/// Deletes probe `key` and its evaluation copy.
fn drop_probe_in_txn(vault: &Vault, wtxn: &mut RwTxn<'_>, key: &[u8; 16]) -> Result<()> {
    EMBEDDING_PROBE.delete(&vault.store, wtxn, key)?;
    repo_projection::drop_probe_query_copy_in_txn(vault, wtxn, key)
}
