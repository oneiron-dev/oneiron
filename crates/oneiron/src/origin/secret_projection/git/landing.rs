//! A built masked Git copy's landing (FIX 9105, FIX 9106): its records in
//! bounded transactions, the graph's own first, then its building
//! directory moved to the graph's, then its refs. A reader admits only a
//! copy whose refs stand, so it never reads a partial one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::super::claims::{RepoProjectionClaim, RepoProjectionRecord};
use super::super::graph_objects::RepoProjectionCopy;
use super::{
    RepoGitProjection, RepoGitProjectionRoots, graph_dir, projection_of, publish_copy_refs,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitObjectKind, GitOid, GitWire};

/// Records written per write transaction after the graph's own (FIX
/// 9106): a copy of any history lands in bounded transactions, never one.
const RECORDS_PER_WRITE: usize = 4096;

/// Lands the copy built in `building` as `graph` (FIX 9105, FIX 9106): its
/// records first, then its directory moved to the graph's, then its refs,
/// so a reader admits it only whole.
///
/// # Errors
/// A failed write, move or publication.
#[allow(clippy::too_many_arguments)]
pub(super) fn land_copy(
    vault: &Vault,
    wire: &GitWire<'_>,
    building: &Path,
    graph: &RepoProjectionClaim,
    store_id: EntityId,
    roots: &RepoGitProjectionRoots,
    copy: &RepoProjectionCopy,
    now: u64,
) -> Result<RepoGitProjection> {
    record_projection(vault, graph, roots, copy)?;
    let dir = graph_dir(vault, store_id, graph.graph)?;
    // A graph directory whose refs were never published is an interrupted
    // landing.
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::rename(building, &dir)?;
    let copy_store = wire
        .existing_projection_store(&dir)?
        .ok_or(Error::InvariantViolation(
            "a landed masked copy has no store",
        ))?;
    publish_copy_refs(wire, &copy_store, roots, copy, now)?;
    Ok(projection_of(graph.clone(), &copy_store, roots, copy))
}

/// Every record of one copy (FIX 9106): the graph first, in its own
/// transaction, so each record about it has it to stand on, then the rest
/// in transactions of [`RECORDS_PER_WRITE`]. Each is idempotent at its id,
/// so a landing started over writes only what is missing.
fn record_projection(
    vault: &Vault,
    graph: &RepoProjectionClaim,
    roots: &RepoGitProjectionRoots,
    copy: &RepoProjectionCopy,
) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
        graph.put_in_txn(vault, wtxn, at).map(|_| ())
    })?;
    let records = copy_records(graph.graph, roots, copy);
    for batch in records.chunks(RECORDS_PER_WRITE) {
        vault.with_write_txn(|wtxn| {
            let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
            for record in batch {
                record.put_in_txn(vault, wtxn, at)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// Every record about the graph `id` one copy writes: each object, each
/// root's copy, each changed link, and each copy commit's originals (FIX
/// 10275).
fn copy_records(
    id: EntityId,
    roots: &RepoGitProjectionRoots,
    copy: &RepoProjectionCopy,
) -> Vec<RepoProjectionClaim> {
    let mut records = Vec::with_capacity(copy.objects.len() + copy.links.len());
    let mut commits: BTreeMap<&GitOid, BTreeSet<&GitOid>> = BTreeMap::new();
    for object in &copy.objects {
        if object.kind == GitObjectKind::Commit {
            commits
                .entry(&object.copy)
                .or_default()
                .insert(&object.original);
        }
        records.push(RepoProjectionClaim::of(
            id,
            RepoProjectionRecord::Object {
                original: object.original.clone(),
                copy: object.copy.clone(),
                kind: object.kind,
                signature_not_preserved: object.signature_not_preserved,
                marks: object.marks.clone(),
                occurrence: object.occurrence.clone(),
            },
        ));
    }
    for (name, original) in &roots.published {
        records.push(RepoProjectionClaim::of(
            id,
            RepoProjectionRecord::Ref {
                name: name.as_str().to_owned(),
                original: original.clone(),
                copy: copy.copy_of(original),
            },
        ));
    }
    if let Some(original) = &roots.private_root {
        records.push(RepoProjectionClaim::of(
            id,
            RepoProjectionRecord::PrivateRoot {
                original: original.clone(),
                copy: copy.copy_of(original),
            },
        ));
    }
    for link in &copy.links {
        records.push(RepoProjectionClaim::of(
            id,
            RepoProjectionRecord::Link {
                parent: link.parent.clone(),
                parent_occurrence: link.parent_occurrence.clone(),
                place: link.place.clone(),
                child_original: link.child_original.clone(),
                child_copy: link.child_copy.clone(),
            },
        ));
    }
    for (copy, originals) in commits {
        records.push(RepoProjectionClaim::of(
            id,
            RepoProjectionRecord::CommitOriginals {
                copy: copy.clone(),
                originals: originals.into_iter().cloned().collect(),
            },
        ));
    }
    records
}
