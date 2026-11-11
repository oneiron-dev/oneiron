//! A hard erase of a source row over the kept step starts it owns (FIX
//! 20329).
//!
//! A step start copies its run's replay row as it stood before the step.
//! An output of that prefix whose input rows name the source holds the
//! source's words: its preview, and its body. The erase of the live row's
//! outputs reads the replay records alone, so the start keeps them. This
//! pass reaches the start through its capsule, in the same writer, before
//! any live output is released.
//!
//! The source owns a start as a checkpoint's rest owners name it
//! ([`step_start_owners_in_txn`]), whether or not the start was ever
//! checkpointed. Each start it owns retires whole. Its capsule marks the
//! start erased and keeps its other bodies and what the step was. The run's
//! occurrence of its manifest is released with its own marks, and so is
//! each of its pieces no kept start of the run and actor names. Each body
//! instance whose last holder this releases retires under the source's
//! erase; an instance another holder keeps owes its retirement to that
//! holder's release. A continuation and a shadow arm then meet the start
//! as erased, and no later checkpoint carries it. A start that does not
//! read is left as it is. A repeated erase finds no start to retire.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::super::super::replay::CodeRunRawOutput;
use super::super::response_erase::release_occurrence_in_txn;
use super::CAPSULES;
use super::pieces::PieceScope;
use super::start_parts::{
    KeptStart, capsule_in_txn, kept_step_starts_in_txn, step_start_owners_in_txn,
};
use super::start_pieces::{release_unnamed_start_pieces_in_txn, start_manifest_pieces_in_txn};
use crate::store::{Store, erase_bodies_for_owner_in_txn};
use crate::{EntityId, Result};

/// The start pieces each run holds for one actor, by run and actor.
type ScopedPieces = BTreeMap<(EntityId, EntityId), BTreeSet<[u8; 32]>>;

/// FIX 20329: retires every kept step start `source` owns, in the hard
/// erase of `source`, in its accepted writer. The caller has made its hold
/// checks. Each piece digest of each start's manifest is read first: its
/// config, its frame, each node and element of each array, or its one piece
/// when it is kept whole. Then every reached capsule is put with its start
/// erased, each manifest occurrence is released, and the pieces of each run
/// and actor no kept start names are released. Only the digests released
/// here retire, under the erase of `source`.
///
/// # Errors
///
/// Storage and custody errors.
pub(in crate::code_run::storage) fn retire_source_step_starts_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let owned = owned_starts_in_txn(store, wtxn, source)?;
    if owned.is_empty() {
        return Ok(());
    }
    let mut pieces = ScopedPieces::new();
    let mut reached = Vec::new();
    for kept in owned {
        let Some((key, capsule)) = capsule_in_txn(store, wtxn, &kept.row)? else {
            continue;
        };
        let Some(start) = &capsule.start else {
            continue;
        };
        let named = pieces.entry((kept.run, kept.actor)).or_default();
        start_manifest_pieces_in_txn(store, wtxn, start.body, named)?;
        reached.push((key, capsule));
    }
    let mut manifests = Vec::new();
    for (key, mut capsule) in reached {
        let run = capsule.run;
        if let Some(start) = &mut capsule.start {
            start.erased = true;
            let handle = CodeRunRawOutput::of_ref(start.body).handle;
            manifests.push((run, start.path.clone(), handle));
        }
        CAPSULES.put(store, wtxn, &key, &capsule)?;
    }
    let mut released: BTreeMap<EntityId, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for (run, path, handle) in manifests {
        if let Some(digest) = release_occurrence_in_txn(store, wtxn, run, path, handle)? {
            released.entry(run).or_default().insert(digest);
        }
    }
    for ((run, actor), named) in pieces {
        let scope = PieceScope { run, actor };
        let digests = release_unnamed_start_pieces_in_txn(store, wtxn, scope, &named)?;
        released.entry(run).or_default().extend(digests);
    }
    for (run, digests) in released {
        let digests: Vec<[u8; 32]> = digests.into_iter().collect();
        erase_bodies_for_owner_in_txn(store, wtxn, source, &run, &digests, false)?;
    }
    Ok(())
}

/// Every kept step start `txn` holds whose rest owners name `source`: each
/// output of its prefix whose input rows name it among them. Each start is
/// read from its own prefix, never from its run's live row. A start whose
/// own actor or run is `source` is left to that erase's existing route
/// (the actor's capsule scrub, the run's owner release), under the cause
/// it already records.
fn owned_starts_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    source: &EntityId,
) -> Result<Vec<KeptStart>> {
    let mut owned = Vec::new();
    for kept in kept_step_starts_in_txn(store, txn)? {
        if kept.actor == *source || kept.run == *source {
            continue;
        }
        if step_start_owners_in_txn(store, txn, &kept)?.contains(source) {
            owned.push(kept);
        }
    }
    Ok(owned)
}
