//! An erase of a spawn's target over the step starts the capsules keep
//! (FIX 9180, Engine C2). A start body carries the run's replay row as it
//! stood when the step began, a second copy of each spawn's ask. For every
//! kept start whose prefix holds a call the erase reached, only those calls
//! take their selective erased form, as the live row's do, so the live row
//! still descends from the prefix byte for byte. The changed start is
//! published again as its pieces (FIX 4192), its manifest under the same
//! occurrence, and the capsule names its new body and digest. The old
//! manifest's instance, and the instance of each superseded piece no kept
//! start names once every reached start is republished, retire under the
//! erase of each erased target that reached them, never the run's; the
//! rest of the capsule, its request, its other answers and its key stay.
//! Inline and file-backed starts alike, at any size. Each kept start is
//! read on its own, whatever its run's live row holds.
//!
//! The erase runs in the erase's own writer, from a store alone, where no
//! body instance can be minted: each republished piece is held inline
//! whatever its size (CALLS "republished step start stays inline",
//! [`republished_start_body`]). A start that is gone, released or does not
//! decode is left as it is and reported.

use std::collections::{BTreeMap, BTreeSet};

use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::super::replay_capsule::{ExecutorStepStart, StepReplayCapsule, StepStartBody};
use super::super::records::{
    RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, RAW_OUTPUTS, StoredBody, owned_body,
};
use super::super::response_erase::release_occurrence_in_txn;
use super::super::spawn_erase::erase_reached_calls;
use super::CAPSULES;
use super::pieces::PieceScope;
use super::start_pieces::{
    release_unnamed_start_pieces_in_txn, republish_start_pieces_in_txn, start_bytes_in_txn,
};
use crate::code_run::{decode_code_run_replay_record, encode_code_run_replay_record};
use crate::compaction::output::OutputRef;
use crate::provenance::body::publish_body_in_txn;
use crate::side_table::SideKey;
use crate::store::{BodyMeter, Store, erase_bodies_for_owner_in_txn};
use crate::{EntityId, Error, Result};

/// A capsule's key: its attempt, lease generation and step.
type CapsuleKey = (EntityId, u64, u64);

/// The superseded start pieces of each run and actor (FIX 4192), each with
/// the erased targets whose erase reached the starts that named it.
type SupersededPieces = BTreeMap<(EntityId, EntityId), BTreeMap<[u8; 32], BTreeSet<EntityId>>>;

/// A kept start an erase reached: its capsule's key, its run and actor, its
/// capsule, and the start with the reached calls in their erased form.
type ReachedStart = (CapsuleKey, PieceScope, StepReplayCapsule, ErasedStart);

/// A kept start with the reached calls of its prefix in their selective
/// erased form, and the erased targets that reached them: the causes its
/// old body retires under.
struct ErasedStart {
    bytes: Vec<u8>,
    causes: BTreeSet<EntityId>,
}

/// FIX 9180 (CALLS "republished step start stays inline"): a step start an
/// erase of a spawn target publishes again is held inline in its row,
/// whatever its size: each new piece and its manifest (FIX 4192). The
/// erase's writer cannot mint the body instance a spill needs, and the
/// start must change in that writer; nothing is cut.
pub(super) fn republished_start_body(bytes: &[u8]) -> StoredBody {
    StoredBody::Inline {
        bytes: bytes.to_vec(),
        held: false,
    }
}

/// The erase of the spawn targets `erased` over every kept step start, in
/// the erase's own writer (FIX 9180): each start whose prefix holds a call
/// one of them seats is published again with only those calls in their
/// selective erased form, and its capsule names the new body. Every kept
/// start is read, whatever its run's live row holds: a row already in its
/// erased form, gone or unreadable exempts none of its starts. FIX 4192:
/// once every reached start is republished, each superseded piece no kept
/// start of its run and actor names is released, and retires under the
/// erase of each target that reached a start naming it.
///
/// # Errors
///
/// Storage and custody errors.
pub(in crate::code_run::storage) fn erase_spawn_prefixes_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut superseded = SupersededPieces::new();
    for (key, scope, mut capsule, changed) in reached_starts_in_txn(store, wtxn, erased)? {
        let Some(start) = capsule.start.take() else {
            continue;
        };
        let republished =
            republish_start_pieces_in_txn(store, wtxn, scope, &start, &changed.bytes)?;
        capsule.start = Some(republished.start);
        CAPSULES.put(store, wtxn, &key, &capsule)?;
        // The old manifest's instance retires as the old whole body's did.
        if let Some(digest) = republished.manifest {
            for cause in &changed.causes {
                erase_bodies_for_owner_in_txn(store, wtxn, cause, &scope.run, &[digest], false)?;
            }
        }
        let pieces = superseded.entry((scope.run, scope.actor)).or_default();
        for digest in republished.superseded {
            pieces
                .entry(digest)
                .or_default()
                .extend(changed.causes.iter().copied());
        }
    }
    for ((run, actor), pieces) in superseded {
        let candidates: BTreeSet<[u8; 32]> = pieces.keys().copied().collect();
        let scope = PieceScope { run, actor };
        for digest in release_unnamed_start_pieces_in_txn(store, wtxn, scope, &candidates)? {
            for cause in pieces.get(&digest).into_iter().flatten() {
                erase_bodies_for_owner_in_txn(store, wtxn, cause, &run, &[digest], false)?;
            }
        }
    }
    Ok(())
}

/// Every kept start whose prefix holds a call one of `erased` seats, read
/// in `txn`, with those calls in their erased form. A start that does not
/// decode is counted and reported.
fn reached_starts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<Vec<ReachedStart>> {
    let mut reached = Vec::new();
    let mut unread = 0_usize;
    for row in CAPSULES.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <CapsuleKey as SideKey>::decode_key(&key) else {
            continue;
        };
        let Ok(capsule) = CAPSULES.decode_value(&bytes) else {
            unread += 1;
            continue;
        };
        // An erased capsule holds no start.
        let (Some(actor), Some(start)) = (capsule.content.actor(), &capsule.start) else {
            continue;
        };
        let scope = PieceScope {
            run: capsule.run,
            actor,
        };
        let Some(held) = start_bytes_in_txn(store, txn, scope, start)? else {
            continue;
        };
        match erased_start(&held, erased)? {
            Some(Some(changed)) => reached.push((key, scope, capsule, changed)),
            Some(None) => {}
            None => unread += 1,
        }
    }
    if unread > 0 {
        tracing::warn!(
            unread,
            "step starts that do not decode keep their bytes; a spawn target erase cannot read their prefix"
        );
    }
    Ok(reached)
}

/// The start body `bytes` with each call of its prefix one of `erased`
/// seats in its selective erased form, and the ids that reached them:
/// `Some(None)` when no call changed, `None` for a body or prefix that does
/// not decode.
///
/// # Errors
///
/// A body that does not encode again.
fn erased_start(bytes: &[u8], erased: &BTreeSet<EntityId>) -> Result<Option<Option<ErasedStart>>> {
    let Ok(mut body) = rmp_serde::from_slice::<StepStartBody>(bytes) else {
        return Ok(None);
    };
    let Ok(mut record) = decode_code_run_replay_record(&body.record) else {
        return Ok(None);
    };
    let causes = erase_reached_calls(&mut record, erased)?;
    if causes.is_empty() {
        return Ok(Some(None));
    }
    body.record = encode_code_run_replay_record(&record)?;
    let bytes = rmp_serde::to_vec_named(&body)
        .map_err(|error| Error::InvalidConfig(format!("capsule start: {error}")))?;
    Ok(Some(Some(ErasedStart { bytes, causes })))
}

/// `bytes`, a start's new manifest (FIX 4192), published as the body run
/// `run` holds at `start`'s path, in place of the body `start` names: the
/// old occurrence is released, its taint and secret marks carried to the
/// new one. Returns the new body's ref and the digest the old occurrence
/// held. Nothing retires here: the source-side erase retires the old body
/// under its causes, and an activation's prune applies what its source
/// retired (FIX 9180, coord-b slice d).
///
/// # Errors
///
/// Storage and custody errors.
pub(super) fn publish_start_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    run: EntityId,
    start: &ExecutorStepStart,
    bytes: &[u8],
) -> Result<(OutputRef, Option<[u8; 32]>)> {
    let old = CodeRunRawOutput {
        path: start.path.clone(),
        ..CodeRunRawOutput::of_ref(start.body)
    };
    let old_marks = ResultOccurrence::of(Some(run), &old)?.mark_key(&old.handle);
    let taint = RAW_OUTPUT_TAINTS.get(store, wtxn, &old_marks)?;
    let marked = RAW_OUTPUT_SECRETS.get(store, wtxn, &old_marks)?;
    let held = release_occurrence_in_txn(store, wtxn, run, start.path.clone(), old.handle)?;
    let mut meter = BodyMeter::new();
    meter.feed(bytes);
    let facts = meter.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS);
    let output = CodeRunRawOutput::from_facts(start.path.clone(), &facts, true)?;
    // Bytes some row already holds stay as that row holds them.
    let body = match RAW_OUTPUTS.get(store, wtxn, &output.handle)? {
        Some(body) => body,
        None => {
            let body = republished_start_body(bytes);
            RAW_OUTPUTS.put(store, wtxn, &output.handle, &body)?;
            body
        }
    };
    let marks = ResultOccurrence::of(Some(run), &output)?.mark_key(&output.handle);
    if let Some(taint) = taint {
        RAW_OUTPUT_TAINTS.put(store, wtxn, &marks, &taint)?;
    }
    if let Some(reason) = marked.or_else(|| facts.secret.map(str::to_owned)) {
        RAW_OUTPUT_SECRETS.put(store, wtxn, &marks, &reason)?;
    }
    publish_body_in_txn(store, wtxn, &owned_body(run, &output, &body)?)?;
    Ok((output.output_ref(), held))
}
