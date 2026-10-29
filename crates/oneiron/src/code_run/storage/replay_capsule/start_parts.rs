//! The step starts a checkpoint carries as parts (FIX 9180, coord-b slice
//! d): each read by its capsule's typed ref, and each republished from its
//! parts, among an image's raw rows on a restore and through the start's
//! own publisher on an activation.
//!
//! A kept start is found by its capsule, never by a path's name: the
//! capsule's run and the start's path are its occurrence, the start's body
//! ref and digest its bytes, inline or file-backed alike. A restore
//! republishes a recomposed start among the image's rows before any row
//! lands, so no prefix reader ever sees the old one: held inline in its row
//! whatever its size (CALLS "republished step start stays inline"), under
//! the same occurrence, its marks moved to its new handle, and its
//! descriptor and its capsule naming the new body. An activation
//! republishes it in its own writer, and erases nothing: what its source
//! retired, the source retired.

use std::collections::BTreeSet;

use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::super::replay_capsule::{ExecutorStepStart, StepReplayCapsule, StepStartBody};
use super::super::records::{
    RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, RAW_OUTPUTS, StoredBody, code_run_body_row_key,
    owned_body,
};
use super::super::replay_bodies::replay_owners;
use super::super::response_erase::release_occurrence_in_txn;
use super::CAPSULES;
use super::spawn_erase::{publish_start_in_txn, republished_start_body, start_bytes_in_txn};
use crate::compaction::output::OutputRef;
use crate::provenance::body::{
    OwnedBody, digest_is_held_in_txn, prune_digest_in_rows, queue_pruned_file_in_txn,
};
use crate::side_table::{self, Named, SideKey, SideTable, SideTableDbs};
use crate::store::{BODY_KEYS, BodyMeter, Store};
use crate::{EntityId, Error, Result};

/// A capsule's key: its attempt, lease generation and step.
type CapsuleKey = (EntityId, u64, u64);

/// An image's raw rows of one database, sorted by key.
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// The body descriptors, as an image's raw rows hold them: a restore's
/// republish of a step start names its new body there.
const BODY_ROWS: SideTable<(EntityId, EntityId), OwnedBody, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY);

/// Who holds a digest, as an image's raw rows hold it.
const BODY_DIGEST_ROWS: SideTable<([u8; 32], EntityId), EntityId, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_DIGEST);

/// The file digests no descriptor holds, as an image's raw rows hold them.
const BODY_RELEASED_ROWS: SideTable<[u8; 32], u64, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_RELEASED);

/// A kept step start, as its capsule names it (FIX 9180).
pub(crate) struct KeptStart {
    /// Its capsule's raw `vault_meta` key.
    pub(crate) row: Vec<u8>,
    /// The run that owns its body.
    pub(crate) run: EntityId,
    /// The actor whose step it is.
    pub(crate) actor: EntityId,
    /// The digest its whole body rests under.
    pub(crate) digest: [u8; 32],
    /// Its body.
    pub(crate) bytes: Vec<u8>,
}

/// Whether `row`, a raw `vault_meta` key, is a step replay capsule's.
pub(crate) fn step_capsule_row(row: &[u8]) -> bool {
    row.starts_with(CAPSULES.decl().prefix)
}

/// Every kept step start `txn` holds, by its capsule: a capsule that does
/// not decode, holds its content no longer, names no start, or whose run
/// no longer holds its start whole, keeps none. A start whose bytes do not
/// read is none here, and is reported: it travels as it did (CALLS "an
/// unread step start travels whole").
///
/// # Errors
///
/// Storage errors.
pub(crate) fn kept_step_starts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<KeptStart>> {
    let mut kept = Vec::new();
    let mut unread = 0_usize;
    for row in CAPSULES.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        match kept_start_in_txn(store, txn, &key, &bytes) {
            Ok(Some(start)) => kept.push(start),
            Ok(None) => {}
            Err(_) => unread += 1,
        }
    }
    if unread > 0 {
        tracing::warn!(
            unread,
            "step starts whose bodies do not read travel whole, as they did"
        );
    }
    Ok(kept)
}

/// The kept start of the capsule row `row` (a raw `vault_meta` key) as
/// `txn` holds it; `None` as [`kept_step_starts_in_txn`] keeps none.
///
/// # Errors
///
/// Storage and custody errors reading its body.
pub(crate) fn kept_step_start_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &[u8],
) -> Result<Option<KeptStart>> {
    let Some(key) = row.strip_prefix(CAPSULES.decl().prefix) else {
        return Ok(None);
    };
    let Some(bytes) = store.side_vault_meta().get(txn, row)? else {
        return Ok(None);
    };
    kept_start_in_txn(store, txn, key, &bytes)
}

/// The kept start of the capsule `bytes` at `key` (after the table's
/// prefix).
fn kept_start_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    bytes: &[u8],
) -> Result<Option<KeptStart>> {
    let Ok(capsule) = CAPSULES.decode_value(bytes) else {
        return Ok(None);
    };
    let (Some(actor), Some(start)) = (capsule.content.actor(), &capsule.start) else {
        return Ok(None);
    };
    let Some(held) = start_bytes_in_txn(store, txn, capsule.run, start)? else {
        return Ok(None);
    };
    if *blake3::hash(&held).as_bytes() != start.digest {
        return Ok(None);
    }
    let mut row = CAPSULES.decl().prefix.to_vec();
    row.extend_from_slice(key);
    Ok(Some(KeptStart {
        row,
        run: capsule.run,
        actor,
        digest: start.body.hash,
        bytes: held,
    }))
}

/// Who owns a kept start's rest (CALLS "step start rest owners"): the actor
/// whose step it is and its run, whose erases retire the whole start body
/// today, and every owner its prefix row's replies name, as a replay row's
/// reply.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn step_start_owners_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    kept: &KeptStart,
) -> Result<Vec<EntityId>> {
    let mut owners = vec![kept.actor, kept.run];
    if let Ok(body) = rmp_serde::from_slice::<StepStartBody>(&kept.bytes) {
        owners.extend(replay_owners(store, txn, &body.record)?);
    }
    owners.sort_unstable();
    owners.dedup();
    Ok(owners)
}

/// The raw `vault_meta` key of the body row the capsule row value `capsule`
/// names as its start's; `None` for one with no start or that does not
/// decode.
pub(crate) fn step_start_body_row(capsule: &[u8]) -> Option<Vec<u8>> {
    let start = CAPSULES.decode_value(capsule).ok()?.start?;
    Some(code_run_body_row_key(&start.body.hash))
}

/// The capsule row `row` names, by its key, as `txn` holds it.
fn capsule_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &[u8],
) -> Result<Option<(CapsuleKey, StepReplayCapsule)>> {
    let Some(key) = row
        .strip_prefix(CAPSULES.decl().prefix)
        .and_then(<CapsuleKey as SideKey>::decode_key)
    else {
        return Ok(None);
    };
    Ok(CAPSULES
        .get_lenient(store, txn, &key)?
        .map(|capsule| (key, capsule)))
}

/// FIX 9180: an activation's republish of the step start the capsule row
/// `row` names, as `bytes`, what its source retired of its parts left of
/// it, through the start's own publisher; the capsule names its new body
/// and digest. The old body goes once nothing holds it.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn republish_step_start_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    row: &[u8],
    bytes: &[u8],
) -> Result<()> {
    let Some((key, mut capsule)) = capsule_in_txn(store, wtxn, row)? else {
        return Ok(());
    };
    let Some(start) = capsule.start.take() else {
        return Ok(());
    };
    let (body, held) = publish_start_in_txn(store, wtxn, capsule.run, &start, bytes)?;
    capsule.start = Some(ExecutorStepStart {
        body,
        digest: *blake3::hash(bytes).as_bytes(),
        ..start
    });
    CAPSULES.put(store, wtxn, &key, &capsule)?;
    if let Some(digest) = held.filter(|digest| *digest != body.hash) {
        drop_unheld_body_in_txn(store, wtxn, &digest)?;
    }
    Ok(())
}

/// FIX 9180: an activation's release of the step start the capsule row
/// `row` names, whose rest its source retired: the run's occurrence goes
/// with its marks, as a retired body's does, and its body once nothing
/// holds it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn release_step_start_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    row: &[u8],
) -> Result<()> {
    let Some((_, capsule)) = capsule_in_txn(store, wtxn, row)? else {
        return Ok(());
    };
    let Some(start) = capsule.start else {
        return Ok(());
    };
    let handle = CodeRunRawOutput::of_ref(start.body).handle;
    if let Some(digest) = release_occurrence_in_txn(store, wtxn, capsule.run, start.path, handle)? {
        drop_unheld_body_in_txn(store, wtxn, &digest)?;
    }
    Ok(())
}

/// The body `digest` once no descriptor holds it: an inline row of its
/// own goes, a file to the collector. A row that holds its body on its own
/// stays.
fn drop_unheld_body_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    if digest_is_held_in_txn(store, wtxn, digest)? {
        return Ok(());
    }
    let handle = CodeRunRawOutput::of_ref(OutputRef {
        hash: *digest,
        byte_len: 0,
    })
    .handle;
    match RAW_OUTPUTS.get(store, wtxn, &handle)? {
        Some(StoredBody::Inline { held: false, .. }) => {
            RAW_OUTPUTS.delete(store, wtxn, &handle)?;
        }
        Some(StoredBody::File { held: false, .. }) => {
            queue_pruned_file_in_txn(store, wtxn, digest)?;
        }
        _ => {}
    }
    Ok(())
}

/// The place of the row `key` among sorted `rows`, or where it goes.
fn place(rows: &Rows, key: &[u8]) -> std::result::Result<usize, usize> {
    rows.binary_search_by(|(row, _)| row.as_slice().cmp(key))
}

/// Puts the row `key` among sorted `rows`, in order.
fn put_row(rows: &mut Rows, key: Vec<u8>, value: Vec<u8>) {
    match place(rows, &key) {
        Ok(at) => rows[at].1 = value,
        Err(at) => rows.insert(at, (key, value)),
    }
}

/// Takes the row `key` out of sorted `rows`.
fn take_row(rows: &mut Rows, key: &[u8]) -> Option<Vec<u8>> {
    place(rows, key).ok().map(|at| rows.remove(at).1)
}

/// FIX 9180: a restore's republish of the step start the capsule row `row`
/// names, as the recomposed `bytes`, among an image's raw `vault_meta`
/// rows, before any lands: held inline whatever its size, under the same
/// occurrence, its taint and secret marks moved to its new handle, its
/// descriptor and holder row naming the new body, and the capsule naming
/// its new body and digest. Returns the digest the start rested under and
/// the one it rests under now; `None` for a capsule that names no start.
///
/// # Errors
///
/// A row that does not decode or encode.
pub(crate) fn republish_step_start_in_rows(
    rows: &mut Rows,
    row: &[u8],
    bytes: &[u8],
) -> Result<Option<([u8; 32], [u8; 32])>> {
    let at = place(rows, row)
        .map_err(|_| Error::CorruptedIndex("a carried step start's capsule row"))?;
    let mut capsule = CAPSULES.decode_value(&rows[at].1)?;
    let Some(start) = capsule.start.take() else {
        return Ok(None);
    };
    let run = capsule.run;
    let old = CodeRunRawOutput {
        path: start.path.clone(),
        ..CodeRunRawOutput::of_ref(start.body)
    };
    let occurrence = ResultOccurrence::of(Some(run), &old)?;
    let mut meter = BodyMeter::new();
    meter.feed(bytes);
    let facts = meter.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS);
    let output = CodeRunRawOutput::from_facts(start.path.clone(), &facts, true)?;
    let (before, after) = (
        occurrence.mark_key(&old.handle),
        occurrence.mark_key(&output.handle),
    );
    if before != after {
        if let Some(taint) = take_row(rows, &RAW_OUTPUT_TAINTS.key_bytes(&before)) {
            put_row(rows, RAW_OUTPUT_TAINTS.key_bytes(&after), taint);
        }
        if let Some(marked) = take_row(rows, &RAW_OUTPUT_SECRETS.key_bytes(&before)) {
            put_row(rows, RAW_OUTPUT_SECRETS.key_bytes(&after), marked);
        }
    }
    let secret = RAW_OUTPUT_SECRETS.key_bytes(&after);
    if let Some(reason) = facts.secret
        && place(rows, &secret).is_err()
    {
        put_row(
            rows,
            secret,
            RAW_OUTPUT_SECRETS.encode_value(&reason.to_owned())?,
        );
    }
    let key = RAW_OUTPUTS.key_bytes(&output.handle);
    let held = place(rows, &key)
        .ok()
        .and_then(|at| RAW_OUTPUTS.decode_value(&rows[at].1).ok())
        .is_some_and(|body| {
            matches!(
                body,
                StoredBody::Inline { held: true, .. } | StoredBody::File { held: true, .. }
            )
        });
    let body = republished_start_body(bytes).holding(held);
    put_row(rows, key, RAW_OUTPUTS.encode_value(&body)?);
    let descriptor = owned_body(run, &output, &body)?;
    put_row(
        rows,
        BODY_ROWS.key_bytes(&(run, occurrence.id())),
        BODY_ROWS.encode_value(&descriptor)?,
    );
    take_row(
        rows,
        &BODY_DIGEST_ROWS.key_bytes(&(old.raw_blake3, occurrence.id())),
    );
    put_row(
        rows,
        BODY_DIGEST_ROWS.key_bytes(&(output.raw_blake3, occurrence.id())),
        BODY_DIGEST_ROWS.encode_value(&run)?,
    );
    take_row(rows, &BODY_RELEASED_ROWS.key_bytes(&output.raw_blake3));
    let moved = (old.raw_blake3, output.raw_blake3);
    capsule.start = Some(ExecutorStepStart {
        body: output.output_ref(),
        digest: *blake3::hash(bytes).as_bytes(),
        ..start
    });
    put_row(rows, row.to_vec(), CAPSULES.encode_value(&capsule)?);
    Ok(Some(moved))
}

/// FIX 9180: a restore's disposition of the step start the capsule row
/// `row` names, whose rest retired, among an image's raw rows, as a
/// retired body leaves one: every descriptor holding its body goes
/// explicitly incomplete, with nothing to show. Returns the digest its
/// body rested under; `None` for a capsule that names no start.
///
/// # Errors
///
/// A row that does not decode.
pub(crate) fn drop_step_start_in_rows(rows: &mut Rows, row: &[u8]) -> Result<Option<[u8; 32]>> {
    let at = place(rows, row)
        .map_err(|_| Error::CorruptedIndex("a carried step start's capsule row"))?;
    let Some(start) = CAPSULES.decode_value(&rows[at].1)?.start else {
        return Ok(None);
    };
    prune_digest_in_rows(rows, &start.body.hash)?;
    Ok(Some(start.body.hash))
}

/// FIX 9180: settles, among an image's raw rows, the whole bodies carried
/// starts rested under (`rested`) once each start landed again as the
/// bodies `landed`: a body row no start lands again goes, as no stream
/// carried its bytes, and the instance row of each names an inline body, as
/// every landed start is held inline now.
///
/// # Errors
///
/// An instance row that does not decode or encode.
pub(crate) fn settle_start_bodies_in_rows(
    rows: &mut Rows,
    rested: &BTreeSet<[u8; 32]>,
    landed: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    for digest in rested.difference(landed) {
        take_row(rows, &code_run_body_row_key(digest));
    }
    for digest in rested.union(landed) {
        let Ok(at) = place(rows, &BODY_KEYS.key_bytes(digest)) else {
            continue;
        };
        let mut key = BODY_KEYS.decode_value(&rows[at].1)?;
        if !key.inline {
            key.inline = true;
            rows[at].1 = BODY_KEYS.encode_value(&key)?;
        }
    }
    Ok(())
}
