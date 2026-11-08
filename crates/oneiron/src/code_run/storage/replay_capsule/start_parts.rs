//! The step starts a checkpoint carries as parts (FIX 9180, coord-b slice
//! d): each read by its capsule's typed ref, and each republished from its
//! parts, among an image's raw rows on a restore and through the start's
//! own piece writer on an activation.
//!
//! A kept start is found by its capsule, never by a path's name: the
//! capsule's run and the start's path are its manifest's occurrence, and
//! the whole start is put together from the pieces the manifest names, as
//! the run holds them for the actor (FIX 4192), inline or file-backed
//! alike. A restore republishes a recomposed start among the image's rows
//! before any row lands, so no prefix reader ever sees the old one: each
//! piece whose row does not hold its bytes is held inline whatever its size
//! (CALLS "republished step start stays inline"), and the manifest goes
//! under the same occurrence, its marks moved to its new handle, with its
//! descriptor and its capsule naming the new body. FIX 4192 review fix: a
//! census carries a carried start's content pieces without their bytes, so
//! they land again only from a live rest; a start whose rest retired leaves
//! each such piece to the settle, which takes every one no live start lands
//! again. An activation republishes it in its own writer, and erases
//! nothing: what its source retired, the source retired.

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
use super::pieces::PieceScope;
use super::spawn_erase::republished_start_body;
use super::start_pieces::{
    StartPieces, manifest_content_pieces, release_unnamed_start_pieces_in_txn,
    republish_start_pieces_in_txn, start_bytes_in_txn, start_manifest_pieces_in_txn,
};
use crate::compaction::output::OutputRef;
use crate::provenance::body::{
    BodyState, OwnedBody, digest_is_held_in_txn, hold_digest_inline_in_rows, prune_digest_in_rows,
    queue_pruned_file_in_txn,
};
use crate::side_table::{self, Named, SideKey, SideTable, SideTableDbs};
use crate::store::{BODY_KEYS, BodyMeter, Store};
use crate::{EntityId, Error, Result};

/// A capsule's key: its attempt, lease generation and step.
type CapsuleKey = (EntityId, u64, u64);

/// An image's raw rows of one database, sorted by key.
pub(super) type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// What a restore's republish of a start left among an image's rows (FIX
/// 4192): the digests that rested without their bytes, and the digests
/// whose body rows it put back.
type StartLanding = (BTreeSet<[u8; 32]>, BTreeSet<[u8; 32]>);

/// The body descriptors, as an image's raw rows hold them: a restore's
/// republish of a step start names its new body there.
const BODY_ROWS: SideTable<(EntityId, EntityId), OwnedBody, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY);

/// Who holds a digest, as an image's raw rows hold it.
pub(super) const BODY_DIGEST_ROWS: SideTable<([u8; 32], EntityId), EntityId, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_DIGEST);

/// The file digests no descriptor holds, as an image's raw rows hold them.
const BODY_RELEASED_ROWS: SideTable<[u8; 32], u64, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_RELEASED);

/// A kept step start, as its capsule names it (FIX 9180).
pub(crate) struct KeptStart {
    /// Its capsule's raw `vault_meta` key.
    pub(crate) row: Vec<u8>,
    /// The run that owns its pieces.
    pub(crate) run: EntityId,
    /// The actor whose step it is.
    pub(crate) actor: EntityId,
    /// Its whole body, put together from its pieces (FIX 4192).
    pub(crate) bytes: Vec<u8>,
}

/// Whether `row`, a raw `vault_meta` key, is a step replay capsule's.
pub(crate) fn step_capsule_row(row: &[u8]) -> bool {
    row.starts_with(CAPSULES.decl().prefix)
}

/// Every kept step start `txn` holds, by its capsule: a capsule that does
/// not decode, holds its content no longer, names no start, or whose run
/// no longer holds its manifest and each of its pieces whole, keeps none.
/// A start whose bytes do not read is none here, and is reported: it
/// travels as it did (CALLS "an unread step start travels whole").
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
    let (Some(scope), Some(start)) = (capsule_scope(&capsule), &capsule.start) else {
        return Ok(None);
    };
    let Some(held) = start_bytes_in_txn(store, txn, scope, start)? else {
        return Ok(None);
    };
    if *blake3::hash(&held).as_bytes() != start.digest {
        return Ok(None);
    }
    let mut row = CAPSULES.decl().prefix.to_vec();
    row.extend_from_slice(key);
    Ok(Some(KeptStart {
        row,
        run: scope.run,
        actor: scope.actor,
        bytes: held,
    }))
}

/// The run and actor whose pieces a capsule's start names (FIX 4192);
/// `None` for a capsule that holds its content no longer.
pub(super) fn capsule_scope(capsule: &StepReplayCapsule) -> Option<PieceScope> {
    let actor = capsule.content.actor()?;
    Some(PieceScope {
        run: capsule.run,
        actor,
    })
}

/// Who owns a kept start's rest (CALLS "step start rest owners"): the actor
/// whose step it is and its run, whose erases retire the whole start body
/// today, and every owner its prefix row's replies name, as a replay row's
/// reply: each fold answer the prefix records names its fold's words id and
/// sources there (FIX 18924). The start's captured folds keep no words (FIX
/// 18694), so they name no owner here.
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
/// names as its start's, its manifest's (FIX 4192); `None` for one with no
/// start or that does not decode.
pub(crate) fn step_start_body_row(capsule: &[u8]) -> Option<Vec<u8>> {
    let start = CAPSULES.decode_value(capsule).ok()?.start?;
    Some(code_run_body_row_key(&start.body.hash))
}

/// The capsule row `row` names, by its key, as `txn` holds it.
pub(super) fn capsule_in_txn(
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
/// it, through the start's own piece writer (FIX 4192); the capsule names
/// its new manifest and digest. The old manifest goes once nothing holds
/// it, and so does each superseded piece no kept start of the run and
/// actor names.
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
    let Some(scope) = capsule_scope(&capsule) else {
        return Ok(());
    };
    let Some(start) = capsule.start.take() else {
        return Ok(());
    };
    let republished = republish_start_pieces_in_txn(store, wtxn, scope, &start, bytes)?;
    capsule.start = Some(republished.start);
    CAPSULES.put(store, wtxn, &key, &capsule)?;
    let superseded = &republished.superseded;
    let released = release_unnamed_start_pieces_in_txn(store, wtxn, scope, superseded)?;
    for digest in republished.manifest.into_iter().chain(released) {
        drop_unheld_body_in_txn(store, wtxn, &digest)?;
    }
    Ok(())
}

/// FIX 9180: an activation's release of the step start the capsule row
/// `row` names, whose rest its source retired: the run's occurrence of its
/// manifest goes with its marks, as a retired body's does, and its body
/// once nothing holds it. FIX 4192: so does each of its pieces no other
/// kept start of the run and actor names.
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
    let Some(start) = &capsule.start else {
        return Ok(());
    };
    let mut named = BTreeSet::new();
    start_manifest_pieces_in_txn(store, wtxn, start.body, &mut named)?;
    let (path, handle) = (
        start.path.clone(),
        CodeRunRawOutput::of_ref(start.body).handle,
    );
    let mut held = Vec::new();
    held.extend(release_occurrence_in_txn(
        store,
        wtxn,
        capsule.run,
        path,
        handle,
    )?);
    if let Some(scope) = capsule_scope(&capsule) {
        held.extend(release_unnamed_start_pieces_in_txn(
            store, wtxn, scope, &named,
        )?);
    }
    for digest in held {
        drop_unheld_body_in_txn(store, wtxn, &digest)?;
    }
    Ok(())
}

/// The body `digest` once no descriptor holds it: an inline row of its
/// own goes, a file to the collector. A row that holds its body on its own
/// stays.
pub(super) fn drop_unheld_body_in_txn(
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
pub(super) fn place(rows: &Rows, key: &[u8]) -> std::result::Result<usize, usize> {
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

/// The inline bytes of `piece` among an image's raw rows: `None` when its
/// body row is a file, is gone, or holds other bytes (a row a census
/// carried without its bytes).
fn inline_in_rows(rows: &Rows, piece: OutputRef) -> Option<Vec<u8>> {
    let at = place(rows, &code_run_body_row_key(&piece.hash)).ok()?;
    match RAW_OUTPUTS.decode_value(&rows[at].1).ok()? {
        StoredBody::Inline { bytes, .. } if *blake3::hash(&bytes).as_bytes() == piece.hash => {
            Some(bytes)
        }
        _ => None,
    }
}

/// The rows that name a body a restore puts back among an image's raw rows
/// (FIX 11415): its descriptor and its holder row, each a key and a value.
pub(super) struct NamingRows {
    pub(super) descriptor: (Vec<u8>, Vec<u8>),
    pub(super) holder: (Vec<u8>, Vec<u8>),
}

/// FIX 11415: the rows that name the body `output` measures, as run `run`
/// holds it at its path, held as `body`. The republish of a step start
/// puts them, and the size of that republish before any body is read is
/// counted from them, so the two use one codec.
///
/// # Errors
///
/// An occurrence that does not derive, and a row that does not encode.
pub(super) fn naming_rows(
    run: EntityId,
    output: &CodeRunRawOutput,
    body: &StoredBody,
) -> Result<NamingRows> {
    let occurrence = ResultOccurrence::of(Some(run), output)?.id();
    let owned = owned_body(run, output, body)?;
    Ok(NamingRows {
        descriptor: (
            BODY_ROWS.key_bytes(&(run, occurrence)),
            BODY_ROWS.encode_value(&owned)?,
        ),
        holder: (
            BODY_DIGEST_ROWS.key_bytes(&(output.raw_blake3, occurrence)),
            BODY_DIGEST_ROWS.encode_value(&run)?,
        ),
    })
}

/// FIX 11415: the start a capsule names once a restore republishes it: its
/// manifest `body` and `digest`, the digest of the whole start, unerased,
/// and the rest as `start` names it. The republish and the size of it
/// before any body is read both build it here.
pub(super) fn republished_step_start(
    start: ExecutorStepStart,
    body: OutputRef,
    digest: [u8; 32],
) -> ExecutorStepStart {
    ExecutorStepStart {
        body,
        digest,
        erased: false,
        ..start
    }
}

/// Whether the body row of `digest` among an image's raw rows holds its
/// bytes (FIX 4192 review fix): inline, or as a file among `files`, the
/// files the image carries. A row a census carried without its bytes holds
/// none.
fn holds_bytes_in_rows(rows: &Rows, files: &BTreeSet<[u8; 32]>, digest: &[u8; 32]) -> bool {
    let Ok(at) = place(rows, &code_run_body_row_key(digest)) else {
        return false;
    };
    match RAW_OUTPUTS.decode_value(&rows[at].1) {
        Ok(StoredBody::Inline { bytes, .. }) => blake3::hash(&bytes).as_bytes() == digest,
        Ok(StoredBody::File { .. }) => files.contains(digest),
        Err(_) => false,
    }
}

/// The content pieces of the start whose manifest is `manifest` whose body
/// rows among an image's raw rows lack their bytes (FIX 4192 review fix):
/// the ones a census carried without them, found from the manifest and
/// the nodes the rows hold. A content piece another start that travels
/// whole names traveled with that start, and is not among them.
fn stripped_pieces_in_rows(
    rows: &Rows,
    files: &BTreeSet<[u8; 32]>,
    manifest: OutputRef,
) -> BTreeSet<[u8; 32]> {
    manifest_content_pieces(manifest, |piece| inline_in_rows(rows, piece))
        .into_iter()
        .filter(|piece| !holds_bytes_in_rows(rows, files, piece))
        .collect()
}

/// FIX 9180: a restore's republish of the step start the capsule row `row`
/// names, as the recomposed `bytes`, among an image's raw `vault_meta`
/// rows, before any lands. FIX 4192: the start lands as its pieces. Each
/// piece whose body row does not hold its bytes, as a piece a census
/// carried without them, is put back inline whatever its size, with the
/// run's descriptor and holder row at its piece path. The manifest goes
/// under the same occurrence, held inline, its taint and secret marks moved
/// to its new handle, and the capsule names it and the digest of the whole
/// start. `files` are the files the image carries. Returns the digests
/// that rested without their bytes (FIX 4192 review fix: each content
/// piece of the old start a census carried without them, and the old
/// manifest when the start names another one and nothing else keeps its
/// bytes), and the digests whose body
/// rows it put back; `None` for a capsule that names no start or no actor.
///
/// # Errors
///
/// A row that does not decode or encode, and a piece that does not encode.
pub(crate) fn republish_step_start_in_rows(
    rows: &mut Rows,
    row: &[u8],
    bytes: &[u8],
    files: &BTreeSet<[u8; 32]>,
) -> Result<Option<StartLanding>> {
    let at = place(rows, row)
        .map_err(|_| Error::CorruptedIndex("a carried step start's capsule row"))?;
    let mut capsule = CAPSULES.decode_value(&rows[at].1)?;
    let Some(scope) = capsule_scope(&capsule) else {
        return Ok(None);
    };
    let Some(start) = capsule.start.take() else {
        return Ok(None);
    };
    let mut rested = stripped_pieces_in_rows(rows, files, start.body);
    let pieces = StartPieces::of(bytes)?;
    let mut landed = BTreeSet::new();
    for (piece, piece_bytes) in pieces.shared() {
        let path = scope.start_path(&piece.hash);
        if land_piece_in_rows(rows, scope.run, &path, piece_bytes, files)? {
            landed.insert(piece.hash);
        }
    }
    let (before, output) = republish_manifest_in_rows(rows, scope.run, &start, pieces.manifest())?;
    if before != output.raw_blake3 && !kept_apart_in_rows(rows, files, &before) {
        rested.insert(before);
    }
    landed.insert(output.raw_blake3);
    let digest = *blake3::hash(bytes).as_bytes();
    capsule.start = Some(republished_step_start(start, output.output_ref(), digest));
    put_row(rows, row.to_vec(), CAPSULES.encode_value(&capsule)?);
    Ok(Some((rested, landed)))
}

/// Puts the start piece `bytes` back among an image's raw rows as the
/// complete body run `run` holds at `path`, before any lands (FIX 4192):
/// its body row inline whatever its size, unless the row holds its bytes
/// already (inline, or a file among `files`, the files the image carries),
/// and the run's descriptor and holder row unless its descriptor holds it
/// whole. A body it puts back inline turns every descriptor of it that
/// names a file to name it inline (FIX 4192). A secret the scan finds
/// marks the run's occurrence. Whether it put the body row.
fn land_piece_in_rows(
    rows: &mut Rows,
    run: EntityId,
    path: &str,
    bytes: &[u8],
    files: &BTreeSet<[u8; 32]>,
) -> Result<bool> {
    let mut meter = BodyMeter::new();
    meter.feed(bytes);
    let facts = meter.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS);
    let output = CodeRunRawOutput::from_facts(path, &facts, true)?;
    let occurrence = ResultOccurrence::of(Some(run), &output)?;
    let key = RAW_OUTPUTS.key_bytes(&output.handle);
    let stored = place(rows, &key)
        .ok()
        .and_then(|at| RAW_OUTPUTS.decode_value(&rows[at].1).ok());
    let whole = match &stored {
        Some(StoredBody::Inline { bytes: held, .. }) => held.as_slice() == bytes,
        Some(StoredBody::File { .. }) => files.contains(&output.raw_blake3),
        None => false,
    };
    let body = match stored {
        Some(body) if whole => body,
        stored => {
            let held = stored.is_some_and(|body| {
                matches!(
                    body,
                    StoredBody::Inline { held: true, .. } | StoredBody::File { held: true, .. }
                )
            });
            let body = republished_start_body(bytes).holding(held);
            put_row(rows, key, RAW_OUTPUTS.encode_value(&body)?);
            // The bytes are inline now: no descriptor may still name a file
            // the image does not carry, or the next census looks for it.
            hold_digest_inline_in_rows(rows, &output.raw_blake3)?;
            body
        }
    };
    let NamingRows { descriptor, holder } = naming_rows(run, &output, &body)?;
    let holds = place(rows, &descriptor.0)
        .ok()
        .and_then(|at| BODY_ROWS.decode_value(&rows[at].1).ok())
        .is_some_and(|owned| {
            matches!(&owned.state, BodyState::Complete { body } if body.blake3 == output.raw_blake3)
        });
    if !holds {
        put_row(rows, descriptor.0, descriptor.1);
        put_row(rows, holder.0, holder.1);
        take_row(rows, &BODY_RELEASED_ROWS.key_bytes(&output.raw_blake3));
    }
    let secret = RAW_OUTPUT_SECRETS.key_bytes(&occurrence.mark_key(&output.handle));
    if let Some(reason) = facts.secret
        && place(rows, &secret).is_err()
    {
        put_row(
            rows,
            secret,
            RAW_OUTPUT_SECRETS.encode_value(&reason.to_owned())?,
        );
    }
    Ok(!whole)
}

/// The manifest `bytes` republished among an image's raw rows as the body
/// run `run` holds at `start`'s path, in place of the body `start` names:
/// held inline whatever its size, under the same occurrence, its taint and
/// secret marks moved to its new handle, and its descriptor and holder row
/// naming the new body. Returns the digest the start rested under and the
/// new body.
fn republish_manifest_in_rows(
    rows: &mut Rows,
    run: EntityId,
    start: &ExecutorStepStart,
    bytes: &[u8],
) -> Result<([u8; 32], CodeRunRawOutput)> {
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
    let (old_rows, new_rows) = (
        naming_rows(run, &old, &body)?,
        naming_rows(run, &output, &body)?,
    );
    put_row(rows, new_rows.descriptor.0, new_rows.descriptor.1);
    take_row(rows, &old_rows.holder.0);
    put_row(rows, new_rows.holder.0, new_rows.holder.1);
    take_row(rows, &BODY_RELEASED_ROWS.key_bytes(&output.raw_blake3));
    Ok((old.raw_blake3, output))
}

/// FIX 9180: a restore's disposition of the step start the capsule row
/// `row` names, whose rest retired, among an image's raw rows, as a
/// retired body leaves one: the run's own occurrence of its manifest goes
/// explicitly incomplete, with nothing to show, and its holder row goes
/// (FIX 4192 review fix: another holder of the same bytes keeps its
/// descriptor). Returns the digests that rest without their bytes: each of
/// its content pieces a census carried without them (FIX 4192 review fix:
/// its config, frame and elements, which no stream carries), found among
/// the rows with `files`, the files the image carries, and its manifest
/// unless another holder or a standalone hold keeps its bytes; none for a
/// capsule that names no start. The settle takes each one no live start
/// lands again.
///
/// # Errors
///
/// A row that does not decode.
pub(crate) fn drop_step_start_in_rows(
    rows: &mut Rows,
    row: &[u8],
    files: &BTreeSet<[u8; 32]>,
) -> Result<Vec<[u8; 32]>> {
    let at = place(rows, row)
        .map_err(|_| Error::CorruptedIndex("a carried step start's capsule row"))?;
    let capsule = CAPSULES.decode_value(&rows[at].1)?;
    let Some(start) = capsule.start else {
        return Ok(Vec::new());
    };
    let mut rested: Vec<[u8; 32]> = stripped_pieces_in_rows(rows, files, start.body)
        .into_iter()
        .collect();
    release_manifest_occurrence_in_rows(rows, capsule.run, &start)?;
    if !kept_apart_in_rows(rows, files, &start.body.hash) {
        rested.push(start.body.hash);
    }
    Ok(rested)
}

/// Releases, among an image's raw rows, only the occurrence run `run`
/// holds of `start`'s manifest (FIX 4192 review fix): its descriptor goes
/// explicitly incomplete, with nothing to show, and its holder row goes.
/// Every other holder of the same bytes keeps its descriptor and holder row.
///
/// # Errors
///
/// An occurrence that does not derive, and a row that does not decode or
/// encode.
fn release_manifest_occurrence_in_rows(
    rows: &mut Rows,
    run: EntityId,
    start: &ExecutorStepStart,
) -> Result<()> {
    let manifest = CodeRunRawOutput {
        path: start.path.clone(),
        ..CodeRunRawOutput::of_ref(start.body)
    };
    let occurrence = ResultOccurrence::of(Some(run), &manifest)?;
    if let Ok(at) = place(rows, &BODY_ROWS.key_bytes(&(run, occurrence.id()))) {
        let mut owned = BODY_ROWS.decode_value(&rows[at].1)?;
        if owned
            .state
            .held()
            .is_some_and(|held| held.blake3 == manifest.raw_blake3)
        {
            owned.state = BodyState::Incomplete { retained: None };
            rows[at].1 = BODY_ROWS.encode_value(&owned)?;
        }
    }
    take_row(
        rows,
        &BODY_DIGEST_ROWS.key_bytes(&(manifest.raw_blake3, occurrence.id())),
    );
    Ok(())
}

/// Whether the bytes `digest` names outlive a start's release of its own
/// occurrence among an image's raw rows (FIX 4192 review fix): the body row
/// holds them (inline, or a file among `files`, the files the image
/// carries), and another holder row or the row's standalone hold keeps
/// them. A restore never prunes such bytes as a start's rest.
fn kept_apart_in_rows(rows: &Rows, files: &BTreeSet<[u8; 32]>, digest: &[u8; 32]) -> bool {
    if !holds_bytes_in_rows(rows, files, digest) {
        return false;
    }
    let held = place(rows, &code_run_body_row_key(digest))
        .ok()
        .and_then(|at| RAW_OUTPUTS.decode_value(&rows[at].1).ok())
        .is_some_and(|body| {
            matches!(
                body,
                StoredBody::Inline { held: true, .. } | StoredBody::File { held: true, .. }
            )
        });
    let mut holders = BODY_DIGEST_ROWS.decl().prefix.to_vec();
    holders.extend_from_slice(digest);
    let (Ok(first) | Err(first)) = place(rows, &holders);
    held || rows
        .get(first)
        .is_some_and(|(key, _)| key.starts_with(&holders))
}

/// FIX 9180: settles, among an image's raw rows, the bodies carried starts
/// rested under without their bytes (`rested`) once each start landed again
/// as the bodies `landed`: a body no start lands again goes, as no stream
/// carried its bytes, and every descriptor holding it goes explicitly
/// incomplete (FIX 4192: a content piece of a start whose rest retired, or
/// of a call whose ask retired); the instance row of each names an inline
/// body, as every landed piece is held inline now.
///
/// # Errors
///
/// A row that does not decode or encode.
pub(crate) fn settle_start_bodies_in_rows(
    rows: &mut Rows,
    rested: &BTreeSet<[u8; 32]>,
    landed: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    for digest in rested.difference(landed) {
        prune_digest_in_rows(rows, digest)?;
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
