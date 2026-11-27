//! Every raw access to the code-run replay tables (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT). One head row per run holds the record's scalar fields, its four counts and its generation; one item row per family element holds that element's bytes as they sit inside the whole encoding. The whole encoding stays the canonical form; every read joins head and items, and every custody, digest and pin reads the joined bytes.

use std::borrow::Cow;

use super::super::codec::{
    ReplayFamily, ReplayHead, decode_binding, decode_bridge_call, decode_code_run_replay_record,
    decode_raw_output, decode_step_checkpoint, encode_code_run_bridge_call_bytes,
    encode_code_run_replay_item, encode_code_run_replay_record, join_canonical, split_canonical,
    validate_bridge_call, validate_code_run_replay_record, validate_raw_output,
};
use super::super::replay::{
    CodeRunBridgeCall, CodeRunReplayGeneration, CodeRunReplayRecord, CodeRunResultBinding,
    held_row_stands_for,
};
use super::super::wait_rows::{keep_wait_rows, wait_rows};
use crate::side_table::{
    self, CodecError, Erased, Raw, RawValue, SideKey, SideTable, SideTableDbs,
};
use crate::store::{ResponseFamily, ResponseRead};
use crate::{EntityId, Error, Result};

mod append;
mod fenced;
mod image;
mod items;

pub(crate) use self::append::put_append;
pub(crate) use self::fenced::{ErasedFormProjection, admit_fenced, put_fenced};
pub(crate) use self::image::{
    canonical_bytes_at, image_value, put_canonical_bytes_at, split_image_rows,
};
pub(crate) use self::items::admit_lifted_item;
use self::items::{
    ReplayItem, ReplayItemKey, decode_call_item, delete_stale_items, encode_call_item,
    family_items, item_value, put_admitted_item, put_raw_item,
};

/// The replay head of one run, keyed by run id. Only this module's functions and three session-overlay
/// sites take the table itself: `routing/replay.rs` (the routed compare-and-put), `read_worlds.rs` and
/// `reader_jobs.rs` (overlay reads).
pub(super) const HEADS: SideTable<EntityId, ReplayHead, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

/// One replay item, keyed by run, family and index.
pub(super) const ITEMS: SideTable<ReplayItemKey, ReplayItem, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY_ITEM);

#[cfg(oneiron_test_support)]
thread_local! {
    static WRITTEN_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Adds `len` to this thread's written replay bytes; nothing outside test support.
#[cfg(oneiron_test_support)]
fn note_written(len: usize) {
    WRITTEN_BYTES.with(|bytes| bytes.set(bytes.get().saturating_add(len as u64)));
}

#[cfg(not(oneiron_test_support))]
fn note_written(_len: usize) {}

/// This thread's total written replay bytes.
#[cfg(oneiron_test_support)]
pub(crate) fn written_bytes() -> u64 {
    WRITTEN_BYTES.with(|bytes| bytes.get())
}

/// A codec error as the seam reports it: a value error as itself, a row shape as its table's.
fn seam_error(decl: &'static crate::side_table::SideTableDecl, error: CodecError) -> Error {
    match error {
        CodecError::Value(error) => error,
        CodecError::Row(problem) => decl.row_error(problem),
    }
}

/// How the side-row wall reads a call item as it is written (FIX FENCE-ERASED-FORM-THROUGH-WALL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallWall {
    /// Every byte of it, as [`put`] writes a record.
    Whole,
    /// All but the erase's fixed words in each part it holds in its erased form, as
    /// [`put_fenced`] writes a record.
    Fenced,
}

/// Writes `head` raw at `run`, past the wall: the caller admitted it already, or it is an erase's own write.
fn put_raw_head(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    head: &ReplayHead,
) -> Result<Vec<u8>> {
    let bytes = HEADS.encode_value(head)?;
    let full = HEADS.key_bytes(run);
    dbs.side_vault_meta().put(wtxn, &full, &bytes)?;
    note_written(bytes.len());
    Ok(full)
}

/// The whole bytes for a decoded `head`: its four families' items joined under its shell.
fn assemble(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
    head: &ReplayHead,
) -> Result<Vec<u8>> {
    let bridge_calls = family_items(dbs, txn, run, ReplayFamily::BridgeCalls, head.counts[0])?;
    let step_checkpoints =
        family_items(dbs, txn, run, ReplayFamily::StepCheckpoints, head.counts[1])?;
    let outputs = family_items(dbs, txn, run, ReplayFamily::Outputs, head.counts[2])?;
    let bindings = family_items(dbs, txn, run, ReplayFamily::Bindings, head.counts[3])?;
    join_canonical(
        &head.shell,
        [&bridge_calls, &step_checkpoints, &outputs, &bindings],
    )
    .map_err(|error| seam_error(HEADS.decl(), error))
}

/// The run's canonical whole bytes: joined for a head, as stored for a marker, if present.
fn joined_bytes(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let Some(head_bytes) = HEADS.get_bytes(dbs, txn, run)? else {
        return Ok(None);
    };
    match HEADS.decode_value(&head_bytes) {
        Ok(head) => Ok(Some(assemble(dbs, txn, run, &head)?)),
        Err(_) => Ok(Some(head_bytes)),
    }
}

/// Every item of `record` through the wall under its head's origin, each call item as `wall`
/// reads it, stale items past its counts deleted; every full item key written or deleted. The
/// caller validated `record` already.
fn write_items(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: &CodeRunReplayRecord,
    wall: CallWall,
) -> Result<Vec<Vec<u8>>> {
    let head_key = HEADS.key_bytes(run);
    let mut keys = Vec::new();
    for family in ReplayFamily::ALL {
        let count = match family {
            ReplayFamily::BridgeCalls => record.bridge_calls.len(),
            ReplayFamily::StepCheckpoints => record.step_checkpoints.len(),
            ReplayFamily::Outputs => record.outputs.len(),
            ReplayFamily::Bindings => record.bindings.len(),
        };
        for index in 0..count {
            let bytes = encode_code_run_replay_item(record, family, index)
                .map_err(|error| seam_error(HEADS.decl(), error))?;
            let Ok(uindex) = u64::try_from(index) else {
                return Err(Error::ArithmeticOverflow("code-run replay item index"));
            };
            let key = ReplayItemKey {
                run: *run,
                family,
                index: uindex,
            };
            let written = match (family, record.bridge_calls.get(index)) {
                (ReplayFamily::BridgeCalls, Some(call)) => {
                    fenced::put_call_item(dbs, wtxn, &head_key, &key, call, &bytes, wall)?
                }
                _ => put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?,
            };
            keys.push(written);
        }
    }
    let counts = [
        u64::try_from(record.bridge_calls.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run bridge call count"))?,
        u64::try_from(record.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run step checkpoint count"))?,
        u64::try_from(record.outputs.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run output count"))?,
        u64::try_from(record.bindings.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run binding count"))?,
    ];
    keys.extend(delete_stale_items(dbs, wtxn, run, counts)?);
    Ok(keys)
}

/// Reads `run`'s replay record, if present.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn get(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<CodeRunReplayRecord>> {
    let Some(bytes) = joined_bytes(dbs, txn, run)? else {
        return Ok(None);
    };
    decode(&bytes).map(Some)
}

/// Reads `run`'s replay record, treating a row that does not decode as absent.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn get_lenient(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<CodeRunReplayRecord>> {
    let Some(bytes) = joined_bytes(dbs, txn, run)? else {
        return Ok(None);
    };
    Ok(decode(&bytes).ok())
}

/// Whether `run` has a replay row.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn contains(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<bool> {
    HEADS.contains(dbs, txn, run)
}

/// `run`'s replay head, if present: `None` for no row and for a marker.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn head(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<ReplayHead>> {
    HEADS.get_lenient(dbs, txn, run)
}

/// The generation of `run`'s stored replay row, from its head.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn generation(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<CodeRunReplayGeneration>> {
    Ok(head(dbs, txn, run)?.map(|head| head.generation()))
}

/// `run`'s stored bridge calls as the side-row wall stored them, read from its head and its call
/// items alone: `None` for no row and for a marker.
///
/// # Errors
///
/// Storage errors, and a call item that does not decode.
pub(crate) fn stored_bridge_calls(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<Vec<CodeRunBridgeCall>>> {
    let Some(head) = head(dbs, txn, run)? else {
        return Ok(None);
    };
    family_items(dbs, txn, run, ReplayFamily::BridgeCalls, head.counts[0])?
        .iter()
        .map(|bytes| decode_call_item(bytes))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// The length of `run`'s canonical replay bytes, if present.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn stored_len(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<usize>> {
    Ok(joined_bytes(dbs, txn, run)?.map(|bytes| bytes.len()))
}

/// Reads `run`'s replay record, answering `ResponseErased` for a retired marker before any decode.
///
/// # Errors
///
/// Storage errors, and `ResponseErased` for a retired marker.
pub(crate) fn present(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<CodeRunReplayRecord>> {
    let Some(raw) = HEADS.get_borrowed(dbs, txn, run)? else {
        return Ok(None);
    };
    let key = HEADS.key_bytes(run);
    let raw = ResponseRead::of(ResponseFamily::Replay, &key, &raw).present()?;
    match HEADS.decode_value(raw) {
        Ok(head) => {
            let whole = assemble(dbs, txn, run, &head)?;
            decode(&whole).map(Some)
        }
        Err(_) => decode(raw).map(Some),
    }
}

/// The run's whole-record bytes as stored, if present.
///
/// # Errors
///
/// Storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn canonical_bytes(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<Vec<u8>>> {
    joined_bytes(dbs, txn, run)
}

/// The item rows of `run`, in every family.
///
/// # Errors
///
/// Storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn item_count(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<u64> {
    let mut count = 0_u64;
    for row in ITEMS.iter_raw_from(dbs, txn, &ReplayItemKey::run_prefix(run))? {
        row?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

/// How many of `run`'s item rows the historical lift sweep walks as authored rows and admits
/// through the run's head origin, each read back as given (a row with no hit).
///
/// # Errors
///
/// Storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn lift_routed_items(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
) -> Result<u64> {
    let mut rows = Vec::new();
    for row in ITEMS.iter_raw_from(dbs, wtxn, &ReplayItemKey::run_prefix(run))? {
        let (suffix, bytes) = row?;
        let mut key = ITEMS.decl().prefix.to_vec();
        key.extend_from_slice(&suffix);
        rows.push((key, bytes));
    }
    let mut routed = 0_u64;
    for (key, bytes) in rows {
        let walked = side_table::authored_vault_meta().any(|decl| key.starts_with(decl.prefix));
        if walked && matches!(admit_lifted_item(dbs, wtxn, &key, &bytes), Some(Ok(None))) {
            routed = routed.saturating_add(1);
        }
    }
    Ok(routed)
}

/// Whether `key` is a replay head key.
pub(crate) fn is_row_key(key: &[u8]) -> bool {
    key.starts_with(HEADS.decl().prefix)
}

/// Whether `key` is a replay item key.
pub(crate) fn is_item_key(key: &[u8]) -> bool {
    key.starts_with(ITEMS.decl().prefix)
}

/// The run id of the full replay row key `key`, if it names one.
pub(super) fn run_id_of_key(key: &[u8]) -> Option<EntityId> {
    key.strip_prefix(HEADS.decl().prefix)
        .and_then(<EntityId as SideKey>::decode_key)
}

/// The head key plus every item key for `record`'s counts, in family and index order.
pub(crate) fn row_keys(record: &CodeRunReplayRecord) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    keys.push(HEADS.key_bytes(&record.run_id));
    for family in ReplayFamily::ALL {
        let count = match family {
            ReplayFamily::BridgeCalls => record.bridge_calls.len(),
            ReplayFamily::StepCheckpoints => record.step_checkpoints.len(),
            ReplayFamily::Outputs => record.outputs.len(),
            ReplayFamily::Bindings => record.bindings.len(),
        };
        for index in 0..count {
            let Ok(uindex) = u64::try_from(index) else {
                continue;
            };
            keys.push(ITEMS.key_bytes(&ReplayItemKey {
                run: record.run_id,
                family,
                index: uindex,
            }));
        }
    }
    keys
}

/// Decodes a replay record from its canonical bytes.
///
/// # Errors
///
/// A row that does not decode.
pub(crate) fn decode(bytes: &[u8]) -> Result<CodeRunReplayRecord> {
    decode_code_run_replay_record(bytes)
}

/// Encodes a replay record to its canonical bytes.
///
/// # Errors
///
/// A record that does not encode.
pub(crate) fn encode(record: &CodeRunReplayRecord) -> Result<Vec<u8>> {
    encode_code_run_replay_record(record)
}

/// Every replay row in key order.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn scan(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, CodeRunReplayRecord)>> {
    let mut out = Vec::new();
    for run in HEADS.scan_keys(dbs, txn, &[])? {
        let Some(record) = get(dbs, txn, &run)? else {
            continue;
        };
        out.push((run, record));
    }
    Ok(out)
}

/// The run ids of every replay row, without decoding values.
///
/// # Errors
///
/// Storage errors.
#[cfg(test)]
pub(crate) fn run_ids(dbs: &impl SideTableDbs, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    HEADS.scan_keys(dbs, txn, &[])
}

/// The replay rows under `key_prefix` undecoded, in key order: head keys with joined bytes, markers as stored.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn iter_canonical_from<'txn>(
    dbs: &'txn impl SideTableDbs,
    txn: &'txn heed::RoTxn<'_>,
    key_prefix: &[u8],
) -> Result<impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'txn> {
    // One run joined at a time, as the sweeps read them: never every run's record at once.
    Ok(HEADS.iter_raw_from(dbs, txn, key_prefix)?.map(move |row| {
        let (suffix, head_bytes) = row?;
        let Ok(head) = HEADS.decode_value(&head_bytes) else {
            return Ok((suffix, head_bytes));
        };
        let Some(run) = <EntityId as SideKey>::decode_key(&suffix) else {
            return Err(Error::CorruptedIndex("code-run replay head key"));
        };
        let whole = assemble(dbs, txn, &run, &head)?;
        Ok((suffix, whole))
    }))
}

/// Persists `record` as `run`'s replay rows, with the side-row wall reading every byte: its head
/// plus every item, stale items past its counts deleted. Every full key written or deleted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: &CodeRunReplayRecord,
) -> Result<Vec<Vec<u8>>> {
    put_record(dbs, wtxn, run, record, CallWall::Whole)
}

/// [`put`], with each call item as `wall` reads it.
fn put_record(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: &CodeRunReplayRecord,
    wall: CallWall,
) -> Result<Vec<Vec<u8>>> {
    encode(record)?;
    let head = ReplayHead::of(record)?;
    note_written(HEADS.put_as_stored(dbs, wtxn, run, &head)?.len());
    let mut keys = vec![HEADS.key_bytes(run)];
    keys.extend(write_items(dbs, wtxn, run, record, wall)?);
    Ok(keys)
}

/// Reads `record` as the wall will store it, before the writer derives anything from it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn admit(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: &mut CodeRunReplayRecord,
) -> Result<()> {
    let bytes = encode(record)?;
    let head_key = HEADS.key_bytes(run);
    if let Some(masked) = crate::batch::secret_scan::admit_side_row(
        dbs,
        wtxn,
        &side_table::CODE_RUN_REPLAY,
        &head_key,
        &bytes,
        |masked| crate::side_table::decodes::<CodeRunReplayRecord, Raw>(masked),
    )? {
        *record = decode(&masked)?;
    }
    Ok(())
}

/// Writes `record`'s erased form at `run`, past the wall.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_erased(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: Erased<CodeRunReplayRecord>,
) -> Result<()> {
    let record = record.into_inner();
    encode(&record)?;
    let head = ReplayHead::of(&record)?;
    put_raw_head(dbs, wtxn, run, &head)?;
    for family in ReplayFamily::ALL {
        let count = match family {
            ReplayFamily::BridgeCalls => record.bridge_calls.len(),
            ReplayFamily::StepCheckpoints => record.step_checkpoints.len(),
            ReplayFamily::Outputs => record.outputs.len(),
            ReplayFamily::Bindings => record.bindings.len(),
        };
        for index in 0..count {
            let bytes = encode_code_run_replay_item(&record, family, index)
                .map_err(|error| seam_error(HEADS.decl(), error))?;
            let Ok(uindex) = u64::try_from(index) else {
                return Err(Error::ArithmeticOverflow("code-run replay item index"));
            };
            put_raw_item(
                dbs,
                wtxn,
                &ReplayItemKey {
                    run: *run,
                    family,
                    index: uindex,
                },
                &bytes,
            )?;
        }
    }
    let counts = [
        u64::try_from(record.bridge_calls.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run bridge call count"))?,
        u64::try_from(record.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run step checkpoint count"))?,
        u64::try_from(record.outputs.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run output count"))?,
        u64::try_from(record.bindings.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run binding count"))?,
    ];
    delete_stale_items(dbs, wtxn, run, counts)?;
    Ok(())
}

/// Writes a record already in its selective erased form, past the wall with no further erase transform.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_erased_unchanged(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: CodeRunReplayRecord,
) -> Result<()> {
    encode(&record)?;
    let head = ReplayHead::of(&record)?;
    put_raw_head(dbs, wtxn, run, &head)?;
    for family in ReplayFamily::ALL {
        let count = match family {
            ReplayFamily::BridgeCalls => record.bridge_calls.len(),
            ReplayFamily::StepCheckpoints => record.step_checkpoints.len(),
            ReplayFamily::Outputs => record.outputs.len(),
            ReplayFamily::Bindings => record.bindings.len(),
        };
        for index in 0..count {
            let bytes = encode_code_run_replay_item(&record, family, index)
                .map_err(|error| seam_error(HEADS.decl(), error))?;
            let Ok(uindex) = u64::try_from(index) else {
                return Err(Error::ArithmeticOverflow("code-run replay item index"));
            };
            put_raw_item(
                dbs,
                wtxn,
                &ReplayItemKey {
                    run: *run,
                    family,
                    index: uindex,
                },
                &bytes,
            )?;
        }
    }
    let counts = [
        u64::try_from(record.bridge_calls.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run bridge call count"))?,
        u64::try_from(record.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run step checkpoint count"))?,
        u64::try_from(record.outputs.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run output count"))?,
        u64::try_from(record.bindings.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run binding count"))?,
    ];
    delete_stale_items(dbs, wtxn, run, counts)?;
    Ok(())
}

/// Writes the erased-unreadable mark over `run`'s row, past the wall, with every item row deleted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_erased_unreadable(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
) -> Result<()> {
    HEADS.put_erased_unreadable(dbs, wtxn, run)?;
    delete_stale_items(dbs, wtxn, run, [0, 0, 0, 0])?;
    Ok(())
}

/// Deletes `run`'s replay rows; `true` when a row was present.
///
/// # Errors
///
/// Storage errors.
#[cfg(test)]
pub(crate) fn delete(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
) -> Result<bool> {
    let head = HEADS.delete(dbs, wtxn, run)?;
    let items = !delete_stale_items(dbs, wtxn, run, [0, 0, 0, 0])?.is_empty();
    Ok(head || items)
}
