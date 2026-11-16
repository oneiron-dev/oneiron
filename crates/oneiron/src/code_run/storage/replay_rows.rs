//! Every raw access to the code-run replay table (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT). The table holds one row per run
//! today, the record's canonical encoding, so each function here reads or writes that row as it stands.

use super::super::codec::{decode_code_run_replay_generation, decode_code_run_replay_held};
use super::super::replay::{CodeRunReplayGeneration, CodeRunReplayHeld, CodeRunReplayRecord};
use crate::side_table::{
    self, CodecError, Erased, ErasedForm, Raw, RawValue, SideKey, SideTable, SideTableDbs,
};
use crate::store::{ResponseFamily, ResponseRead};
use crate::{EntityId, Result};

/// The replay record of one run, keyed by run id. Only this module's functions and three session-overlay
/// sites take the table itself: `routing/replay.rs` (the routed compare-and-put), `read_worlds.rs` and
/// `reader_jobs.rs` (overlay reads).
pub(super) const REPLAY_RECORDS: SideTable<EntityId, CodeRunReplayRecord, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

/// A replay record in the selective form a spawn target's erase leaves it:
/// written as encoded, past the side-row wall, as an erase's own write is.
struct SpawnErased(CodeRunReplayRecord);

impl RawValue for SpawnErased {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        self.0.to_raw()
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        CodeRunReplayRecord::from_raw(bytes).map(Self)
    }
}

/// The selective form is already the erase's: erasing it again changes
/// nothing.
impl ErasedForm for SpawnErased {
    fn into_erased(self) -> Result<Self> {
        Ok(self)
    }
}

/// The replay rows, as a spawn target's erase writes them back.
const SPAWN_ERASED: SideTable<EntityId, SpawnErased, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

#[cfg(oneiron_test_support)]
thread_local! {
    static WRITTEN_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(oneiron_test_support)]
fn note_written(len: usize) {
    WRITTEN_BYTES.with(|bytes| bytes.set(bytes.get().saturating_add(len as u64)));
}

/// This thread's total written replay bytes.
#[cfg(oneiron_test_support)]
pub(crate) fn written_bytes() -> u64 {
    WRITTEN_BYTES.with(|bytes| bytes.get())
}

/// Reads `run`'s replay record, if present.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn get(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<CodeRunReplayRecord>> {
    REPLAY_RECORDS.get(dbs, txn, run)
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
    REPLAY_RECORDS.get_lenient(dbs, txn, run)
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
    REPLAY_RECORDS.contains(dbs, txn, run)
}

/// What a guarded append reads from `run`'s stored row: its generation and the calls it keeps.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn held(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<CodeRunReplayHeld>> {
    REPLAY_RECORDS
        .get_borrowed(dbs, txn, run)?
        .map(|bytes| decode_code_run_replay_held(&bytes))
        .transpose()
}

/// The generation of `run`'s stored replay row, decoded from its bytes in place.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn generation(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<CodeRunReplayGeneration>> {
    REPLAY_RECORDS
        .get_borrowed(dbs, txn, run)?
        .as_deref()
        .map(decode_code_run_replay_generation)
        .transpose()
}

/// The length of `run`'s stored replay row, if present.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn stored_len(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<usize>> {
    Ok(REPLAY_RECORDS
        .get_borrowed(dbs, txn, run)?
        .as_deref()
        .map(<[u8]>::len))
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
    let Some(raw) = REPLAY_RECORDS.get_borrowed(dbs, txn, run)? else {
        return Ok(None);
    };
    let key = REPLAY_RECORDS.key_bytes(run);
    let raw = ResponseRead::of(ResponseFamily::Replay, &key, &raw).present()?;
    REPLAY_RECORDS.decode_value(raw).map(Some)
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
    REPLAY_RECORDS.get_bytes(dbs, txn, run)
}

/// The replay row's bytes at the full row key `key`, if present.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn canonical_bytes_at(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    Ok(dbs
        .side_vault_meta()
        .get(txn, key)?
        .map(|bytes| bytes.into_owned()))
}

/// Writes `bytes` at the full replay row key `key`, past the wall as stored.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_canonical_bytes_at(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
    bytes: &[u8],
) -> Result<()> {
    #[cfg(oneiron_test_support)]
    note_written(bytes.len());
    dbs.side_vault_meta().put(wtxn, key, bytes)
}

/// Whether `key` is a replay row key.
pub(crate) fn is_row_key(key: &[u8]) -> bool {
    key.starts_with(REPLAY_RECORDS.decl().prefix)
}

/// The run id of the full replay row key `key`, if it names one.
pub(super) fn run_id_of_key(key: &[u8]) -> Option<EntityId> {
    key.strip_prefix(REPLAY_RECORDS.decl().prefix)
        .and_then(<EntityId as SideKey>::decode_key)
}

/// The full stored key of `run`'s replay row.
pub(crate) fn key_bytes(run: &EntityId) -> Vec<u8> {
    REPLAY_RECORDS.key_bytes(run)
}

/// Decodes a replay record from its canonical bytes.
///
/// # Errors
///
/// A row that does not decode.
pub(crate) fn decode(bytes: &[u8]) -> Result<CodeRunReplayRecord> {
    REPLAY_RECORDS.decode_value(bytes)
}

/// Encodes a replay record to its canonical bytes.
///
/// # Errors
///
/// A record that does not encode.
pub(crate) fn encode(record: &CodeRunReplayRecord) -> Result<Vec<u8>> {
    REPLAY_RECORDS.encode_value(record)
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
    REPLAY_RECORDS.scan(dbs, txn)
}

/// The run ids of every replay row, without decoding values.
///
/// # Errors
///
/// Storage errors.
#[cfg(test)]
pub(crate) fn run_ids(dbs: &impl SideTableDbs, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    REPLAY_RECORDS.scan_keys(dbs, txn, &[])
}

/// The replay rows under `key_prefix` undecoded, in key order.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn iter_canonical_from<'txn>(
    dbs: &impl SideTableDbs,
    txn: &'txn heed::RoTxn<'_>,
    key_prefix: &[u8],
) -> Result<impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'txn> {
    REPLAY_RECORDS.iter_raw_from(dbs, txn, key_prefix)
}

/// Persists `record` as `run`'s replay row, through the wall.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: &CodeRunReplayRecord,
) -> Result<()> {
    #[cfg(oneiron_test_support)]
    note_written(REPLAY_RECORDS.encode_value(record)?.len());
    REPLAY_RECORDS.put(dbs, wtxn, run, record)
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
    REPLAY_RECORDS.admit(dbs, wtxn, run, record)
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
    REPLAY_RECORDS.put_erased(dbs, wtxn, run, record)
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
    SPAWN_ERASED.put_erased(dbs, wtxn, run, Erased::of(SpawnErased(record))?)
}

/// Writes the erased-unreadable mark over `run`'s row, past the wall.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_erased_unreadable(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
) -> Result<()> {
    REPLAY_RECORDS.put_erased_unreadable(dbs, wtxn, run)
}

/// Deletes `run`'s replay row; `true` when a row was present.
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
    REPLAY_RECORDS.delete(dbs, wtxn, run)
}
