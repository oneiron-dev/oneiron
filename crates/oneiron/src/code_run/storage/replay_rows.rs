//! Every raw access to the code-run replay tables (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT). One head row per run holds the record's scalar fields, its four counts and its generation; one item row per family element holds that element's bytes as they sit inside the whole encoding. The whole encoding stays the canonical form; every read joins head and items, and every custody, digest and pin reads the joined bytes.

use std::borrow::Cow;

use super::super::codec::{
    ReplayFamily, ReplayHead, decode_binding, decode_bridge_call, decode_code_run_replay_record,
    decode_raw_output, decode_step_checkpoint, encode_code_run_bridge_call_bytes,
    encode_code_run_replay_item, encode_code_run_replay_record, join_canonical, split_canonical,
    validate_bridge_call, validate_code_run_replay_record, validate_raw_output,
};
use super::super::replay::{CodeRunReplayGeneration, CodeRunReplayRecord, CodeRunResultBinding};
use super::super::wait_rows::{keep_wait_rows, wait_rows};
use crate::side_table::{
    self, CodecError, Erased, Raw, RawValue, SideKey, SideTable, SideTableDbs,
};
use crate::store::{ResponseFamily, ResponseRead};
use crate::{EntityId, Error, Result};

/// The replay head of one run, keyed by run id. Only this module's functions and three session-overlay
/// sites take the table itself: `routing/replay.rs` (the routed compare-and-put), `read_worlds.rs` and
/// `reader_jobs.rs` (overlay reads).
pub(super) const HEADS: SideTable<EntityId, ReplayHead, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

/// One replay item, keyed by run, family and index.
pub(super) const ITEMS: SideTable<ReplayItemKey, ReplayItem, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY_ITEM);

/// One item row's key: its run, family and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayItemKey {
    /// The run holding the item.
    pub(crate) run: EntityId,
    /// The item's family.
    pub(crate) family: ReplayFamily,
    /// The item's index in its family.
    pub(crate) index: u64,
}

impl ReplayItemKey {
    /// The key prefix for `run`'s `family` items: id16 plus tag, in index order under it.
    pub(crate) fn family_prefix(run: &EntityId, family: ReplayFamily) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.extend_from_slice(run.as_bytes());
        out.push(family.tag());
        out
    }

    /// The key prefix for `run`'s items in every family: id16.
    pub(crate) fn run_prefix(run: &EntityId) -> Vec<u8> {
        run.as_bytes().to_vec()
    }
}

impl SideKey for ReplayItemKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.run.as_bytes());
        out.push(self.family.tag());
        out.extend_from_slice(&self.index.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (run, rest) = bytes.split_at_checked(16)?;
        let (tag, index) = rest.split_at_checked(1)?;
        let family = ReplayFamily::from_tag(tag[0])?;
        let index = u64::from_be_bytes(index.try_into().ok()?);
        let run = EntityId::from_bytes(run.try_into().ok()?).ok()?;
        Some(Self { run, family, index })
    }
}

/// One item row's bytes: one family's element as it sits inside the whole encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayItem(
    /// The element's MessagePack bytes.
    pub(crate) Vec<u8>,
);

impl RawValue for ReplayItem {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.clone())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self(bytes.to_vec()))
    }
}

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

/// A codec error as the seam reports it: a value error as itself, a row shape as its table's.
fn seam_error(decl: &'static crate::side_table::SideTableDecl, error: CodecError) -> Error {
    match error {
        CodecError::Value(error) => error,
        CodecError::Row(problem) => decl.row_error(problem),
    }
}

/// Whether `masked` still reads as one `family` element, for the wall's check of a masked copy.
fn decodes_item(masked: &[u8], family: ReplayFamily) -> bool {
    let mut cursor = masked;
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return false;
    };
    if !cursor.is_empty() {
        return false;
    }
    match family {
        ReplayFamily::BridgeCalls => match decode_bridge_call(&value) {
            Ok(call) => validate_bridge_call(&call).is_ok(),
            Err(_) => false,
        },
        ReplayFamily::StepCheckpoints => decode_step_checkpoint(&value).is_ok(),
        ReplayFamily::Outputs => match decode_raw_output(&value) {
            Ok(output) => validate_raw_output(&output).is_ok(),
            Err(_) => false,
        },
        ReplayFamily::Bindings => match decode_binding(&value) {
            Ok(binding) => CodeRunResultBinding::is_valid_name(&binding.name),
            Err(_) => false,
        },
    }
}

/// The historical lift sweep's admission of the stored replay item `row` at the full key `key`
/// (OF-067): through its run's head origin and checked as one element of its family, as the
/// item's own write admits it. `None` when `key` is not a replay item key.
pub(crate) fn admit_lifted_item(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
    row: &[u8],
) -> Option<Result<Option<Vec<u8>>>> {
    let item = ReplayItemKey::decode_key(key.strip_prefix(ITEMS.decl().prefix)?)?;
    let head_key = HEADS.key_bytes(&item.run);
    Some(crate::batch::secret_scan::admit_side_row(
        dbs,
        wtxn,
        &side_table::CODE_RUN_REPLAY,
        &head_key,
        row,
        |masked| decodes_item(masked, item.family),
    ))
}

/// Writes `bytes` raw at the item `key`, past the wall: the caller admitted them already.
fn put_raw_item(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &ReplayItemKey,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let full = ITEMS.key_bytes(key);
    dbs.side_vault_meta().put(wtxn, &full, bytes)?;
    #[cfg(oneiron_test_support)]
    note_written(bytes.len());
    Ok(full)
}

/// Writes one item through its head's wall origin: admitted, or as given when the wall leaves it.
fn put_admitted_item(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    head_key: &[u8],
    key: &ReplayItemKey,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let admitted = crate::batch::secret_scan::admit_side_row(
        dbs,
        wtxn,
        &side_table::CODE_RUN_REPLAY,
        head_key,
        bytes,
        |masked| decodes_item(masked, key.family),
    )?;
    let stored = admitted.as_deref().unwrap_or(bytes);
    put_raw_item(dbs, wtxn, key, stored)
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
    #[cfg(oneiron_test_support)]
    note_written(bytes.len());
    Ok(full)
}

/// Deletes `run`'s stored items past `counts`, in [`ReplayFamily::ALL`] order; every full key deleted.
fn delete_stale_items(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    counts: [u64; 4],
) -> Result<Vec<Vec<u8>>> {
    let mut deleted = Vec::new();
    for row in ITEMS.iter_raw_from(dbs, wtxn, &ReplayItemKey::run_prefix(run))? {
        let (suffix, _) = row?;
        let Some(key) = ReplayItemKey::decode_key(&suffix) else {
            return Err(Error::CorruptedIndex("code-run replay item key"));
        };
        let slot = match key.family {
            ReplayFamily::BridgeCalls => 0,
            ReplayFamily::StepCheckpoints => 1,
            ReplayFamily::Outputs => 2,
            ReplayFamily::Bindings => 3,
        };
        if key.index >= counts[slot] {
            let full = ITEMS.key_bytes(&key);
            dbs.side_vault_meta().delete(wtxn, &full)?;
            deleted.push(full);
        }
    }
    Ok(deleted)
}

/// `run`'s `family` items in index order, checked exactly `0..count`: a gap or an extra row is corrupted.
fn family_items(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
    family: ReplayFamily,
    count: u64,
) -> Result<Vec<Vec<u8>>> {
    let mut items = Vec::new();
    for row in ITEMS.iter_raw_from(dbs, txn, &ReplayItemKey::family_prefix(run, family))? {
        let (suffix, bytes) = row?;
        let Some(key) = ReplayItemKey::decode_key(&suffix) else {
            return Err(Error::CorruptedIndex("code-run replay item key"));
        };
        if key.run != *run || key.family != family {
            return Err(Error::CorruptedIndex("code-run replay item key"));
        }
        items.push((key.index, bytes));
    }
    if items.len() as u64 != count {
        return Err(Error::CorruptedIndex("code-run replay item index"));
    }
    let mut ordered = Vec::with_capacity(items.len());
    for (position, (index, bytes)) in items.into_iter().enumerate() {
        if index != position as u64 {
            return Err(Error::CorruptedIndex("code-run replay item index"));
        }
        ordered.push(bytes);
    }
    Ok(ordered)
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

/// Every item of `record` through the wall under its head's origin, stale items past its counts
/// deleted; every full item key written or deleted. The caller validated `record` already.
fn write_items(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: &CodeRunReplayRecord,
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
            keys.push(put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?);
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

/// The replay row's bytes at the full row key `key`, if present: joined for a head, as stored otherwise.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn canonical_bytes_at(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    if !is_row_key(key) {
        return Ok(dbs
            .side_vault_meta()
            .get(txn, key)?
            .map(|bytes| bytes.into_owned()));
    }
    let Some(run) = run_id_of_key(key) else {
        return Ok(dbs
            .side_vault_meta()
            .get(txn, key)?
            .map(|bytes| bytes.into_owned()));
    };
    joined_bytes(dbs, txn, &run)
}

/// The vault_meta row's image value: `None` skips an item key, a head key's canonical bytes,
/// or the value as it rests for any other row.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn image_value<'a>(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    value: &'a [u8],
) -> Result<Option<Cow<'a, [u8]>>> {
    if is_item_key(key) {
        return Ok(None);
    }
    if !is_row_key(key) {
        return Ok(Some(Cow::Borrowed(value)));
    }
    Ok(canonical_bytes_at(dbs, txn, key)?.map(Cow::Owned))
}

/// Splits every head-key value in `rows` that starts a record map into its head value plus its
/// item rows, for a restore whose image holds canonical whole bytes. Markers and non-map values
/// stay as they are; a value that does not split stays whole.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn split_image_rows(rows: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
    let mut items = Vec::new();
    for (key, value) in rows.iter_mut() {
        if !is_row_key(key) {
            continue;
        }
        if !matches!(value.first(), Some(0x80..=0x8f | 0xde | 0xdf)) {
            continue;
        }
        let Some(run) = run_id_of_key(key) else {
            continue;
        };
        let Ok((_, families)) = split_canonical(value) else {
            continue;
        };
        let Ok(record) = decode(value) else {
            continue;
        };
        let Ok(head) = ReplayHead::of(&record) else {
            continue;
        };
        let Ok(head_bytes) = HEADS.encode_value(&head) else {
            continue;
        };
        *value = head_bytes;
        for (family, elements) in ReplayFamily::ALL.into_iter().zip(families.iter()) {
            for (index, bytes) in elements.iter().enumerate() {
                let Ok(uindex) = u64::try_from(index) else {
                    continue;
                };
                items.push((
                    ITEMS.key_bytes(&ReplayItemKey {
                        run,
                        family,
                        index: uindex,
                    }),
                    bytes.clone(),
                ));
            }
        }
    }
    if !items.is_empty() {
        // The image's rows stay in key order: item keys sort after the heads and among other tables.
        rows.extend(items);
        rows.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    }
    Ok(())
}

/// Writes `bytes` at the full replay row key `key`, past the wall as stored: split when they start
/// a record map, or a marker with every item of the run deleted.
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
    if !is_row_key(key) {
        #[cfg(oneiron_test_support)]
        note_written(bytes.len());
        return dbs.side_vault_meta().put(wtxn, key, bytes);
    }
    let Some(run) = run_id_of_key(key) else {
        #[cfg(oneiron_test_support)]
        note_written(bytes.len());
        return dbs.side_vault_meta().put(wtxn, key, bytes);
    };
    let starts_map = matches!(bytes.first(), Some(0x80..=0x8f | 0xde | 0xdf));
    if !starts_map {
        dbs.side_vault_meta().put(wtxn, key, bytes)?;
        #[cfg(oneiron_test_support)]
        note_written(bytes.len());
        delete_stale_items(dbs, wtxn, &run, [0, 0, 0, 0])?;
        return Ok(());
    }
    let (_, families) = split_canonical(bytes).map_err(|error| seam_error(HEADS.decl(), error))?;
    let mut counts = [0_u64; 4];
    for (slot, items) in families.iter().enumerate() {
        counts[slot] = u64::try_from(items.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run replay item count"))?;
    }
    let decoded = decode(bytes)?;
    let head = ReplayHead::of(&decoded)?;
    put_raw_head(dbs, wtxn, &run, &head)?;
    for (family, items) in ReplayFamily::ALL.into_iter().zip(families.iter()) {
        for (index, bytes) in items.iter().enumerate() {
            let Ok(uindex) = u64::try_from(index) else {
                return Err(Error::ArithmeticOverflow("code-run replay item index"));
            };
            let key = ReplayItemKey {
                run,
                family,
                index: uindex,
            };
            put_raw_item(dbs, wtxn, &key, bytes)?;
        }
    }
    delete_stale_items(dbs, wtxn, &run, counts)?;
    Ok(())
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

/// The full stored key of `run`'s replay row.
pub(crate) fn key_bytes(run: &EntityId) -> Vec<u8> {
    HEADS.key_bytes(run)
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

/// Persists `record` as `run`'s replay rows, through the wall: its head plus every item, stale items
/// past its counts deleted. Every full key written or deleted.
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
    encode(record)?;
    let head = ReplayHead::of(record)?;
    let stored = HEADS.put_as_stored(dbs, wtxn, run, &head)?;
    #[cfg(oneiron_test_support)]
    note_written(stored.len());
    let mut keys = vec![HEADS.key_bytes(run)];
    keys.extend(write_items(dbs, wtxn, run, record)?);
    Ok(keys)
}

/// Appends `fenced` onto `stored`, writing only what moved: the head, new items, fence-changed
/// items and changed calls. A stored prefix item stays as the wall admitted it (OF-067), keeping
/// any reply rows a delivery added since (FIX 5455); an append's bytes are flat in the run's length.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_append(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    stored: &ReplayHead,
    written: &CodeRunReplayRecord,
    fenced: &CodeRunReplayRecord,
) -> Result<Vec<Vec<u8>>> {
    validate_code_run_replay_record(fenced)?;
    let birth = stored.birth_world()?.or(fenced.birth_world);
    let fenced_for_head: Cow<'_, CodeRunReplayRecord> = if birth == fenced.birth_world {
        Cow::Borrowed(fenced)
    } else {
        let mut owned = fenced.clone();
        owned.birth_world = birth;
        Cow::Owned(owned)
    };
    let head = ReplayHead::of(&fenced_for_head)?;
    let run = fenced.run_id;
    let head_key = HEADS.key_bytes(&run);
    let stored_head = HEADS.put_as_stored(dbs, wtxn, &run, &head)?;
    #[cfg(oneiron_test_support)]
    note_written(stored_head.len());
    let mut keys = vec![head_key.clone()];
    let fenced_changed = !std::ptr::eq(fenced, written);
    let stored_calls = usize::try_from(stored.counts[0])
        .map_err(|_| Error::CorruptedIndex("code-run replay head count"))?;
    let stored_checkpoints = usize::try_from(stored.counts[1])
        .map_err(|_| Error::CorruptedIndex("code-run replay head count"))?;
    let stored_outputs = usize::try_from(stored.counts[2])
        .map_err(|_| Error::CorruptedIndex("code-run replay head count"))?;
    for (index, call) in fenced.bridge_calls.iter().enumerate() {
        if index >= stored_calls {
            let bytes = encode_code_run_replay_item(fenced, ReplayFamily::BridgeCalls, index)
                .map_err(|error| seam_error(HEADS.decl(), error))?;
            let key = ReplayItemKey {
                run,
                family: ReplayFamily::BridgeCalls,
                index: index as u64,
            };
            keys.push(put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?);
            continue;
        }
        if fenced_changed && written.bridge_calls.get(index) != Some(call) {
            let bytes = encode_code_run_replay_item(fenced, ReplayFamily::BridgeCalls, index)
                .map_err(|error| seam_error(HEADS.decl(), error))?;
            let key = ReplayItemKey {
                run,
                family: ReplayFamily::BridgeCalls,
                index: index as u64,
            };
            keys.push(put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?);
            continue;
        }
        if !written.changed_calls.contains(index as u64) {
            continue;
        }
        let key = ReplayItemKey {
            run,
            family: ReplayFamily::BridgeCalls,
            index: index as u64,
        };
        let Some(stored_bytes) = ITEMS.get_bytes(dbs, wtxn, &key)? else {
            return Err(Error::CorruptedIndex("code-run replay item index"));
        };
        let mut cursor = stored_bytes.as_slice();
        let value = rmpv::decode::read_value(&mut cursor)
            .map_err(|_| Error::CorruptedIndex("code-run replay item bytes"))?;
        if !cursor.is_empty() {
            return Err(Error::CorruptedIndex("code-run replay item bytes"));
        }
        let mut kept = decode_bridge_call(&value)?;
        if let Some(rows) = wait_rows(&call.outcome) {
            keep_wait_rows(&mut kept.outcome, &rows);
        }
        let bytes = encode_code_run_bridge_call_bytes(&kept)
            .map_err(|error| seam_error(HEADS.decl(), error))?;
        keys.push(put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?);
    }
    for (index, checkpoint) in fenced.step_checkpoints.iter().enumerate() {
        if index >= stored_checkpoints
            || (fenced_changed && written.step_checkpoints.get(index) != Some(checkpoint))
        {
            let bytes = encode_code_run_replay_item(fenced, ReplayFamily::StepCheckpoints, index)
                .map_err(|error| seam_error(HEADS.decl(), error))?;
            let key = ReplayItemKey {
                run,
                family: ReplayFamily::StepCheckpoints,
                index: index as u64,
            };
            keys.push(put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?);
        }
    }
    for (index, output) in fenced.outputs.iter().enumerate() {
        if index >= stored_outputs || (fenced_changed && written.outputs.get(index) != Some(output))
        {
            let bytes = encode_code_run_replay_item(fenced, ReplayFamily::Outputs, index)
                .map_err(|error| seam_error(HEADS.decl(), error))?;
            let key = ReplayItemKey {
                run,
                family: ReplayFamily::Outputs,
                index: index as u64,
            };
            keys.push(put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?);
        }
    }
    let stored_bindings = family_items(dbs, wtxn, &run, ReplayFamily::Bindings, stored.counts[3])?;
    for (index, _) in fenced.bindings.iter().enumerate() {
        let bytes = encode_code_run_replay_item(fenced, ReplayFamily::Bindings, index)
            .map_err(|error| seam_error(HEADS.decl(), error))?;
        if stored_bindings.get(index) == Some(&bytes) {
            continue;
        }
        let key = ReplayItemKey {
            run,
            family: ReplayFamily::Bindings,
            index: index as u64,
        };
        keys.push(put_admitted_item(dbs, wtxn, &head_key, &key, &bytes)?);
    }
    let counts = [
        u64::try_from(fenced.bridge_calls.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run bridge call count"))?,
        u64::try_from(fenced.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run step checkpoint count"))?,
        u64::try_from(fenced.outputs.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run output count"))?,
        u64::try_from(fenced.bindings.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run binding count"))?,
    ];
    // An append never shrinks the calls, checkpoints or outputs (`appends_to`); only the
    // bindings can, so their stale rows are deleted by key and the append reads no other item.
    for index in counts[3]..stored.counts[3] {
        let key = ITEMS.key_bytes(&ReplayItemKey {
            run,
            family: ReplayFamily::Bindings,
            index,
        });
        dbs.side_vault_meta().delete(wtxn, &key)?;
        keys.push(key);
    }
    Ok(keys)
}

/// Persists `record`'s items, through the wall, stale items past its counts deleted; every full
/// item key written or deleted, no head.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_items(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    record: &CodeRunReplayRecord,
) -> Result<Vec<Vec<u8>>> {
    encode(record)?;
    write_items(dbs, wtxn, run, record)
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
