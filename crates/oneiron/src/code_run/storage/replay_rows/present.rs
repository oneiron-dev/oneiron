//! The replay reads a hot reader makes of one run: the whole record, or only its counts, its
//! outputs or its bridge calls, through one funnel that refuses a retired marker before any decode
//! (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT).

use super::*;

/// A present replay row: a split head still to join, or a marker's whole record already decoded.
enum PresentRow {
    /// A split head; the caller joins its items.
    Head(ReplayHead),
    /// A marker row's whole record.
    Whole(CodeRunReplayRecord),
}

/// `run`'s present replay row, if any: the borrowed head read, a retired marker refused before any
/// decode, a head as [`PresentRow::Head`], any other value decoded whole.
fn present_row(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<PresentRow>> {
    let Some(raw) = HEADS.get_borrowed(dbs, txn, run)? else {
        return Ok(None);
    };
    note_read(raw.len());
    let key = HEADS.key_bytes(run);
    let raw = ResponseRead::of(ResponseFamily::Replay, &key, &raw).present()?;
    match HEADS.decode_value(raw) {
        Ok(head) => Ok(Some(PresentRow::Head(head))),
        Err(_) => decode(raw).map(|record| Some(PresentRow::Whole(record))),
    }
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
    let Some(row) = present_row(dbs, txn, run)? else {
        return Ok(None);
    };
    match row {
        PresentRow::Head(head) => {
            let whole = assemble(dbs, txn, run, &head)?;
            decode(&whole).map(Some)
        }
        PresentRow::Whole(record) => Ok(Some(record)),
    }
}

/// `run`'s four replay family counts in [`ReplayFamily::ALL`] order, if present.
///
/// # Errors
///
/// Storage errors, `ResponseErased` for a retired marker, and a row that does not decode.
pub(crate) fn present_counts(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<[u64; 4]>> {
    let Some(row) = present_row(dbs, txn, run)? else {
        return Ok(None);
    };
    match row {
        PresentRow::Head(head) => Ok(Some(head.counts)),
        PresentRow::Whole(record) => {
            let count = |len: usize| {
                u64::try_from(len).map_err(|_| Error::ArithmeticOverflow("code-run replay count"))
            };
            Ok(Some([
                count(record.bridge_calls.len())?,
                count(record.step_checkpoints.len())?,
                count(record.outputs.len())?,
                count(record.bindings.len())?,
            ]))
        }
    }
}

/// One stored output item's bytes as the whole decode reads one output element: the same value
/// decode and the same check.
fn decode_output_item(bytes: &[u8]) -> Result<CodeRunRawOutput> {
    let output = decode_raw_output(&item_value(bytes)?)?;
    validate_raw_output(&output)?;
    Ok(output)
}

/// `run`'s replay outputs, if present, without reading the other families.
///
/// # Errors
///
/// Storage errors, `ResponseErased` for a retired marker, and a row that does not decode.
pub(crate) fn present_outputs(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<Vec<CodeRunRawOutput>>> {
    let Some(row) = present_row(dbs, txn, run)? else {
        return Ok(None);
    };
    match row {
        PresentRow::Head(head) => {
            let items = family_items(dbs, txn, run, ReplayFamily::Outputs, head.counts[2])?;
            items
                .iter()
                .map(|bytes| decode_output_item(bytes))
                .collect::<Result<Vec<_>>>()
                .map(Some)
        }
        PresentRow::Whole(record) => Ok(Some(record.outputs)),
    }
}

/// One stored bridge-call item's bytes as the whole decode reads one bridge call: the same value
/// decode and the same check.
fn decode_checked_call_item(bytes: &[u8]) -> Result<CodeRunBridgeCall> {
    let call = decode_call_item(bytes)?;
    validate_bridge_call(&call)?;
    Ok(call)
}

/// `run`'s replay bridge calls, if present, without reading the other families: as the side-row
/// wall stored them.
///
/// # Errors
///
/// Storage errors, `ResponseErased` for a retired marker, and a row that does not decode.
pub(crate) fn present_bridge_calls(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
) -> Result<Option<Vec<CodeRunBridgeCall>>> {
    let Some(row) = present_row(dbs, txn, run)? else {
        return Ok(None);
    };
    match row {
        PresentRow::Head(head) => {
            let items = family_items(dbs, txn, run, ReplayFamily::BridgeCalls, head.counts[0])?;
            items
                .iter()
                .map(|bytes| decode_checked_call_item(bytes))
                .collect::<Result<Vec<_>>>()
                .map(Some)
        }
        PresentRow::Whole(record) => Ok(Some(record.bridge_calls)),
    }
}
