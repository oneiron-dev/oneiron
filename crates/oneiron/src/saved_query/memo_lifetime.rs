//! A verdict memo lives no longer than the evidence it explains (FIX 10089).
//!
//! A memo keeps a judge's `why`, which can repeat what the candidate's
//! claims, edges or exemplars said. It names every row its evidence was read
//! from ([`VerdictMemoRow::source_refs`]), beside its query and candidate,
//! and the erase of any one of them takes the memo at both delete doors, in
//! the erase's own transaction. A memo whose sources are not known whole
//! goes with any erase. Memos are a node-local derivation cache: the next
//! evaluation over the evidence that remains derives its own, so no current
//! authorized hit is lost. A checkpoint carries a memo row as a row-held
//! response owned by those same rows, so their erase retires every image's
//! copy too, and a retired memo row leaves nothing behind.
use super::evidence::{VerdictMemoKey, VerdictMemoRow};
use super::storage::MEMOS;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::{ResponseCarriage, ResponseScan, Store};

/// The field a memo row names its sources under; a row without it does not
/// know them whole.
const SOURCE_REFS_FIELD: &[u8] = b"\"source_refs\"";

/// Whose the memo is: its query, its candidate and every source row, or
/// `None` when the sources are not known whole.
fn owners(row: &VerdictMemoRow) -> Option<Vec<EntityId>> {
    let mut owners = vec![row.key.query_ref, row.key.entity_ref];
    owners.extend(row.source_refs.as_ref()?.iter().copied());
    owners.sort_unstable();
    owners.dedup();
    Some(owners)
}

/// Who owns the memo row `value`: its query, candidate and sources; just the
/// query and candidate for a row that does not know its sources; none for a
/// row that does not decode.
pub(crate) fn memo_owners(value: &[u8]) -> Vec<EntityId> {
    let Ok(row) = MEMOS.decode_value(value) else {
        return Vec::new();
    };
    owners(&row).unwrap_or_else(|| vec![row.key.query_ref, row.key.entity_ref])
}

/// What a checkpoint carries of the memo row `value`: the whole row, and
/// nothing once retired, as a captured request is carried (its retirement
/// drops the row, in images and live alike). A row that does not decode is
/// carried whole as an opaque response (FIX 6227).
pub(crate) fn memo_carriage(value: &[u8]) -> ResponseScan {
    if MEMOS.decode_value(value).is_err() {
        return ResponseScan::opaque_row();
    }
    ResponseScan::Decoded(ResponseCarriage {
        keep: 0,
        stub: Vec::new(),
        retired: 0,
    })
}

/// The erase of `source` takes every memo it is a source of, its `why`
/// included, in the erase's own transaction at both delete doors; a memo
/// that does not know its sources whole goes too. A row that does not
/// decode stays as it is (FIX 5736); images' copies retire through the rows'
/// obligations.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_memos_for_source_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let needle = source.to_hex();
    let mut gone = Vec::new();
    for row in MEMOS.iter_raw_from(store, wtxn, &[])? {
        let (key, bytes) = row?;
        // A source rests in its row as its hex text, and a row that knows
        // its sources names the field: any other row is not decoded.
        let names = |text: &[u8]| bytes.windows(text.len()).any(|window| window == text);
        if !names(needle.as_bytes()) && names(SOURCE_REFS_FIELD) {
            continue;
        }
        let Ok(memo) = MEMOS.decode_value(&bytes) else {
            continue;
        };
        if owners(&memo).is_none_or(|owners| owners.contains(source)) {
            gone.push(key);
        }
    }
    for key in gone {
        let Some(key) = <VerdictMemoKey as SideKey>::decode_key(&key) else {
            continue;
        };
        MEMOS.delete(store, wtxn, &key)?;
    }
    Ok(())
}
