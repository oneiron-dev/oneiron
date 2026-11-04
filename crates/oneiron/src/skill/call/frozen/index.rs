//! The frozen cases' index (FIX 12180): each case under the rows it was made
//! from, or under its caller's receipt while those are unknown. It is written
//! with its case and deleted with it, so an erase finds the cases that name
//! its row by key and reads no other case.

use serde::{Deserialize, Serialize};

use super::FrozenCall;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// Key: [`SOURCE`] + source id16 + case key, or [`RECEIPT`] + u16be receipt
/// length + receipt + case key.
const INDEX: SideTable<Vec<u8>, (), Raw> = SideTable::new(&side_table::SKILL_CALLABLE_CASE_INDEX);

/// The stored cases, read for the two fields their entries are made from.
const INDEXED: SideTable<Vec<u8>, IndexedFields, Named> =
    SideTable::new(&side_table::SKILL_CALLABLE_CASE);

/// The tag of an entry under a known source row.
const SOURCE: u8 = b'S';
/// The tag of an entry under the caller's receipt.
const RECEIPT: u8 = b'R';
/// Where a case key's receipt starts: after id16 + u64be at + u64be seq.
const CASE_KEY_RECEIPT_AT: usize = 32;

/// A stored case's receipt and sources, read on their own: a case whose
/// other fields no longer decode still finds its entries.
#[derive(Serialize, Deserialize)]
struct IndexedFields {
    receipt: String,
    source_rows: Option<Vec<EntityId>>,
}

fn source_prefix(source: &EntityId) -> Vec<u8> {
    let mut key = vec![SOURCE];
    key.extend_from_slice(source.as_bytes());
    key
}

fn receipt_prefix(receipt: &str) -> Result<Vec<u8>> {
    let length = u16::try_from(receipt.len()).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidSkillBody(
            "a frozen case's receipt is too long to index",
        ))
    })?;
    let mut key = vec![RECEIPT];
    key.extend_from_slice(&length.to_be_bytes());
    key.extend_from_slice(receipt.as_bytes());
    Ok(key)
}

/// The entries of the case under `case_key`: one per known source row, or
/// its receipt's when the sources are unknown.
fn entries(
    case_key: &[u8],
    receipt: &str,
    source_rows: Option<&[EntityId]>,
) -> Result<Vec<Vec<u8>>> {
    let prefixes: Vec<Vec<u8>> = match source_rows {
        Some(rows) => rows.iter().map(source_prefix).collect(),
        None => vec![receipt_prefix(receipt)?],
    };
    Ok(prefixes
        .into_iter()
        .map(|mut key| {
            key.extend_from_slice(case_key);
            key
        })
        .collect())
}

/// Writes the entries of the case `row` under `case_key`.
pub(super) fn index_case_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    case_key: &[u8],
    row: &FrozenCall,
) -> Result<()> {
    for entry in entries(case_key, &row.receipt, row.source_rows.as_deref())? {
        INDEX.put(store, wtxn, &entry, &())?;
    }
    Ok(())
}

/// Deletes the entries of the stored case under `case_key`, in the writer
/// that deletes the case. With neither field readable, the receipt in its
/// key names its entry.
pub(super) fn unindex_case_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    case_key: &Vec<u8>,
) -> Result<()> {
    let found = match INDEXED.get_lenient(store, wtxn, case_key)? {
        Some(fields) => entries(case_key, &fields.receipt, fields.source_rows.as_deref()),
        None => std::str::from_utf8(case_key.get(CASE_KEY_RECEIPT_AT..).unwrap_or_default())
            .map_err(|_| Error::EntityNotFound)
            .and_then(|receipt| entries(case_key, receipt, None)),
    };
    // A key that could never have been indexed has no entry to delete.
    for entry in found.unwrap_or_default() {
        INDEX.delete(store, wtxn, &entry)?;
    }
    Ok(())
}

/// The keys of the cases indexed under `source`, a known source row.
pub(super) fn source_cases_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
) -> Result<Vec<Vec<u8>>> {
    let prefix = source_prefix(source);
    Ok(INDEX
        .scan_keys(store, txn, &prefix)?
        .into_iter()
        .filter_map(|entry| entry.get(prefix.len()..).map(<[u8]>::to_vec))
        .collect())
}

/// Deletes every entry under `source`, a known source row.
pub(super) fn forget_source_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    INDEX.delete_from(store, wtxn, &source_prefix(source))?;
    Ok(())
}

/// The keys of the cases indexed under `receipt`, a caller's receipt: its
/// calls whose sources are unknown. A receipt too long to index has none.
pub(super) fn receipt_case_keys_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<Vec<Vec<u8>>> {
    let Ok(prefix) = receipt_prefix(receipt) else {
        return Ok(Vec::new());
    };
    Ok(INDEX
        .scan_keys(store, txn, &prefix)?
        .into_iter()
        .filter_map(|entry| entry.get(prefix.len()..).map(<[u8]>::to_vec))
        .collect())
}

/// Each receipt that cases with unknown sources are indexed under, once, in
/// key order, with the keys of its cases.
pub(super) fn receipt_cases_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(String, Vec<Vec<u8>>)>> {
    let mut grouped: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    for entry in INDEX.scan_keys(store, txn, &[RECEIPT])? {
        let Some((receipt, case_key)) = split_receipt_entry(&entry) else {
            continue;
        };
        // A receipt's entries are adjacent in key order.
        if let Some(cases) = grouped
            .last_mut()
            .and_then(|(last, cases)| (last.as_str() == receipt).then_some(cases))
        {
            cases.push(case_key.to_vec());
            continue;
        }
        grouped.push((receipt.to_owned(), vec![case_key.to_vec()]));
    }
    Ok(grouped)
}

/// A receipt entry's receipt and case key.
fn split_receipt_entry(entry: &[u8]) -> Option<(&str, &[u8])> {
    let (&tag, rest) = entry.split_first()?;
    if tag != RECEIPT {
        return None;
    }
    let (length, rest) = rest.split_first_chunk::<2>()?;
    let (receipt, case_key) = rest.split_at_checked(usize::from(u16::from_be_bytes(*length)))?;
    Some((std::str::from_utf8(receipt).ok()?, case_key))
}
