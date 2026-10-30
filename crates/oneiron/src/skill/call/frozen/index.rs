//! The frozen cases' index (FIX 12180): each case under the rows it was made
//! from, or under its caller's receipt while those are unknown. It is written
//! with its case and deleted with it, so an erase finds the cases that name
//! its row by key and reads no other case.

use super::FrozenCall;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Key: [`SOURCE`] + source id16 + case key, or [`RECEIPT`] + u16be receipt
/// length + receipt + case key.
const INDEX: SideTable<Vec<u8>, (), Raw> =
    SideTable::new(&side_table::SKILL_CALLABLE_CASE_INDEX);

/// The tag of an entry under a known source row.
const SOURCE: u8 = b'S';
/// The tag of an entry under the caller's receipt.
const RECEIPT: u8 = b'R';
/// Where a case key's receipt starts: after id16 + u64be at + u64be seq.
const CASE_KEY_RECEIPT_AT: usize = 32;

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

/// The entries of the case `row` under `case_key`: one per known source
/// row, or its receipt's when the sources are unknown.
fn entries(case_key: &[u8], row: &FrozenCall) -> Result<Vec<Vec<u8>>> {
    let prefixes: Vec<Vec<u8>> = match &row.source_rows {
        Some(rows) => rows.iter().map(source_prefix).collect(),
        None => vec![receipt_prefix(&row.receipt)?],
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
    for entry in entries(case_key, row)? {
        INDEX.put(store, wtxn, &entry, &())?;
    }
    Ok(())
}

/// Deletes the entries of the case under `case_key`. With no row that
/// decodes, the receipt in its key names its one findable entry.
pub(super) fn unindex_case_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    case_key: &[u8],
    row: Option<&FrozenCall>,
) -> Result<()> {
    // A key that could never have been indexed has no entry to delete.
    let found = match row {
        Some(row) => entries(case_key, row).unwrap_or_default(),
        None => case_key
            .get(CASE_KEY_RECEIPT_AT..)
            .and_then(|receipt| std::str::from_utf8(receipt).ok())
            .and_then(|receipt| receipt_prefix(receipt).ok())
            .map(|mut key| {
                key.extend_from_slice(case_key);
                vec![key]
            })
            .unwrap_or_default(),
    };
    for entry in found {
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
