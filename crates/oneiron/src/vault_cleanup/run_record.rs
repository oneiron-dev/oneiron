//! Durable cleanup results close the job-commit → queue-settlement crash gap.
//!
//! A retried attempt returns its original result, even if its proposal has
//! since been accepted or rejected. The scan, the decision and this record
//! co-commit; retries never open another proposal or scan again.
//!
//! The row also carries what the run archived (`snapshot`, written by the
//! archive itself: the auto arm, or the owner's later accept) and its revert's
//! stored answer (`revert`). Each is Nil until it happens. Writers set their
//! own key and keep every other, so the report keys stay as the run wrote
//! them.

use super::*;
use crate::side_table::{self, Raw, SideTable};

const RUN_LABEL: &str = "cleanup run result";

/// The RUN row key holding what the run archived; Nil until it archives.
pub(super) const KEY_SNAPSHOT: &str = "snapshot";

/// The RUN row key holding the stored answer of the run's revert; Nil until
/// the owner reverts it.
pub(super) const KEY_REVERT: &str = "revert";

/// Durable cleanup-scan result for one attempt. Key: id16 (AttemptId).
const RUN: SideTable<[u8; 16], Vec<u8>, Raw> = SideTable::new(&side_table::VAULT_CLEANUP_RUN);

pub(super) fn read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptId,
) -> Result<Option<CleanupRunReport>> {
    let Some(raw) = RUN.get(&vault.store, txn, attempt.as_bytes())? else {
        return Ok(None);
    };
    let fields = decode_row(&raw, RUN_LABEL)?;
    let posture = field(&fields, KEY_POSTURE)
        .and_then(Value::as_str)
        .and_then(CleanupPosture::parse)
        .ok_or(Error::CorruptedIndex(RUN_LABEL))?;
    let Some(Value::Array(rows)) = field(&fields, KEY_CANDIDATES) else {
        return Err(Error::CorruptedIndex(RUN_LABEL));
    };
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(parts) = row else {
            return Err(Error::CorruptedIndex(RUN_LABEL));
        };
        let entity = field(parts, KEY_ENTITY)
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::CorruptedIndex(RUN_LABEL))?;
        let kind = field(parts, KEY_KIND)
            .and_then(Value::as_str)
            .and_then(CleanupKind::parse)
            .ok_or(Error::CorruptedIndex(RUN_LABEL))?;
        candidates.push(CleanupCandidate { entity, kind });
    }
    Ok(Some(CleanupRunReport {
        attempt: *attempt,
        posture,
        candidates,
        proposal: optional_id(&fields, KEY_PROPOSAL)?,
        archived: id_list(&fields, KEY_ARCHIVED, RUN_LABEL)?,
        digest: optional_id(&fields, "digest")?,
    }))
}

fn optional_id(fields: &[(Value, Value)], key: &str) -> Result<Option<EntityId>> {
    match field(fields, key) {
        Some(Value::Nil) => Ok(None),
        Some(Value::String(value)) => value
            .as_str()
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .map(Some)
            .ok_or(Error::CorruptedIndex(RUN_LABEL)),
        _ => Err(Error::CorruptedIndex(RUN_LABEL)),
    }
}

/// Writes `report` to its RUN row. A snapshot the same transaction already
/// recorded there stays; a new row starts with no snapshot and no revert.
pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    report: &CleanupRunReport,
) -> Result<()> {
    let optional = |id: Option<EntityId>| id.map_or(Value::Nil, |id| Value::from(id.to_hex()));
    let mut fields = match RUN.get(&vault.store, txn, report.attempt.as_bytes())? {
        Some(raw) => decode_row(&raw, RUN_LABEL).unwrap_or_default(),
        None => Vec::new(),
    };
    set(
        &mut fields,
        KEY_POSTURE,
        Value::from(report.posture.as_str()),
    );
    set(
        &mut fields,
        KEY_CANDIDATES,
        Value::Array(
            report
                .candidates
                .iter()
                .map(|candidate| {
                    Value::Map(vec![
                        (
                            Value::from(KEY_ENTITY),
                            Value::from(candidate.entity.to_hex()),
                        ),
                        (Value::from(KEY_KIND), Value::from(candidate.kind.as_str())),
                    ])
                })
                .collect(),
        ),
    );
    set(&mut fields, KEY_PROPOSAL, optional(report.proposal));
    set(&mut fields, KEY_ARCHIVED, id_value_list(&report.archived));
    set(&mut fields, "digest", optional(report.digest));
    for key in [KEY_SNAPSHOT, KEY_REVERT] {
        if field(&fields, key).is_none() {
            fields.push((Value::from(key), Value::Nil));
        }
    }
    write_in_txn(vault, txn, &report.attempt, fields)
}

/// The RUN row of `attempt` as its map's entries; none when the run left no
/// row.
pub(super) fn fields_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptId,
) -> Result<Option<Vec<(Value, Value)>>> {
    RUN.get(&vault.store, txn, attempt.as_bytes())?
        .map(|raw| decode_row(&raw, RUN_LABEL))
        .transpose()
}

/// Sets one key of `attempt`'s RUN row and keeps every other key. A run with
/// no row yet starts one holding that key. A row that does not read is left
/// as it is, and the answer is false.
pub(super) fn set_field_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &AttemptId,
    key: &str,
    value: Value,
) -> Result<bool> {
    let mut fields = match RUN.get(&vault.store, txn, attempt.as_bytes())? {
        Some(raw) => {
            let Ok(fields) = decode_row(&raw, RUN_LABEL) else {
                return Ok(false);
            };
            fields
        }
        None => Vec::new(),
    };
    set(&mut fields, key, value);
    write_in_txn(vault, txn, attempt, fields)?;
    Ok(true)
}

/// Whether `attempt` left a RUN row.
pub(super) fn exists_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptId,
) -> Result<bool> {
    RUN.contains(&vault.store, txn, attempt.as_bytes())
}

/// Every RUN row as stored, in attempt order.
pub(super) fn rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<([u8; 16], Vec<u8>)>> {
    RUN.scan(&vault.store, txn)
}

/// A stored RUN row's map entries.
pub(super) fn decode_fields(raw: &[u8]) -> Result<Vec<(Value, Value)>> {
    decode_row(raw, RUN_LABEL)
}

/// The proposal a RUN row's report names, if the run opened one.
pub(super) fn proposal_of(fields: &[(Value, Value)]) -> Result<Option<EntityId>> {
    optional_id(fields, KEY_PROPOSAL)
}

fn set(fields: &mut Vec<(Value, Value)>, key: &str, value: Value) {
    match fields
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(key))
    {
        Some((_, slot)) => *slot = value,
        None => fields.push((Value::from(key), value)),
    }
}

fn write_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &AttemptId,
    fields: Vec<(Value, Value)>,
) -> Result<()> {
    RUN.put(
        &vault.store,
        txn,
        attempt.as_bytes(),
        &encode_row(&Value::Map(fields), RUN_LABEL)?,
    )
}
