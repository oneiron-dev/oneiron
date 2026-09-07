//! Durable cleanup results close the job-commit → queue-settlement crash gap.
//!
//! A retried attempt returns its original result, even if its proposal has
//! since been accepted or rejected. Cursor progress, the decision and this
//! record co-commit; retries never open another proposal or advance the scan.

use super::*;

const RUN_PREFIX: &[u8] = b"vault_cleanup.run.v1:";
const RUN_LABEL: &str = "cleanup run result";

fn run_key(attempt: &AttemptId) -> Vec<u8> {
    let mut key = RUN_PREFIX.to_vec();
    key.extend_from_slice(attempt.as_bytes());
    key
}

pub(super) fn read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptId,
) -> Result<Option<CleanupRunReport>> {
    let Some(raw) = vault.store.vault_meta.get(txn, &run_key(attempt))? else {
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

pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    report: &CleanupRunReport,
) -> Result<()> {
    let optional = |id: Option<EntityId>| id.map_or(Value::Nil, |id| Value::from(id.to_hex()));
    let row = Value::Map(vec![
        (
            Value::from(KEY_POSTURE),
            Value::from(report.posture.as_str()),
        ),
        (
            Value::from(KEY_CANDIDATES),
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
        ),
        (Value::from(KEY_PROPOSAL), optional(report.proposal)),
        (Value::from(KEY_ARCHIVED), id_value_list(&report.archived)),
        (Value::from("digest"), optional(report.digest)),
    ]);
    vault.store.vault_meta.put(
        txn,
        &run_key(&report.attempt),
        &encode_row(&row, RUN_LABEL)?,
    )?;
    Ok(())
}
