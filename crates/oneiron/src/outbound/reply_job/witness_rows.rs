//! The conversation rows a reply job's exchange was witnessed into, as a
//! participant's erase finds them (FIX 10897).

use super::*;

/// The (MESSAGE, TURN) ids of each reply job's witnessed exchange whose job
/// names one of `erased`: its agent, or its event's actor, receiving
/// identity or known counterparty. Each such job gives its inbound side and
/// its reply, at the ids the witness derives them at, whether or not a side
/// landed. Read before the payload erase clears the job's event, while the
/// job still names them. A job whose event no longer decodes, or that names
/// none of `erased`, gives none.
///
/// # Errors
/// Storage errors.
pub(crate) fn connector_witness_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<BTreeSet<(EntityId, EntityId)>> {
    let mut rows = BTreeSet::new();
    // Every row, as the payload erase reads them: one that does not decode
    // names nobody and never holds the erase back.
    for row in vault.store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(record) = crate::attempt_queue::decode_record(&raw, id) else {
            continue;
        };
        if record.kind != CONNECTOR_REPLY_JOB_KIND {
            continue;
        }
        let Ok(job) = serde_json::from_slice::<ConnectorReplyJob>(&record.payload) else {
            continue;
        };
        if job.event.payload.is_null() || !job.named_ids().iter().any(|id| erased.contains(id)) {
            continue;
        }
        let Ok(origin) = SurfaceConnectorPayload::from_connector_event(&job.event) else {
            continue;
        };
        if let Ok(sides) =
            crate::ingest::connector_witness_row_ids(&origin, job.agent, CONNECTOR_REPLY_REF)
        {
            rows.extend(sides);
        }
    }
    Ok(rows)
}
