//! The door's second scan after a placing plan, over the ops the plan
//! changed (FIX 12212). It runs when the door's first scan read the batch
//! clean and the owner kept no value in the batch's records.
//!
//! The door's scan reads each op alone: a put's type and body, a claim
//! candidate under its envelope, a text op's fields, a phonetic op's codes,
//! by the owner's switch. Nothing between the two scans writes the
//! transaction, so the switch reads the same. An op the plan left as the
//! first scan read it is read the same again, and the first scan read it
//! clean. So the first hit among the changed ops, in op order, is the first
//! hit among all the ops.

use heed::RoTxn;

use super::super::scan_batch_ops;
use crate::batch::BatchOp;
use crate::error::Result;
use crate::store::Store;

/// The door's scan of `planned`, the plan's copy of `read`, which the
/// door's first scan read clean: each op the plan changed, in op order.
pub(super) fn scan_changed_ops(
    store: &Store,
    txn: &RoTxn<'_>,
    planned: &[BatchOp],
    read: &[BatchOp],
) -> Result<()> {
    for (op, before) in planned.iter().zip(read) {
        if !scan_reads_same(op, before) {
            scan_batch_ops(store, txn, std::slice::from_ref(op))?;
        }
    }
    Ok(())
}

/// Whether the door's scan reads `op` as it read `before`: each part it
/// reads is equal. It reads nothing of any other kind of op.
fn scan_reads_same(op: &BatchOp, before: &BatchOp) -> bool {
    match (op, before) {
        (
            BatchOp::Put {
                entity_type, data, ..
            },
            BatchOp::Put {
                entity_type: read_type,
                data: read_data,
                ..
            },
        ) => entity_type == read_type && data == read_data,
        (
            BatchOp::ClaimCandidate {
                candidate,
                envelope,
                ..
            },
            BatchOp::ClaimCandidate {
                candidate: read_candidate,
                envelope: read_envelope,
                ..
            },
        ) => candidate == read_candidate && envelope == read_envelope,
        (BatchOp::Text { fields, .. }, BatchOp::Text { fields: read, .. }) => fields == read,
        (BatchOp::Phonetic { codes, .. }, BatchOp::Phonetic { codes: read, .. }) => codes == read,
        _ => !matches!(
            op,
            BatchOp::Put { .. }
                | BatchOp::ClaimCandidate { .. }
                | BatchOp::Text { .. }
                | BatchOp::Phonetic { .. }
        ),
    }
}
