//! Gate-decision references held by durable share admissions.

use crate::error::{Error, Result};
use crate::store::{GateDecisionId, Store};

use super::{ADMISSIONS, ShareAdmission};

/// Durable admission references are operational, even after revocation: the
/// historical share receipt still needs its original allowing Gate decision.
/// Do not infer liveness from a gate read while deciding whether to prune it.
pub(crate) fn share_gate_decision_refs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<std::collections::HashSet<GateDecisionId>> {
    let mut ids = std::collections::HashSet::new();
    for (_, raw) in ADMISSIONS.scan(store, txn)? {
        let admission =
            ShareAdmission::decode(&raw).ok_or(Error::CorruptedIndex("share admission"))?;
        ids.insert(admission.gate_id);
    }
    Ok(ids)
}
