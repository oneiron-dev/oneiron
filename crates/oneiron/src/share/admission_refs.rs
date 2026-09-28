//! Gate-decision references held by durable share admissions.

use crate::error::{Error, Result};
use crate::store::{GateDecisionId, Store};

use super::{SHARE_ADMISSION_PREFIX, ShareAdmission};

/// Durable admission references are operational, even after revocation: the
/// historical share receipt still needs its original allowing Gate decision.
/// Do not infer liveness from a gate read while deciding whether to prune it.
pub(crate) fn share_gate_decision_refs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<std::collections::HashSet<GateDecisionId>> {
    let mut ids = std::collections::HashSet::new();
    for row in store.vault_meta.prefix_iter(txn, SHARE_ADMISSION_PREFIX)? {
        let (key, raw) = row?;
        let id = key
            .strip_prefix(SHARE_ADMISSION_PREFIX)
            .ok_or(Error::CorruptedIndex("share admission key"))?;
        let _: [u8; 16] = id
            .try_into()
            .map_err(|_| Error::CorruptedIndex("share admission key"))?;
        let admission =
            ShareAdmission::decode(&raw).ok_or(Error::CorruptedIndex("share admission"))?;
        ids.insert(admission.gate_id);
    }
    Ok(ids)
}
