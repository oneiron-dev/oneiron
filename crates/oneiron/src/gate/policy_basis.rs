//! The policy a Gate receipt stands on, resolved in the decision's own
//! transaction. Resolving the manifest is the gate's job, so the receipt
//! writer takes the result and never calls up into the gate.

#![allow(dead_code, reason = "first callers: UC-03 stage 1")]

use heed::RoTxn;

use super::resolve_policy_manifest;
use crate::error::Result;
use crate::store::{PolicyBasis, Store};

/// The policy in force in `txn`: the read frontier of the manifest it
/// resolves to, under the current policy schema version.
pub(crate) fn policy_basis_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<PolicyBasis> {
    Ok(PolicyBasis::frontier(
        resolve_policy_manifest(store, txn)?.read_frontier_hash()?,
    ))
}
