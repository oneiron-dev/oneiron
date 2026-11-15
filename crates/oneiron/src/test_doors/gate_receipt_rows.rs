//! Doors for `tests/gate_receipt_rows.rs` (UC-03 PR 0) on PR 0's base: one
//! Gate ledger row read back by its id, and the read frontier of the policy
//! the vault resolves to now. The base has no receipt draft or mint, so the
//! mint doors of PR 0's head are absent here and `tests/gate_receipt_mint.rs`
//! does not build.

use crate::error::Result;
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::vault::Vault;

/// The Gate ledger row `decision` names, as the store decodes it.
pub fn gate_row(vault: &Vault, decision: GateDecisionId) -> Result<Option<GateDecisionRecord>> {
    let txn = vault.store.env.read_txn()?;
    vault.store.gate_decision_in_txn(&txn, decision)
}

/// The read frontier of the policy manifest the vault resolves to now.
pub fn policy_frontier(vault: &Vault) -> Result<[u8; 32]> {
    let txn = vault.store.env.read_txn()?;
    crate::gate::resolve_policy_manifest(&vault.store, &txn)?.read_frontier_hash()
}
