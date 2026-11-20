//! Doors for `tests/check_in_legal_hold_restarted_act.rs` (row
//! CHECK-IN-LEGAL-HOLD-RESTARTED-ACT-NO-DECISION): the `erase` act a waiting
//! lift-and-erase names, and the row a crash between its confirm's writer and
//! its act start leaves, which the legal-hold pass restarts (FIX 10401).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::legal_hold as hold_store;

/// The `erase` act the waiting erase of `record` names; `None` when no erase
/// of `record` waits, or it names no act.
pub fn waiting_erase_act(vault: &Vault, record: &EntityId) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        hold_store::pending_erase_in_txn(&vault.store, &txn, record)?
            .and_then(|pending| pending.veto_act),
    )
}

/// Leaves the waiting erase of `record` as a crash between its confirm's
/// writer and its act start leaves it: the row names no act, and the act it
/// named is withdrawn with its started events. The act it withdrew; `None`
/// when the row named none.
pub fn forget_waiting_erase_act(vault: &Vault, record: &EntityId) -> Result<Option<String>> {
    let mut txn = vault.store.env.write_txn()?;
    let Some(act) = hold_store::take_pending_veto_act_in_txn(&vault.store, &mut txn, record)?
    else {
        return Ok(None);
    };
    if let Some(started) = vault.pending_authority_act_in_txn(&txn, &act)? {
        let starter = EntityId::from_hex(&started.starter)?;
        vault.withdraw_authority_act_in_txn(&mut txn, &act, starter)?;
    }
    txn.commit()?;
    Ok(Some(act))
}
