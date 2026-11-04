//! An actor's erase takes the actor out of the escalation rows that name it
//! (FIX 4700). A ledger or standing-policy row whose scope carries the erased
//! hex names the [`ERASED_CALL_IDENTITY`] token instead, and a standing-policy
//! row the erased holder answered forgets the who while the act stands: its
//! `accepted_by`/`decision_ref` pair clears and `accepted_at` stays. Keys
//! derive from scope, so a rewritten row is deleted and re-put under its
//! recomputed digest; the deterministic token keeps one scope's converged
//! history under one digest instead of scattering it.

use super::storage::{
    ESCALATION, STANDING_POLICY, ScopeTriggerKey, StoredStandingPolicy, scope_key,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;

/// Scrubs the erased actor's hex from every escalation ledger row's scope and
/// every standing-policy row's scope and answerer pair. Registered on both
/// escalation stores; the first call does all of them, and the second finds
/// no hex substring left to scrub.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_escalation_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, entity)? {
        return Ok(());
    }
    let hex = entity.to_hex();
    erase_ledger_scopes_in_txn(vault, wtxn, &hex)?;
    erase_policy_scopes_in_txn(vault, wtxn, &hex)
}

/// Rewrites the scope of every ledger row naming `hex` to the erased token
/// and re-keys it under the recomputed digest.
fn erase_ledger_scopes_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, hex: &str) -> Result<()> {
    let rows = ESCALATION
        .iter_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for ((_, id), mut row) in rows {
        if !row.scope.contains(hex) {
            continue;
        }
        let old = (scope_key(&row.scope), id);
        row.scope = row.scope.replace(hex, ERASED_CALL_IDENTITY);
        ESCALATION.delete(&vault.store, wtxn, &old)?;
        ESCALATION.put(&vault.store, wtxn, &(scope_key(&row.scope), id), &row)?;
    }
    Ok(())
}

/// Rewrites the scope of every standing-policy row naming `hex`, re-keys it
/// under the recomputed digest, and clears the answerer pair on every row the
/// erased holder answered.
fn erase_policy_scopes_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, hex: &str) -> Result<()> {
    let rows = STANDING_POLICY
        .iter_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, _) in rows {
        // An earlier convergence in this same pass may have folded this key's
        // row into another destination; scrub the live row, never a stale
        // snapshot, so folded history is not overwritten.
        let mut row = match STANDING_POLICY.get(&vault.store, wtxn, &key)? {
            Some(live) => live,
            None => continue,
        };
        if !scrub_policy_row(&mut row, hex) {
            continue;
        }
        let new = ScopeTriggerKey {
            scope_digest: scope_key(&row.scope),
            trigger: key.trigger,
        };
        if new != key {
            STANDING_POLICY.delete(&vault.store, wtxn, &key)?;
            // The destination may already hold a row: a pre-existing converged
            // policy, or one folded earlier in this pass. Fold the rewritten
            // row into its superseded history instead of overwriting it, so
            // the erase removes nothing (review round 1).
            if let Some(mut kept) = STANDING_POLICY.get(&vault.store, wtxn, &new)? {
                kept.superseded.append(&mut row.superseded);
                kept.superseded.push(row);
                STANDING_POLICY.put(&vault.store, wtxn, &new, &kept)?;
                continue;
            }
        }
        STANDING_POLICY.put(&vault.store, wtxn, &new, &row)?;
    }
    Ok(())
}

/// Scrubs one standing-policy row: its scope's erased hex, and its answerer
/// pair when the erased holder answered it — the pair clears together while
/// `accepted_at` stays, so the act stands and the who is forgotten. Recurses
/// into `superseded`, whose rows carry their own scopes and pairs. Whether
/// anything changed.
fn scrub_policy_row(row: &mut StoredStandingPolicy, hex: &str) -> bool {
    let mut touched = false;
    if row.scope.contains(hex) {
        row.scope = row.scope.replace(hex, ERASED_CALL_IDENTITY);
        touched = true;
    }
    if row.accepted_by.as_deref() == Some(hex) {
        row.accepted_by = None;
        row.decision_ref = None;
        touched = true;
    }
    for superseded in &mut row.superseded {
        touched |= scrub_policy_row(superseded, hex);
    }
    touched
}
