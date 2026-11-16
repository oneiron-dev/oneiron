//! The runtime hooks' catalogue keys (DESIGN 15-setting-primitive): the owner's cap on
//! the body budget a hook selector may name. Default = today: nothing changes until the owner
//! sets the key.

use super::body::{DEFAULT_HOOK_MAX_BUDGET_MS, HookMaxBudgetMs};
use crate::setting::{Kind, lower_is_tighter};
use crate::{Result, Vault};

fn default_hook_max_budget_ms() -> HookMaxBudgetMs {
    HookMaxBudgetMs(DEFAULT_HOOK_MAX_BUDGET_MS)
}

crate::setting::setting_keys! {
    /// The longest body budget, in milliseconds, a hook selector may name; an accounting
    /// deadline, never a stop; at least 1; a higher value is a loosening.
    pub(crate) HOOK_MAX_BUDGET_MS: HookMaxBudgetMs = "runtime_hooks.hook.max_budget_ms" {
        kind: Kind::new(default_hook_max_budget_ms).tighter(lower_is_tighter::<HookMaxBudgetMs>),
    };
}

/// The cap in force for `vault` in the caller's snapshot: the owner's row, or the default
/// when none stands.
///
/// # Errors
///
/// An unreadable deciding row on a key that names no strictest value; storage errors.
pub(crate) fn hook_max_budget_ms_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<u32> {
    Ok(HOOK_MAX_BUDGET_MS
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0)
}

/// [`hook_max_budget_ms_in_txn`], in a read of its own, for a caller that holds no
/// transaction. A caller that holds one uses [`hook_max_budget_ms_in_txn`] with it instead:
/// a second read never opens beside a held one.
///
/// # Errors
///
/// As [`hook_max_budget_ms_in_txn`].
pub(crate) fn hook_max_budget_ms(vault: &Vault) -> Result<u32> {
    let txn = vault.store.env.read_txn()?;
    hook_max_budget_ms_in_txn(vault, &txn)
}
