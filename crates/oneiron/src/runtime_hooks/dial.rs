//! The vault's hook switch, `hooks.enabled` (ARCH-0080 §10). On by default.

use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::{Result, Vault};

/// The switch row. Absent means on.
const ENABLED: SideTable<(), bool, Named> = SideTable::new(&side_table::HOOKS_ENABLED);

impl Vault {
    /// The owner turns every hook on or off. The runner checks it per pass;
    /// while off, cursors stay where they are.
    pub fn set_hooks_enabled(&self, owner: &AuthenticatedOwner, enabled: bool) -> Result<()> {
        self.with_write_txn_grouped_after_commit(
            |txn| {
                owner.revalidate_in_txn(self, txn)?;
                let reenabled = enabled && !ENABLED.get(&self.store, txn, &())?.unwrap_or(true);
                ENABLED.put(&self.store, txn, &(), &enabled)?;
                Ok(reenabled)
            },
            |reenabled| {
                self.verb_hook_bindings_changed();
                if reenabled {
                    self.notify_verb_hook_ask_changes();
                }
                Ok(())
            },
        )
    }

    /// Whether hooks run on this vault.
    pub fn hooks_enabled(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        self.hooks_enabled_in_txn(&rtxn)
    }

    /// [`Self::hooks_enabled`], in the caller's snapshot.
    pub(super) fn hooks_enabled_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        Ok(ENABLED.get(&self.store, txn, &())?.unwrap_or(true))
    }
}
