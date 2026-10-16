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
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            ENABLED.put(&self.store, txn, &(), &enabled)
        })?;
        self.verb_hook_bindings_changed();
        Ok(())
    }

    /// Whether hooks run on this vault.
    pub fn hooks_enabled(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(ENABLED.get(&self.store, &rtxn, &())?.unwrap_or(true))
    }
}
