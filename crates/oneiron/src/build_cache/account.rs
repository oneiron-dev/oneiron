//! Host-bound account cache: no process-global registry and no implicit cross-tenant lookup.
use super::*;

/// The tenant/account identity a build-cache vault is bound to. Key: ().
const ACCOUNT: SideTable<(), String, Raw> = SideTable::new(&side_table::BUILD_CACHE_ACCOUNT);

impl<'a> BuildCache<'a> {
    /// Bind a vault to its authenticated account. Hosts supply the account identity;
    /// a later call cannot move an existing vault to another tenant.
    pub fn bind_account(vault: &Vault, account: &str) -> BuildCacheResult<()> {
        if account.is_empty() || account.len() > 1024 {
            return Err(BuildCacheError::InvalidAction("invalid account"));
        }
        let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
        match ACCOUNT.get(&vault.store, &txn, &())? {
            Some(existing) if existing != account => {
                return Err(BuildCacheError::AccountMismatch);
            }
            Some(_) => (),
            None => ACCOUNT.put(&vault.store, &mut txn, &(), &account.to_owned())?,
        }
        txn.commit().map_err(Error::from)?;
        Ok(())
    }
    /// The account vault owns BOTH the index and artifact bytes. Member vaults
    /// never reinterpret account artifact IDs in their own entity namespace.
    pub fn for_account(
        member: &Vault,
        account_vault: &'a Vault,
        account: &str,
    ) -> BuildCacheResult<Self> {
        for vault in [member, account_vault] {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            if ACCOUNT.get(&vault.store, &txn, &())?.as_deref() != Some(account) {
                return Err(BuildCacheError::AccountMismatch);
            }
        }
        Ok(Self::new(account_vault))
    }
    pub fn artifact_vault(&self) -> &'a Vault {
        self.vault
    }
}
