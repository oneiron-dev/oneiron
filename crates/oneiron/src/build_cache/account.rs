//! Host-bound account cache: no process-global registry and no implicit cross-tenant lookup.
use super::*;

/// The tenant/account identity a build-cache vault is bound to. Key: ().
const ACCOUNT: SideTable<(), String, Raw> = SideTable::new(&side_table::BUILD_CACHE_ACCOUNT);

impl<'a> BuildCache<'a> {
    /// The public account-local door. The requested account is an expectation,
    /// never authority: it must be the live owner authenticated on this vault.
    pub fn bind_owner_account(
        vault: &'a Vault,
        owner: &'a crate::consent::AuthenticatedOwner,
        account: &str,
    ) -> BuildCacheResult<()> {
        let mut txn = vault.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(vault, &txn)?;
        if account != actor.to_hex() {
            return Err(BuildCacheError::AccountMismatch);
        }
        match ACCOUNT.get(&vault.store, &txn, &())? {
            Some(existing) if existing != account => return Err(BuildCacheError::AccountMismatch),
            Some(_) => (),
            None => ACCOUNT.put(&vault.store, &mut txn, &(), &account.to_owned())?,
        }
        txn.commit().map_err(Error::from)?;
        Ok(())
    }

    pub fn for_owner(
        vault: &'a Vault,
        owner: &'a crate::consent::AuthenticatedOwner,
        account: &str,
    ) -> BuildCacheResult<Self> {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let actor = owner.revalidate_in_txn(vault, &txn)?;
        if account != actor.to_hex()
            || ACCOUNT.get(&vault.store, &txn, &())?.as_deref() != Some(account)
        {
            return Err(BuildCacheError::AccountMismatch);
        }
        Ok(Self {
            vault,
            owner: Some(owner),
        })
    }

    pub(crate) fn admit_account_in_txn(&self, txn: &heed::RoTxn<'_>) -> BuildCacheResult<()> {
        if let Some(owner) = self.owner {
            let actor = owner.revalidate_in_txn(self.vault, txn)?;
            if ACCOUNT.get(&self.vault.store, txn, &())?.as_deref() != Some(actor.to_hex().as_str())
            {
                return Err(BuildCacheError::AccountMismatch);
            }
        }
        Ok(())
    }

    /// Bind a vault to its authenticated account. Hosts supply the account identity;
    /// a later call cannot move an existing vault to another tenant.
    pub fn bind_account(vault: &Vault, account: &str) -> BuildCacheResult<()> {
        if account.is_empty() || account.len() > 1024 {
            return Err(BuildCacheError::InvalidAction("invalid account"));
        }
        let mut txn = vault.store.env.write_txn()?;
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
