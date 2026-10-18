//! Shared-act policy reads (DOOR-129). ARCH-0043: "Which acts wait, and for
//! how long, is data in the shared-vault preset."
//!
//! A live Owner reads every row: the rows the vault kind ships, the vault's
//! own rows, and the row each act resolves to, with the digest of both
//! sources.
use std::collections::BTreeMap;

use super::{ActPolicies, SharedActPolicy, check_vault, invalid};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;

/// The domain of the digest a change binds.
const POLICY_HASH_DOMAIN: &[u8] = b"oneiron/shared-act/policy-hash/v1";

/// Every shared-act policy row of one shared vault, as a live Owner reads it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActPoliciesView {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The rows the vault kind ships, `_default` included.
    pub shipped: BTreeMap<String, SharedActPolicy>,
    /// The vault's own rows, which the Owners changed together.
    pub overrides: BTreeMap<String, SharedActPolicy>,
    /// The row each named act resolves to: its own row, its shipped row,
    /// then the `_default` row. An act named nowhere takes `_default`.
    pub effective: BTreeMap<String, SharedActPolicy>,
    /// The digest of both sources, which a proposed change binds.
    pub policy_hash: String,
}

impl ActPolicies {
    /// Every row name either source carries, resolved as an act resolves it.
    fn effective_rows(&self) -> Result<BTreeMap<String, SharedActPolicy>> {
        self.shipped
            .keys()
            .chain(self.stored.keys())
            .map(|act| Ok((act.clone(), self.effective(act)?)))
            .collect()
    }

    /// The digest of both sources: any change of either moves it.
    fn digest(&self) -> Result<String> {
        let rows = serde_json::to_vec(&(&self.shipped, &self.stored)).map_err(|_| invalid())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(POLICY_HASH_DOMAIN);
        hasher.update(&rows);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

impl Vault {
    /// `vault_id`'s shared-act policy rows, for a live Owner of the vault.
    pub fn shared_act_policies(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<SharedActPoliciesView> {
        let txn = self.store.env.read_txn()?;
        // Owner tier: the rows are the Owners' authority data.
        owner.revalidate_in_txn(self, &txn)?;
        let creation = check_vault(self, &txn, vault_id)?;
        let policies = self.act_policies_in_txn(&txn, &creation)?;
        let effective = policies.effective_rows()?;
        let policy_hash = policies.digest()?;
        Ok(SharedActPoliciesView {
            vault_id,
            shipped: policies.shipped,
            overrides: policies.stored,
            effective,
            policy_hash,
        })
    }
}
