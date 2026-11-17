//! The owner's sandbox provider switch (L8-43; provider-adapter-architecture-v1
//! #default-switch-off, "with our option as default you can switch off of"):
//! whose machines run the vault's finite Foreign and Untrusted guests. One row
//! holds it, and an absent row reads as ours.
//!
//! The owner alone changes it (`vault.settings.sandbox_provider.replace`),
//! under the owner's proof, as the web connector's switch is changed. Every
//! finite-run selection reads it ([`Vault::sandbox_provider`]). A vendor this
//! host cannot serve refuses the run, typed, and ours never runs in its place
//! (L8-43-SWITCH = A). Browser, native and artifact sessions stay on ours
//! until a vendor serves sessions; the answer says so in `sessions`.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::code_sandbox::SandboxProvider;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::memory::{Memory, MemoryResult};
use crate::side_table::{self, Named, SideTable};

/// The owner's switch. Key: ().
const SETTING: SideTable<(), SandboxProviderSetting, Named> =
    SideTable::new(&side_table::SANDBOX_PROVIDER_SETTING);

/// The read verb's name.
pub const READ_VERB: &str = "vault.settings.sandbox_provider";
/// The replace verb's name.
pub const REPLACE_VERB: &str = "vault.settings.sandbox_provider.replace";

/// The owner's switch: the stored row, and the replace verb's input.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SandboxProviderSetting {
    /// Whose machines run the vault's finite Foreign and Untrusted guests.
    pub provider: SandboxProvider,
}

/// What both verbs answer: the switch in force, and whose machines run the
/// vault's sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SandboxProviderAnswer {
    /// Whose machines run the vault's finite Foreign and Untrusted guests.
    pub provider: SandboxProvider,
    /// Whose machines run browser, native and artifact sessions: ours in
    /// this build, whatever the switch.
    pub sessions: SandboxProvider,
}

impl From<SandboxProviderSetting> for SandboxProviderAnswer {
    fn from(setting: SandboxProviderSetting) -> Self {
        Self {
            provider: setting.provider,
            sessions: SandboxProvider::Ours,
        }
    }
}

impl Vault {
    /// The provider the vault's finite Foreign and Untrusted runs take: the
    /// owner's switch, or ours when the owner set none.
    pub fn sandbox_provider(&self) -> Result<SandboxProvider> {
        let txn = self.store.env.read_txn()?;
        Ok(SETTING
            .get(&self.store, &txn, &())?
            .unwrap_or_default()
            .provider)
    }

    /// The switch, read under the owner proof.
    pub fn sandbox_provider_setting_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<SandboxProviderAnswer> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        Ok(SETTING
            .get(&self.store, &txn, &())?
            .unwrap_or_default()
            .into())
    }

    /// Replaces the switch under the owner proof. The answer is the switch
    /// this transaction stored.
    pub fn replace_sandbox_provider_setting_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        setting: SandboxProviderSetting,
    ) -> Result<SandboxProviderAnswer> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        SETTING.put(&self.store, &mut txn, &(), &setting)?;
        txn.commit()?;
        Ok(setting.into())
    }
}

/// `vault.settings.sandbox_provider` for the embedded owner.
pub fn read_sandbox_provider_setting_embedded(
    memory: &Memory<'_>,
) -> MemoryResult<SandboxProviderAnswer> {
    Ok(memory
        .vault()
        .sandbox_provider_setting_as_owner(&memory.embedded_owner(READ_VERB)?)?)
}

/// `vault.settings.sandbox_provider.replace` for the embedded owner.
pub fn replace_sandbox_provider_setting_embedded(
    memory: &Memory<'_>,
    input: SandboxProviderSetting,
) -> MemoryResult<SandboxProviderAnswer> {
    Ok(memory
        .vault()
        .replace_sandbox_provider_setting_as_owner(&memory.embedded_owner(REPLACE_VERB)?, input)?)
}
