//! Single-vault identity and lifecycle for account and organization hosts.

use crate::host::{Host, HostFuture, HostLimits};
use serde::{Deserialize, Serialize};
use std::{
    path::{Component, Path, PathBuf},
    time::SystemTime,
};
use zeroize::Zeroizing;

/// These are hosting account ids, not actor references inside a vault.
/// A member's personal vault keeps its owner when it leaves an organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultTenancy {
    Account {
        owner: [u8; 32],
    },
    OrganizationMember {
        organization: [u8; 32],
        member: [u8; 32],
    },
    OrganizationShared {
        organization: [u8; 32],
    },
}

impl VaultTenancy {
    pub fn owner(self) -> [u8; 32] {
        match self {
            Self::Account { owner } => owner,
            Self::OrganizationMember { member, .. } => member,
            Self::OrganizationShared { organization } => organization,
        }
    }

    pub fn organization(self) -> Option<[u8; 32]> {
        match self {
            Self::Account { .. } => None,
            Self::OrganizationMember { organization, .. }
            | Self::OrganizationShared { organization } => Some(organization),
        }
    }
}

/// Trusted host metadata for exactly one vault. It carries neither membership
/// grants nor keys. The directory and owner stay fixed through a restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBinding {
    vault_name: String,
    data_dir: PathBuf,
    tenancy: VaultTenancy,
}

impl VaultBinding {
    pub fn new(
        vault_name: String,
        data_dir: PathBuf,
        tenancy: VaultTenancy,
    ) -> anyhow::Result<Self> {
        let binding = Self {
            vault_name,
            data_dir,
            tenancy,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validate again after decoding a host-supplied registry projection.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            crate::valid_vault_name(&self.vault_name),
            "invalid vault name"
        );
        anyhow::ensure!(
            self.data_dir.is_absolute()
                && !self
                    .data_dir
                    .components()
                    .any(|part| matches!(part, Component::CurDir | Component::ParentDir)),
            "vault directory must be an absolute path without dot components"
        );
        Ok(())
    }

    pub fn vault_name(&self) -> &str {
        &self.vault_name
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn tenancy(&self) -> VaultTenancy {
        self.tenancy
    }

    pub fn owner(&self) -> [u8; 32] {
        self.tenancy.owner()
    }
}

/// One adapter instance per vault, never an engine over several vaults.
/// The boot callback receives the same binding on both start and restart.
pub struct VaultHost<H> {
    binding: VaultBinding,
    adapter: H,
}

impl<H: Host> VaultHost<H> {
    pub fn new(binding: VaultBinding, adapter: H) -> anyhow::Result<Self> {
        binding.validate()?;
        Ok(Self { binding, adapter })
    }

    pub fn binding(&self) -> &VaultBinding {
        &self.binding
    }

    pub fn adapter(&self) -> &H {
        &self.adapter
    }

    pub fn adapter_mut(&mut self) -> &mut H {
        &mut self.adapter
    }

    pub fn start_vault(
        &mut self,
        boot: impl FnOnce(&VaultBinding, H::Listener) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let binding = &self.binding;
        self.adapter.start(|listener| boot(binding, listener))
    }

    pub fn stop_vault(&mut self) -> anyhow::Result<()> {
        self.adapter.stop()
    }

    /// A managed adapter consumes its start descriptors. Restart therefore
    /// obtains a fresh adapter, but never a different vault binding.
    pub fn restart_vault(
        &mut self,
        adapter: impl FnOnce(&VaultBinding) -> anyhow::Result<H>,
        boot: impl FnOnce(&VaultBinding, H::Listener) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.stop_vault()?;
        self.adapter = adapter(&self.binding)?;
        self.start_vault(boot)
    }

    pub fn idle_vault(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        self.adapter.idle(next_wake)
    }
}

impl<H: Host> Host for VaultHost<H> {
    type Listener = H::Listener;

    fn listener(&mut self) -> anyhow::Result<Self::Listener> {
        self.adapter.listener()
    }

    fn ready(&mut self) -> anyhow::Result<()> {
        self.adapter.ready()
    }

    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.adapter.secret(name)
    }

    fn on_stop(&mut self) -> anyhow::Result<()> {
        self.adapter.on_stop()
    }

    fn limits(&self) -> HostLimits {
        self.adapter.limits()
    }

    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        self.idle_vault(next_wake)
    }
}
