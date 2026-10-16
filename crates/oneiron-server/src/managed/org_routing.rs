//! Read-only organization-to-vault routing over a host's registry projection.
//! Provisioning, account authentication and fleet placement belong to the host.
//! Resolving a route is not a membership grant: policy stays in the selected
//! vault. Guests use federation into their own vault, not this routing door.

use super::{ManagedArgs, ManagedError, open_managed_vault};
use oneiron::federation::derivation::DerivationOwner;
use oneiron_vault_contract::{
    Credentials,
    host::Host,
    tenancy::{VaultBinding, VaultHost, VaultTenancy},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum OrgRoutingError {
    #[error("invalid organization vault route: {0}")]
    InvalidRoute(String),
    #[error("duplicate vault route {vault:?}")]
    DuplicateVault { vault: String },
    #[error("vault routes {first:?} and {second:?} share a {resource}")]
    AliasedVaults {
        first: String,
        second: String,
        resource: &'static str,
    },
    #[error("no route for vault {vault:?} in this organization")]
    NotFound { vault: String },
}

/// A local route contains no key, user data, hostname policy or query surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgVaultRoute {
    binding: VaultBinding,
    http_socket: PathBuf,
    ctl_socket: PathBuf,
}

impl OrgVaultRoute {
    pub fn new(
        binding: VaultBinding,
        http_socket: PathBuf,
        ctl_socket: PathBuf,
    ) -> Result<Self, OrgRoutingError> {
        let route = Self {
            binding,
            http_socket,
            ctl_socket,
        };
        route.validate()?;
        Ok(route)
    }

    fn validate(&self) -> Result<(), OrgRoutingError> {
        self.binding
            .validate()
            .map_err(|error| OrgRoutingError::InvalidRoute(error.to_string()))?;
        if self.binding.tenancy().organization().is_none() {
            return Err(OrgRoutingError::InvalidRoute(
                "an organization route needs an organization".into(),
            ));
        }
        for path in [&self.http_socket, &self.ctl_socket] {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            {
                return Err(OrgRoutingError::InvalidRoute(
                    "socket paths must be absolute without dot components".into(),
                ));
            }
        }
        if self.http_socket == self.ctl_socket {
            return Err(OrgRoutingError::InvalidRoute(
                "HTTP and control sockets must be distinct".into(),
            ));
        }
        Ok(())
    }

    pub fn binding(&self) -> &VaultBinding {
        &self.binding
    }

    pub fn http_socket(&self) -> &Path {
        &self.http_socket
    }

    pub fn ctl_socket(&self) -> &Path {
        &self.ctl_socket
    }

    /// Reject a spawn for a different vault before it consumes any descriptor.
    pub fn check_managed_args(&self, args: &ManagedArgs) -> Result<(), ManagedError> {
        self.validate()
            .map_err(|error| ManagedError::VaultRoutingRejected {
                reason: error.to_string(),
            })?;
        if args.vault_binding()? != self.binding
            || args.http_socket != self.http_socket
            || args.ctl_socket != self.ctl_socket
        {
            return Err(ManagedError::VaultRoutingRejected {
                reason: "spawn does not match the selected vault route".into(),
            });
        }
        Ok(())
    }

    pub fn bind_host<H: Host>(&self, adapter: H) -> Result<VaultHost<H>, OrgRoutingError> {
        self.validate()?;
        VaultHost::new(self.binding.clone(), adapter)
            .map_err(|error| OrgRoutingError::InvalidRoute(error.to_string()))
    }

    /// Open only the selected vault, using the existing isolation and DEK gates.
    pub fn open(
        &self,
        config: oneiron::VaultConfig,
        credentials: &Credentials,
    ) -> Result<oneiron::Vault, ManagedError> {
        self.validate()
            .map_err(|error| ManagedError::VaultRoutingRejected {
                reason: error.to_string(),
            })?;
        open_managed_vault(
            self.binding.data_dir(),
            config,
            self.binding.vault_name(),
            credentials,
            DerivationOwner(self.binding.owner()),
        )
    }
}

/// Replace this projection as a whole when the private registry changes.
/// A lookup always selects one vault; it never merges reads across vaults.
#[derive(Default)]
pub struct OrgVaultRouter {
    routes: BTreeMap<String, OrgVaultRoute>,
}

impl OrgVaultRouter {
    pub fn new(routes: impl IntoIterator<Item = OrgVaultRoute>) -> Result<Self, OrgRoutingError> {
        let mut router = Self::default();
        for route in routes {
            route.validate()?;
            let name = route.binding.vault_name();
            if router.routes.contains_key(name) {
                return Err(OrgRoutingError::DuplicateVault {
                    vault: name.to_owned(),
                });
            }
            for existing in router.routes.values() {
                let data = route.binding.data_dir();
                let other = existing.binding.data_dir();
                let resource = if data.starts_with(other) || other.starts_with(data) {
                    Some("data directory")
                } else if [&route.http_socket, &route.ctl_socket]
                    .iter()
                    .any(|socket| {
                        *socket == &existing.http_socket || *socket == &existing.ctl_socket
                    })
                {
                    Some("socket")
                } else {
                    None
                };
                if let Some(resource) = resource {
                    return Err(OrgRoutingError::AliasedVaults {
                        first: existing.binding.vault_name().to_owned(),
                        second: name.to_owned(),
                        resource,
                    });
                }
            }
            router.routes.insert(name.to_owned(), route);
        }
        Ok(router)
    }

    /// `organization` is supplied by the authenticated host, never an HTTP
    /// header forwarded unchecked. The vault still checks member authority.
    pub fn resolve(
        &self,
        organization: [u8; 32],
        vault_name: &str,
    ) -> Result<&OrgVaultRoute, OrgRoutingError> {
        self.routes
            .get(vault_name)
            .filter(|route| route.binding.tenancy().organization() == Some(organization))
            .ok_or_else(|| OrgRoutingError::NotFound {
                vault: vault_name.to_owned(),
            })
    }

    /// Registry metadata only, not a cross-vault query or a membership list.
    pub fn vaults(&self, organization: [u8; 32]) -> impl Iterator<Item = &OrgVaultRoute> {
        self.routes
            .values()
            .filter(move |route| route.binding.tenancy().organization() == Some(organization))
    }
}

impl ManagedArgs {
    pub fn vault_binding(&self) -> Result<VaultBinding, ManagedError> {
        let tenancy = match (self.organization_owner, self.member_vault) {
            (None, false) => VaultTenancy::Account {
                owner: self.derivation_owner.0,
            },
            (None, true) => {
                return Err(ManagedError::MissingFlag {
                    flag: "organization-owner",
                });
            }
            (Some(organization), true) => VaultTenancy::OrganizationMember {
                organization: organization.0,
                member: self.derivation_owner.0,
            },
            (Some(organization), false) => {
                if organization != self.derivation_owner {
                    return Err(ManagedError::VaultRoutingRejected {
                        reason: "a shared vault must be sealed to its organization owner".into(),
                    });
                }
                VaultTenancy::OrganizationShared {
                    organization: organization.0,
                }
            }
        };
        VaultBinding::new(self.vault_name.clone(), self.data_dir.clone(), tenancy).map_err(
            |error| ManagedError::VaultRoutingRejected {
                reason: error.to_string(),
            },
        )
    }
}
