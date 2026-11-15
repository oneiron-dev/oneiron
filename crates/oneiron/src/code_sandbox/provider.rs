//! Whose machines run a finite Foreign or Untrusted guest: ours, or a vendor
//! the owner names (L8-43; provider-adapter-architecture-v1 #default-switch-off,
//! "with our option as default you can switch off of").
//!
//! The vault's one switch ([`crate::settings::sandbox_provider`]) holds a
//! [`SandboxProvider`]; [`super::microvm::select_backend_for_tier`] reads it.
//! Core names the vendors and never their backends: a binary that carries a
//! vendor's backend answers it from `SandboxBackends::vendor`.
use serde::{Deserialize, Serialize};

/// A sandbox vendor an adapter may serve (provider-adapter-architecture-v1:49;
/// the owner's boat and InstaBox, 15 Nov 00:43).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SandboxVendor {
    /// Daytona (`app.daytona.io`).
    Daytona,
    /// E2B (`e2b.dev`).
    E2b,
    /// Modal (`modal.com`).
    Modal,
    /// boat (`boat.dev`): Ubuntu VMs over SSH.
    Boat,
    /// InstaBox (`instabox.sh`).
    Instabox,
}

impl SandboxVendor {
    /// Every vendor, in the ruled build order (L8-43-VENDORS = A).
    pub const ALL: [Self; 5] = [
        Self::Daytona,
        Self::E2b,
        Self::Modal,
        Self::Boat,
        Self::Instabox,
    ];

    /// The vendor's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daytona => "daytona",
            Self::E2b => "e2b",
            Self::Modal => "modal",
            Self::Boat => "boat",
            Self::Instabox => "instabox",
        }
    }

    /// The effector the owner's key for this vendor is bound to in custody,
    /// the twin of the web connector's `connector:web`.
    #[must_use]
    pub const fn effector(self) -> &'static str {
        match self {
            Self::Daytona => "sandbox:daytona",
            Self::E2b => "sandbox:e2b",
            Self::Modal => "sandbox:modal",
            Self::Boat => "sandbox:boat",
            Self::Instabox => "sandbox:instabox",
        }
    }

    /// The label a vendor backend's `MicroVmBackend::name` answers.
    #[must_use]
    pub const fn backend_name(self) -> &'static str {
        match self {
            Self::Daytona => "vendor:daytona",
            Self::E2b => "vendor:e2b",
            Self::Modal => "vendor:modal",
            Self::Boat => "vendor:boat",
            Self::Instabox => "vendor:instabox",
        }
    }
}

/// Whose machines run the vault's finite Foreign and Untrusted guests.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProvider {
    /// Oneiron's own backends: Firecracker on a KVM host, else the OCI fenced
    /// container. The default.
    #[default]
    Ours,
    /// The named vendor's sandbox. A vendor this host cannot serve refuses the
    /// run, typed: ours never runs in its place (L8-43-SWITCH = A).
    Vendor(SandboxVendor),
}
