//! How a managed vault came up (contract v3): the readiness every `Ping`
//! reports, and the facilities it names missing.

use serde::{Deserialize, Serialize};

/// How a managed vault came up (contract v3), on every `Ping`: a boot
/// snapshot, taken before the vault signalled ready, that does not change
/// while the process runs. Either way the vault serves: reads and sync go
/// on, and only a missing facility's own acts refuse, as they would anyway.
/// A supervisor shows it; a degraded vault is no failed start and no call to
/// restart it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ManagedReadiness {
    /// Every facility the vault was given came up.
    Ready,
    /// The vault serves without each facility `missing` names.
    Degraded { missing: Vec<FacilityNotice> },
}

impl ManagedReadiness {
    /// `Ready` when nothing is missing, else `Degraded` naming each.
    #[must_use]
    pub fn from_missing(missing: Vec<FacilityNotice>) -> Self {
        if missing.is_empty() {
            Self::Ready
        } else {
            Self::Degraded { missing }
        }
    }

    /// This readiness with `notice` named missing too.
    #[must_use]
    pub fn and_missing(self, notice: FacilityNotice) -> Self {
        let mut missing = match self {
            Self::Ready => Vec::new(),
            Self::Degraded { missing } => missing,
        };
        missing.push(notice);
        Self::Degraded { missing }
    }
}

/// One facility a managed vault serves without, and why, in closed names:
/// never a path or an error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacilityNotice {
    pub facility: ManagedFacility,
    pub reason: FacilityReason,
}

/// A facility a managed vault's readiness names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedFacility {
    /// The key directory the supervisor binds (`--keystore-dir`).
    KeystoreDirectory,
    /// This install's this-device-only keystore, in that directory.
    DeviceKeystore,
    /// This install's signing keys, loaded from that keystore.
    InstallSigningKeys,
    /// The host's own node in the vault's roster, written with those keys.
    HostNodeProfile,
    /// The backup handoff policy that lets retention prune a backup once
    /// the node supervisor's stage ack names it (FIX 6705). Without it,
    /// pruning past `keep` is held and every backup is kept; backups are
    /// still taken.
    BackupHandoff,
}

impl ManagedFacility {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeystoreDirectory => "keystore_directory",
            Self::DeviceKeystore => "device_keystore",
            Self::InstallSigningKeys => "install_signing_keys",
            Self::HostNodeProfile => "host_node_profile",
            Self::BackupHandoff => "backup_handoff",
        }
    }
}

/// Why a managed vault serves without a facility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacilityReason {
    /// The supervisor passed no binding for it, and the owner did not turn
    /// it off.
    MissingBinding,
    /// It would not open.
    OpenFailed,
    /// It opened, and what it holds did not load.
    PrepareFailed,
    /// Writing the profile failed.
    ProfileFailed,
    /// It could not be installed.
    InstallFailed,
}

impl FacilityReason {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingBinding => "missing_binding",
            Self::OpenFailed => "open_failed",
            Self::PrepareFailed => "prepare_failed",
            Self::ProfileFailed => "profile_failed",
            Self::InstallFailed => "install_failed",
        }
    }
}
