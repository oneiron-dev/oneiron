//! Moved from `crates/oneiron/src/skill_hub/install_transition.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::write_envelope::skill_record::lifecycle::SkillLifecycle;

/// Lifecycle observed at the end of the install operation, not at source fetch.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InstallLifecycle {
    Candidate,
    Active,
    Stale,
    Quarantined,
    Superseded,
}

impl InstallLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
        }
    }
}

impl From<SkillLifecycle> for InstallLifecycle {
    fn from(value: SkillLifecycle) -> Self {
        match value {
            SkillLifecycle::Candidate => Self::Candidate,
            SkillLifecycle::Active => Self::Active,
            SkillLifecycle::Stale => Self::Stale,
            SkillLifecycle::Quarantined => Self::Quarantined,
            SkillLifecycle::Superseded => Self::Superseded,
        }
    }
}

/// The locally owned decision that prevented an installation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InstallHoldReason {
    SourceOnly,
    RulesHit,
    CodeAutoInstallOff,
    QualificationRequired,
    NoFit,
    LocalApproval,
    UnloadableApproval,
    Stale,
    Quarantined,
    Superseded,
    Advisories,
}

impl InstallHoldReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceOnly => "source_only",
            Self::RulesHit => "rules_hit",
            Self::CodeAutoInstallOff => "code_auto_install_off",
            Self::QualificationRequired => "qualification_required",
            Self::NoFit => "not_fit",
            Self::LocalApproval => "local_decision",
            Self::UnloadableApproval => "unloadable_approval",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
            Self::Advisories => "advisories",
        }
    }
}

/// A result may claim installed only when the committed record passes the loader's predicate.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InstallDisposition {
    Installed,
    AlreadyInstalled,
    PendingPermission,
    NotInstalled(InstallHoldReason),
}

impl InstallDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::AlreadyInstalled => "already_installed",
            Self::PendingPermission => "ask_permissions",
            Self::NotInstalled(reason) => reason.as_str(),
        }
    }

    pub const fn is_pending(self) -> bool {
        matches!(self, Self::PendingPermission)
    }
}
