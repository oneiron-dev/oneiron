//! Deployment-tier participation is separate from permission to train.
//!
//! What a deployment exports is the content-free tier-1 aggregate
//! ([`Vault::export_tier1_failure_counts`](crate::Vault::export_tier1_failure_counts)):
//! closed dimensions and counts. Nothing samples transcript text for export.
//! Telemetry never carries world text (owner ruling 2026-10-14), and redacting
//! a sample does not make it safe to send, so there is no text tier to opt into.
//!
//! The same switch gates the two code-fix exports (FIX6, owner ruling
//! 2026-10-16): the Coach's invented examples and candidate fixes' fixed or
//! not-fixed results ([`Vault::pending_code_fix_records`](crate::Vault::pending_code_fix_records)).
//! Neither carries real chat text, and a failure that touched a private world
//! sends counts only.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTier {
    Managed,
    SelfHost,
    #[default]
    Oss,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FailureSignalConfig {
    pub deployment: DeploymentTier,
    /// The owner's "Help improve Oneiron" choice, for the tier-1 counts and
    /// both code-fix exports, in every tier: `Some` is an explicit yes or
    /// no and stands as given; `None` takes [`default_exports`].
    pub export_opt_in: Option<bool>,
    /// Explicit, independent permission. Export never grants training rights.
    pub training_opt_in: bool,
}

/// Whether a deployment exports when its owner has not chosen (owner ruling
/// 2026-10-19, FIX 4488): on for a vault our cloud hosts, which its owner can
/// turn off; off on self-host and OSS until the owner turns it on.
pub const fn default_exports(deployment: DeploymentTier) -> bool {
    match deployment {
        DeploymentTier::Managed => true,
        DeploymentTier::SelfHost | DeploymentTier::Oss => false,
    }
}

impl FailureSignalConfig {
    pub fn exports(self) -> bool {
        self.export_opt_in
            .unwrap_or(default_exports(self.deployment))
    }
    pub fn permits_training(self) -> bool {
        self.training_opt_in
    }
}
