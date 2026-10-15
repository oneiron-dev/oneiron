//! Deployment-tier participation is separate from permission to train.
//!
//! What a deployment exports is the content-free tier-1 aggregate
//! ([`Vault::export_tier1_failure_counts`](crate::Vault::export_tier1_failure_counts)):
//! closed dimensions and counts. Nothing samples transcript text for export.
//! Telemetry never carries world text (owner ruling 2026-10-14), and redacting
//! a sample does not make it safe to send, so there is no text tier to opt into.

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
    /// An OSS/self-host participation choice. Managed terms mandate export of
    /// the tier-1 counts, so this cannot disable export in the managed tier.
    pub export_opt_in: bool,
    /// Explicit, independent permission. Export never grants training rights.
    pub training_opt_in: bool,
}
impl FailureSignalConfig {
    pub fn exports(self) -> bool {
        self.deployment == DeploymentTier::Managed || self.export_opt_in
    }
    pub fn permits_training(self) -> bool {
        self.training_opt_in
    }
}
