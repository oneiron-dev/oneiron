//! Deployment-tier participation is separate from permission to train.

use serde::{Deserialize, Serialize};

mod samples;
pub(crate) use samples::purge_tier2_for_source_in_txn;
pub use samples::{
    RedactionKind, RedactionSpan, Tier2Redactor, Tier2Sample, capture_tier2_samples,
    read_tier2_samples,
};

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
    /// An OSS/self-host participation choice. Managed terms mandate export,
    /// so this cannot disable export in the managed tier.
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
