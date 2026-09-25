//! Deployment-tier participation is separate from permission to train.

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tier_matrix_never_infers_training_consent_from_export() {
        for deployment in [
            DeploymentTier::Managed,
            DeploymentTier::SelfHost,
            DeploymentTier::Oss,
        ] {
            let config = FailureSignalConfig {
                deployment,
                ..Default::default()
            };
            assert_eq!(config.exports(), deployment == DeploymentTier::Managed);
            assert!(!config.permits_training());
            let opted = FailureSignalConfig {
                export_opt_in: true,
                ..config
            };
            assert!(opted.exports());
            assert!(!opted.permits_training());
            assert!(
                FailureSignalConfig {
                    training_opt_in: true,
                    ..config
                }
                .permits_training()
            );
        }
    }
}
