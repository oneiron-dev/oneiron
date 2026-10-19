//! The owner's "Help improve Oneiron" switch (`export_opt_in`, with
//! [`default_exports`] when he has not chosen) decides whether a vault
//! exports, and is separate from permission to train.
//!
//! What a vault exports is the content-free tier-1 aggregate
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
//!
//! Training on what the switch sends is its own yes or no, and when the owner
//! has not chosen it takes the switch's default (owner ruling 2026-10-19, FIX
//! 5188). Real conversations stay under each person's own choice (FIX 4489).

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
    /// The owner's training choice on what the switch sends, in every tier:
    /// `Some` is an explicit yes or no and stands as given, whatever the
    /// switch says; `None` takes [`default_exports`], on for a vault our
    /// cloud hosts and off on self-host and OSS.
    pub training_opt_in: Option<bool>,
}

/// Whether a deployment exports, and permits training on what it sends,
/// when its owner has not chosen (owner rulings 2026-10-19, FIX 4488 and
/// FIX 5188): on for a vault our cloud hosts, which its owner can turn off;
/// off on self-host and OSS until the owner turns it on.
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
            .unwrap_or(default_exports(self.deployment))
    }
}
