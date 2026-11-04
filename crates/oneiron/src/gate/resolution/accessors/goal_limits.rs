//! The resolved goal-limit bundle; split from its parent accessors.

use super::PolicyManifestResolution;

impl PolicyManifestResolution {
    #[must_use]
    pub(crate) fn goal_limits(&self) -> crate::policy_model::goal_limits::GoalLimits {
        self.goal_limits.clone().unwrap_or_default()
    }
}
