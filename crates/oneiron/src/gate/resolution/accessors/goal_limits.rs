//! The resolved goal-limit bundle; split from its parent accessors.

use super::PolicyManifestResolution;

impl PolicyManifestResolution {
    #[must_use]
    pub(crate) fn goal_limits(&self) -> crate::workspace_roster::GoalLimits {
        self.goal_limits.unwrap_or_default()
    }
}
