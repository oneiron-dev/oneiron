//! The setting keys `workspace_roster::project` declares (Setting stage 1): the crate's build
//! script lists each row in the setting catalogue.

use super::ProjectHistoryPolicy;
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// The per-project history budget (decision 9, ruling F2 (a)): how many revisions a
    /// project folds fresh before it serves its persisted frontier, and how many worlds one
    /// member of a parent cycle has before the solver raises its scan check. 10,000 revisions
    /// and 64 worlds unless the owner sets it; each budget admits at least one. The next read
    /// folds against a changed budget, and the next write to a project clears its freeze.
    pub(crate) HISTORY_POLICY: ProjectHistoryPolicy = "projects.history_policy" {
        kind: Kind::new(ProjectHistoryPolicy::default),
    };
}
