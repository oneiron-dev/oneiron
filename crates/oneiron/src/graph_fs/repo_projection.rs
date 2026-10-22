//! The repo byte-recipient hint a graph-FS mount carries (FIX 7608 slice
//! 2b-ii-A, FIX 8964): whether its mounting handle reads repo bytes masked.
//! It shares the mount's admitted scoped read and changes nothing a mount
//! admits, pages or cursors; only which repo bytes a file read returns.

use super::GraphFsResolver;

impl GraphFsResolver<'_, '_> {
    /// This mount, reading repo bytes masked when `masked`: a hint the
    /// mounting handle carries, never a scoped-read key.
    #[must_use]
    pub(crate) fn with_repo_masked(mut self, masked: bool) -> Self {
        self.repo_masked = masked;
        self
    }

    /// Whether this mount reads repo bytes masked.
    pub(crate) const fn repo_masked(&self) -> bool {
        self.repo_masked
    }
}
