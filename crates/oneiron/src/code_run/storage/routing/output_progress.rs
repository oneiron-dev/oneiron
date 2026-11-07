//! Pre-publication descriptors for canonical runtime files.

use super::ExecutorStorage;
use crate::{EntityId, Result};

impl ExecutorStorage<'_> {
    /// The canonical retained-result status can see this unfinished occurrence.
    /// Session streams keep their existing session-owned body lifecycle.
    pub(crate) fn begin_code_run_output(&self, owner: EntityId, path: &str) -> Result<()> {
        match self {
            Self::Canonical(vault) => vault.begin_code_run_output(owner, path),
            Self::Session(_) => Ok(()),
        }
    }
}
