//! WorldSet conjunction on every frame-bound read and mediated target.

use super::LensRenderFrame;
use crate::claim::ScopedRead;
use crate::pipeline::WorldScope;
use crate::{EntityId, Result};

impl LensRenderFrame {
    /// Bind lens execution to the same WorldSet key as the turn's retrieval.
    /// It only narrows the principal's existing ScopedRead authority.
    pub fn with_world_set(mut self, key: crate::codebase::CodebaseScopeKey) -> Self {
        self.world_scope = WorldScope::WorldSet(key);
        self
    }

    pub fn world_scope(&self) -> WorldScope {
        self.world_scope
    }

    pub fn scoped_body(&self, read: &ScopedRead<'_>, id: &EntityId) -> Result<Option<Vec<u8>>> {
        self.ensure_scoped_read_actor(read)?;
        if let WorldScope::WorldSet(key) = self.world_scope {
            let vault = read.vault();
            let txn = vault.store.env.read_txn()?;
            if !crate::codebase::codebase_candidate_matches_scope_key(&vault.store, &txn, id, &key)?
            {
                return Ok(None);
            }
        }
        read.get(id)
    }
}
