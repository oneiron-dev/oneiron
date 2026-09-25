//! Ordinary world-id and repository membership clamps on every frame-bound read.

use super::LensRenderFrame;
use crate::claim::ScopedRead;
use crate::pipeline::{WorldAuthoritySet, WorldScope};
use crate::{EntityId, Error, Result};

impl LensRenderFrame {
    /// Narrow this frame to ordinary world ids and an explicit base membership.
    /// Principal disclosure authority is still enforced by ScopedRead.
    pub fn with_world_set(mut self, worlds: WorldAuthoritySet) -> Self {
        self.world_scope = WorldScope::WorldSet(worlds);
        self
    }

    /// Narrow this frame to repository-indexed entities, not ordinary world ids.
    pub fn with_codebase_scope(mut self, key: crate::codebase::CodebaseScopeKey) -> Self {
        self.world_scope = WorldScope::CodebaseSet(key);
        self
    }

    pub fn world_scope(&self) -> &WorldScope {
        &self.world_scope
    }

    pub fn scoped_body(&self, read: &ScopedRead<'_>, id: &EntityId) -> Result<Option<Vec<u8>>> {
        self.ensure_scoped_read_actor(read)?;
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = read.get_entity_parts_with_receipt(id, None)?;
        let Some((kind, _, body)) = value else {
            return Ok(None);
        };
        // Check the exact body admitted by ScopedRead, not a second raw read
        // that could observe a changed world after disclosure was authorized.
        let world = if kind == crate::registry::ENTITY_TYPE_CLAIM {
            crate::claim::decode_claim_body(&body, true)?.world
        } else {
            None
        };
        let admitted = match &self.world_scope {
            WorldScope::All => true,
            WorldScope::CodebaseSet(key) => {
                let vault = read.vault();
                let txn = vault.store.env.read_txn()?;
                crate::codebase::codebase_candidate_matches_scope_key(&vault.store, &txn, id, key)?
            }
            WorldScope::ActiveSet => {
                return Err(Error::InvalidConfig(
                    "lens ActiveSet requires a resolved world-id set".into(),
                ));
            }
            WorldScope::WorldSet(worlds) => worlds.admits(world),
            WorldScope::Base => world.is_none(),
            WorldScope::World(selected) => world.is_none() || world == Some(*selected),
        };
        Ok(admitted.then_some(body))
    }
}
