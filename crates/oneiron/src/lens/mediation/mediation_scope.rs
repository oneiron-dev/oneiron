//! Ordinary world-id and repository membership clamps on every frame-bound read.

use super::LensRenderFrame;
use crate::claim::world_access::WorldAuthoritySet;
use crate::claim::{PointRead, ReadRow, ScopedRead, ScopedReadResult};
use crate::pipeline::WorldScope;
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

    /// The body the acting principal may read inside this frame's world
    /// scope. A readable row outside the frame's worlds is counted on the
    /// receipt as withheld, the same as a row the principal cannot read.
    ///
    /// ScopedRead admits the row first; the world or repository filter then
    /// reads in the same snapshot ScopedRead served the body from (FIX 4300).
    /// A codebase scope is a filter, never a Grant.
    pub fn scoped_body(
        &self,
        read: &ScopedRead<'_>,
        id: &EntityId,
    ) -> Result<ScopedReadResult<Option<Vec<u8>>>> {
        self.ensure_scoped_read_actor(read)?;
        let ScopedReadResult {
            value: (body, filtered),
            mut receipt,
        } = read.read_projected(&[PointRead::id(*id)], None, |txn, rows| {
            self.frame_filtered_body(read, txn, id, rows.into_iter().next().flatten())
        })?;
        if filtered {
            receipt.add_suppressed(1);
        }
        Ok(ScopedReadResult {
            value: body,
            receipt,
        })
    }

    /// The admitted `row`'s body when this frame's world scope admits it,
    /// judged in `txn`, the snapshot ScopedRead admitted it in, and whether
    /// the scope filtered a readable body out.
    fn frame_filtered_body(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: Option<ReadRow>,
    ) -> Result<(Option<Vec<u8>>, bool)> {
        let Some(ReadRow {
            entity_type: kind,
            body: Some(body),
            ..
        }) = row
        else {
            return Ok((None, false));
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
            WorldScope::CodebaseSet(key) => crate::codebase::codebase_candidate_matches_scope_key(
                &read.vault().store,
                txn,
                id,
                key,
            )?,
            WorldScope::ActiveSet => {
                return Err(Error::InvalidConfig(
                    "lens ActiveSet requires a resolved world-id set".into(),
                ));
            }
            WorldScope::WorldSet(worlds) => worlds.admits(world),
            WorldScope::Base => world.is_none(),
            WorldScope::World(selected) => world.is_none() || world == Some(*selected),
        };
        Ok((admitted.then_some(body), !admitted))
    }
}
