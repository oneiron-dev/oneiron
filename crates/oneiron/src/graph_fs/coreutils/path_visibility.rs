//! Whether a coreutil's walk may name a path (moved from `coreutils.rs`
//! with the memory fork's row check, L3-39).

use super::*;

impl GraphFsResolver<'_, '_> {
    /// Whether a walk may name `path`: the reader's live read admits the rows
    /// it stands on, and at a memory fork each of them reads there too, so a
    /// root born after the frontier prints nothing, as its listing shows
    /// nothing ([`Self::path_rows_at_fork`]).
    pub(in crate::graph_fs) fn coreutils_path_visible(&self, path: &str) -> Result<bool> {
        let components = path_components(path)?;
        if self.snapshot.is_some() {
            return self.snapshot_visible(path);
        }
        let live = match components.as_slice() {
            ["claims", "by-id"] | ["claims", "by-time"] | ["claims", "by-time", _] => Ok(true),
            ["claims", "by-time", _, claim] => self
                .scoped_read
                .is_entity_readable(&parse_entity_id(claim)?),
            ["claims", claim] | ["claims", "by-id", claim] => self
                .scoped_read
                .is_entity_readable(&parse_entity_id(claim)?),
            ["entities", entity, ..] | ["backlinks", entity, ..] => {
                self.coreutils_entity_visible(&parse_entity_id(entity)?)
            }
            ["worlds", "base", ..] => Ok(true),
            ["worlds", world, ..] => self.coreutils_entity_visible(&parse_entity_id(world)?),
            _ => Ok(true),
        }?;
        Ok(live && self.path_rows_at_fork(&components)?)
    }

    fn coreutils_entity_visible(&self, id: &EntityId) -> Result<bool> {
        self.scoped_read.persist_grant_clock()?;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.live_policy_manifest_in(&rtxn)?;
        self.coreutils_entity_visible_in(&rtxn, &policy, id)
    }
}
