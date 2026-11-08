//! The rows a skill import stands on as far as it got (FIX 11699), for a
//! caller that lists its answer's rows (`vault.shape.apply`).

use crate::{EntityId, Error, Result};

/// The rows a skill import read that its answer stands on, kept whether the
/// import lands or is refused.
///
/// - `hub` is the SKILL_HUB row its source names, once that row was read.
/// - `existing` is the stored skill its content deduplicated to, once that
///   lookup found one.
///
/// A candidate the import writes is its answer, not a row it read. The
/// writes' own admission reads (batch, claims, provenance) are listed by no
/// caller, on a landing or a refusal alike.
#[derive(Debug, Default)]
pub(crate) struct SkillImportRows {
    pub(crate) hub: Option<EntityId>,
    pub(crate) existing: Option<EntityId>,
}

impl SkillImportRows {
    /// Notes the read of the hub `hub`, whose outcome is `read`: listed
    /// unless no such row exists.
    pub(crate) fn hub_read<T>(&mut self, hub: EntityId, read: &Result<T>) {
        if !matches!(read, Err(Error::EntityNotFound)) {
            self.hub = Some(hub);
        }
    }

    /// The rows noted, hub first.
    pub(crate) fn rows(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.hub.iter().chain(self.existing.iter()).copied()
    }
}
