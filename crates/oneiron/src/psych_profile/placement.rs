//! Where a snapshot's sources live, stamped as it is written (FIX 11149,
//! 8141). A source revision the snapshot cites that names a live record is
//! placed at that record and each world it lies in, read in the writing
//! transaction, so a recipient read honours the owner's recipient choice for
//! every source's world. A placement the writer supplied stands as given. A
//! revision that names no live record, whose record cannot prove its world,
//! or whose placement cannot be read, gets none, and only the read's own
//! world is judged for it, as before; the write goes on. Word spans are not
//! recorded.

use super::record::{PsychProfile, PsychProfileSource};
use crate::claim::base_world_id;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::ScopeAxis;
use crate::federation::record_scope::note_world::note_worlds_in;
use crate::federation::record_scope::record_world_in;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

impl crate::Vault {
    /// `profile` with a placement for every source revision it cites that
    /// none of its own placements covers: the record the revision names and
    /// each world that record lies in, read in `txn`.
    pub(super) fn psych_profile_placed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        profile: &PsychProfile,
    ) -> Result<PsychProfile> {
        let mut sources = profile.sources.clone();
        for revision in &profile.source_revision_ids {
            if profile
                .sources
                .iter()
                .any(|source| source.revision_ref == *revision)
            {
                continue;
            }
            let worlds = self
                .psych_profile_source_worlds_in(txn, revision)
                .unwrap_or_default();
            for world_ref in worlds {
                sources.push(PsychProfileSource {
                    revision_ref: *revision,
                    document_ref: *revision,
                    world_ref,
                });
            }
        }
        if sources.len() == profile.sources.len() {
            return Ok(profile.clone());
        }
        profile.clone().with_sources(sources)
    }

    /// Each world the live record `id` lies in, as every read that checks
    /// a world places it (`record_world_in`), `None` for base reality: a
    /// NOTE in base reality among other worlds is base reality's, as a base
    /// read keeps it, and one in other worlds alone lies in each. None for
    /// a record that is not live or cannot prove its world.
    fn psych_profile_source_worlds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<Option<EntityId>>> {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&self.store, txn, id)?
        else {
            return Ok(Vec::new());
        };
        let reported = |world: EntityId| Some(world).filter(|world| *world != base_world_id());
        if entity_type == ENTITY_TYPE_NOTE {
            return Ok(match note_worlds_in(&self.store, txn, *id).axis() {
                ScopeAxis::Some(worlds) => {
                    worlds.into_iter().map(|world| reported(world.0)).collect()
                }
                ScopeAxis::All | ScopeAxis::Bottom => Vec::new(),
            });
        }
        Ok(record_world_in(&self.store, txn, *id, entity_type, &body)?
            .map(|world| world.and_then(reported))
            .into_iter()
            .collect())
    }
}
