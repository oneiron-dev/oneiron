//! Where a snapshot's sources live, supplemented as it is written (FIX
//! 11149, 8141, 11766). Each source the producer supplied names one record,
//! the exact version of it read and the words of that version the profile
//! was built from; that association stands as given, attached to the version
//! it names. Placement only adds each world the record lies in now, read in
//! the writing transaction, as a further placement of that same source, so a
//! recipient read honours the owner's recipient choice for every source's
//! world. It never makes a source, a version or a span: a record that is not
//! live, cannot prove its world, or whose placement cannot be read gets no
//! added world, and the write goes on.

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
    /// `profile` with each of its sources also placed in every world its
    /// record lies in now, read in `txn`.
    pub(super) fn psych_profile_placed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        profile: &PsychProfile,
    ) -> Result<PsychProfile> {
        let mut sources = profile.sources.clone();
        for source in &profile.sources {
            let worlds = self
                .psych_profile_source_worlds_in(txn, &source.document_ref)
                .unwrap_or_default();
            sources.extend(worlds.into_iter().map(|world_ref| PsychProfileSource {
                world_ref,
                ..source.clone()
            }));
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
